"""P2-11: auto-attach stored session auth to the commands the agent dispatches.

When the stateful-session feature is on, the auth a session already harvested
(headers, cookies) rides along automatically so the model need not re-paste a
token each turn. The feature is OFF by default and, when off, an EXACT no-op:
the command string is unchanged before dispatch, so the frozen experiment arms
are byte-for-byte unaffected.

These tests assert against the real `tool_executor.attach_session_auth` and the
real `execute_tool`, driven by a store that implements the shared SessionStore
contract — NOT a re-implementation of either. The store is the one external
dependency a sibling slice owns (`orchestrator.session_state`); the stub here
implements only its documented surface (`auth_headers()`, `cookies()`, `all()`),
so the slice is testable before that module merges.
"""

import pathlib

import pytest

import orchestrator.tool_executor as TE


# --- A store matching the shared SessionStore contract --------------------- #

class _Primitive:
    """Primitive(kind, name, value, source, scope_host) — the contract shape."""

    def __init__(self, kind, name, value, scope_host=None, source="harvested"):
        self.kind = kind
        self.name = name
        self.value = value
        self.source = source
        self.scope_host = scope_host


class _Store:
    """Minimal SessionStore: the accessors the attach step consumes, plus all()."""

    def __init__(self, headers=None, cookies=None, primitives=None):
        self._headers = dict(headers or {})
        self._cookies = dict(cookies or {})
        self._prims = list(primitives or [])

    def auth_headers(self):
        return dict(self._headers)

    def cookies(self):
        return dict(self._cookies)

    def all(self, kind=None):
        if kind is None:
            return list(self._prims)
        return [p for p in self._prims if p.kind == kind]


def _store_for(host="target.test", with_cookie=True):
    headers = {"Authorization": "Bearer eyJhdHRhY2s.payload.sig"}
    cookies = {"sessionId": "s3cr3t"} if with_cookie else {}
    prims = [_Primitive("token", "authorization", "eyJhdHRhY2s.payload.sig", host)]
    if with_cookie:
        prims.append(_Primitive("cookie", "sessionId", "s3cr3t", host))
    return _Store(headers, cookies, prims)


# --- attach_session_auth: the unit under test ------------------------------ #

class TestAttachSessionAuth:
    def test_curl_gets_the_header_and_the_cookie(self):
        cmd, note = TE.attach_session_auth(
            "curl -s http://target.test/api", _store_for(), "http://target.test")
        assert "-H 'Authorization: Bearer eyJhdHRhY2s.payload.sig'" in cmd
        assert "-b sessionId=s3cr3t" in cmd
        assert note and "Authorization" in note and "cookie" in note

    def test_the_original_command_is_a_prefix_of_the_result(self):
        base = "curl -s http://target.test/api"
        cmd, _ = TE.attach_session_auth(base, _store_for(), "http://target.test")
        assert cmd.startswith(base + " ")

    def test_the_note_never_carries_the_secret_value(self):
        _, note = TE.attach_session_auth(
            "curl http://target.test/", _store_for(), "http://target.test")
        assert "eyJhdHRhY2s" not in note
        assert "s3cr3t" not in note

    def test_a_tool_that_takes_a_cookie_header_uses_one(self):
        # ffuf has no cookie flag in the map; the cookie rides as a Cookie header.
        cmd, _ = TE.attach_session_auth(
            "ffuf -u http://target.test/FUZZ -w w.txt", _store_for(), "http://target.test")
        assert "-H 'Cookie: sessionId=s3cr3t'" in cmd
        assert "-b " not in cmd

    def test_an_unsupported_tool_is_left_untouched(self):
        base = "nmap -sV target.test"
        cmd, note = TE.attach_session_auth(base, _store_for(), "http://target.test")
        assert cmd == base and note is None

    def test_a_command_that_already_authenticates_is_left_untouched(self):
        base = 'curl -s -H "Authorization: Bearer mine" http://target.test/'
        cmd, note = TE.attach_session_auth(base, _store_for(), "http://target.test")
        assert cmd == base and note is None

    def test_no_store_is_a_no_op(self):
        base = "curl http://target.test/"
        assert TE.attach_session_auth(base, None, "http://target.test") == (base, None)

    def test_an_empty_store_is_a_no_op(self):
        base = "curl http://target.test/"
        cmd, note = TE.attach_session_auth(base, _Store(), "http://target.test")
        assert cmd == base and note is None


class TestScopeIsTheBoundary:
    """The scope_host rule — never attach a credential to a host it was not
    harvested for — is the control this feature cannot be allowed to weaken. If
    any assertion here passes while the guard is removed, the guard is decorative;
    each was confirmed to FAIL against a mutant with the check deleted."""

    def test_a_command_naming_another_host_gets_nothing(self):
        base = "curl -s http://evil.test/collect"
        cmd, note = TE.attach_session_auth(base, _store_for(), "http://target.test")
        assert cmd == base and note is None, "a token must never leave for another host"

    def test_a_command_naming_no_host_gets_nothing(self):
        # No explicit target in the command -> do not guess where the token goes.
        base = "curl -s /relative/path"
        cmd, note = TE.attach_session_auth(base, _store_for(), "http://target.test")
        assert cmd == base and note is None

    def test_with_no_session_target_nothing_is_attached(self):
        base = "curl http://target.test/"
        assert TE.attach_session_auth(base, _store_for(), None) == (base, None)

    def test_a_credential_harvested_for_a_different_host_is_dropped(self):
        # Token in scope for target.test; cookie was harvested for other.test.
        store = _Store(
            {"Authorization": "Bearer ok-token"},
            {"sess": "cookie-for-other"},
            [_Primitive("token", "authorization", "ok-token", "target.test"),
             _Primitive("cookie", "sess", "cookie-for-other", "other.test")])
        cmd, note = TE.attach_session_auth(
            "curl http://target.test/a", store, "http://target.test")
        assert "ok-token" in cmd, "the in-scope token should ride along"
        assert "cookie-for-other" not in cmd, "the other host's cookie must be dropped"
        assert "cookie" not in (note or "")

    def test_an_unscoped_credential_rides_the_session_target(self):
        # scope_host unset = session-wide; it belongs on the session target.
        store = _Store({"Authorization": "Bearer anytok"}, {},
                       [_Primitive("token", "authorization", "anytok", None)])
        cmd, _ = TE.attach_session_auth(
            "curl http://target.test/a", store, "http://target.test")
        assert "anytok" in cmd

    def test_a_port_difference_is_still_the_same_host(self):
        cmd, note = TE.attach_session_auth(
            "curl http://target.test:8443/a", _store_for(), "http://target.test")
        assert note is not None and "Authorization" in note


# --- execute_tool integration: the flag gate and the no-op guarantee ------- #

class TestExecuteToolGate:
    async def _run(self, monkeypatch, *, stateful, store, command="curl -s http://target.test/a"):
        seen = {}

        def fake_exec(cmd, timeout, argv=None):
            seen["command"] = cmd
            return {"output": "ok", "returncode": 0, "error": None}

        monkeypatch.setattr(TE, "_sync_docker_exec", fake_exec)
        monkeypatch.setattr(TE, "ERLIK_NATIVE", True)  # skip the container check
        r = await TE.execute_tool(command, ["curl"], target_url="http://target.test",
                                  stateful_session=stateful, session_store=store)
        return r, seen

    async def test_on_attaches_and_reports_it(self, monkeypatch):
        r, seen = await self._run(monkeypatch, stateful=True, store=_store_for())
        assert "Authorization: Bearer" in seen["command"]
        assert r.get("auth_attached"), "the result must report the attach honestly"

    async def test_off_is_byte_for_byte_unchanged(self, monkeypatch):
        r_off, off = await self._run(monkeypatch, stateful=False, store=_store_for())
        # A store is present but the flag is off: the command must be identical to
        # the one a store-less run would dispatch.
        _, none = await self._run(monkeypatch, stateful=False, store=None)
        assert off["command"] == none["command"]
        assert "Authorization" not in off["command"]
        assert "auth_attached" not in r_off

    async def test_on_without_a_store_is_also_a_no_op(self, monkeypatch):
        r, seen = await self._run(monkeypatch, stateful=True, store=None)
        assert "Authorization" not in seen["command"]
        assert "auth_attached" not in r

    async def test_attach_does_not_fire_for_an_out_of_scope_command(self, monkeypatch):
        # The scope guard inside execute_tool refuses an unrelated public host
        # BEFORE dispatch, so the attach never even runs.
        r, seen = await self._run(monkeypatch, stateful=True, store=_store_for(),
                                  command="curl -s http://example.org/x")
        assert seen == {}, "an out-of-scope command must not reach dispatch"
        assert r["executed"] is False


def test_the_agent_loop_passes_the_lever_and_store_to_execute_tool():
    """Wiring guard: a run_config key nothing reads is this codebase's signature
    defect. stateful_session AND the store must both reach execute_tool, or the
    feature is inert whatever the dashboard shows."""
    src = (pathlib.Path(__file__).resolve().parents[1]
           / "orchestrator" / "main.py").read_text()
    assert 'stateful_session=runcfg.get("stateful_session"' in src
    assert "session_store=_session_store" in src
