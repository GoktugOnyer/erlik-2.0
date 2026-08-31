"""Credentials: the one thing erlik must hold and must not leak.

A pentest tool has to log in, so it has to hold a client's password. This is
also the milestone the coverage table says unblocks the most: Broken Access
Control is 6 of the 35 ground-truth items on the benchmark target and NEITHER
lane has ever matched one, because WSTG-AUTHZ-04 needs a low- and a
high-privilege session to compare and has been a named skip on every recorded
run.

The properties, in the order they matter:

  NOTHING READABLE IS STORED. A test walks the live database asserting no
  credential column ever holds plaintext.

  A MISSING KEY IS A REFUSAL. Falling back to plaintext when encryption is
  unavailable looks identical from the outside and is precisely the failure
  encryption exists to prevent.

  UNVERIFIED IS NOT AUTHENTICATED. A login form that answers 200 with "invalid
  credentials" must not be stored as a working session, or every downstream
  case runs unauthenticated while claiming otherwise.
"""

import asyncio
import json

import pytest

from orchestrator import credentials as C
from orchestrator import secrets as S
from orchestrator.login import extract_token

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop"


def _db(tmp_path, monkeypatch):
    import orchestrator.database as db_mod
    monkeypatch.setattr(db_mod, "DB_PATH", str(tmp_path / "c.db"))
    return db_mod


class TestEncryptionAtRest:
    def test_round_trip(self):
        assert S.decrypt(S.encrypt("hunter2")) == "hunter2"

    def test_ciphertext_does_not_contain_the_secret(self):
        assert "hunter2" not in S.encrypt("hunter2")

    def test_the_same_secret_encrypts_differently_each_time(self):
        """Deterministic ciphertext would let anyone with the database tell
        which accounts share a password."""
        assert S.encrypt("hunter2") != S.encrypt("hunter2")

    def test_a_missing_key_refuses_rather_than_falling_back(self, monkeypatch,
                                                            tmp_path):
        """The worst possible behaviour would be storing plaintext when the key
        is unavailable: identical from the outside, and the exact failure this
        module exists to prevent."""
        monkeypatch.setattr(S, "KEY_FILE", tmp_path / "nope" / "deeper" / "k")
        monkeypatch.setenv(S.KEY_ENV, "not-a-valid-fernet-key")
        with pytest.raises(S.SecretError):
            S.encrypt("hunter2")

    def test_the_mask_does_not_leak_length(self):
        assert S.masked(S.encrypt("a")) == S.masked(S.encrypt("a" * 64))

    def test_the_key_is_never_in_the_database(self):
        """A key stored beside the ciphertext it protects is a filing decision,
        not encryption."""
        import pathlib
        src = (pathlib.Path(__file__).resolve().parents[1] / "orchestrator"
               / "secrets.py").read_text()
        assert "ERLIK_SECRET_KEY" in src
        assert "INSERT" not in src and "sqlite" not in src.lower()

    def test_the_key_file_is_gitignored(self):
        import pathlib
        ig = (pathlib.Path(__file__).resolve().parents[1] / ".gitignore").read_text()
        assert "data/.secret_key" in ig


class TestNothingReturnsASecret:
    def test_the_listing_masks_and_drops_the_ciphertext(self, tmp_path, monkeypatch):
        db_mod = _db(tmp_path, monkeypatch)

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            await C.store(db, "http://t.example", "admin", "root", "hunter2",
                          role="high", login_url="http://t.example/login")
            await db.commit()
            rows = await C.listing(db, "http://t.example")
            await db.close()
            return rows

        rows = asyncio.run(go())
        assert len(rows) == 1
        r = rows[0]
        assert r["secret"] == S.MASK
        assert r["has_secret"] is True
        assert "secret_enc" not in r, "the ciphertext is still in the read view"
        assert "hunter2" not in str(r)

    def test_the_stored_column_is_ciphertext(self, tmp_path, monkeypatch):
        db_mod = _db(tmp_path, monkeypatch)

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            await C.store(db, "http://t.example", "a", "u", "hunter2")
            await db.commit()
            row = await (await db.execute(
                "SELECT secret_enc FROM engagement_credentials")).fetchone()
            await db.close()
            return row[0]

        stored = asyncio.run(go())
        assert "hunter2" not in stored
        assert S.is_encrypted(stored)

    def test_the_live_database_holds_no_readable_credential(self):
        """Walks the real database. If this ever fails, a secret is sitting in
        plaintext on disk right now."""
        import pathlib
        import sqlite3
        db = pathlib.Path(__file__).resolve().parents[1] / "data" / "pentest.db"
        if not db.exists():
            pytest.skip("no live database")
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            rows = con.execute(
                "SELECT secret_enc FROM engagement_credentials").fetchall()
        except sqlite3.OperationalError:
            pytest.skip("table not present")
        for (value,) in rows:
            assert not value or S.is_encrypted(value), "plaintext credential on disk"


class TestAccessControlBecomesReachable:
    """The reason this milestone was ranked first."""

    def test_two_roles_supply_what_authz_04_has_always_skipped_for(self, tmp_path,
                                                                   monkeypatch):
        db_mod = _db(tmp_path, monkeypatch)

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            lo = await C.store(db, "http://t.example", "low", "u1", "p1", role="low")
            hi = await C.store(db, "http://t.example", "high", "u2", "p2", role="high")
            await C.save_session(db, lo, "t.example:80", token=JWT + "lo",
                                 status="verified")
            await C.save_session(db, hi, "t.example:80", token=JWT + "hi",
                                 status="verified")
            await db.commit()
            got = await C.auth_inputs(db, "http://t.example")
            lo_t, _ = await C.resolve(db, got["low_priv_token"])
            hi_t, _ = await C.resolve(db, got["high_priv_token"])
            await db.close()
            return got, lo_t, hi_t

        got, lo_t, hi_t = asyncio.run(go())
        # The PLAN receives a handle; only resolution yields the token.
        assert C.HANDLE_RX.fullmatch(got["low_priv_token"])
        assert C.HANDLE_RX.fullmatch(got["high_priv_token"])
        assert lo_t.endswith("lo")
        assert hi_t.endswith("hi")
        assert lo_t != hi_t, "both roles resolved to the same session"

    def test_the_skip_reason_names_the_remedy(self, tmp_path):
        from orchestrator.testcase.sweep import UNSUPPLIABLE
        assert "store low- and high-privilege" in UNSUPPLIABLE["low_priv_token"]
        assert "log in" in UNSUPPLIABLE["jwt"]

    def test_an_unverified_session_supplies_nothing(self, tmp_path, monkeypatch):
        """A login that returned 200 with "invalid credentials" must not become
        a working session — every downstream case would run unauthenticated and
        report clean results."""
        db_mod = _db(tmp_path, monkeypatch)

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            cid = await C.store(db, "http://t.example", "a", "u", "p", role="high")
            await C.save_session(db, cid, "t.example:80", token=JWT,
                                 status="unverified")
            await db.commit()
            got = await C.auth_inputs(db, "http://t.example")
            await db.close()
            return got

        assert asyncio.run(go()) == {}

    def test_a_rejected_session_supplies_nothing(self, tmp_path, monkeypatch):
        db_mod = _db(tmp_path, monkeypatch)

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            cid = await C.store(db, "http://t.example", "a", "u", "p", role="high")
            await C.save_session(db, cid, "t.example:80", token=JWT, status="rejected")
            await db.commit()
            got = await C.auth_inputs(db, "http://t.example")
            await db.close()
            return got

        assert asyncio.run(go()) == {}

    def test_no_credentials_means_no_inputs_not_an_error(self, tmp_path, monkeypatch):
        db_mod = _db(tmp_path, monkeypatch)

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            got = await C.auth_inputs(db, "http://nothing.example")
            await db.close()
            return got

        assert asyncio.run(go()) == {}


class TestTokenExtraction:
    @pytest.mark.parametrize("body,expected", [
        ('{"token":"%s"}' % JWT, JWT),
        ('{"authentication":{"token":"%s"}}' % JWT, JWT),
        ('{"access_token":"Bearer %s"}' % JWT, JWT),
        ('{"data":{"token":"%s"}}' % JWT, JWT),
    ])
    def test_common_shapes(self, body, expected):
        assert extract_token(body) == expected

    @pytest.mark.parametrize("body", [
        "<html>invalid credentials</html>", '{"token":""}', '{"token":"short"}',
        '{"token":"has spaces"}', '{"token":"<script>alert(1)</script>"}',
        "not json at all", "",
    ])
    def test_an_error_page_is_not_a_credential(self, body):
        """The token is about to be interpolated into an Authorization
        header."""
        assert extract_token(body) == ""


class TestTheSecretNeverReachesACommandLine:
    def test_login_uses_an_http_client_not_a_shell_tool(self):
        """A curl command carrying a password would be written into
        steps.tool_input and read back by anything that renders a run."""
        import pathlib
        src = (pathlib.Path(__file__).resolve().parents[1] / "orchestrator"
               / "login.py").read_text()
        assert "httpx" in src
        # The property is "no shell, no tool executor", not "the word curl is
        # absent" — the docstring names curl precisely to explain why it is not
        # used, and a naive string check flagged that explanation.
        for shell_route in ("execute_tool", "subprocess", "os.system", "shell=True"):
            assert shell_route not in src, f"the login can reach a shell via {shell_route}"

    def test_the_failure_message_carries_no_payload(self):
        import inspect
        from orchestrator.login import authenticate
        src = inspect.getsource(authenticate)
        assert "type(e).__name__" in src, (
            "the exception text could contain the posted credentials")


class TestVerificationIsDifferential:
    """The first version of `_verify` returned True for anything that was not
    401/403 — and DVWA answers an unauthenticated /index.php with
    `302 -> login.php`. A form login that never sent DVWA's CSRF token was
    therefore recorded as `verified`, which is the exact failure the function
    exists to prevent. Reproduced against the live container before fixing.

    A status allowlist cannot see this: the "protected" response and the
    rejection are both perfectly ordinary. So the probe is made twice and the
    session is verified only when it CHANGES the answer.
    """

    @staticmethod
    def _probe(with_session, anonymous):
        import asyncio
        from unittest.mock import patch
        from orchestrator.login import _verify

        class R:
            def __init__(self, status, location="", body=b""):
                self.status_code = status
                self.headers = {"location": location} if location else {}
                self.content = body

        class Client:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            def __init__(self, *a, **k):
                self.calls = 0

            async def get(self, url, headers=None):
                self.calls += 1
                return with_session if headers else anonymous

        with patch("orchestrator.login.httpx.AsyncClient", Client):
            return asyncio.run(_verify("http://t/x", "tok", "", "Authorization", 5))

    class _R:
        def __init__(self, status, location="", body=b""):
            self.status_code = status
            self.headers = {"location": location} if location else {}
            self.content = body

    def test_an_identical_response_is_not_verified(self):
        """The DVWA case: both redirect to the login page, so the credentials
        changed nothing."""
        same = self._R(302, "login.php")
        assert self._probe(same, self._R(302, "login.php")) is False

    def test_a_changed_response_is_verified(self):
        assert self._probe(self._R(200, body=b"welcome admin"),
                           self._R(302, "login.php")) is True

    def test_401_is_never_verified_even_if_it_differs(self):
        assert self._probe(self._R(401), self._R(200, body=b"x")) is False

    def test_403_is_never_verified(self):
        assert self._probe(self._R(403), self._R(200, body=b"x")) is False

    def test_with_no_session_material_there_is_nothing_to_verify(self):
        import asyncio
        from orchestrator.login import _verify
        assert asyncio.run(_verify("http://t/x", "", "", "Authorization", 5)) is False

    def test_a_trivial_length_difference_does_not_count_as_access(self):
        """A page carrying a CSRF token or a timestamp differs by a few bytes
        on every request; that is not evidence of authentication."""
        assert self._probe(self._R(200, body=b"a" * 100),
                           self._R(200, body=b"a" * 130)) is False

    def test_the_check_reads_both_responses(self):
        import inspect
        from orchestrator.login import _verify
        src = inspect.getsource(_verify)
        assert "anonymous" in src, "the anonymous control request is gone"
        assert src.count("await cli.get") == 2


class TestASecretNeverLeavesTheStore:
    """The plan is returned by /api/v2/sweep/plan and rendered in the browser.
    `StepResult.command` is the RENDERED command, written to the database and
    shown in the run detail view. A live token in the target dict leaks to both.

    This project has already shipped that bug once — a credential pair reached
    an export because one field sat on a masking exemption list. Handles remove
    the exemption question: there is nothing to mask, because the plaintext was
    never in the object.
    """

    SECRET = "eyJhbGciOiJIUzI1NiJ9.SUPERSECRETVALUE.sig"

    def _target(self, tmp_path, monkeypatch):
        db_mod = _db(tmp_path, monkeypatch)

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            cid = await C.store(db, "http://t.example", "a", "u", "p", role="high")
            await C.save_session(db, cid, "t.example:80", token=self.SECRET,
                                 cookie="SID=SUPERSECRETVALUE", status="verified")
            await db.commit()
            got = await C.auth_inputs(db, "http://t.example")
            await db.close()
            return got

        return asyncio.run(go())

    def test_auth_inputs_returns_no_plaintext_anywhere(self, tmp_path, monkeypatch):
        got = self._target(tmp_path, monkeypatch)
        assert got, "fixture produced no auth inputs"
        blob = json.dumps(got)
        assert "SUPERSECRETVALUE" not in blob, f"secret leaked into auth_inputs: {blob}"

    def test_the_planned_target_carries_no_plaintext(self, tmp_path, monkeypatch):
        """The full path an operator actually sees: auth_inputs -> plan_sweep."""
        from orchestrator.testcase.sweep import plan_sweep
        extra = self._target(tmp_path, monkeypatch)
        cases = [{"id": "X", "name": "n", "category": "c", "severity": "high",
                  "target_schema": {"required": ["url"],
                                    "optional": ["auth_header", "cookie"]}}]
        plan = plan_sweep(cases, "http://t.example", "", None, extra)
        blob = json.dumps(plan)
        assert "SUPERSECRETVALUE" not in blob, f"secret leaked into the plan: {blob}"
        # ...but the auth DID arrive, or this test proves nothing.
        assert "ERLIK_SECRET" in blob, "auth never reached the target at all"

    def test_a_handle_survives_the_injection_check(self, tmp_path, monkeypatch):
        """build_target drops any field that looks injectable. If a handle
        tripped that check, auth would be silently absent from every plan."""
        from orchestrator.engagement import looks_injectable
        got = self._target(tmp_path, monkeypatch)
        for field, value in got.items():
            assert not looks_injectable(value), f"{field} would be dropped: {value}"

    def test_a_handle_is_shell_inert(self, tmp_path, monkeypatch):
        import shlex
        for value in self._target(tmp_path, monkeypatch).values():
            assert shlex.quote(value) == value, value

    def test_resolution_yields_a_usable_header(self, tmp_path, monkeypatch):
        db_mod = _db(tmp_path, monkeypatch)

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            cid = await C.store(db, "http://t.example", "a", "u", "p", role="high")
            await C.save_session(db, cid, "t.example:80", token=self.SECRET,
                                 status="verified")
            await db.commit()
            got = await C.auth_inputs(db, "http://t.example")
            cmd, vals = await C.resolve(db, f"curl -H '{got['auth_header']}' http://t")
            await db.close()
            return cmd, vals

        cmd, vals = asyncio.run(go())
        assert f"Authorization: Bearer {self.SECRET}" in cmd
        assert self.SECRET in vals[0]

    def test_scrub_removes_a_secret_echoed_back_by_a_tool(self):
        out = f"> Authorization: Bearer {self.SECRET}\n< 200 OK"
        assert "SUPERSECRETVALUE" not in C.scrub(out, [self.SECRET])

    def test_an_unverified_session_cannot_be_resolved(self, tmp_path, monkeypatch):
        """Revocation must bite at RUN time, not only at plan time — a plan can
        be minutes old when it executes."""
        db_mod = _db(tmp_path, monkeypatch)

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            cid = await C.store(db, "http://t.example", "a", "u", "p", role="high")
            await C.save_session(db, cid, "t.example:80", token=self.SECRET,
                                 status="verified")
            await db.commit()
            got = await C.auth_inputs(db, "http://t.example")
            # the session is revoked after the plan was built
            await db.execute("UPDATE engagement_sessions SET status = 'rejected'")
            await db.commit()
            cmd, vals = await C.resolve(db, got["auth_header"])
            await db.close()
            return cmd, vals

        cmd, vals = asyncio.run(go())
        assert vals == []
        assert C.has_handle(cmd), "handle was silently dropped instead of kept"


class TestTheRunnerRefusesToRunUnauthenticated:
    """An unresolved handle must FAIL the step. Stripping it and sending the
    request anyway yields an unauthenticated result labelled authenticated —
    a false negative wearing a clean bill of health, which is this project's
    recurring defect shape.
    """

    def test_the_runner_checks_for_handles_before_executing(self):
        import inspect
        from orchestrator.testcase import runner
        src = inspect.getsource(runner.run_test_case)
        assert "_CRED.has_handle" in src, "handle check removed from the runner"
        assert "_CRED.resolve" in src, "resolution removed from the runner"
        assert src.index("_CRED.resolve") < src.index("await execute_tool"), \
            "resolution must happen before execution"

    def test_the_stored_command_is_the_handle_form_not_the_live_one(self):
        import inspect
        from orchestrator.testcase import runner
        src = inspect.getsource(runner.run_test_case)
        assert "live_cmd," in src and "execute_tool(\n                live_cmd" in src, \
            "the resolved command must be what executes"
        assert "command=cmd,                       # handles" in src, \
            "the STORED command must be the handle form"

    # --- behavioural: the request must not go out ---------------------------

    @staticmethod
    def _run(monkeypatch, cmd_template, db):
        """Run a one-step case and report whether the request was SENT."""
        from orchestrator.testcase import runner as R
        from orchestrator.testcase.schema import TestCase, TestStep

        sent = []

        async def spy(cmd, **kw):
            sent.append(cmd)
            return {"success": True, "output": "200 OK"}

        monkeypatch.setattr(R, "execute_tool", spy)
        tc = TestCase(
            id="T", name="t", category="c", severity="high",
            target_schema={"required": ["url"], "optional": ["auth_header"]},
            steps=[TestStep(name="s", tool="curl", command=cmd_template)])
        target = {"url": "http://t.example",
                  "scope": {"allow_hosts": ["t.example"], "allow_ports": [80]}}
        res = asyncio.run(R.run_test_case(tc, target, db=db))
        return res, sent

    def test_a_revoked_session_stops_the_step_instead_of_sending_it(
            self, tmp_path, monkeypatch):
        """THE case a source-inspection test missed. A plan can be minutes old
        when it runs; if the session was revoked in between, the request must
        NOT go out unauthenticated and come back "clean"."""
        db_mod = _db(tmp_path, monkeypatch)

        async def setup():
            await db_mod.init_db()
            db = await db_mod.get_db()
            cid = await C.store(db, "http://t.example", "a", "u", "p", role="high")
            sid = await C.save_session(db, cid, "t.example:80", token=JWT,
                                       status="verified")
            await db.commit()
            return db, C.handle(sid, "auth_header")

        db, h = asyncio.run(setup())
        asyncio.run(db.execute("UPDATE engagement_sessions SET status='rejected'"))
        asyncio.run(db.commit())

        res, sent = self._run(monkeypatch, f"curl -H '{h}' http://t.example", db)
        asyncio.run(db.close())

        assert sent == [], "an unauthenticated request was SENT and would be reported clean"
        assert res.stopped_early
        assert "no longer verified" in (res.steps[-1].error or "")

    def test_no_credential_store_means_a_named_failure(self, monkeypatch):
        """db=None with a handle in the command: fail, never send."""
        h = C.handle("deadbeef", "auth_header")
        res, sent = self._run(monkeypatch, f"curl -H '{h}' http://t.example", None)
        assert sent == []
        assert res.stopped_early
        assert "no credential store" in (res.steps[-1].error or "")

    def test_a_verified_session_DOES_send_the_resolved_command(
            self, tmp_path, monkeypatch):
        """Positive control. Without this, every test above would still pass if
        auth simply never worked at all."""
        db_mod = _db(tmp_path, monkeypatch)

        async def setup():
            await db_mod.init_db()
            db = await db_mod.get_db()
            cid = await C.store(db, "http://t.example", "a", "u", "p", role="high")
            sid = await C.save_session(db, cid, "t.example:80", token=JWT,
                                       status="verified")
            await db.commit()
            return db, C.handle(sid, "auth_header")

        db, h = asyncio.run(setup())
        res, sent = self._run(monkeypatch, f"curl -H '{h}' http://t.example", db)
        asyncio.run(db.close())

        assert len(sent) == 1
        assert f"Authorization: Bearer {JWT}" in sent[0], sent[0]
        # ...and the STORED command still carries only the handle.
        assert JWT not in res.steps[-1].command
        assert "ERLIK_SECRET" in res.steps[-1].command


class TestTheWiringIsLive:
    """Three capabilities shipped earlier in this project had zero callers.
    A producer nothing consumes looks exactly like a working feature, so the
    call site itself is asserted."""

    def test_the_plan_endpoint_consumes_auth_and_discovered_endpoints(self):
        import inspect
        import orchestrator.main as M
        src = inspect.getsource(M.v2_sweep_plan)
        assert "auth_inputs" in src, "verified sessions never reach a plan"
        assert "as_sweep_inputs" in src, "discovered endpoints never reach a plan"
        assert "discovered=discovered" in src

    def test_operator_supplied_extra_overrides_inferred_auth(self):
        import inspect
        import orchestrator.main as M
        src = inspect.getsource(M.v2_sweep_plan)
        i = src.index("extra = {")
        line = src[i:src.index("\n", i)]
        assert line.index("auth_inputs") < line.index('body.get("extra")'), \
            "inferred auth would override what the operator typed"

    def test_the_run_endpoint_gives_the_runner_a_credential_store(self):
        import inspect
        import orchestrator.main as M
        src = inspect.getsource(M.run_v2_test_case)
        assert "db=await get_db()" in src, \
            "the runner cannot resolve a handle, so every authed step would fail"


class TestLoginFormIsSubmittedLikeABrowser:
    """A browser posts every successful control, not {username, password}.

    DVWA gates its entire login branch on `isset($_POST['Login'])` — and
    `Login` is the SUBMIT BUTTON, not a hidden input. erlik posted
    username+password+CSRF, got HTTP 200 with no login attempted, and recorded
    the session as `rejected` for a reason that had nothing to do with the
    credentials. Harvesting hidden inputs alone was not enough.
    """

    DVWA = '''<html><body>
      <form action="login.php" method="post">
        <input type="text" name="username">
        <input type="password" AUTOCOMPLETE="off" name="password">
        <p class="submit"><input type="submit" value="Login" name="Login"></p>
        <input type='hidden' name='user_token' value='3cd98fd081ec11180d1d38dd1fb14772' />
      </form></body></html>'''

    def _f(self, html, url="http://t.example/login.php"):
        from orchestrator.login import login_form
        return login_form(html, url)

    def test_the_submit_button_is_submitted(self):
        """THE DVWA bug. Without this the application never runs its login
        branch at all and answers 200 as if nothing was tried."""
        f = self._f(self.DVWA)
        assert f["fields"].get("Login") == "Login"

    def test_the_csrf_token_is_submitted(self):
        assert self._f(self.DVWA)["fields"]["user_token"].startswith("3cd98fd0")

    def test_the_action_is_resolved_against_the_page(self):
        f = self._f(self.DVWA, "http://t.example/dvwa/login.php")
        assert f["url"] == "http://t.example/dvwa/login.php"

    def test_a_form_posting_off_host_is_refused_not_rewritten(self):
        """The page is attacker-controlled on a pentest. Silently posting to
        the page URL instead would hide a hostile form from the operator; the
        one mistake here that cannot be walked back is sending the customer's
        password to a third party."""
        html = '<form action="https://evil.test/collect" method="post">' \
               '<input type="password" name="password"></form>'
        f = self._f(html)
        assert f.get("error") and "another origin" in f["error"]
        assert "url" not in f

    def test_the_login_form_is_picked_not_the_search_box(self):
        """A login page routinely also carries a search box and a newsletter
        signup. Submitting those is indistinguishable from a wrong password."""
        html = '''<form action="/search"><input type="text" name="q">
                    <input type="submit" name="go" value="Search"></form>
                  <form action="/session"><input type="text" name="username">
                    <input type="password" name="password">
                    <input type="submit" name="Login" value="Login"></form>'''
        f = self._f(html)
        assert f["url"].endswith("/session")
        assert "q" not in f["fields"]

    def test_unchecked_boxes_are_not_submitted_but_checked_ones_are(self):
        html = '''<form><input type="password" name="password">
                  <input type="checkbox" name="remember" value="1">
                  <input type="checkbox" name="tos" value="yes" checked></form>'''
        fields = self._f(html)["fields"]
        assert "remember" not in fields
        assert fields["tos"] == "yes"

    def test_a_select_submits_its_selected_option(self):
        html = '''<form><input type="password" name="password">
                  <select name="realm"><option value="a">A</option>
                  <option value="b" selected>B</option></select></form>'''
        assert self._f(html)["fields"]["realm"] == "b"

    def test_a_select_with_no_selection_submits_the_first_option(self):
        html = '''<form><input type="password" name="password">
                  <select name="realm"><option value="a">A</option>
                  <option value="b">B</option></select></form>'''
        assert self._f(html)["fields"]["realm"] == "a"

    def test_only_one_submit_button_is_sent_and_it_is_the_login_one(self):
        """A browser sends only the button that was clicked. Sending them all
        could register an account or cancel the request."""
        html = '''<form><input type="password" name="password">
                  <input type="submit" name="cancel" value="Cancel">
                  <input type="submit" name="Login" value="Log in"></form>'''
        fields = self._f(html)["fields"]
        assert fields.get("Login") == "Log in"
        assert "cancel" not in fields

    def test_malformed_markup_does_not_abort_a_login(self):
        assert self._f("<form><input type=password name=password><b>") is not None

    def test_a_page_with_no_form_yields_nothing(self):
        assert self._f("<html><body>no forms here</body></html>") is None


class TestCookiesOnASingleLabelHost:
    """THE bug that made DVWA look like a wrong password.

    http.cookiejar appends ".local" to a dotless request host, so a cookie set
    by `localhost` with `domain=localhost` is stored and never returned. Every
    request got a fresh session, the CSRF token belonged to a session that no
    longer existed, and the login was recorded `rejected`. Nothing errored.

    erlik's recon deliberately accepts single-label internal names — `intranet`,
    `jira`, `vpn` — so this broke cookie auth on exactly the internal
    engagements the feature exists for.
    """

    def test_a_dotless_host_cookie_is_returned(self):
        """The regression test. With stdlib jar semantics this is False."""
        from orchestrator.login import Jar

        class R:
            headers = _Headers([("set-cookie",
                                 "PHPSESSID=abc123; path=/; domain=localhost; HttpOnly")])

        jar = Jar()
        jar.update(R())
        assert jar.header() == "PHPSESSID=abc123"

    def test_the_stdlib_jar_really_does_drop_it(self):
        """Guard on the premise: if http.cookiejar ever started returning this,
        the hand-rolled tracking above would be unnecessary complexity."""
        from http.cookiejar import CookieJar
        import urllib.request
        jar = CookieJar()
        req = urllib.request.Request("http://localhost:8081/login.php")
        res = _FakeResponse(["PHPSESSID=abc123; path=/; domain=localhost"])
        jar.extract_cookies(res, req)
        out = urllib.request.Request("http://localhost:8081/login.php")
        jar.add_cookie_header(out)
        assert out.get_header("Cookie") is None, (
            "stdlib now returns dotless-host cookies; simplify Jar")

    def test_cookies_accumulate_across_requests(self):
        """The session cookie is usually set by the first GET; using only the
        last response's cookies loses it."""
        from orchestrator.login import Jar
        jar = Jar()
        jar.update(_Resp(["PHPSESSID=one; path=/"]))
        jar.update(_Resp(["security=impossible; path=/"]))
        assert "PHPSESSID=one" in jar.header()
        assert "security=impossible" in jar.header()

    def test_a_later_value_replaces_an_earlier_one(self):
        from orchestrator.login import Jar
        jar = Jar()
        jar.update(_Resp(["PHPSESSID=one"]))
        jar.update(_Resp(["PHPSESSID=two"]))
        assert jar.header() == "PHPSESSID=two"

    def test_attributes_are_not_mistaken_for_cookies(self):
        from orchestrator.login import Jar
        jar = Jar()
        jar.update(_Resp(["a=1; path=/; HttpOnly; SameSite=Strict; Max-Age=86400"]))
        assert jar.header() == "a=1"


class _Headers:
    def __init__(self, pairs):
        self._pairs = pairs

    def get_list(self, name):
        return [v for k, v in self._pairs if k.lower() == name.lower()]


class _Resp:
    def __init__(self, cookies):
        self.headers = _Headers([("set-cookie", c) for c in cookies])


class _FakeResponse:
    def __init__(self, cookies):
        self._cookies = cookies

    def info(self):
        import email.message
        m = email.message.Message()
        for c in self._cookies:
            m["Set-Cookie"] = c
        return m


class TestRedirectsAreFollowedSafely:
    class _Client:
        """Replays a scripted redirect chain and records what was sent."""

        def __init__(self, script):
            self.script = script
            self.sent = []

        async def request(self, method, url, data=None, json=None, auth=None,
                          headers=None):
            self.sent.append({"method": method, "url": url, "data": data,
                              "cookie": (headers or {}).get("Cookie")})
            status, location = self.script.pop(0)
            return _Resp2(status, location)

    def _go(self, script, **kw):
        import asyncio
        from orchestrator.login import Jar, request
        cli = self._Client(list(script))
        jar = Jar()
        r = asyncio.run(request(cli, "POST", "http://t.example/login", jar,
                                data={"password": "hunter2"}, **kw))
        return cli, jar, r

    def test_a_same_origin_redirect_is_followed(self):
        cli, _, _ = self._go([(302, "http://t.example/index"), (200, None)])
        assert [s["url"] for s in cli.sent] == [
            "http://t.example/login", "http://t.example/index"]

    def test_a_302_drops_the_credential_body_and_becomes_a_get(self):
        """Reposting the password to the redirect target sends it somewhere
        the operator never named."""
        cli, _, _ = self._go([(302, "/next"), (200, None)])
        assert cli.sent[1]["method"] == "GET"
        assert cli.sent[1]["data"] is None, "the password was reposted"

    def test_a_cross_origin_redirect_is_not_followed(self):
        """Following it would send the customer's session — and on a 307/308
        their password — to a third party."""
        cli, _, r = self._go([(302, "https://evil.test/collect"), (200, None)])
        assert len(cli.sent) == 1, "followed a redirect off-origin"
        assert r.status_code == 302

    def test_cookies_are_carried_across_the_chain(self):
        cli, _, _ = self._go([(302, "/next"), (200, None)])
        assert cli.sent[0]["cookie"] is None
        assert cli.sent[1]["cookie"] == "sid=1", \
            "the session set by the first hop was not carried"

    def test_a_redirect_loop_terminates(self):
        """The bound is ABSOLUTE, not derived from MAX_REDIRECTS — a test that
        reads the same constant it is checking passes at any value, including
        500, and this one did until that was noticed."""
        cli, _, _ = self._go([(302, "/loop")] * 200)
        assert len(cli.sent) <= 21, f"followed {len(cli.sent)} redirects"

    def test_the_redirect_bound_is_sane(self):
        from orchestrator.login import MAX_REDIRECTS
        assert 1 <= MAX_REDIRECTS <= 20


class _Resp2:
    """A redirect hop that also sets a session cookie, like a real login."""

    def __init__(self, status, location):
        self.status_code = status
        pairs = [("set-cookie", "sid=1; path=/; domain=localhost")]
        if location:
            pairs.append(("location", location))
        self.headers = _Headers2(pairs)


class _Headers2(_Headers):
    def get(self, name, default=None):
        vals = self.get_list(name)
        return vals[0] if vals else default


class TestTargetAuthStateIsDerivedNotStored:
    """`engagement_targets.auth_state` is a column written by NOTHING, and the
    engagement page displayed it — so every target read "auth: none" for ever,
    including ones erlik held a verified session for.

    Storing it would have been the worse fix: a flag saying "session verified"
    outlives the session that justified it, and a stale reassurance is exactly
    what this project keeps removing. It is derived from the credential store
    at read time instead.
    """

    @staticmethod
    def _run(tmp_path, setup):
        import asyncio
        import orchestrator.database as db_mod
        from orchestrator import credentials as C
        old = db_mod.DB_PATH
        db_mod.DB_PATH = str(tmp_path / "as.db")
        try:
            async def go():
                await db_mod.init_db()
                db = await db_mod.get_db()
                await setup(db, C)
                await db.commit()
                out = await C.auth_state(db, "http://t.example")
                await db.close()
                return out
            return asyncio.run(go())
        finally:
            db_mod.DB_PATH = old

    def test_no_credential_reads_as_none(self, tmp_path):
        async def setup(db, C):
            pass
        out = self._run(tmp_path, setup)
        assert out["state"] == "none"
        assert out["verified_roles"] == []

    def test_a_credential_without_a_verified_session_is_not_authenticated(self, tmp_path):
        """"credentials stored" and "we can log in" are different claims, and
        sending an operator to the wrong one wastes a run."""
        async def setup(db, C):
            await C.store(db, "http://t.example", "u", "u", "p", role="low")
        out = self._run(tmp_path, setup)
        assert out["state"] == "credentials only"
        assert out["verified_roles"] == []

    def test_a_REJECTED_session_is_not_authenticated(self, tmp_path):
        """The whole point of the differential check in login._verify."""
        async def setup(db, C):
            cid = await C.store(db, "http://t.example", "u", "u", "p", role="high")
            await C.save_session(db, cid, C.target_key("http://t.example"),
                                 token="t", status="rejected")
        assert self._run(tmp_path, setup)["state"] == "credentials only"

    def test_a_verified_session_is_authenticated(self, tmp_path):
        async def setup(db, C):
            cid = await C.store(db, "http://t.example", "u", "u", "p", role="high")
            await C.save_session(db, cid, C.target_key("http://t.example"),
                                 token="t", status="verified")
        out = self._run(tmp_path, setup)
        assert out["state"] == "authenticated"
        assert out["verified_roles"] == ["high"]

    def test_two_privilege_levels_are_called_out(self, tmp_path):
        """WSTG-AUTHZ-04 needs a low AND a high session and has been a named
        skip on every recorded run for want of them."""
        async def setup(db, C):
            for role in ("low", "high"):
                cid = await C.store(db, "http://t.example", role, "u", "p", role=role)
                await C.save_session(db, cid, C.target_key("http://t.example"),
                                     token="t", status="verified")
        out = self._run(tmp_path, setup)
        assert out["verified_roles"] == ["high", "low"]
        assert "access-control" in out["detail"]

    def test_the_summary_attaches_it_to_every_target(self, tmp_path):
        import asyncio
        import orchestrator.database as db_mod
        from orchestrator import engagement as E
        old = db_mod.DB_PATH
        db_mod.DB_PATH = str(tmp_path / "sum.db")
        try:
            async def go():
                await db_mod.init_db()
                db = await db_mod.get_db()
                eid = await E.create(db, "Acme", "acme.example")
                await E.add_target(db, eid, "http://app.acme.example")
                await db.commit()
                out = await E.summary(db, eid)
                await db.close()
                return out
            out = asyncio.run(go())
        finally:
            db_mod.DB_PATH = old
        t = out["targets"][0]
        assert t["auth"]["state"] == "none"
        # the legacy column is overwritten with the derived answer, so a reader
        # of either field gets the same truth
        assert t["auth_state"] == "none"

    def test_the_ui_renders_the_derived_object_not_the_column(self):
        from pathlib import Path
        html = Path("dashboard/templates/index.html").read_text()
        assert "function engAuthBadge" in html
        assert "${engAuthBadge(t)}" in html
        i = html.index("function engAuthBadge")
        blk = html[i:i + 1400]
        assert "t.auth ||" in blk, "the badge reads the stale column first"
        assert "access-control testing possible" in blk
