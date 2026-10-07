"""Config-driven login provider (P2-11).

The provider is the product path that generalises the lab's hardcoded
juice-shop login. The properties that matter, in order:

  OFF IS AN EXACT NO-OP. With the master flag `stateful_session` off, the
  provider never runs, seeds nothing, and leaves `login-helper` and every other
  auth path untouched. This is mutation-tested below (break the gate, watch the
  no-op test fail, restore).

  VERIFIED-OR-NOTHING. Only a session that login.authenticate marked `verified`
  (its differential probe changed the server's answer) is seeded. An unverified
  session authenticates nothing, so seeding the agent from one would be a lie.

  NO SECRET IN THE REPORT. The report is logged, broadcast and persisted; a
  token or cookie VALUE must never appear in it.

  NO PLAINTEXT CREDENTIAL IN THE CONFIG. The config names a credential by id;
  the password stays encrypted at rest and is resolved only inside
  login.authenticate, which the provider reuses rather than re-implementing.
"""

import asyncio
from dataclasses import dataclass

import pytest

from orchestrator import credentials as C
from orchestrator import login_provider as LP

# A bearer-shaped token and a two-cookie string, so the seed path exercises both
# primitive kinds and the cookie-name label.
TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop"
COOKIE = "PHPSESSID=deadbeefcafe; remember=1"
TARGET_KEY = "t.example:80"


# --- a contract-faithful stand-in for the sibling's SessionStore ------------
# orchestrator/session_state.py is built by a sibling slice and may be unmerged.
# These doubles implement exactly the documented contract so the REAL provider
# logic is exercised against it; they are a collaborator double, not a
# re-implementation of the code under test.
@dataclass
class _P:
    kind: str
    name: str
    value: str
    source: str
    scope_host: str


class _Store:
    def __init__(self):
        self.items: list[_P] = []

    def add(self, primitive):
        self.items.append(primitive)

    def all(self, kind=None):
        return [p for p in self.items if kind is None or p.kind == kind]

    def summary_facts(self):
        # SECRET-FREE: kind, name and scope only — never the value.
        return "\n".join(f"- {p.kind}:{p.name} @ {p.scope_host}" for p in self.items)


@pytest.fixture
def store_available(monkeypatch):
    """Make the provider believe the shared store contract is importable."""
    monkeypatch.setattr(LP, "_HAVE_STORE", True)
    monkeypatch.setattr(LP, "Primitive", _P)


def _db(tmp_path, monkeypatch):
    import orchestrator.database as db_mod
    monkeypatch.setattr(db_mod, "DB_PATH", str(tmp_path / "lp.db"))
    return db_mod


async def _verified_session(db, credential_id="cred1", *, token=TOKEN,
                            cookie=COOKIE, status="verified"):
    """A persisted session with real encrypted material, as a login would leave."""
    sid = await C.save_session(db, credential_id, TARGET_KEY, token=token,
                               cookie=cookie, header_name="Authorization",
                               status=status, verify_url="http://t.example/me")
    await db.commit()
    return sid


def _patch_authenticate(monkeypatch, *, sid, status="verified"):
    async def fake_auth(db, credential_id, **kw):
        return {"ok": status != "rejected", "session_id": sid, "status": status,
                "has_token": True, "has_cookie": True, "note": "HTTP 200"}
    monkeypatch.setattr("orchestrator.login.authenticate", fake_auth)


# ---------------------------------------------------------------------------
# OFF IS A NO-OP  (the guard — mutation-tested)
# ---------------------------------------------------------------------------
class TestOffIsANoOp:
    def test_flag_off_does_not_run_and_touches_no_store(self, tmp_path, monkeypatch,
                                                        store_available):
        db_mod = _db(tmp_path, monkeypatch)
        store = _Store()
        # If the gate were broken this would call authenticate; make that loud.
        async def boom(db, cid, **kw):  # noqa: ANN001
            raise AssertionError("authenticate must not be reached with the flag off")
        monkeypatch.setattr("orchestrator.login.authenticate", boom)

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            try:
                return await LP.seed(db, store, {"stateful_session": False,
                                                 "login_provider": {"credential_id": "cred1"}},
                                     "http://t.example")
            finally:
                await db.close()

        rep = asyncio.run(go())
        assert rep["ran"] is False
        assert rep["seeded"] == []
        assert store.items == []          # the store was never written
        assert "off" in rep["reason"].lower()

    def test_config_from_run_gates_on_the_master_flag(self):
        # The one gate every entry point shares.
        assert LP.config_from_run({"stateful_session": False,
                                   "login_provider": {"credential_id": "x"}}) is None
        assert LP.config_from_run({"stateful_session": True}) == {}
        assert LP.config_from_run(
            {"stateful_session": True, "login_provider": {"credential_id": "x"}}
        ) == {"credential_id": "x"}


# ---------------------------------------------------------------------------
# DECLARE, DON'T DROP  (flag on, but cannot proceed)
# ---------------------------------------------------------------------------
class TestDeclareDontDrop:
    def test_store_unavailable_is_named_not_swallowed(self, tmp_path, monkeypatch):
        # _HAVE_STORE left False (session_state unmerged); passing a store makes
        # no difference because Primitive cannot be constructed.
        monkeypatch.setattr(LP, "_HAVE_STORE", False)
        db_mod = _db(tmp_path, monkeypatch)

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            try:
                return await LP.seed(db, _Store(), {"stateful_session": True,
                                                    "login_provider": {"credential_id": "c"}},
                                     "http://t.example")
            finally:
                await db.close()

        rep = asyncio.run(go())
        assert rep["ran"] is False
        assert "store" in rep["reason"].lower()

    def test_missing_credential_id_is_named(self, tmp_path, monkeypatch, store_available):
        db_mod = _db(tmp_path, monkeypatch)

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            try:
                return await LP.seed(db, _Store(), {"stateful_session": True,
                                                    "login_provider": {}},
                                     "http://t.example")
            finally:
                await db.close()

        rep = asyncio.run(go())
        assert rep["ran"] is False
        assert "credential_id" in rep["reason"]

    def test_unknown_credential_is_named(self, tmp_path, monkeypatch, store_available):
        db_mod = _db(tmp_path, monkeypatch)

        async def missing(db, cid, **kw):
            raise KeyError(cid)
        monkeypatch.setattr("orchestrator.login.authenticate", missing)

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            try:
                return await LP.seed(db, _Store(), {"stateful_session": True,
                                                    "login_provider": {"credential_id": "nope"}},
                                     "http://t.example")
            finally:
                await db.close()

        rep = asyncio.run(go())
        assert rep["ran"] is False
        assert "not found" in rep["reason"]


# ---------------------------------------------------------------------------
# VERIFIED-OR-NOTHING
# ---------------------------------------------------------------------------
class TestVerifiedOrNothing:
    def test_an_unverified_login_seeds_nothing(self, tmp_path, monkeypatch, store_available):
        db_mod = _db(tmp_path, monkeypatch)
        store = _Store()

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            try:
                sid = await _verified_session(db, status="unverified")
                _patch_authenticate(monkeypatch, sid=sid, status="unverified")
                return await LP.seed(db, store, {"stateful_session": True,
                                                 "login_provider": {"credential_id": "cred1"}},
                                     "http://t.example")
            finally:
                await db.close()

        rep = asyncio.run(go())
        assert rep["ran"] is False
        assert store.items == []
        assert "verified" in rep["reason"].lower()


# ---------------------------------------------------------------------------
# THE HAPPY PATH
# ---------------------------------------------------------------------------
class TestSeedsAVerifiedSession:
    def _run(self, tmp_path, monkeypatch, cfg):
        db_mod = _db(tmp_path, monkeypatch)
        store = _Store()

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            try:
                sid = await _verified_session(db)
                _patch_authenticate(monkeypatch, sid=sid)
                rep = await LP.seed(db, store, cfg, "http://t.example")
                return rep, store, sid
            finally:
                await db.close()

        return asyncio.run(go())

    def test_a_verified_login_seeds_token_and_cookie(self, tmp_path, monkeypatch,
                                                     store_available):
        rep, store, _ = self._run(
            tmp_path, monkeypatch,
            {"stateful_session": True, "login_provider": {"credential_id": "cred1"}})
        assert rep["ran"] is True
        assert sorted(rep["seeded"]) == ["cookie", "token"]
        kinds = {p.kind for p in store.items}
        assert kinds == {"token", "cookie"}
        tok = store.all("token")[0]
        assert tok.value == TOKEN
        assert tok.name == "Authorization"
        assert tok.source == "login_provider:cred1"
        cook = store.all("cookie")[0]
        assert cook.value == COOKIE
        assert cook.name == "PHPSESSID"       # first cookie's name as the label

    def test_scope_host_defaults_to_the_sessions_target(self, tmp_path, monkeypatch,
                                                        store_available):
        rep, store, _ = self._run(
            tmp_path, monkeypatch,
            {"stateful_session": True, "login_provider": {"credential_id": "cred1"}})
        assert rep["scope_host"] == TARGET_KEY
        assert all(p.scope_host == TARGET_KEY for p in store.items)

    def test_an_explicit_scope_host_overrides(self, tmp_path, monkeypatch,
                                             store_available):
        rep, store, _ = self._run(
            tmp_path, monkeypatch,
            {"stateful_session": True,
             "login_provider": {"credential_id": "cred1", "scope_host": "api.example:443"}})
        assert rep["scope_host"] == "api.example:443"
        assert all(p.scope_host == "api.example:443" for p in store.items)

    def test_the_report_carries_no_secret(self, tmp_path, monkeypatch, store_available):
        """The report is logged, broadcast and persisted — a token or cookie
        value in it would leak to every one of those sinks."""
        rep, _, _ = self._run(
            tmp_path, monkeypatch,
            {"stateful_session": True, "login_provider": {"credential_id": "cred1"}})
        blob = repr(rep)
        assert TOKEN not in blob
        assert "deadbeefcafe" not in blob      # the cookie value

    def test_summary_facts_stay_secret_free(self, tmp_path, monkeypatch, store_available):
        """main.py injects store.summary_facts() into the prompt; the values must
        not ride along. (Asserted against the contract-faithful double.)"""
        _, store, _ = self._run(
            tmp_path, monkeypatch,
            {"stateful_session": True, "login_provider": {"credential_id": "cred1"}})
        facts = store.summary_facts()
        assert TOKEN not in facts and "deadbeefcafe" not in facts
        assert "token" in facts and "cookie" in facts


# ---------------------------------------------------------------------------
# SMALL HELPERS
# ---------------------------------------------------------------------------
class TestScopeHostHelper:
    def test_fills_the_default_port(self):
        assert LP._scope_host("http://h.example/login") == "h.example:80"
        assert LP._scope_host("https://h.example/login") == "h.example:443"
        assert LP._scope_host("http://h.example:8081/x") == "h.example:8081"

    def test_empty_when_unparseable(self):
        assert LP._scope_host("") == ""
        assert LP._scope_host("not a url") == ""

    def test_cookie_name_label(self):
        assert LP._cookie_name("PHPSESSID=abc; x=1") == "PHPSESSID"
        assert LP._cookie_name("") == "session"


# ---------------------------------------------------------------------------
# WIRING GUARD — a run_config key nothing reads is this codebase's signature
# defect. The flag MUST be consumed by the agent loop.
# ---------------------------------------------------------------------------
class TestWiredIntoTheAgentLoop:
    def test_main_reads_the_flag_and_calls_the_provider(self):
        import pathlib
        src = (pathlib.Path(__file__).resolve().parents[1]
               / "orchestrator" / "main.py").read_text()
        assert 'runcfg.get("stateful_session")' in src, (
            "the agent loop must read stateful_session, or the flag is inert")
        assert "login_provider" in src and ".seed(" in src, (
            "the agent loop must call the provider's seed()")
