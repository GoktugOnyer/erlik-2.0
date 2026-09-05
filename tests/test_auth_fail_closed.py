"""With no token configured, the API must refuse anything off-loopback.

Before this, an install that set nothing served every route to whoever could
reach the port -- /api/engagements, /api/v2/targets/credentials,
/api/thesis/export. The only thing between a hosted Erlik and its engagement
records was that the operator remembered an environment variable nothing
prompted them for. "Secure if you configure it" is not a posture; the default
is what ships.

The rule implemented: no token AND the instance looks reachable off-loopback
=> 401. Loopback stays open, because that is the entire local workflow and
breaking it would only teach operators to set ERLIK_ALLOW_UNAUTHENTICATED=1
everywhere.

Two signals decide "off-loopback" and both are tested, because each alone has
a blind spot. ERLIK_HOST is what run.sh and scripts/ bind, and it is known
before any request arrives -- but someone typing `uvicorn --host 0.0.0.0`
sets nothing. The peer address covers that case, and a forwarded header covers
the proxy case, where the peer address is loopback and therefore worthless as
evidence.
"""

import importlib

import pytest
from fastapi.testclient import TestClient

PROBE = "/api/engagements"      # returns customer records
TOKEN = "s3cr3t-token"


# ---------------------------------------------------------------------------
# A clean clone has no data/ directory at all -- it is gitignored -- so the
# DB-backed reads these tests probe raise `unable to open database file` rather
# than returning anything the guard could be judged on. CI caught exactly that.
# Point the module at a temporary database and create the schema, following the
# pattern already used in test_redaction.py. The subject here is the auth
# decision, but it has to be read off a route that actually works, or a passing
# assertion means only that the request failed for some other reason.
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _temp_db(tmp_path):
    import asyncio

    import orchestrator.database as db_mod
    old_path, old_dir = db_mod.DB_PATH, db_mod.DB_DIR
    db_mod.DB_DIR = tmp_path
    db_mod.DB_PATH = tmp_path / "auth.db"
    try:
        asyncio.run(db_mod.init_db())
        yield
    finally:
        db_mod.DB_PATH, db_mod.DB_DIR = old_path, old_dir


def _reload(monkeypatch, **env):
    for k in ("ERLIK_API_TOKEN", "ERLIK_HOST", "ERLIK_ALLOW_UNAUTHENTICATED"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    import orchestrator.main as M
    importlib.reload(M)
    return M


@pytest.fixture(autouse=True)
def _restore():
    """Every test here reloads the module under a doctored environment; put it
    back afterwards or the next file inherits a fail-closed app."""
    yield
    import orchestrator.main as M
    importlib.reload(M)


class TestTheBindSignal:
    @pytest.mark.parametrize("host", ["0.0.0.0", "::", "*", "10.0.0.5"])
    def test_an_exposed_bind_with_no_token_is_refused(self, monkeypatch, host):
        M = _reload(monkeypatch, ERLIK_HOST=host)
        r = TestClient(M.app).get(PROBE)
        assert r.status_code == 401, (
            f"ERLIK_HOST={host} with no token served customer records"
        )
        assert "ERLIK_API_TOKEN" in r.json()["detail"], (
            "the refusal must name the variable that fixes it, or the operator "
            "just sees a broken app"
        )

    @pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost", ""])
    def test_a_loopback_bind_stays_open(self, monkeypatch, host):
        """The negative control. If this fails the change is not 'fail closed',
        it is 'fail'."""
        M = _reload(monkeypatch, ERLIK_HOST=host)
        assert TestClient(M.app).get(PROBE).status_code != 401

    def test_unset_is_treated_as_loopback(self, monkeypatch):
        """run.sh defaults to 127.0.0.1, so absence is not exposure -- and the
        whole test suite runs with it unset."""
        M = _reload(monkeypatch)
        assert M._bind_is_exposed() is False
        assert TestClient(M.app).get(PROBE).status_code != 401


class TestThePeerSignal:
    def test_a_forwarded_header_counts_as_remote(self, monkeypatch):
        """A proxy makes the peer address loopback, so the peer address alone
        would wave every proxied request through."""
        M = _reload(monkeypatch)
        c = TestClient(M.app)
        assert c.get(PROBE, headers={"X-Forwarded-For": "203.0.113.7"}).status_code == 401
        assert c.get(PROBE, headers={"X-Real-IP": "203.0.113.7"}).status_code == 401

    def test_a_non_loopback_peer_counts_as_remote(self, monkeypatch):
        """`uvicorn --host 0.0.0.0` sets no ERLIK_HOST at all; the peer address
        is the only evidence there is."""
        M = _reload(monkeypatch)
        assert M._request_is_remote(_fake_request("203.0.113.7")) is True
        assert M._request_is_remote(_fake_request("10.0.0.5")) is True
        assert M._request_is_remote(_fake_request("127.0.0.1")) is False
        assert M._request_is_remote(_fake_request("::1")) is False

    def test_an_unknown_peer_does_not_manufacture_a_denial(self, monkeypatch):
        """request.client is None for some transports. Unknown is not evidence
        of remoteness, and a predicate used only to DENY must not invent one."""
        M = _reload(monkeypatch)
        assert M._request_is_remote(_fake_request(None)) is False


def _fake_request(host):
    class _C:
        pass

    r = _C()
    r.headers = {}
    r.client = None if host is None else type("_P", (), {"host": host})()
    return r


class TestTheOptOut:
    @pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
    def test_the_escape_hatch_works(self, monkeypatch, value):
        """A deployment behind an authenticating proxy has to be able to say
        so, or the guard just gets patched out downstream."""
        M = _reload(monkeypatch, ERLIK_HOST="0.0.0.0",
                    ERLIK_ALLOW_UNAUTHENTICATED=value)
        assert TestClient(M.app).get(PROBE).status_code != 401

    @pytest.mark.parametrize("value", ["0", "false", "no", "", "maybe"])
    def test_anything_else_does_not_open_it(self, monkeypatch, value):
        """Guard on the opt-out: a truthiness test written as `if os.environ.get(...)`
        would treat "0" and "false" as consent."""
        M = _reload(monkeypatch, ERLIK_HOST="0.0.0.0",
                    ERLIK_ALLOW_UNAUTHENTICATED=value)
        assert TestClient(M.app).get(PROBE).status_code == 401


class TestTheTokenStillWins:
    def test_a_token_serves_an_exposed_bind(self, monkeypatch):
        """Fail-closed is the fallback for an UNCONFIGURED instance. Setting a
        token is the supported way to expose one, and must keep working."""
        M = _reload(monkeypatch, ERLIK_API_TOKEN=TOKEN, ERLIK_HOST="0.0.0.0")
        c = TestClient(M.app)
        assert c.get(PROBE, headers={"X-API-Token": TOKEN}).status_code != 401
        assert c.get(PROBE).status_code == 401

    def test_the_wrong_token_is_still_refused_off_loopback(self, monkeypatch):
        M = _reload(monkeypatch, ERLIK_API_TOKEN=TOKEN, ERLIK_HOST="0.0.0.0")
        assert TestClient(M.app).get(
            PROBE, headers={"X-API-Token": "wrong"}).status_code == 401

    def test_the_opt_out_does_not_disable_a_configured_token(self, monkeypatch):
        """ERLIK_ALLOW_UNAUTHENTICATED must only relax the no-token fallback.
        If it also skipped the token check it would be a remote auth bypass."""
        M = _reload(monkeypatch, ERLIK_API_TOKEN=TOKEN, ERLIK_HOST="0.0.0.0",
                    ERLIK_ALLOW_UNAUTHENTICATED="1")
        assert TestClient(M.app).get(PROBE).status_code == 401


class TestLivenessStaysOpen:
    def test_health_answers_from_anywhere_without_a_token(self, monkeypatch):
        """A load balancer probes it before anything is configured, and it
        discloses no engagement data."""
        M = _reload(monkeypatch, ERLIK_HOST="0.0.0.0")
        r = TestClient(M.app).get("/api/health",
                                  headers={"X-Forwarded-For": "203.0.113.7"})
        assert r.status_code == 200

    def test_the_dashboard_itself_is_not_gated(self, monkeypatch):
        """The guard covers /api/* only. Gating the HTML too would mean an
        exposed instance shows a blank page instead of an app that then
        explains it needs a token."""
        M = _reload(monkeypatch, ERLIK_HOST="0.0.0.0")
        assert TestClient(M.app).get("/").status_code == 200


class TestLoopbackClassification:
    """`_is_loopback` decides all of the above. It is used only to DENY, so an
    unparseable host must resolve to 'not remote' rather than inventing a
    refusal on a local box."""

    @pytest.mark.parametrize("host", ["127.0.0.1", "127.1.2.3", "::1",
                                      "localhost", "testclient"])
    def test_local(self, monkeypatch, host):
        M = _reload(monkeypatch)
        assert M._is_loopback(host) is True

    @pytest.mark.parametrize("host", ["10.0.0.5", "203.0.113.7", "0.0.0.0",
                                      "example.com", "", None])
    def test_not_local(self, monkeypatch, host):
        M = _reload(monkeypatch)
        assert M._is_loopback(host) is False


class TestTheTwoRefusalsAreDistinguishable:
    """The dashboard prompts for a token on 401. On an unconfigured instance
    there is no token to enter, so that prompt loops forever and every failure
    reads to the operator as "I typed it wrong". The server labels which 401
    it is; the dashboard branches on the label.
    """

    def test_the_unconfigured_refusal_is_labelled(self, monkeypatch):
        M = _reload(monkeypatch, ERLIK_HOST="0.0.0.0")
        r = TestClient(M.app).get(PROBE)
        assert r.status_code == 401
        assert r.headers.get("X-Erlik-Auth") == "unconfigured"

    def test_a_wrong_token_is_labelled_differently(self, monkeypatch):
        M = _reload(monkeypatch, ERLIK_API_TOKEN=TOKEN, ERLIK_HOST="0.0.0.0")
        r = TestClient(M.app).get(PROBE, headers={"X-API-Token": "wrong"})
        assert r.status_code == 401
        assert r.headers.get("X-Erlik-Auth") == "token-required", (
            "a bad token must still make the dashboard prompt; labelling it "
            "'unconfigured' would replace a working prompt with a banner"
        )

    def test_the_dashboard_branches_on_the_label(self):
        """Guard on the pairing. The header is only worth sending if the client
        reads it, and the two live in different files."""
        from pathlib import Path
        ui = Path(__file__).resolve().parents[1] / "dashboard" / "templates" / "index.html"
        src = ui.read_text()
        i = src.index("resp.status === 401")
        block = src[i:src.index("return resp;", i)]
        assert "X-Erlik-Auth" in block and "unconfigured" in block, block
        assert "prompt(" in block, "the configured-token path must still prompt"
        assert "_erlikAuthBanner" in block

    def test_the_banner_function_exists_and_says_what_to_do(self):
        from pathlib import Path
        ui = Path(__file__).resolve().parents[1] / "dashboard" / "templates" / "index.html"
        src = ui.read_text()
        i = src.index("function _erlikAuthBanner()")
        body = src[i:i + 1400]
        assert "ERLIK_API_TOKEN" in body
        assert "ERLIK_ALLOW_UNAUTHENTICATED" in body
