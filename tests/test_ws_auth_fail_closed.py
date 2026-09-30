"""WebSocket streams must fail closed off-loopback when the instance is
unconfigured — the hole the HTTP guard already closed but that never reached
/ws/.

THREAT MODEL. `_api_token_guard` is `@app.middleware("http")`, so it never runs
for a WebSocket. AccessMiddleware gated base `/ws/` only when a shared secret was
set. So an install that set NOTHING and bound off-loopback returned 401 on the
HTTP API but still ACCEPTED `/ws/{session_id}` and `/ws/benchmark/{id}`, which
stream live agent tool output and findings to anyone who connected. The HTTP API
failing closed while the live stream stayed open is the exact "secure if you
configure it" default the HTTP fix rejected.

THE RULE, now identical on both surfaces: no shared secret AND reachable
off-loopback => refuse (ws close 4401), unless ERLIK_ALLOW_UNAUTHENTICATED is
set; loopback stays open (the local dev / thesis workflow); an operator token
authenticates even with the shared secret retired.

Each positive test has a negative control in the same class, so a change that
simply broke websockets (refusing everything) fails the "stays open" assertions
rather than passing this file vacuously.
"""

import asyncio

import pytest
from fastapi import FastAPI, WebSocket
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import orchestrator.integrations.access as access
import orchestrator.operators as operators


@pytest.fixture(autouse=True)
def _temp_db(tmp_path):
    """A clean clone has no data/ dir; the operator-token test needs a DB to
    resolve against. Point the module at a temporary one (test_auth_fail_closed
    pattern)."""
    import orchestrator.database as db_mod
    old_path, old_dir = db_mod.DB_PATH, db_mod.DB_DIR
    db_mod.DB_DIR = tmp_path
    db_mod.DB_PATH = tmp_path / "ws.db"
    try:
        asyncio.run(db_mod.init_db())
        yield
    finally:
        db_mod.DB_PATH, db_mod.DB_DIR = old_path, old_dir


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in ("ERLIK_API_TOKEN", "ERLIK_HOST", "ERLIK_ALLOW_UNAUTHENTICATED"):
        monkeypatch.delenv(k, raising=False)
    yield


def _app():
    app = FastAPI()
    app.add_middleware(access.AccessMiddleware)

    @app.websocket("/ws/session")
    async def socket(ws: WebSocket):
        await ws.accept()
        await ws.send_text("live-agent-output")
        await ws.close()

    @app.websocket("/ws/integrations/x")
    async def isocket(ws: WebSocket):
        await ws.accept()
        await ws.send_text("client-evidence")
        await ws.close()

    return app


def _refused(client, path="/ws/session", headers=None):
    try:
        with client.websocket_connect(path, headers=headers or {}) as ws:
            ws.receive_text()
        return False
    except WebSocketDisconnect:
        return True


def _allowed(client, path="/ws/session", headers=None):
    with client.websocket_connect(path, headers=headers or {}) as ws:
        return ws.receive_text()


class TestUnconfiguredWebsocketFailsClosedOffLoopback:
    def test_an_exposed_bind_refuses(self, monkeypatch):
        monkeypatch.setenv("ERLIK_HOST", "0.0.0.0")
        assert _refused(TestClient(_app())), \
            "an unconfigured 0.0.0.0 bind streamed live agent output over ws"

    def test_a_forwarded_header_refuses(self):
        # The peer is loopback (testclient), but a proxy header means off-box —
        # the same blind spot the HTTP peer signal covers.
        assert _refused(TestClient(_app()),
                        headers={"X-Forwarded-For": "203.0.113.7"})

    def test_loopback_stays_open(self):
        """Negative control. If this fails the change is not 'fail closed', it
        is 'fail' — and it would break the entire local workflow."""
        assert _allowed(TestClient(_app())) == "live-agent-output"

    def test_the_opt_out_reopens_an_exposed_bind(self, monkeypatch):
        monkeypatch.setenv("ERLIK_HOST", "0.0.0.0")
        monkeypatch.setenv("ERLIK_ALLOW_UNAUTHENTICATED", "1")
        assert _allowed(TestClient(_app())) == "live-agent-output"


class TestIntegrationWebsocketIsAlwaysShut:
    def test_integration_ws_refused_without_a_token_even_on_loopback(self):
        # /ws/integrations/ holds client evidence — gated whether or not a token
        # exists, so with none configured it is unreachable by construction.
        assert _refused(TestClient(_app()), path="/ws/integrations/x")


class TestAConfiguredTokenStillGovernsWebsockets:
    def test_no_token_refused_and_the_token_accepted(self, monkeypatch):
        monkeypatch.setenv("ERLIK_API_TOKEN", "tok")
        c = TestClient(_app())
        assert _refused(c)
        assert _allowed(c, headers={"X-API-Token": "tok"}) == "live-agent-output"


class TestOperatorTokenWithTheSharedSecretRetired:
    """Gap 2 on the ws surface: retiring ERLIK_API_TOKEN (the documented way to
    close the bootstrap credential) must not lock a valid operator out of the
    live stream off-loopback."""

    def _mint(self):
        import orchestrator.database as db_mod

        async def _mk():
            db = await db_mod.get_db()
            try:
                return await operators.create(db, "alice@x", role=operators.ROLE_ADMIN)
            finally:
                await db.close()

        return asyncio.run(_mk())

    def test_an_operator_token_authenticates_offloopback(self, monkeypatch):
        monkeypatch.setenv("ERLIK_HOST", "0.0.0.0")  # off-loopback, no shared secret
        op = self._mint()
        c = TestClient(_app())
        assert _refused(c), "sanity: off-loopback with no credential must refuse"
        assert _allowed(c, headers={"X-API-Token": op["token"]}) == "live-agent-output"

    def test_a_bogus_operator_shaped_token_is_still_refused(self, monkeypatch):
        monkeypatch.setenv("ERLIK_HOST", "0.0.0.0")
        self._mint()
        bogus = operators.new_token()  # well-shaped, never stored
        assert _refused(TestClient(_app()), headers={"X-API-Token": bogus})

    def test_the_ws_operator_path_stamps_last_seen(self, monkeypatch):
        """main._api_token_guard records last-seen for HTTP, but it is an
        @app.middleware("http") and never runs for /ws/. So the ws admission path
        must stamp it here or a ws-only operator reads as permanently inactive."""
        monkeypatch.setenv("ERLIK_HOST", "0.0.0.0")
        op = self._mint()
        touched = []
        real_touch = operators.touch

        async def _spy(db, op_id):
            touched.append(op_id)
            return await real_touch(db, op_id)

        # access.py resolves `from orchestrator import operators as _ops` lazily,
        # so patching the module attribute is what the ws path actually calls.
        monkeypatch.setattr(operators, "touch", _spy)
        assert _allowed(TestClient(_app()),
                        headers={"X-API-Token": op["token"]}) == "live-agent-output"
        assert op["id"] in touched, "ws operator admission did not stamp last-seen"
