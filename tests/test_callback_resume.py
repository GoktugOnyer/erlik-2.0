"""E-002: a paused run has to be able to resume its pending callback checks.

docs/future-plan.md, R0: "A paused run resumes pending SSRF checks with fresh
correlation IDs; previously issued probes are not silently replayed; interrupted
collection remains explicitly incomplete."

Resume is not a separate code path: it is a second `service.run(session_id)`,
which picks up work with

    SELECT * FROM integration_stages WHERE session_id=? AND status IN ('queued','needs_auth')

and `POST /api/sessions/{id}/start` permits it only while the assessment row says
`queued` or `needs_auth` — once, then 409. So the stage row IS the resume marker,
and there is exactly one chance to use it.

The pause used to erase that marker with its own cleanup. Authentication expiry
sets the stage to `needs_auth` and breaks the loop; the collector sweep then runs
`persist_result` for the SAME stage id with status `partial`, and that UPDATE is
unconditional. The assessment then invited a resume that could select nothing.
"""
import asyncio

import pytest

from orchestrator.integrations.contracts import AssessmentConfig, StageResult


def config(**overrides):
    return AssessmentConfig(
        scope={"allow_hosts": ["app.test"], "allow_ports": [443]},
        stages=["interactsh"], active=True,
        callback={"server": "https://callback.test",
                  "probes": [{"url": "https://app.test/fetch", "parameter": "next"}]},
        **overrides)


@pytest.fixture
async def database(tmp_path, monkeypatch):
    import orchestrator.database as original
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    from orchestrator.integrations import persistence
    await original.init_db()
    await persistence.migrate()
    return persistence


class _Collector:
    """Mints a fresh correlation host per instance, as interactsh-client does."""

    minted = []

    def __init__(self, ctx):
        self.ctx = ctx
        self.host = f"probe{len(_Collector.minted)}.callback.test"
        _Collector.minted.append(self.host)
        self.issued = []

    async def start(self):
        return self

    async def probe(self, sandbox):
        self.issued.append(self.host)
        return StageResult()

    async def finish(self, wait=True):
        return StageResult()

    async def close(self):
        pass


@pytest.fixture
def lane(monkeypatch):
    from orchestrator.integrations import service
    import orchestrator.integrations.service as module

    class _Sandbox:
        def __init__(self, *a, **kw):
            self.policy = {}
            self.on_close = None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    async def _noop(*a, **kw):
        return None

    _Collector.minted = []
    monkeypatch.setattr(service, "Sandbox", _Sandbox)
    monkeypatch.setattr(service, "preflight", _noop)
    monkeypatch.setattr(service, "record", _noop)
    module.Collector = _Collector
    return service


async def _pause_then_resume(service, monkeypatch, database):
    """Run once with authentication failing mid-stage, then run again."""
    attempts = {"n": 0}

    async def authenticate(ctx, sandbox):
        # Succeeds on entry, fails the post-stage re-check of the first run only.
        attempts["n"] += 1
        return attempts["n"] != 2

    monkeypatch.setattr(service, "authenticate", authenticate)
    from orchestrator.integrations.security import SecretStore
    identity_id = SecretStore().put({
        "name": "reader", "target_origin": "https://app.test",
        "check": {"url": "https://app.test/me", "expected_status": 200, "body_contains": "reader"}})
    await service.register("pause", "https://app.test", config(identity_ids=[identity_id]))
    first = await service.run("pause")
    rows = await database.rows("SELECT status, reason FROM integration_stages WHERE session_id='pause'")
    paused = dict(rows[0])

    async def always(ctx, sandbox):
        return True

    monkeypatch.setattr(service, "authenticate", always)
    second = await service.run("pause")
    return first, paused, second


async def test_a_paused_run_can_still_select_its_callback_stage(lane, database, monkeypatch):
    """The stage row is the resume marker, and the sweep must not erase it."""
    first, paused, second = await _pause_then_resume(lane, monkeypatch, database)
    assert first == "needs_auth"
    assert paused["status"] == "needs_auth", (
        f"the pause left the stage {paused['status']!r}, which `run()` cannot select again — "
        f"so the one resume the API permits finds nothing to do")


async def test_the_resume_issues_a_fresh_correlation_id_and_replays_nothing(
        lane, database, monkeypatch):
    first, paused, second = await _pause_then_resume(lane, monkeypatch, database)
    hosts = _Collector.minted
    assert len(hosts) >= 2, (
        "the resume never constructed a collector, so no pending check was re-issued")
    assert len(set(hosts)) == len(hosts), "a correlation host was reused across runs"


async def test_the_interruption_is_still_reported(lane, database, monkeypatch):
    """Resumability must not be bought by hiding the interruption: the reason has
    to say the observation was cut short."""
    first, paused, second = await _pause_then_resume(lane, monkeypatch, database)
    assert "interrupted" in (paused["reason"] or ""), paused
    assert "authentication" in (paused["reason"] or "").lower()
