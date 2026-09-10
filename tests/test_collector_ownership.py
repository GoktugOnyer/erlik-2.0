"""E-001: a collector that is never registered must still be closed.

docs/future-plan.md, R0: "Cancellation and timeout at every awaited
startup/probe boundary close all owned jobs; evidence remains available."

The ownership handoff in service.run() is three statements:

    collector = await Collector(ctx).start()     # (a) owns a Sandbox and a task
    result = await collector.probe(sandbox)      # (b)
    collectors.append((collector, stage))        # (c) ownership recorded

Everything that closes a collector iterates `collectors`, so a failure between
(a) and (c) leaves the Sandbox entered and the interactsh-client task running.
Two ways in, and the caller catches neither:

    asyncio.TimeoutError  is an Exception and IS caught — by a branch above the
                          one that closes the collector, which does not.
    asyncio.CancelledError inherits from BaseException and not Exception
                          (verified on this interpreter), so neither handler
                          sees it at all.
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
    """A collector that owns something, and records whether it was released."""

    instances = []

    def __init__(self, ctx, raising):
        self.ctx = ctx
        self.raising = raising
        self.closed = False
        self.finished = False
        _Collector.instances.append(self)

    async def start(self):
        return self

    async def probe(self, sandbox):
        raise self.raising

    async def finish(self, wait=True):
        self.finished = True
        return StageResult()

    async def close(self):
        self.closed = True


@pytest.fixture
def lane(monkeypatch):
    """service.run() with everything below the ownership handoff faked out."""
    from orchestrator.integrations import service

    class _Sandbox:
        def __init__(self, *a, **kw):
            self.policy = {}
            self.on_close = None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    _Collector.instances = []
    monkeypatch.setattr(service, "Sandbox", _Sandbox)
    monkeypatch.setattr(service, "preflight", lambda *a, **kw: _noop())
    monkeypatch.setattr(service, "authenticate", lambda *a, **kw: _true())
    monkeypatch.setattr(service, "record", lambda *a, **kw: _noop())
    return service


async def _noop():
    return None


async def _true():
    return True


async def _drive(service, database, raising):
    from orchestrator.integrations import service as svc
    await svc.register("own", "https://app.test", config())
    svc_collector = lambda ctx: _Collector(ctx, raising)
    import orchestrator.integrations.service as module
    module.Collector = svc_collector
    try:
        await svc.run("own")
    except BaseException:
        pass
    return _Collector.instances


@pytest.mark.parametrize("raising,why", [
    (asyncio.TimeoutError(), "the TimeoutError branch does not close the collector"),
    (asyncio.CancelledError(), "CancelledError is a BaseException; neither handler sees it"),
])
async def test_a_collector_that_never_got_registered_is_still_closed(
        raising, why, lane, database, monkeypatch):
    instances = await _drive(lane, database, raising)
    assert instances, "the fake collector was never constructed; the test proves nothing"
    assert instances[0].closed, f"leaked an owned Sandbox and task — {why}"


def test_cancellederror_really_is_outside_except_exception():
    """The premise of the second case, checked rather than assumed — if a future
    Python changes this, the reasoning above needs revisiting, not the test."""
    assert issubclass(asyncio.CancelledError, BaseException)
    assert not issubclass(asyncio.CancelledError, Exception)


async def test_closing_twice_is_safe():
    """Two paths can now close the same collector — the guard at the ownership
    boundary and the sweep over registered ones — and exiting a Sandbox twice is
    not a defined operation."""
    from orchestrator.integrations.interactsh import Collector

    exits = []

    class _Sandbox:
        async def __aexit__(self, *a):
            exits.append(1)

    collector = Collector.__new__(Collector)
    collector.task = None
    collector.sandbox = _Sandbox()
    await collector.close()
    await collector.close()
    assert exits == [1], "the sandbox was exited more than once"


async def test_a_registered_collector_is_still_swept(lane, database):
    """The guard must not change what happens on the success path: a collector
    that probed cleanly is registered, finished, and closed by the sweep."""
    from orchestrator.integrations import service as svc
    import orchestrator.integrations.service as module

    class _Ok(_Collector):
        async def probe(self, sandbox):
            return StageResult()

    _Collector.instances = []
    module.Collector = lambda ctx: _Ok(ctx, None)
    await svc.register("kept", "https://app.test", config())
    await svc.run("kept")
    assert _Collector.instances[0].finished, "a registered collector was never finished"
    assert _Collector.instances[0].closed, "a registered collector was never closed"
