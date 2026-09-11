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
    # A VERDICT, not a bool — see service.authenticate.
    monkeypatch.setattr(service, "authenticate", lambda *a, **kw: _verdict("authenticated"))
    monkeypatch.setattr(service, "record", lambda *a, **kw: _noop())
    return service


async def _noop():
    return None


async def _verdict(value):
    return value


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


# ===========================================================================
# The other half of the acceptance clause, and a defect the first fix caused.
# "Cancellation and timeout at every awaited startup/probe boundary close all
#  owned jobs; EVIDENCE REMAINS AVAILABLE."
# ===========================================================================

class _CollectorWithCallback(_Collector):
    """Owns a callback that already arrived before the failure."""

    def __init__(self, ctx, raising):
        super().__init__(ctx, raising)
        self.ingested = False

    async def finish(self, wait=True):
        # The real finish() is the ONLY code that reads callbacks.jsonl and
        # records it. close() cancels the task and exits the sandbox; it ingests
        # nothing.
        self.ingested = True
        self.finished = True
        return StageResult()


async def test_a_callback_that_already_arrived_is_ingested_before_release(
        lane, database, monkeypatch):
    """Closing is not ingesting.

    An out-of-band finding has no other basis — the whole claim is a lookup of a
    host only this assessment knew about — so losing the captured callback loses
    the finding entirely, not merely its diagnostics."""
    import orchestrator.integrations.service as module
    _Collector.instances = []
    module.Collector = lambda ctx: _CollectorWithCallback(ctx, asyncio.TimeoutError())
    from orchestrator.integrations import service as svc
    await svc.register("ingest", "https://app.test", config())
    try:
        await svc.run("ingest")
    except BaseException:
        pass
    owned = _Collector.instances[0]
    assert owned.closed, "regression: the owned job was not released"
    assert owned.ingested, (
        "the callback it had already captured was never read — close() releases, "
        "only finish() ingests")


class _CollectorBadClose(_Collector):
    def __init__(self, ctx, raising, fail_closes):
        super().__init__(ctx, raising)
        self.fail_closes = fail_closes
        self.close_calls = 0

    async def finish(self, wait=True):
        self.finished = True
        return StageResult()

    async def close(self):
        self.close_calls += 1
        self.closed = True
        if self.close_calls <= self.fail_closes:
            raise RuntimeError("docker rm -f refused")


@pytest.mark.parametrize("fail_closes,why", [
    (99, "a cleanup that always fails"),
    (1, "a cleanup that fails once"),
])
async def test_a_failing_cleanup_does_not_replace_the_failure_it_cleaned_up_after(
        fail_closes, why, lane, database, monkeypatch):
    """Introduced by the first E-001 fix, and the worse of the two shapes is the
    transient one.

    `except BaseException: await collector.close(); raise` lets a close() that
    itself raises REPLACE the exception being reported. When the original was a
    CancelledError and the retry succeeds, nothing escapes at all: the run
    returns normally, the cancellation is swallowed, and a cancelled asyncio task
    returning normally breaks whoever awaits it during shutdown."""
    import orchestrator.integrations.service as module
    _Collector.instances = []
    module.Collector = lambda ctx: _CollectorBadClose(ctx, asyncio.CancelledError(), fail_closes)
    from orchestrator.integrations import service as svc
    await svc.register("badclose", "https://app.test", config())

    with pytest.raises(asyncio.CancelledError):
        await svc.run("badclose")

    rows = await database.rows("SELECT status FROM integration_stages WHERE session_id='badclose'")
    assert rows[0]["status"] != "running", (
        f"{why}: the stage was left mid-flight because the cleanup error "
        f"displaced the original and skipped the handler that records it")
