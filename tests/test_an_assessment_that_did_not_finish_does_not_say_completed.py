"""`status` was "completed" from the top of `run()` and no handler stood between.

`service.run` initialises `status = "completed"`, then runs the stage loop, then finalizes
each registered collector, then rolls the stage statuses up into `partial` if any is not
terminal. The enclosing `try` had handlers for `asyncio.TimeoutError` and
`asyncio.CancelledError` and a `finally` that writes `status` — and nothing for an ordinary
exception. So anything raised after the last assignment wrote `completed` on the way out,
and the rollup that would have said otherwise is the statement after the one that raised.

Measured before the fix, with a `Collector.finish` that raises:

    integration_assessments.status  'completed'
    the interactsh stage row        'running', reason ''
    report()'s engagement status    'completed'

A record that contradicts itself. `persist_result` raising gives the same shape, and so does
the broadcast in the sweep — `finish()` succeeds, the stage row correctly reads `partial`,
and the assessment still says `completed` because the rollup is the very next statement.

THE TRIGGER IS NOT HYPOTHETICAL. `Collector.finish` parses the proxy audit log with
`json_lines(audit.read_text())`, which raises on the first line it cannot parse — and a
truncated last line is exactly what a killed mitmproxy leaves. See
`tests/test_a_truncated_diagnostic_line_is_not_an_assessment_failure.py`.

The exception still PROPAGATES. The caller's error is the only place an unexpected failure
is visible, and swallowing it would trade a wrong status for a silent one.
"""
import asyncio
import json

import pytest

from orchestrator.integrations.contracts import AssessmentConfig, StageResult


def config(**overrides):
    return AssessmentConfig(
        scope={"allow_hosts": ["app.test"], "allow_ports": [443]},
        stages=["interactsh"], active=True,
        callback={"server": "https://callback.test",
                  "probes": [{"url": "https://app.test/fetch", "parameter": "next"}]},
        **overrides)


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


async def _authenticated(*a, **kw):
    return "authenticated"


class _Collector:
    """Probes cleanly; fails only where each test asks it to."""
    instances = []

    def __init__(self, ctx, *, finish_raises=False, close_raises=False):
        self.ctx, self.closed = ctx, False
        self.finish_raises, self.close_raises = finish_raises, close_raises
        _Collector.instances.append(self)

    async def start(self):
        return self

    async def probe(self, sandbox):
        return StageResult()

    async def finish(self, wait=True):
        if self.finish_raises:
            raise RuntimeError("interactsh client log was unreadable")
        return StageResult()

    async def close(self):
        if self.close_raises:
            raise RuntimeError("sandbox exit failed")
        self.closed = True


@pytest.fixture
def lane(tmp_path, monkeypatch):
    import orchestrator.database as original
    from orchestrator.integrations import service
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(service, "Sandbox", _Sandbox)
    monkeypatch.setattr(service, "preflight", lambda *a, **kw: _noop())
    monkeypatch.setattr(service, "authenticate", lambda *a, **kw: _authenticated())
    monkeypatch.setattr(service, "record", lambda *a, **kw: _noop())
    _Collector.instances = []
    return service


@pytest.fixture
async def store(lane):
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    await original.init_db()
    await db.migrate()
    return db


async def drive(lane, store, session, *, identities=0, **collector_kw):
    import orchestrator.integrations.service as module
    from orchestrator.integrations.security import SecretStore
    ids = [SecretStore().put({"name": f"id{n}", "target_origin": "https://app.test",
                              "role": f"r{n}"}) for n in range(identities)]
    module.Collector = lambda ctx: _Collector(ctx, **collector_kw)
    await lane.register(session, "https://app.test",
                        config(identity_ids=ids, anonymous_arm=False) if ids else config())
    raised = None
    try:
        await lane.run(session)
    except BaseException as exc:
        raised = exc
    assessment = (await store.rows("SELECT status FROM integration_assessments "
                                   "WHERE session_id=?", (session,)))[0]["status"]
    stages = [r["status"] for r in await store.rows(
        "SELECT status FROM integration_stages WHERE session_id=?", (session,))]
    return raised, assessment, stages


# --------------------------------------------------------------- the status is honest

async def test_a_clean_run_still_completes(lane, store):
    """The control. Everything below must leave this untouched."""
    raised, assessment, stages = await drive(lane, store, "ok")
    assert (raised, assessment, stages) == (None, "completed", ["completed"])


async def test_a_finalization_error_is_not_a_completed_assessment(lane, store):
    raised, assessment, stages = await drive(lane, store, "boom", finish_raises=True)
    assert assessment == "partial"
    assert isinstance(raised, RuntimeError), "the failure must still reach the caller"


async def test_it_leaves_no_stage_stuck_running(lane, store):
    """Degrading only the assessment moved the self-contradiction one level down, and
    `recover()` repairs stage rows at the next start while leaving the assessment's own
    status alone — so a `running` stage under a finished assessment is a state nothing
    resolves."""
    _, assessment, stages = await drive(lane, store, "boom", finish_raises=True)
    assert "running" not in stages and "queued" not in stages, stages
    assert assessment == "partial"


async def test_the_reason_is_recorded_where_an_assessment_can_carry_one(lane, store):
    """`integration_assessments` has no `reason` column, so it goes in an evidence
    artifact — the way the optional summary already does."""
    await drive(lane, store, "boom", finish_raises=True)
    kinds = {r["kind"]: r for r in await store.rows(
        "SELECT kind,id FROM integration_evidence WHERE session_id='boom'")}
    assert "finalization-error" in kinds
    body = json.loads(await store.evidence_bytes(kinds["finalization-error"]["id"]))
    assert "RuntimeError" in body["error"]
    assert "did not finish" in body["establishes"]


async def test_findings_already_collected_survive(lane, store):
    """The degrade must touch no finding row."""
    from orchestrator.integrations.contracts import IntegrationFinding
    await store.execute("INSERT INTO integration_assessments(session_id,target,status,config) "
                        "VALUES(?,?,?,?)", ("keep", "https://app.test", "queued", "{}"))
    await store.persist_findings("keep", [IntegrationFinding(
        fingerprint="f", title="t", url="https://app.test/x", rule="r", source="zap",
        basis="b")])
    before = await store.rows("SELECT payload FROM integration_findings WHERE session_id='keep'")
    await drive(lane, store, "boom", finish_raises=True)
    after = await store.rows("SELECT payload FROM integration_findings WHERE session_id='keep'")
    assert [r["payload"] for r in before] == [r["payload"] for r in after]


async def test_a_failing_release_is_not_a_failed_assessment(lane, store):
    """The other direction. The work finished; only the cleanup did not, and that is
    recorded rather than promoted into the assessment's verdict."""
    raised, assessment, stages = await drive(lane, store, "leak", close_raises=True)
    assert (assessment, stages) == ("completed", ["completed"])
    assert raised is None, "a release failure must not escape as the run's outcome"


# ------------------------------------------------------- and the releases all happen

async def test_one_failing_release_does_not_strand_the_others(lane, store):
    """Measured before the fix with two collectors and a first `close()` that raises:
    `released=[False, False]` — the second was never reached, and both updates in the
    `finally` were skipped, leaving the assessment at `running`. `running` is not merely
    untidy: `POST /start` permits a resume only while the row says `queued` or `needs_auth`
    and 409s otherwise, so the assessment became permanently unresumable."""
    import orchestrator.integrations.service as module
    from orchestrator.integrations.security import SecretStore
    ids = [SecretStore().put({"name": n, "target_origin": "https://app.test", "role": n})
           for n in ("a", "b", "c")]
    seen = {"n": 0}

    def make(ctx):
        seen["n"] += 1
        return _Collector(ctx, close_raises=(seen["n"] == 1))

    module.Collector = make
    await lane.register("many", "https://app.test",
                        config(identity_ids=ids, anonymous_arm=False))
    await lane.run("many")
    released = [c.closed for c in _Collector.instances]
    assert released == [False, True, True], released
    assessment = (await store.rows("SELECT status FROM integration_assessments "
                                   "WHERE session_id='many'"))[0]["status"]
    assert assessment == "completed", "the terminal status is written before the releases"


async def test_an_unreleased_collector_is_named(lane, store):
    """A leaked collector holds a container and a client task until `recover_orphans()`
    sweeps at the next orchestrator start. An operator has to be able to find out."""
    await drive(lane, store, "leak", close_raises=True)
    rows = {r["kind"]: r["id"] for r in await store.rows(
        "SELECT kind,id FROM integration_evidence WHERE session_id='leak'")}
    assert "collector-not-released" in rows
    body = json.loads(await store.evidence_bytes(rows["collector-not-released"]))
    assert body["leaked"][0]["adapter"] == "interactsh"
    assert "RuntimeError" in body["leaked"][0]["error"]
    assert "recover_orphans" in body["establishes"]


async def test_a_second_cancellation_during_cleanup_releases_everything(lane, store):
    """A cancelled task cannot await: the bare `await collector.close()` raised
    CancelledError at once for every collector after the one the cancellation landed in.
    Measured on three cleanups with the second cancel landing inside the first —

        bare        completed [2, 3]
        shielded    completed [1, 2, 3]

    `service.release` shields, so the close runs even when we stop waiting."""
    import orchestrator.integrations.service as module
    from orchestrator.integrations.security import SecretStore
    ids = [SecretStore().put({"name": n, "target_origin": "https://app.test", "role": n})
           for n in ("a", "b", "c")]
    seen = {"n": 0}

    class _Slow(_Collector):
        async def probe(self, sandbox):
            if self.block:
                await asyncio.sleep(3600)
            return StageResult()

        async def close(self):
            await asyncio.sleep(0.05)       # a real close awaits a container stop
            self.closed = True

    def make(ctx):
        seen["n"] += 1
        collector = _Slow(ctx)
        collector.block = seen["n"] == 3
        return collector

    module.Collector = make
    await lane.register("cancel", "https://app.test",
                        config(identity_ids=ids, anonymous_arm=False))
    task = asyncio.create_task(lane.run("cancel"))
    await asyncio.sleep(0.3)
    task.cancel()
    await asyncio.sleep(0.01)               # the second lands inside the cleanup loop
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(0.3)
    assert all(c.closed for c in _Collector.instances), [c.closed for c in _Collector.instances]


async def test_a_cancellation_inside_the_status_write_still_writes_it(lane, store,
                                                                     monkeypatch):
    """The outer shield, which the per-release shield does not cover.

    Each release is shielded individually, so the releases survive a cancellation on their
    own — but the two status UPDATEs and the terminal broadcast are not releases, and a
    cancellation delivered inside them leaves the assessment at `running`, which `POST
    /start` refuses to resume. An adversarial pass measured that window at 0.8ms against
    0.4s for a release, so it is narrow rather than absent; here it is forced open so the
    shield is tested rather than assumed.
    """
    import orchestrator.integrations.service as module
    from orchestrator.integrations import persistence as db

    real = db.execute
    pending = {"task": None}

    async def slow(sql, *args, **kwargs):
        # THE TEARDOWN'S write, identified by `elapsed_seconds`. Matching
        # "UPDATE integration_assessments SET status=" also matched the one at the TOP of
        # run() that sets `running`, so the cancellation landed before any stage ran and the
        # row simply stayed `queued` — the assertion below then passed without the shield
        # doing anything, which is the vacuous-pass shape this file is about.
        if "elapsed_seconds=elapsed_seconds" in sql:
            # Cancel while this statement is in flight, the way a second Stop click does.
            if pending["task"] is not None:
                pending["task"].cancel()
            await asyncio.sleep(0.05)
        return await real(sql, *args, **kwargs)

    module.Collector = lambda ctx: _Collector(ctx)
    await lane.register("late", "https://app.test", config())
    assert await store.rows("SELECT 1 FROM integration_assessments WHERE session_id='late'")
    # Patched AFTER register, so only the teardown's own write is slowed.
    monkeypatch.setattr(module.db, "execute", slow)
    task = asyncio.create_task(lane.run("late"))
    pending["task"] = task
    await asyncio.sleep(0.4)
    task.cancel()
    try:
        await task
    except BaseException:
        pass
    await asyncio.sleep(0.3)
    # Restore ONLY what this test patched. `monkeypatch.undo()` undoes every setattr made
    # through the same fixture instance — including the lane fixture's DB_PATH — so the
    # query below then ran against a different database and found no row at all.
    module.db.execute = real
    status = (await store.rows("SELECT status FROM integration_assessments "
                              "WHERE session_id='late'"))[0]["status"]
    # `completed`, because the cancellation arrives during the TEARDOWN — the run itself
    # finished — so the status the teardown was carrying is the one that must land. Without
    # the shield the teardown runs inside the cancelled task, the sleep above raises, the
    # UPDATE never executes and the row stays `running`. That is the difference this asserts.
    assert status == "completed", (
        f"the terminal status was not written (row says {status!r}); POST /start permits a "
        f"resume only while it says queued or needs_auth, so this assessment is stuck")
