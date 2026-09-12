"""E-033: an arm could lose its callback collector for the rest of the session.

`CatalogueAdapter` runs the out-of-band case through the collector its own arm's interactsh
stage started, and `run()` selects stages at `queued` or `needs_auth` only. So any pass-1
path that left the interactsh row at some OTHER status removed that dependency permanently
while leaving the catalogue row resumable. Measured on the committed code, with
`Collector.start()` raising and the next stage pausing on authentication:

    pass 1   interactsh failed "callback registration refused"   testcases queued
    resume   selects katana + testcases, NOT interactsh
    pass 2   testcases partial "SSRF check incomplete: callback collector unavailable"

and the assessment is then `partial`, which `POST /start` refuses — so the check could not
run for that session at all, by any route short of a new assessment. The skip itself was
already honest (see `test_a_skipped_callback_case_is_recorded_as_skipped`); what was wrong is
that no resume could clear it.

`requeue_lost_collectors` re-queues the dependency along with the catalogue work that needs
it. The interesting half of this file is not that the retry happens — it is the four places
it must NOT: a healthy arm, an arm whose catalogue work is already done, the OTHER arm, an
assessment that selected no callback case, and the `needs_auth` pause path that already
worked. A retry that fires where it is not needed costs a container and an authentication
probe per arm, and rewriting a `needs_auth` row would break the one resume the API permits.

It is also not a promise that the retry succeeds: a cause that persists fails pass 2
identically, and the catalogue must still record the case as not run. The last test here
guards that, and is a regression guard rather than an ablation target.
"""
import json
import uuid

import pytest

from orchestrator.integrations.contracts import AssessmentConfig, StageResult

CASE = "WSTG-INPV-19"


def config(**overrides):
    return AssessmentConfig(**{
        "scope": {"allow_hosts": ["app.test"], "allow_ports": [443]},
        "stages": ["interactsh", "katana"], "active": True, "surface_read": False,
        "test_cases": [CASE],
        "callback": {"server": "https://callback.test",
                     "probes": [{"url": "https://app.test/fetch", "parameter": "next"}]},
        **overrides})


@pytest.fixture
async def database(tmp_path, monkeypatch):
    import orchestrator.database as original
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    from orchestrator.integrations import persistence
    await original.init_db()
    await persistence.migrate()
    await persistence.execute(
        "INSERT INTO integration_assessments(session_id,target,status,config) VALUES(?,?,?,?)",
        ("s", "https://app.test/", "needs_auth", "{}"))
    return persistence


async def stages(database, *rows):
    """(adapter, identity, status) triples, in the order `register` would create them."""
    made = []
    for adapter, identity, status in rows:
        stage_id = uuid.uuid4().hex
        await database.execute(
            "INSERT INTO integration_stages(id,session_id,adapter,identity_id,status,reason,"
            "finished_at) VALUES(?,?,?,?,?,?,?)",
            (stage_id, "s", adapter, identity, status, f"pass 1 said {status}",
             "2026-09-12T00:00:00"))
        made.append(stage_id)
    return made


async def current(database):
    return {(r["adapter"], r["identity_id"]): dict(r) for r in await database.rows(
        "SELECT adapter,identity_id,status,reason,finished_at FROM integration_stages "
        "WHERE session_id='s'")}


# ---------------------------------------------------------------- the retry happens


class _Collector:
    """Counts how many collectors a pass mints, which is what a wasted retry costs."""

    minted = []
    fail_starts = 0

    def __init__(self, ctx):
        self.ctx = ctx
        self.host = f"probe{len(_Collector.minted)}.callback.test"
        _Collector.minted.append((self.host, ctx.identity_id))

    async def start(self):
        if _Collector.fail_starts > 0:
            _Collector.fail_starts -= 1
            raise RuntimeError("callback registration refused")
        return self

    async def probe(self, sandbox):
        return StageResult()

    async def finish(self, wait=True):
        return StageResult()

    async def close(self):
        pass

    async def run_test_case(self, tc, target, target_sandbox):
        from orchestrator.testcase.runner import RunResult, StepResult
        return RunResult(test_case_id=tc.id, target=target, steps=[StepResult(
            step="issue out-of-band probe", command="curl", success=True,
            output="HTTP/1.1 200 OK", duration_ms=1)])


@pytest.fixture
def lane(monkeypatch, tmp_path):
    from orchestrator.integrations import service
    import orchestrator.integrations.service as module

    class _Sandbox:
        def __init__(self, *a, **kw):
            self.policy = {}
            self.on_close = None
            self.images = {}
            self.directory = tmp_path / "sandbox"
            self.output = self.directory / "output"
            self.output.mkdir(parents=True, exist_ok=True)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    async def _noop(*a, **kw):
        return None

    class _Katana:
        async def run(self, ctx, sandbox):
            return StageResult(status="completed")

    async def controls(session_id, cfg):
        return {"any": {"blocked": False, "status": 401, "body": ""}}

    _Collector.minted = []
    _Collector.fail_starts = 0
    monkeypatch.setattr(service, "Sandbox", _Sandbox)
    monkeypatch.setattr(service, "preflight", _noop)
    monkeypatch.setattr(service, "record", _noop)
    monkeypatch.setattr(service, "authentication_controls", controls)
    monkeypatch.setitem(service.ADAPTERS, "katana", _Katana())
    module.Collector = _Collector
    return service


async def _lose_then_resume(service, database, monkeypatch):
    """The measured pass-1 path: the collector fails to start, then the NEXT stage pauses.

    A pause is what leaves the catalogue row `queued` — without it the catalogue stage runs
    in pass 1 and there is nothing to resume. This is the narrowest reproduction of the
    three real paths, and the only one that does not need a real container.
    """
    from orchestrator.integrations.security import SecretStore
    identity_id = SecretStore().put({
        "name": "reader", "target_origin": "https://app.test",
        "check": {"url": "https://app.test/me", "expected_status": 200,
                  "body_contains": "reader"}})
    await database.execute("DELETE FROM integration_assessments WHERE session_id='s'")
    await service.register("lost", "https://app.test", config(identity_ids=[identity_id]))
    _Collector.fail_starts = 1
    seen = {"n": 0}

    async def authenticate(ctx, sandbox, controls=None):
        seen["n"] += 1
        return "needs_auth" if seen["n"] == 2 else "authenticated"

    monkeypatch.setattr(service, "authenticate", authenticate)
    first = await service.run("lost")

    async def always(ctx, sandbox, controls=None):
        return "authenticated"

    monkeypatch.setattr(service, "authenticate", always)
    rows = {(r["adapter"], r["identity_id"]): dict(r) for r in await database.rows(
        "SELECT adapter,identity_id,status,reason FROM integration_stages "
        "WHERE session_id='lost'")}
    second = await service.run("lost")
    after = {(r["adapter"], r["identity_id"]): dict(r) for r in await database.rows(
        "SELECT adapter,identity_id,status,reason,result FROM integration_stages "
        "WHERE session_id='lost'")}
    return identity_id, first, rows, second, after


async def test_a_resume_re_runs_the_collector_stage_its_catalogue_work_needs(
        lane, database, monkeypatch):
    """End to end through `run()`, so the call site is covered and not only the helper."""
    identity, first, before, second, after = await _lose_then_resume(lane, database, monkeypatch)
    assert first == "needs_auth"
    assert before[("interactsh", identity)]["status"] == "failed", (
        "the reproduction did not happen: pass 1 was supposed to leave this arm's collector "
        f"stage at a status no resume selects, and left it {before[('interactsh', identity)]}")
    assert before[("testcases", identity)]["status"] == "queued", before

    assert after[("interactsh", identity)]["status"] == "completed", (
        "the resume did not re-run the collector stage, so this arm's out-of-band case "
        f"cannot have run: {after[('interactsh', identity)]}")
    observed = json.loads(after[("testcases", identity)]["result"] or "{}").get("observations", [])
    kinds = {o["type"] for o in observed if o.get("test_case_id") == CASE}
    assert "test_case" in kinds, f"the case still did not run for this arm: {observed}"
    assert "test_case_not_run" not in kinds, (
        f"the case was skipped again for want of a collector, which is the whole defect: "
        f"{observed}")


async def test_the_retry_is_issued_a_new_correlation_host(lane, database, monkeypatch):
    """A replayed payload is not evidence. The re-run mints its own, as a pause does."""
    identity, _, _, _, _ = await _lose_then_resume(lane, database, monkeypatch)
    hosts = [host for host, who in _Collector.minted if who == identity]
    assert len(hosts) == 2, f"this arm minted {hosts}, so the retry reused or skipped one"
    assert len(set(hosts)) == 2, f"a correlation host was replayed across passes: {hosts}"


async def test_the_requeue_says_what_pass_one_left_behind(database):
    """`persist_result` overwrites the reason, so the cause goes to evidence as well."""
    from orchestrator.integrations.service import requeue_lost_collectors
    await stages(database, ("interactsh", "arm-a", "failed"), ("testcases", "arm-a", "queued"))
    requeued = await requeue_lost_collectors("s", config())
    assert [r["identity_id"] for r in requeued] == ["arm-a"], requeued
    assert requeued[0]["pass_1_status"] == "failed"
    assert requeued[0]["pass_1_reason"] == "pass 1 said failed"

    row = (await current(database))[("interactsh", "arm-a")]
    assert row["status"] == "queued"
    assert "pass 1 left it failed" in row["reason"], row
    assert "pass 1 said failed" in row["reason"], (
        f"the reason dropped what pass 1 recorded, which is the only cause a reader has: "
        f"{row['reason']!r}")
    kinds = [r["kind"] for r in await database.rows(
        "SELECT kind FROM integration_evidence WHERE session_id='s'")]
    assert "collector-requeued" in kinds, kinds


async def test_the_requeued_row_does_not_claim_it_finished_before_it_started(database):
    """`run()` stamps `started_at` on selection; pass 1's `finished_at` would then sit
    before it, which is a record contradicting itself — the class of defect this lane
    keeps finding."""
    from orchestrator.integrations.service import requeue_lost_collectors
    await stages(database, ("interactsh", "arm-a", "failed"), ("testcases", "arm-a", "queued"))
    await requeue_lost_collectors("s", config())
    assert (await current(database))[("interactsh", "arm-a")]["finished_at"] is None


# ------------------------------------------------------- and the five places it must not


async def test_a_healthy_arm_is_not_re_run(database):
    from orchestrator.integrations.service import requeue_lost_collectors
    await stages(database, ("interactsh", "arm-a", "completed"), ("testcases", "arm-a", "queued"))
    assert await requeue_lost_collectors("s", config()) == []
    assert (await current(database))[("interactsh", "arm-a")]["status"] == "completed"


async def test_an_arm_whose_catalogue_work_is_done_is_not_re_run(database):
    """Nothing in this pass will ask for a collector, so re-running the stage that starts
    one buys a container and an authentication probe for nothing."""
    from orchestrator.integrations.service import requeue_lost_collectors
    await stages(database, ("interactsh", "arm-a", "failed"),
                 ("testcases", "arm-a", "completed"))
    assert await requeue_lost_collectors("s", config()) == []
    assert (await current(database))[("interactsh", "arm-a")]["status"] == "failed"


async def test_only_the_arm_that_still_needs_a_collector_is_re_run(database):
    """One arm's pending catalogue work must not re-run another arm's collector stage.

    A resume of a three-arm assessment where one arm paused would otherwise re-run every
    arm's collector — the identity correlation is what keeps the retry proportional.
    """
    from orchestrator.integrations.service import requeue_lost_collectors
    await stages(database,
                 ("interactsh", "arm-a", "failed"), ("testcases", "arm-a", "queued"),
                 ("interactsh", "arm-b", "failed"), ("testcases", "arm-b", "completed"))
    requeued = await requeue_lost_collectors("s", config())
    assert [r["identity_id"] for r in requeued] == ["arm-a"], requeued
    rows = await current(database)
    assert rows[("interactsh", "arm-b")]["status"] == "failed", (
        "arm-b has no pending catalogue work, so its collector stage was re-run because of "
        "another arm")


async def test_an_assessment_that_selects_no_callback_case_is_untouched(database):
    """The collector is only a dependency of the cases that use it. An assessment whose
    catalogue selects none of them has a failed interactsh stage and nothing waiting on
    it."""
    from orchestrator.integrations.service import requeue_lost_collectors
    from orchestrator.integrations.inventory import COLLECTOR_CASES, executable_test_cases
    other = next(case for case in executable_test_cases() if case not in COLLECTOR_CASES)
    await stages(database, ("interactsh", "arm-a", "failed"), ("testcases", "arm-a", "queued"))
    assert await requeue_lost_collectors("s", config(test_cases=[other])) == []
    assert (await current(database))[("interactsh", "arm-a")]["status"] == "failed"


async def test_no_other_stage_is_re_run_with_it(database):
    """Only the stage that STARTS the collector is a dependency of the catalogue.

    A scanner stage that failed is a separate decision with its own cost — re-running
    katana spends the URL budget again — and nothing in the catalogue waits on it. Without
    this the retry would quietly re-run every unfinished stage of any arm with pending
    catalogue work, which is a different feature than the one measured.
    """
    from orchestrator.integrations.service import requeue_lost_collectors
    await stages(database, ("katana", "arm-a", "failed"), ("testcases", "arm-a", "queued"))
    assert await requeue_lost_collectors("s", config()) == []
    assert (await current(database))[("katana", "arm-a")]["status"] == "failed"


@pytest.mark.parametrize("status", ["queued", "needs_auth"])
async def test_a_stage_a_resume_can_already_select_is_left_alone(database, status):
    """`needs_auth` is the pause marker and carries the interruption reason — see
    `test_callback_resume`. Rewriting it to `queued` would destroy that reason for no
    gain, since `run()` selects both statuses anyway."""
    from orchestrator.integrations.service import requeue_lost_collectors
    await stages(database, ("interactsh", "arm-a", status), ("testcases", "arm-a", "queued"))
    assert await requeue_lost_collectors("s", config()) == []
    row = (await current(database))[("interactsh", "arm-a")]
    assert row["status"] == status
    assert row["reason"] == f"pass 1 said {status}", (
        f"the pause reason was overwritten: {row['reason']!r}")


# -------------------------------------------------------------------- the regression guard


async def test_a_collector_that_cannot_be_re_established_is_still_recorded_as_not_run(
        lane, database, monkeypatch):
    """A GUARD, not an ablation target: it passes on the committed code before this fix.

    The retry is not a promise. When the cause persists the case must still be recorded as
    not run, because that observation is what stops `coverage()` and the report reading a
    zero here as clean.
    """
    from orchestrator.integrations.security import SecretStore
    identity_id = SecretStore().put({
        "name": "reader", "target_origin": "https://app.test",
        "check": {"url": "https://app.test/me", "expected_status": 200,
                  "body_contains": "reader"}})
    await database.execute("DELETE FROM integration_assessments WHERE session_id='s'")
    await lane.register("stuck", "https://app.test", config(identity_ids=[identity_id]))
    _Collector.fail_starts = 1
    seen = {"n": 0}

    async def authenticate(ctx, sandbox, controls=None):
        seen["n"] += 1
        return "needs_auth" if seen["n"] == 2 else "authenticated"

    monkeypatch.setattr(lane, "authenticate", authenticate)
    await lane.run("stuck")

    async def always(ctx, sandbox, controls=None):
        return "authenticated"

    monkeypatch.setattr(lane, "authenticate", always)
    _Collector.fail_starts = 1              # the retry hits the same refusal
    await lane.run("stuck")
    row = [dict(r) for r in await database.rows(
        "SELECT status,reason,result FROM integration_stages WHERE session_id='stuck' "
        "AND adapter='testcases' AND identity_id=?", (identity_id,))][0]
    assert row["status"] == "partial", row
    observed = json.loads(row["result"] or "{}").get("observations", [])
    assert any(o["type"] == "test_case_not_run" and o["test_case_id"] == CASE
               for o in observed), (
        f"the retry failed again and the case was not recorded as not run: {observed}")
