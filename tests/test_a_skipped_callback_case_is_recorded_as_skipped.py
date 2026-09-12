"""The SSRF case can be skipped for the whole assessment and `coverage()` called it clean.

When the catalogue stage runs with no collector, `CatalogueAdapter.run` sets the stage to
`partial` with a reason and moves on. That much is honest — and it is the only trace. The
stage `reason` is a single string that the next case to set one overwrites, and `coverage()`
is built from OBSERVATIONS, so the pair reported `not_attempted`: indistinguishable from an
endpoint no case was ever eligible for.

AND THE ARM COULD LOSE ITS COLLECTOR WITHOUT GETTING IT BACK. The reported claim was that a
resume after a credential replacement loses callback support, and the headline mechanism is
refuted — on every pause path where the collector reached `collectors`, the `needs_auth`
sweep rewrites the interactsh row to `needs_auth` and the resume re-selects it. What was real
is narrower: three pass-1 paths leave the interactsh stage at a status no resume can select
(`Collector.start()` failing -> `failed`; the probe timing out -> `partial`; a
`probe_refused` pre-stage verdict -> `failed`) while the testcases row stays resumable. The
resume then ran this stage with `collector=None` again, and the SSRF check never ran for that
session at all. That half is fixed in `service.requeue_lost_collectors`, tested by
`test_an_arm_does_not_lose_its_collector_for_good.py` — which also guards the property THIS
file is about, because the retry is not a promise and a persistent cause still lands here.

So the skip is recorded where coverage can see it: `test_case_not_run`, which
`inventory.coverage` already maps to the `not_run` state. A zero there reads as untested
rather than as clean.
"""
import json
import uuid

import pytest

from orchestrator.integrations.contracts import AssessmentConfig


@pytest.fixture
async def lane(tmp_path, monkeypatch):
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    await db.execute("INSERT INTO integration_assessments(session_id,target,status,config) "
                     "VALUES(?,?,?,?)", ("s", "http://app.test/", "running", "{}"))
    stage = uuid.uuid4().hex
    await db.execute("INSERT INTO integration_stages(id,session_id,adapter,identity_id,status)"
                     " VALUES(?,?,?,?,?)", (stage, "s", "testcases", "anonymous", "running"))
    await db.execute("INSERT INTO integration_endpoints"
                     "(session_id,url,method,identity_id,sources) VALUES(?,?,?,?,?)",
                     ("s", "http://app.test/fetch", "GET", "anonymous", json.dumps(["katana"])))
    return {"db": db, "stage": stage, "root": tmp_path / "sandbox"}


async def run_catalogue(lane, cases, collector=None):
    from orchestrator.integrations.adapters import Context
    from orchestrator.integrations.deterministic import CatalogueAdapter

    # `stages=["interactsh"]` is not decoration: `AssessmentConfig` REFUSES the SSRF case
    # without it ("the integration SSRF test case requires the Interactsh stage"). Which is
    # the point — an assessment selecting this case always HAS that stage, so the only way
    # the catalogue sees no collector is that the stage did not produce one.
    config = AssessmentConfig(scope={"allow_hosts": ["app.test"], "allow_ports": [80]},
                              active=True, test_cases=cases, surface_read=False,
                              stages=["interactsh"],
                              callback={"server": "https://callback.test",
                                        "probes": [{"url": "http://app.test/fetch",
                                                    "parameter": "next"}]})
    ctx = Context("s", lane["stage"], "http://app.test/", config, "anonymous", None)

    class _Sandbox:
        policy = {}
        on_close = None
        images = {}

        def __init__(self, root):
            self.directory = root
            self.output = root / "output"
            self.output.mkdir(parents=True, exist_ok=True)

    return await CatalogueAdapter().run(ctx, _Sandbox(lane["root"]), collector)


def not_run(result, case_id):
    return [o for o in result.observations
            if o.get("type") == "test_case_not_run" and o.get("test_case_id") == case_id]


async def test_the_skipped_callback_case_is_recorded(lane):
    result = await run_catalogue(lane, ["WSTG-INPV-19"])
    assert result.status == "partial"
    assert "collector unavailable" in (result.reason or "")
    recorded = not_run(result, "WSTG-INPV-19")
    assert recorded, "nothing said the case did not run; coverage() reads observations"
    assert "untested, not clean" in recorded[0]["reason"]
    assert recorded[0]["url"] == "http://app.test/fetch"


async def test_coverage_still_cannot_see_this_case_at_all(lane):
    """THE LIMIT OF THE FIX, asserted rather than left for someone to assume away.

    `coverage()` indexes per-url observations by `(url, parameter, identity)` against rows
    in `integration_endpoints`, and applies case-wide ones only to pairs the case was
    eligible for. `WSTG-INPV-19` never appears in `eligible_test_cases` for any url or
    parameter — its targets come from `config.callback.probes`, a surface `coverage()` does
    not model — so neither shape of this observation reaches it. Both were tried and both
    reported `not_attempted`.

    This test exists so that the next person to read the comment above does not have to
    take it on trust, and so that a future change which DOES wire the callback probes into
    coverage fails here and gets the comment corrected with it.
    """
    from orchestrator.integrations.inventory import coverage, eligible_test_cases

    assert "WSTG-INPV-19" not in eligible_test_cases("http://app.test/fetch", "GET", ["next"])
    result = await run_catalogue(lane, ["WSTG-INPV-19"])
    await lane["db"].persist_result("s", lane["stage"], result)
    states = {(r["url"], r["state"]) for r in await coverage("s")}
    assert ("http://app.test/fetch", "not_run") not in states
    assert ("http://app.test/fetch", "not_attempted") in states, states


async def test_the_record_survives_a_later_case_setting_the_stage_reason(lane):
    """Why it is an observation and not the stage reason: the reason is one string, and the
    next case to set one wins."""
    result = await run_catalogue(lane, ["WSTG-INPV-19", "WSTG-CONF-06"])
    assert not_run(result, "WSTG-INPV-19"), (
        f"the skip was lost; reason is now {result.reason!r}")


async def test_the_record_is_specific_to_the_missing_collector(lane):
    """The negative control. Other cases also record `test_case_not_run` — for their own
    reasons — so an observation that said nothing distinguishing would say nothing at all.

    (The first version of this asserted the OTHER case recorded nothing, which was simply
    false in this harness: without a real sandbox it cannot run either, and it says so.)
    """
    result = await run_catalogue(lane, ["WSTG-INPV-19", "WSTG-CONF-06"])
    reasons = {o["test_case_id"]: o["reason"] for o in result.observations
               if o.get("type") == "test_case_not_run"}
    assert "collector" in reasons["WSTG-INPV-19"]
    assert "collector" not in reasons.get("WSTG-CONF-06", ""), reasons
