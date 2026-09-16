"""E-017: a retest says fixed only when the check that found it ran again.

The entry's acceptance is written in this project's own idiom — "a probe that received no
bytes is not-retested, never fixed — the 2026-09-10 run shows how readily an empty response
reads as a clean one" — and `COVERAGE_STATES` says the sharper version beside it: even
`answered` only means bytes came back, not that a check exercised anything.

So absence is never evidence. Three things must hold before `fixed`:

  1. the stage that produced the finding FINISHED in the retest, for that arm;
  2. the retest reached the same (url, parameter, identity) pair;
  3. for a catalogue finding, the SAME case ran against that pair, not merely some case.

Anything short is `not_retested`, which is a different claim and must not collapse into
`fixed` — automatic closure is how a live vulnerability leaves a client's tracker.

AND ONE THING THIS CANNOT DO, asserted rather than left to be discovered: a cross-arm finding
can never be `fixed` here. Those come from an on-demand route over stored evidence and nothing
records that the route ran, so a retest that never invoked it is indistinguishable from one
that invoked it and found nothing.
"""
import json
import uuid

import pytest

from orchestrator.integrations.inventory import RETEST_STATES, compare_assessments

URL = "http://app.test/vulnerabilities/sqli/"
CASE = "WSTG-INPV-05"


@pytest.fixture
async def lane(tmp_path, monkeypatch):
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    return db


async def assessment(db, session, *, findings=(), probed=True, stage_status="completed",
                     case=CASE, config=None):
    """One session: a testcases stage, an endpoint, and whatever it found.

    `probed` writes the observation that makes `coverage` report the pair `answered` — which
    is the positive evidence a `fixed` verdict has to rest on.
    """
    await db.execute("INSERT INTO integration_assessments(session_id,target,status,config) "
                     "VALUES(?,?,?,?)",
                     (session, "http://app.test/", "completed",
                      json.dumps(config or {"test_cases": [CASE], "stages": ["zap"]})))
    stage = uuid.uuid4().hex
    observations = []
    if probed:
        observations.append({"type": "test_case", "test_case_id": case, "url": URL,
                             "parameter": "id", "steps": [], "evidence_id": "e1"})
    await db.execute(
        "INSERT INTO integration_stages(id,session_id,adapter,identity_id,status,result) "
        "VALUES(?,?,?,?,?,?)",
        (stage, session, "testcases", "anonymous", stage_status,
         json.dumps({"observations": observations})))
    await db.execute(
        "INSERT INTO integration_endpoints(session_id,url,method,identity_id,sources,"
        "parameters) VALUES(?,?,?,?,?,?)",
        (session, URL, "GET", "anonymous", json.dumps(["katana"]), json.dumps(["id"])))
    for finding in findings:
        await db.execute("INSERT INTO integration_findings VALUES(?,?,?)",
                         (session, finding["fingerprint"], json.dumps(finding)))


def sqli(**overrides):
    data = {"fingerprint": "fp-sqli", "url": URL, "parameter": "id", "identity": "anonymous",
            "rule": f"{CASE}:error_based", "source": "testcase", "severity": "high",
            "confidence": "confirmed", "triage_state": "open"}
    data.update(overrides)
    return data


def state_of(result, fingerprint="fp-sqli"):
    return next(row for row in result["findings"] if row["fingerprint"] == fingerprint)


# ------------------------------------------------------------- fixed is earned, not assumed


async def test_a_finding_the_same_check_re_probed_and_did_not_report_is_fixed(lane):
    """The positive control. Without it every assertion below would pass on a comparison
    that can never say `fixed` at all."""
    await assessment(lane, "before", findings=[sqli()])
    await assessment(lane, "after", findings=[])
    result = await compare_assessments("before", "after")
    assert state_of(result)["state"] == "fixed", state_of(result)
    assert result["states"]["fixed"] == 1


async def test_a_finding_nothing_re_probed_is_not_retested(lane):
    """The headline. The finding is absent from the retest and the retest never looked."""
    await assessment(lane, "before", findings=[sqli()])
    await assessment(lane, "after", findings=[], probed=False)
    row = state_of(await compare_assessments("before", "after"))
    assert row["state"] == "not_retested", row
    assert row["reason"], "a not_retested row with no reason cannot be acted on"


async def test_a_stage_that_did_not_finish_cannot_fix_anything(lane):
    """A partial retest closes nothing. The stage is the first of the three conditions."""
    await assessment(lane, "before", findings=[sqli()])
    await assessment(lane, "after", findings=[], stage_status="failed")
    row = state_of(await compare_assessments("before", "after"))
    assert row["state"] == "not_retested"
    assert "did not finish" in row["reason"], row["reason"]


async def test_a_different_check_probing_the_same_operation_is_not_a_retest(lane):
    """The third condition, and the subtlest: the operation was reached, by something else.
    An XSS probe answering on the URL says nothing about the SQL injection that was there."""
    await assessment(lane, "before", findings=[sqli()])
    await assessment(lane, "after", findings=[], case="WSTG-INPV-01")
    row = state_of(await compare_assessments("before", "after"))
    assert row["state"] == "not_retested"
    assert "WSTG-INPV-01" in row["reason"] and CASE in row["reason"], row["reason"]


async def test_an_operation_the_retest_never_discovered_is_not_retested(lane):
    """The endpoint dropped out of the retest's crawl entirely — no coverage row at all,
    which is different from a row saying it was not probed.

    This is the easiest way for a live vulnerability to read as fixed: the URL stops being
    discovered (a budget, a changed link, a slower page) and the finding simply vanishes.
    """
    await assessment(lane, "before", findings=[sqli()])
    await assessment(lane, "after", findings=[])
    # The retest read a different part of the application and never reached this operation.
    await lane.execute("DELETE FROM integration_endpoints WHERE session_id='after'")
    await lane.execute(
        "UPDATE integration_stages SET result=? WHERE session_id='after'",
        (json.dumps({"observations": []}),))
    row = state_of(await compare_assessments("before", "after"))
    assert row["state"] == "not_retested", row
    assert "no coverage record" in row["reason"], row["reason"]


async def test_the_reason_quotes_what_coverage_said(lane):
    """`not_retested` is only useful if it says what to change. The coverage row's own reason
    is the specific one — a budget that ran out reads differently from an arm that failed."""
    await assessment(lane, "before", findings=[sqli()])
    await assessment(lane, "after", findings=[], probed=False)
    row = state_of(await compare_assessments("before", "after"))
    assert "not_attempted" in row["reason"] or "no coverage record" in row["reason"], row


# -------------------------------------------------------------------- the other states


async def test_a_finding_present_in_both_is_unchanged(lane):
    await assessment(lane, "before", findings=[sqli()])
    await assessment(lane, "after", findings=[sqli()])
    assert state_of(await compare_assessments("before", "after"))["state"] == "unchanged"


async def test_a_finding_whose_grade_moved_is_changed(lane):
    await assessment(lane, "before", findings=[sqli(confidence="likely")])
    await assessment(lane, "after", findings=[sqli(confidence="confirmed")])
    row = state_of(await compare_assessments("before", "after"))
    assert row["state"] == "changed"
    assert "likely -> confirmed" in row["reason"], row["reason"]


async def test_a_finding_triaged_fixed_and_found_again_is_regressed(lane):
    """The state that matters most to a client: it was signed off and it is back."""
    await assessment(lane, "before", findings=[sqli(triage_state="fixed")])
    await assessment(lane, "after", findings=[sqli()])
    row = state_of(await compare_assessments("before", "after"))
    assert row["state"] == "regressed"
    assert "found it again" in row["reason"]


async def test_a_finding_only_the_retest_has_is_new(lane):
    await assessment(lane, "before", findings=[])
    await assessment(lane, "after", findings=[sqli()])
    assert state_of(await compare_assessments("before", "after"))["state"] == "new"


# ------------------------------------------------ what it cannot establish, said out loud


async def test_a_cross_arm_finding_is_never_reported_fixed(lane):
    """Nothing records that an on-demand check RAN, so its absence cannot be told from its
    never having been asked. Reported as that, rather than as a fix."""
    crossing = sqli(fingerprint="fp-xarm", source="cross-arm",
                    rule="erlik:authorization:abc123")
    await assessment(lane, "before", findings=[crossing])
    await assessment(lane, "after", findings=[])
    row = state_of(await compare_assessments("before", "after"), "fp-xarm")
    assert row["state"] == "not_retested"
    assert "nothing records that the check ran" in row["reason"], row["reason"]


async def test_a_configuration_change_is_reported_beside_the_states(lane):
    """A retest against a different scope or a different set of checks can move a finding
    for a reason that is not a fix, and a reader of the state column alone would not know."""
    await assessment(lane, "before", findings=[sqli()],
                     config={"test_cases": [CASE], "stages": ["zap"]})
    await assessment(lane, "after", findings=[],
                     config={"test_cases": [CASE, "WSTG-INPV-01"], "stages": ["zap", "katana"]})
    result = await compare_assessments("before", "after")
    fields = {difference["field"] for difference in result["configuration_differences"]}
    assert {"test_cases", "stages"} <= fields, result["configuration_differences"]
    assert "not a like-for-like retest" in result["establishes"]


async def test_an_identical_configuration_reports_no_difference(lane):
    """It must not cry wolf, or the line above it gets ignored."""
    await assessment(lane, "before", findings=[sqli()])
    await assessment(lane, "after", findings=[])
    result = await compare_assessments("before", "after")
    assert result["configuration_differences"] == []
    assert "not a like-for-like" not in result["establishes"]


async def test_the_summary_names_what_was_not_retested(lane):
    """A count of `fixed` on its own is the number an operator would act on; the count of
    what nobody looked at is the one that stops them."""
    await assessment(lane, "before", findings=[sqli()])
    await assessment(lane, "after", findings=[], probed=False)
    result = await compare_assessments("before", "after")
    assert result["states"]["not_retested"] == 1 and result["states"]["fixed"] == 0
    assert "unknown rather than fixed" in result["establishes"]
    assert set(result["states"]) == set(RETEST_STATES)


# ----------------------------------------------------------------------- the route


async def test_the_route_refuses_to_compare_an_assessment_with_itself(lane):
    """A session compared against itself reports everything `unchanged`, which reads as a
    clean retest and is the one answer that cannot be true."""
    from fastapi import HTTPException

    from orchestrator.integrations.api import retest_report

    await assessment(lane, "only", findings=[sqli()])
    with pytest.raises(HTTPException) as raised:
        await retest_report("only", baseline="only")
    assert raised.value.status_code == 422


@pytest.mark.parametrize("missing", ["retest", "baseline"])
async def test_the_route_404s_on_an_assessment_that_does_not_exist(lane, missing):
    from fastapi import HTTPException

    from orchestrator.integrations.api import retest_report

    await assessment(lane, "known", findings=[])
    args = {"session_id": "known", "baseline": "known"}
    args["session_id" if missing == "retest" else "baseline"] = "nope"
    with pytest.raises(HTTPException) as raised:
        await retest_report(**args)
    assert raised.value.status_code == 404
    assert "nope" in raised.value.detail


async def test_the_route_returns_the_comparison(lane):
    from orchestrator.integrations.api import retest_report

    await assessment(lane, "before", findings=[sqli()])
    await assessment(lane, "after", findings=[])
    body = await retest_report("after", baseline="before")
    assert body["states"]["fixed"] == 1
    assert body["findings"][0]["fingerprint"] == "fp-sqli"
