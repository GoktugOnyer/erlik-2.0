"""E-018: a retest outcome reaching the client's tracker, and the three things it will not do.

E-017 produces the states; the DefectDojo export maps `triage_state` to a remote record.
Nothing connected them, so a verified fix stayed `open` until somebody clicked it, and a
regression stayed `fixed`.

`apply_retest` is the bridge, and every rule in it is about what it REFUSES:

  * It never acts on `not_retested`. That state means nobody looked, and closing on it is the
    automatic closure E-017 exists to prevent — "a probe that received no bytes is
    not-retested, never fixed".
  * It never overwrites `false_positive`. A human judged the finding not to be a bug; a retest
    reporting `fixed` would replace that judgement with a weaker one, and `regressed` would
    resurface noise somebody already dismissed.
  * It writes nothing without a trace. Every change records an artifact naming the retest, the
    state it established and the reason, because a finding that closed with no record of why
    is indistinguishable from one closed by hand — and only one of those can be checked.

And it is a PREVIEW by default. This decides what a later export tells a client's tracker, so
`confirm` is what turns a report into a write.
"""
import json
import uuid

import pytest

from orchestrator.integrations.inventory import RETEST_TRIAGE, apply_retest

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


def sqli(**overrides):
    data = {"fingerprint": "fp-sqli", "url": URL, "parameter": "id", "identity": "anonymous",
            "rule": f"{CASE}:error_based", "source": "testcase", "severity": "high",
            "confidence": "confirmed", "triage_state": "open"}
    data.update(overrides)
    return data


async def assessment(db, session, *, findings=(), probed=True):
    await db.execute("INSERT INTO integration_assessments(session_id,target,status,config) "
                     "VALUES(?,?,?,?)", (session, "http://app.test/", "completed",
                                         json.dumps({"test_cases": [CASE]})))
    stage = uuid.uuid4().hex
    observations = ([{"type": "test_case", "test_case_id": CASE, "url": URL,
                      "parameter": "id", "steps": [], "evidence_id": "e1"}] if probed else [])
    await db.execute(
        "INSERT INTO integration_stages(id,session_id,adapter,identity_id,status,result) "
        "VALUES(?,?,?,?,?,?)",
        (stage, session, "testcases", "anonymous", "completed",
         json.dumps({"observations": observations})))
    await db.execute(
        "INSERT INTO integration_endpoints(session_id,url,method,identity_id,sources,"
        "parameters) VALUES(?,?,?,?,?,?)",
        (session, URL, "GET", "anonymous", json.dumps(["katana"]), json.dumps(["id"])))
    for finding in findings:
        await db.execute("INSERT INTO integration_findings VALUES(?,?,?)",
                         (session, finding["fingerprint"], json.dumps(finding)))


async def triage_of(db, session, fingerprint="fp-sqli"):
    rows = await db.rows(
        "SELECT payload FROM integration_findings WHERE session_id=? AND fingerprint=?",
        (session, fingerprint))
    return json.loads(rows[0]["payload"]).get("triage_state")


# ----------------------------------------------------------------- what it refuses to do


async def test_a_not_retested_finding_is_never_closed(lane):
    """The headline. The finding is absent from the retest and the retest never looked."""
    await assessment(lane, "before", findings=[sqli()])
    await assessment(lane, "after", findings=[], probed=False)
    result = await apply_retest("before", "after", confirm=True)
    assert result["changes"] == [], result["changes"]
    assert result["not_retested"] == 1
    assert await triage_of(lane, "before") == "open"
    assert "closing them is the automatic closure this refuses to do" in result["establishes"]


async def test_not_retested_is_not_in_the_map_at_all(_=None):
    """Structural, because the map is the whole safety argument: a state that is not in it
    cannot move a triage, whatever a future branch does."""
    assert "not_retested" not in RETEST_TRIAGE
    assert set(RETEST_TRIAGE) == {"fixed", "regressed"}


async def test_an_operator_false_positive_is_left_alone_and_listed(lane):
    """A human judged this not to be a bug. A retest reporting `fixed` would replace that
    with a weaker claim, and the operator would never know it happened."""
    await assessment(lane, "before", findings=[sqli(triage_state="false_positive")])
    await assessment(lane, "after", findings=[])
    result = await apply_retest("before", "after", confirm=True)
    assert result["changes"] == []
    assert result["left_alone"][0]["fingerprint"] == "fp-sqli"
    assert "does not overrule" in result["left_alone"][0]["left_alone_because"]
    assert await triage_of(lane, "before") == "false_positive"


async def test_an_unchanged_finding_is_not_touched(lane):
    """Still there, still open. Nothing to do, and a report claiming a change would be
    noise an operator learns to scroll past."""
    await assessment(lane, "before", findings=[sqli()])
    await assessment(lane, "after", findings=[sqli()])
    assert (await apply_retest("before", "after", confirm=True))["changes"] == []
    assert await triage_of(lane, "before") == "open"


# --------------------------------------------------------------------- what it does do


async def test_a_verified_fix_closes_the_baseline_finding(lane):
    """The positive control: the check that found it ran again and did not report it."""
    await assessment(lane, "before", findings=[sqli()])
    await assessment(lane, "after", findings=[])
    result = await apply_retest("before", "after", confirm=True)
    assert [c["fingerprint"] for c in result["changes"]] == ["fp-sqli"]
    assert result["changes"][0]["from"] == "open" and result["changes"][0]["to"] == "fixed"
    assert await triage_of(lane, "before") == "fixed"


async def test_a_regression_reopens_the_finding_that_was_called_fixed(lane):
    """The earlier claim was wrong. Leaving it closed with a contradiction beside it is the
    self-contradicting record this project keeps removing."""
    await assessment(lane, "before", findings=[sqli(triage_state="fixed")])
    await assessment(lane, "after", findings=[sqli()])
    result = await apply_retest("before", "after", confirm=True)
    assert result["changes"][0]["to"] == "open"
    assert result["changes"][0]["retest_state"] == "regressed"
    assert await triage_of(lane, "before") == "open"


async def test_every_change_records_why(lane):
    """A finding that closed with no record of why is indistinguishable from one closed by
    hand, and only one of those can be checked."""
    await assessment(lane, "before", findings=[sqli()])
    await assessment(lane, "after", findings=[])
    await apply_retest("before", "after", confirm=True)
    rows = [dict(r) for r in await lane.rows(
        "SELECT kind FROM integration_evidence WHERE session_id='before'")]
    assert any(r["kind"] == "retest-applied" for r in rows), rows
    note = json.loads((await lane.rows(
        "SELECT payload FROM integration_findings WHERE session_id='before'"
    ))[0]["payload"])["triage_note"]
    assert "after" in note and "fixed" in note, note


# ------------------------------------------------------------------ preview by default


async def test_it_writes_nothing_without_confirm(lane):
    """This decides what a later export tells a client's tracker. "Keep external sending
    explicit", one step earlier — at the thing that decides what gets sent."""
    await assessment(lane, "before", findings=[sqli()])
    await assessment(lane, "after", findings=[])
    result = await apply_retest("before", "after")
    assert result["applied"] is False
    assert [c["fingerprint"] for c in result["changes"]] == ["fp-sqli"], (
        "a preview that shows nothing is not a preview")
    assert await triage_of(lane, "before") == "open", "it wrote without confirm"
    assert "run again with confirm" in result["establishes"]
    assert not await lane.rows(
        "SELECT id FROM integration_evidence WHERE session_id='before' AND kind='retest-applied'")


async def test_a_preview_and_the_write_agree(lane):
    """The preview is only useful if confirming does what it said."""
    await assessment(lane, "before", findings=[sqli()])
    await assessment(lane, "after", findings=[])
    preview = await apply_retest("before", "after")
    applied = await apply_retest("before", "after", confirm=True)
    assert [c["fingerprint"] for c in preview["changes"]] == [
        c["fingerprint"] for c in applied["changes"]]
    assert [c["to"] for c in preview["changes"]] == [c["to"] for c in applied["changes"]]


async def test_applying_twice_changes_nothing_the_second_time(lane):
    """Idempotent, so a retry after a network failure does not re-record a change that
    already happened."""
    await assessment(lane, "before", findings=[sqli()])
    await assessment(lane, "after", findings=[])
    await apply_retest("before", "after", confirm=True)
    again = await apply_retest("before", "after", confirm=True)
    assert again["changes"] == []


async def test_a_configuration_difference_travels_with_the_plan(lane):
    """A retest against a different scope can move a finding for a reason that is not a fix,
    and the operator deciding whether to apply needs that in front of them."""
    await assessment(lane, "before", findings=[sqli()])
    await lane.execute("UPDATE integration_assessments SET config=? WHERE session_id='before'",
                       (json.dumps({"test_cases": [CASE], "stages": ["zap"]}),))
    await assessment(lane, "after", findings=[])
    result = await apply_retest("before", "after")
    assert result["configuration_differences"], result


# ------------------------------------------------------------------------- the route


async def test_the_route_previews_by_default(lane):
    from orchestrator.integrations.api import RetestApplyInput, retest_apply

    await assessment(lane, "before", findings=[sqli()])
    await assessment(lane, "after", findings=[])
    body = await retest_apply("after", RetestApplyInput(baseline="before"))
    assert body["applied"] is False
    assert await triage_of(lane, "before") == "open"


async def test_the_route_refuses_to_apply_a_session_to_itself(lane):
    from fastapi import HTTPException

    from orchestrator.integrations.api import RetestApplyInput, retest_apply

    await assessment(lane, "only", findings=[sqli()])
    with pytest.raises(HTTPException) as raised:
        await retest_apply("only", RetestApplyInput(baseline="only", confirm=True))
    assert raised.value.status_code == 422
