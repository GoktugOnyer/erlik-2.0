"""A report that lists only what it found reads as a clean bill of health.

`service.report` already says this about TRIAGE, in its own comment: a reader seeing a
count of N had no way to know M more had been triaged away, and "a report listing only what
remains reads as a clean bill of health for everything it omits". It then said it about
triage only. `coverage` answers the same question one layer down and the report never asked.

THE MEASURED COST IS THE RUN THIS LANE IS CALIBRATED AGAINST. On 2026-09-10, 156 of 208
injection-case steps received ZERO bytes — every probe of sqli, sqli_blind, xss_r and csrf —
and the stage reported `completed` with no findings. A report of that run and a report of a
thorough one were the same document: findings, triage, synchronization, and nothing about
what was never touched.

`/sessions/{id}/coverage` has carried the answer all along. A client reading the report is
not calling the API.

WHAT THIS DOES NOT DO is call anything "tested". The caveat is copied verbatim from the
coverage route rather than reworded, because two wordings of one caveat is how one of them
gets weaker: `answered` means bytes came back, which is not proof the check exercised
anything — a probe refused for want of a token still answers.
"""
import json
import uuid

import pytest

from orchestrator.integrations.inventory import COVERAGE_STATES, REACHED_STATES
from orchestrator.integrations.service import report

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


async def assessment(db, session, *, observation=None, findings=()):
    await db.execute("INSERT INTO integration_assessments(session_id,target,status,config) "
                     "VALUES(?,?,?,?)",
                     (session, "http://app.test/", "completed",
                      json.dumps({"test_cases": [CASE], "stages": ["zap"]})))
    await db.execute(
        "INSERT INTO integration_stages(id,session_id,adapter,identity_id,status,result) "
        "VALUES(?,?,?,?,?,?)",
        (uuid.uuid4().hex, session, "testcases", "anonymous", "completed",
         json.dumps({"observations": [observation] if observation else []})))
    await db.execute(
        "INSERT INTO integration_endpoints(session_id,url,method,identity_id,sources,"
        "parameters) VALUES(?,?,?,?,?,?)",
        (session, URL, "GET", "anonymous", json.dumps(["katana"]), json.dumps(["id"])))
    for finding in findings:
        await db.execute("INSERT INTO integration_findings VALUES(?,?,?)",
                         (session, finding["fingerprint"], json.dumps(finding)))


def observation(kind, reason=""):
    return {"type": kind, "test_case_id": CASE, "url": URL, "parameter": "id",
            "steps": [], "evidence_id": "e1", "reason": reason}


EMPTY = ("all 4 executed steps received an empty response, so this check tested nothing "
         "here; a zero from it is untested coverage, not a clean result")


# ------------------------------------------------------------------ the block exists


async def test_the_report_carries_coverage_at_all(lane):
    await assessment(lane, "s", observation=observation("test_case"))
    body = await report("s")
    assert "coverage" in body, "the report still says only what it found"
    assert set(body["coverage"]) >= {"known_pairs", "reached", "not_reached", "states"}


async def test_a_probe_that_answered_counts_as_reached(lane):
    await assessment(lane, "s", observation=observation("test_case"))
    coverage = (await report("s"))["coverage"]
    assert coverage["reached"] == 1 and coverage["not_reached"] == 0
    assert coverage["states"]["answered"] == 1


async def test_a_probe_that_got_nothing_counts_as_not_reached(lane):
    """The 2026-09-10 shape. The pair is KNOWN, the check ran, and nothing came back."""
    await assessment(lane, "s", observation=observation("test_case_unreachable", EMPTY))
    coverage = (await report("s"))["coverage"]
    assert coverage["reached"] == 0
    assert coverage["not_reached"] == 1
    assert coverage["states"]["unreachable"] == 1


async def test_reached_and_not_reached_account_for_every_known_pair(lane):
    """Two numbers that do not sum to the third are worse than one number."""
    await assessment(lane, "s", observation=observation("test_case_unreachable", EMPTY))
    coverage = (await report("s"))["coverage"]
    assert coverage["reached"] + coverage["not_reached"] == coverage["known_pairs"]
    assert sum(coverage["states"].values()) == coverage["known_pairs"]


# ------------------------------------------------- reaching nothing is said, not implied


async def test_a_run_that_reached_nothing_says_so_in_words(lane):
    """The reader most likely to miss it is the one skimming a findings count, so the
    report states it rather than leaving it to be derived from reached == 0."""
    await assessment(lane, "s", observation=observation("test_case_unreachable", EMPTY))
    warning = (await report("s"))["coverage"]["warning"]
    assert warning and "reached NONE" in warning
    assert "untested coverage rather than a clean result" in warning


async def test_a_run_that_reached_something_carries_no_warning(lane):
    """A warning on every report is a warning nobody reads."""
    await assessment(lane, "s", observation=observation("test_case"))
    assert (await report("s"))["coverage"]["warning"] is None


async def test_an_assessment_with_no_known_pairs_is_not_warned_about(lane):
    """Nothing known is not the same claim as nothing reached — a run that discovered no
    surface has a different problem, and this clause has nothing to say about it."""
    await assessment(lane, "s")
    await lane.execute("DELETE FROM integration_endpoints WHERE session_id=?", ("s",))
    coverage = (await report("s"))["coverage"]
    assert coverage["known_pairs"] == 0
    assert coverage["warning"] is None


# --------------------------------------------------------------- it refuses to say tested


async def test_the_caveat_is_the_routes_caveat_word_for_word(lane):
    """Copied rather than reworded: two wordings of one caveat is how one gets weaker."""
    import inspect

    from orchestrator.integrations import api

    await assessment(lane, "s", observation=observation("test_case"))
    said = (await report("s"))["coverage"]["establishes"]
    assert "No state means `tested`." in said
    assert "refused for want of a token still answers" in said
    route = inspect.getsource(api.coverage_report)
    for fragment in ("a probe refused for want", "No state means `tested`"):
        assert fragment in route, fragment


async def test_reached_is_the_two_states_that_mean_bytes_came_back(lane):
    """Behaviourally: `answered` and `verified` count, and nothing else does. A test that
    read REACHED_STATES would agree with any edit to it."""
    for kind, state in (("test_case_not_run", "not_run"),
                        ("parameter_refused", "refused"),
                        ("indistinct_url", "indistinct")):
        session = "s-" + state
        await assessment(lane, session, observation=observation(kind, f"reason {state}"))
        coverage = (await report(session))["coverage"]
        assert coverage["reached"] == 0, f"{kind} counted as reached"
        assert coverage["states"][state] == 1
    assert set(REACHED_STATES) == {"answered", "verified"}
    assert set(REACHED_STATES) < set(COVERAGE_STATES)
