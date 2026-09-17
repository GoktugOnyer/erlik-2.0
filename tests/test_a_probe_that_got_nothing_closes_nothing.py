"""E-017's headline rule, which had no test: a probe that received no bytes is never `fixed`.

The acceptance says it in those words, and names why — "the 2026-09-10 run shows how readily
an empty response reads as a clean one". On that run 156 of the 208 injection-case steps
received ZERO bytes, every probe of sqli, sqli_blind, xss_r and csrf, and the stage reported
`completed` with no findings. The zero was read as a hardened application.

`deterministic.py` emits `test_case_unreachable` for exactly that shape — every executed step
empty — `coverage` maps it to the `unreachable` state, and `REACHED_STATES` is
`("answered", "verified")`, so `retested()` refuses to close on it. The rule is implemented
correctly.

IT WAS NOT GUARDED. Measured before this file: `unreachable` appeared zero times in the retest
suite and `REACHED_STATES` was referenced by no test anywhere. The existing cases cover a
finding with NO coverage row, a stage that did not finish, and a different case probing the
same pair — all real, none of them this one, where the probe ran, produced a row, and the row
says nothing came back. Adding "unreachable" to `REACHED_STATES` is a one-word edit that would
close live findings on empty responses, and nothing in the suite would have failed.

So these assert the states BEHAVIOURALLY rather than asserting the tuple's contents: a test
that reads `REACHED_STATES` would agree with any edit to it.
"""
import json
import uuid

import pytest

from orchestrator.integrations.inventory import (
    COVERAGE_STATES, REACHED_STATES, compare_assessments)

from tests.test_a_finding_is_not_fixed_until_something_looked import (  # noqa: F401
    CASE, URL, lane, sqli, state_of)


async def assessment(db, session, *, findings=(), observation=None):
    """One retest session whose single catalogue stage recorded `observation`.

    Deliberately not the sibling file's helper: that one writes a `test_case` observation,
    which is the ANSWERED path. The whole subject here is the other kinds.
    """
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


def observation(kind, reason):
    return {"type": kind, "test_case_id": CASE, "url": URL, "parameter": "id",
            "steps": [], "evidence_id": "e1", "reason": reason}


EMPTY = ("all 4 executed steps received an empty response, so this check tested nothing "
         "here; a zero from it is untested coverage, not a clean result")


# ----------------------------------------------------- the rule the acceptance is named for


async def test_a_probe_that_received_no_bytes_does_not_close_the_finding(lane):
    """The 2026-09-10 shape exactly: the check RAN against this pair and every step came back
    empty. There is a coverage row, so "nothing was probed" does not catch it."""
    await assessment(lane, "before", findings=[sqli()])
    await assessment(lane, "after", observation=observation("test_case_unreachable", EMPTY))
    row = state_of(await compare_assessments("before", "after"))
    assert row["state"] == "not_retested", row
    assert row["state"] != "fixed"


async def test_the_operator_is_told_it_was_the_emptiness(lane):
    """A `not_retested` with a vague reason sends someone to look in the wrong place. The
    coverage reason is quoted verbatim, so the words that explain the zero survive."""
    await assessment(lane, "before", findings=[sqli()])
    await assessment(lane, "after", observation=observation("test_case_unreachable", EMPTY))
    reason = state_of(await compare_assessments("before", "after"))["reason"]
    assert "unreachable" in reason
    assert "untested coverage, not a clean result" in reason


async def test_the_same_pair_answering_normally_still_closes_it(lane):
    """The positive control this file needs, or every assertion above would pass on a
    comparison that cannot say `fixed` for this fixture at all."""
    await assessment(lane, "before", findings=[sqli()])
    await assessment(lane, "after", observation=observation("test_case", ""))
    assert state_of(await compare_assessments("before", "after"))["state"] == "fixed"


# -------------------------------------------- every state that is not a read, behaviourally


@pytest.mark.parametrize("kind,expected_state", [
    ("test_case_unreachable", "unreachable"),
    ("test_case_not_run", "not_run"),
    ("test_case_truncated", "not_run"),
    ("parameter_refused", "refused"),
    ("form_url_withheld", "refused"),
    ("indistinct_url", "indistinct"),
])
async def test_no_state_but_a_real_read_can_close_a_finding(lane, kind, expected_state):
    """Asserted through the comparison rather than by reading `REACHED_STATES`, because a
    test that reads the tuple agrees with every edit to it. `indistinct_url` is included
    deliberately: it means this URL answered with a response another URL already gave, which
    is a reasonable thing to call "covered" and still is not this check probing this pair."""
    await assessment(lane, "before", findings=[sqli()])
    await assessment(lane, "after", observation=observation(kind, f"reason for {kind}"))
    row = state_of(await compare_assessments("before", "after"))
    assert row["state"] == "not_retested", f"{kind} closed a finding: {row}"
    assert expected_state in row["reason"], row["reason"]


def test_the_reached_states_are_the_two_that_mean_bytes_came_back():
    """The tuple itself, stated once. `answered` is the weak one and the module says so —
    bytes came back, which is not proof the check exercised anything — which is why closing
    also requires the same CASE to have run against the pair."""
    assert set(REACHED_STATES) == {"answered", "verified"}
    assert set(REACHED_STATES) < set(COVERAGE_STATES)
    for state in ("unreachable", "refused", "not_run", "indistinct", "inferred",
                  "not_attempted"):
        assert state not in REACHED_STATES, state
