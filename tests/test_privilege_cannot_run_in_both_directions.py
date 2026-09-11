"""Swapping `privileged` and `unprivileged` was not refused, and wrote the inverse.

Privilege is an ORDER. `admin is above customer` and `customer is above admin` cannot
both hold, and the product cannot tell which one an operator meant — `Identity.role` is a
label it deliberately does not interpret, and guessing from a name is exactly the
assumption-driven finding that `role_not_declared` already refuses to make.

What it CAN tell is that it is being asked to hold both. Measured on the real Juice Shop
session before this existed:

    privileged=admin, unprivileged=customer   refused=[]  2 findings
    privileged=customer, unprivileged=admin   refused=[]  2 findings
                                              -> 4 high/confirmed/verified rows for 2
                                                 violations, two of them titled
                                                 "admin reached a privileged function"

An export carrying that tells a client the administrator broke into a function the
administrator owns.

THE PAIR, NOT ONE HALF OF IT. A three-tier engagement legitimately records `manager` as
the unprivileged arm against `admin` and then asks about `manager` against `customer`;
matching on the privileged arm alone would refuse that. `IntegrationFinding.compared_with`
exists because `identity` alone cannot carry an ordered claim.

THE OBJECT CHECK GETS NO SUCH RULE. "jim read a record attributed to the administrator"
and "the administrator read a record attributed to jim" are two findings that can both be
true. There is no order to contradict, and inventing a symmetry rule there would suppress
a real finding.
"""
import json

import pytest

from orchestrator.integrations.inventory import (
    AUTHORIZATION_RULES, _already_compared_the_other_way, authorization_findings)

TARGET = "http://app.test/"
FUNCTION_RULE = AUTHORIZATION_RULES["function"]


def result(privileged, unprivileged):
    return {"refused_because": [], "findings": [{
        "url": "http://app.test/api/Users",
        "privileged": privileged, "privileged_role": "admin",
        "unprivileged": unprivileged, "unprivileged_role": "customer",
        "marker_digest": "c5c79a1df019"}]}


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
                     "VALUES(?,?,?,?)", ("s", TARGET, "completed", "{}"))
    return db


# ------------------------------------------------- the claim is recorded as a pair

def test_a_finding_records_both_arms():
    """Without this, no inversion is detectable: half an ordered pair has no direction."""
    finding = authorization_findings(TARGET, "function", result("H", "L"))[0]
    assert finding.identity == "L", "the arm that crossed"
    assert finding.compared_with == "H", "the arm it was compared against"


def test_an_object_finding_records_the_owner_arm_too():
    findings = authorization_findings(TARGET, "object", {"refused_because": [], "findings": [{
        "url": "http://app.test/rest/basket/1", "caller": "L", "caller_subject_id": "2",
        "owner": "H", "asserted_owner": 1, "owner_field": "data.UserId"}]})
    assert (findings[0].identity, findings[0].compared_with) == ("L", "H")


def test_a_catalogue_finding_carries_no_pair():
    """`compared_with` is empty for a single-arm claim, not a default that reads as one."""
    from orchestrator.integrations.contracts import IntegrationFinding
    assert IntegrationFinding(fingerprint="f", title="t", url="u", rule="r",
                              source="zap", basis="b").compared_with == ""


# ------------------------------------------------------------- and the inverse is seen

async def test_the_inverse_is_found(lane):
    await lane.persist_findings("s", authorization_findings(TARGET, "function",
                                                            result("H", "L")))
    assert await _already_compared_the_other_way("s", FUNCTION_RULE, "L", "H"), (
        "asking about L-over-H when the session already says H-over-L is a contradiction")


async def test_the_same_direction_is_not_a_contradiction(lane):
    await lane.persist_findings("s", authorization_findings(TARGET, "function",
                                                            result("H", "L")))
    assert not await _already_compared_the_other_way("s", FUNCTION_RULE, "H", "L"), (
        "re-running the direction already recorded must stay runnable")


async def test_a_third_tier_is_not_a_contradiction(lane):
    """admin > manager and manager > customer are consistent, and both are askable.

    This is what matching on the privileged arm alone would have broken.
    """
    await lane.persist_findings("s", authorization_findings(TARGET, "function",
                                                            result("admin", "manager")))
    assert not await _already_compared_the_other_way("s", FUNCTION_RULE,
                                                     "manager", "customer")


async def test_another_rule_is_not_a_contradiction(lane):
    """The object check records pairs too, and they carry no privilege order."""
    await lane.persist_findings("s", authorization_findings(TARGET, "object", {
        "refused_because": [], "findings": [{
            "url": "http://app.test/rest/basket/1", "caller": "L", "caller_subject_id": "2",
            "owner": "H", "asserted_owner": 1, "owner_field": "data.UserId"}]}))
    assert not await _already_compared_the_other_way("s", FUNCTION_RULE, "L", "H")


async def test_a_false_positive_stops_contradicting(lane):
    """The recovery path, and the reason the refusal is not a dead end.

    An operator who ran the wrong direction first must be able to run the right one.
    Triage is how they say "I know that row is wrong", and it is the only signal the
    product has for which direction was the mistake — so it is the one it uses.
    """
    findings = authorization_findings(TARGET, "function", result("H", "L"))
    await lane.persist_findings("s", findings)
    payload = json.loads((await lane.rows(
        "SELECT payload FROM integration_findings WHERE fingerprint=?",
        (findings[0].fingerprint,)))[0]["payload"])
    payload.update(triage_state="false_positive", triage_note="wrong direction")
    await lane.execute("UPDATE integration_findings SET payload=? WHERE fingerprint=?",
                       (json.dumps(payload), findings[0].fingerprint))
    assert not await _already_compared_the_other_way("s", FUNCTION_RULE, "L", "H")


async def test_a_session_is_not_contradicted_by_another_session(lane):
    await lane.execute("INSERT INTO integration_assessments(session_id,target,status,config) "
                       "VALUES(?,?,?,?)", ("other", TARGET, "completed", "{}"))
    await lane.persist_findings("other", authorization_findings(TARGET, "function",
                                                                result("H", "L")))
    assert not await _already_compared_the_other_way("s", FUNCTION_RULE, "L", "H")


# ------------------------------------------------------------- and the check refuses

async def test_the_check_refuses_the_opposite_direction(lane, monkeypatch):
    """End to end through the real check, which must refuse before it compares anything."""
    from orchestrator.integrations import inventory as inv
    from orchestrator.integrations.security import SecretStore

    high = SecretStore().put({"name": "admin", "role": "admin",
                              "target_origin": "http://app.test"})
    low = SecretStore().put({"name": "jim", "role": "customer",
                             "target_origin": "http://app.test"})
    await lane.persist_findings("s", authorization_findings(
        TARGET, "function", result(high, low)))

    refused = await inv.cross_arm_privileged_function("s", low, high, "marker",
                                                      anonymous="anonymous")
    assert "arms_already_compared_in_the_opposite_direction" in refused["refused_because"]
    assert refused["findings"] == []
    assert refused["contradicting_findings"], (
        "a bare reason token would leave the operator hunting for the rows to triage")
    assert authorization_findings(TARGET, "function", refused) == [], (
        "a refused check records nothing — the rule every refusal here relies on")


async def test_the_declared_direction_still_runs(lane, monkeypatch):
    """The negative control: nothing above may make the ordinary call refuse."""
    from orchestrator.integrations import inventory as inv
    from orchestrator.integrations.security import SecretStore

    high = SecretStore().put({"name": "admin", "role": "admin",
                              "target_origin": "http://app.test"})
    low = SecretStore().put({"name": "jim", "role": "customer",
                             "target_origin": "http://app.test"})
    result_ = await inv.cross_arm_privileged_function("s", high, low, "marker",
                                                      anonymous="anonymous")
    assert "arms_already_compared_in_the_opposite_direction" not in result_["refused_because"]
