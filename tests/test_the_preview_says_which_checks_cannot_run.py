"""E-010: "the preview should state what the run **will not** do, not only what it will."

The budget half of that was already there — `preview` reports per-case target budgets and how
many case-targets `max_urls` will not reach. This is the other half, and it is the one that
costs a whole assessment: the cross-arm checks are the highest-value capability in the
product, and the commonest way to lose them is a declaration nobody filled in. Measured
repeatedly while building them — `role_not_declared`, `caller_has_no_subject_id`,
`arms_share_a_role`. Every one of those refusals is honest, and every one arrives after the
containers have run.

ONE PREDICATE. `declaration_refusals` is called by the checks AND by the preview, because the
alternative is a preview that predicts one thing while the check does another.
`test_the_preview_predicts_what_the_check_actually_does` walks a matrix of declarations and
asserts the two agree — without it, this file would be testing a second implementation of a
guess.

AND IT DOES NOT PREDICT ARGUMENTS IT CANNOT SEE. The anonymous arm, the owner field and the
marker reach the checks from the route rather than the configuration. The preview says whether
an anonymous arm will be REGISTERED — both checks refuse without one — and says nothing about
a marker. Guessing at the operator's next keystroke would be wrong for free.
"""
import json
import uuid

import pytest

from orchestrator.integrations.contracts import AssessmentConfig, Identity
from orchestrator.integrations.inventory import (
    authorization_readiness, declaration_refusals)
from orchestrator.integrations.security import SecretStore

URL = "http://app.test/api/Users/1"


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


def who(name, **kw):
    return Identity.model_validate({
        "name": name, "target_origin": "http://app.test",
        "check": {"url": "http://app.test/me", "method": "GET"}, **kw})


def settings(ids, anonymous=True):
    return AssessmentConfig(scope={"allow_hosts": ["app.test"], "allow_ports": [80]},
                            identity_ids=ids, anonymous_arm=anonymous)


DECLARATIONS = {
    "nothing declared": ({}, {}),
    "roles but no subjects": ({"role": "admin"}, {"role": "customer"}),
    "subjects but no roles": ({"subject_id": "1"}, {"subject_id": "2"}),
    "one subject missing": ({"subject_id": "1", "role": "admin"}, {"role": "customer"}),
    "both arms one role": ({"subject_id": "1", "role": "same"},
                           {"subject_id": "2", "role": "same"}),
    "fully declared": ({"subject_id": "1", "role": "admin"},
                       {"subject_id": "2", "role": "customer"}),
}


# --------------------------------------------------------------- what it predicts


@pytest.mark.parametrize("label", sorted(DECLARATIONS))
def test_the_preview_names_the_declaration_that_is_missing(label):
    first, second = DECLARATIONS[label]
    store = SecretStore()
    ids = [store.put(who("a", **first).model_dump()), store.put(who("b", **second).model_dump())]
    readiness = authorization_readiness(settings(ids))
    refused = {reason for pair in readiness["pairs"] for reason in pair["will_refuse"]}
    expected = {
        "nothing declared": {"caller_has_no_subject_id", "owner_has_no_subject_id",
                             "role_not_declared"},
        "roles but no subjects": {"caller_has_no_subject_id", "owner_has_no_subject_id"},
        "subjects but no roles": {"role_not_declared"},
        "one subject missing": {"caller_has_no_subject_id", "owner_has_no_subject_id"},
        "both arms one role": {"arms_share_a_role"},
        "fully declared": set(),
    }[label]
    assert refused == expected, readiness["pairs"]


def test_a_complete_configuration_is_reported_runnable():
    """The positive control. Every assertion above is only meaningful because this one
    reports no obstacle — a readiness report that always found something would be ignored."""
    store = SecretStore()
    ids = [store.put(who("admin", subject_id="1", role="admin").model_dump()),
           store.put(who("jim", subject_id="2", role="customer").model_dump())]
    readiness = authorization_readiness(settings(ids))
    assert readiness["runnable_pairs"] == len(readiness["pairs"]) == 4
    assert readiness["remedy"] == "every identity pair can be compared in both directions"


def test_both_directions_are_reported_separately():
    """Which identity is the caller and which the owner is the operator's choice at the
    route, and a configuration can support one direction and not the other."""
    store = SecretStore()
    ids = [store.put(who("admin", subject_id="1", role="admin").model_dump()),
           store.put(who("jim", role="customer").model_dump())]
    readiness = authorization_readiness(settings(ids))
    object_pairs = {(p["first"], p["second"]): p["will_refuse"]
                    for p in readiness["pairs"] if p["check"] == "object"}
    assert object_pairs[("admin", "jim")] == ["owner_has_no_subject_id"]
    assert object_pairs[("jim", "admin")] == ["caller_has_no_subject_id"]


def test_a_missing_anonymous_arm_is_reported():
    store = SecretStore()
    ids = [store.put(who("admin", subject_id="1", role="admin").model_dump()),
           store.put(who("jim", subject_id="2", role="customer").model_dump())]
    assert authorization_readiness(settings(ids, anonymous=False))[
        "anonymous_arm_registered"] is False
    assert "anonymous_arm" in authorization_readiness(settings(ids, anonymous=False))["remedy"]
    assert authorization_readiness(settings(ids))["anonymous_arm_registered"] is True


def test_one_identity_cannot_be_compared_with_itself():
    store = SecretStore()
    ids = [store.put(who("admin", subject_id="1", role="admin").model_dump())]
    readiness = authorization_readiness(settings(ids))
    assert readiness["pairs"] == []
    assert "fewer than two identities" in readiness["remedy"]


def test_the_preview_does_not_predict_arguments_it_cannot_see():
    """The marker, the owner field and the anonymous ARGUMENT arrive at the route. A preview
    that guessed at them would be predicting the operator's next keystroke."""
    store = SecretStore()
    ids = [store.put(who("admin", subject_id="1", role="admin").model_dump()),
           store.put(who("jim", subject_id="2", role="customer").model_dump())]
    rendered = json.dumps(authorization_readiness(settings(ids)))
    for unknowable in ("marker_unusable", "owner_field", "arms_share_one_identity",
                       "did_not_run"):
        assert unknowable not in rendered, (
            f"the preview claims something about {unknowable}, which it cannot know before "
            f"the run")


# ------------------------------------------- and it predicts what the check actually does


async def seed(db, first_kw, second_kw):
    store = SecretStore()
    first = store.put(who("a", **first_kw).model_dump())
    second = store.put(who("b", **second_kw).model_dump())
    await db.execute("INSERT INTO integration_assessments(session_id,target,status,config) "
                     "VALUES(?,?,?,?)", ("s", "http://app.test/", "completed", "{}"))
    body = json.dumps({"data": {"id": 1, "UserId": "1", "email": "admin@app.test"}})
    for arm in (first, second, "anonymous"):
        stage = uuid.uuid4().hex
        await db.execute(
            "INSERT INTO integration_stages(id,session_id,adapter,identity_id,status,result)"
            " VALUES(?,?,?,?,?,?)",
            (stage, "s", "testcases", arm, "completed", json.dumps({"status": "completed"})))
        await db.execute(
            "INSERT OR REPLACE INTO integration_endpoints"
            "(session_id,url,method,identity_id,sources,parameters) VALUES(?,?,?,?,?,?)",
            ("s", URL, "GET", arm, json.dumps(["katana"]), json.dumps([])))
        got = body if arm != "anonymous" else json.dumps({"status": "error", "message": {}})
        status = 200 if arm != "anonymous" else 401
        await db.evidence("s", stage, "testcase:WSTG-AUTHZ-04.2", json.dumps({
            "test_case_id": "WSTG-AUTHZ-04.2", "target": {"url": URL, "parameter": ""},
            "findings": [], "chain_next": [], "stopped_early": False, "duration_ms": 5,
            "produced": {}, "steps": [{
                "step": "read", "command": f'curl -s -i "{URL}"', "success": True,
                "duration_ms": 5, "exit_code": 0, "skipped": False, "error": None,
                "output": f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n"
                          + got}]}))
    return first, second


@pytest.mark.parametrize("label", sorted(DECLARATIONS))
async def test_the_preview_predicts_what_the_check_actually_does(lane, label):
    """THE TEST THIS FILE RESTS ON. A preview is only worth reading if the run agrees with
    it, and the way a preview goes wrong is by drifting from the thing it predicts."""
    from orchestrator.integrations.inventory import (
        cross_arm_authorization, cross_arm_privileged_function)

    first_kw, second_kw = DECLARATIONS[label]
    first, second = await seed(lane, first_kw, second_kw)
    predicted = {(p["check"], p["first"], p["second"]): set(p["will_refuse"])
                 for p in authorization_readiness(
                     settings([first, second]))["pairs"]}

    actual_object = await cross_arm_authorization("s", first, second, "data.UserId",
                                                  "anonymous")
    actual_function = await cross_arm_privileged_function("s", first, second,
                                                          "admin@app.test", "anonymous")
    for check, result in (("object", actual_object), ("function", actual_function)):
        forecast = predicted[(check, "a", "b")]
        assert forecast <= set(result["refused_because"]), (
            f"{check}: the preview predicted {sorted(forecast)} and the check refused with "
            f"{sorted(result['refused_because'])}")
        # And nothing declaration-shaped was refused that the preview did not foresee.
        declaration_shaped = {r for r in result["refused_because"]
                              if r in {"caller_has_no_subject_id", "owner_has_no_subject_id",
                                       "role_not_declared", "arms_share_a_role"}}
        assert declaration_shaped == forecast, (
            f"{check}: the check refused with {sorted(declaration_shaped)} which the preview "
            f"did not predict ({sorted(forecast)})")


def test_the_checks_and_the_preview_read_the_same_predicate():
    """Two copies of one fact is what would let the differential above start passing for the
    wrong reason — each copy tested against itself."""
    import inspect

    from orchestrator.integrations import inventory

    for reader in (inventory.cross_arm_authorization,
                   inventory.cross_arm_privileged_function,
                   inventory.authorization_readiness):
        assert "declaration_refusals(" in inspect.getsource(reader), reader.__name__


async def test_the_launch_preview_carries_it(lane):
    """It has to be in the thing an operator actually reads before launching."""
    from orchestrator.integrations.inventory import preview

    store = SecretStore()
    ids = [store.put(who("admin", subject_id="1", role="admin").model_dump()),
           store.put(who("jim", role="customer").model_dump())]
    out = await preview("s", settings(ids))
    assert "authorization_readiness" in out
    assert out["authorization_readiness"]["runnable_pairs"] < len(
        out["authorization_readiness"]["pairs"])
