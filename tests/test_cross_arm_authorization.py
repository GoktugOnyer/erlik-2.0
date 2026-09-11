"""Increment 7: authorization compared ACROSS stages — E-011's remaining half.

Increment 6 ended at a measured boundary. A lane stage carries exactly ONE identity, so
the `ownership` evaluator — which needs the caller, the declared owner and an anonymous
arm in a single case execution — can never run inside one. The lane-native shape is to
compare what each STAGE received, which is what this does.

IT COMPOSES ON THE ISOLATION GATE RATHER THAN REPEATING IT. `compare_arms` already
establishes whether two arms describe the same surface and refuses when they do not —
including the case the operation key introduces, where both arms reached an operation at
DIFFERENT concrete URLs because one carried a single-use token. Comparing responses from
arms that issued different requests measures the request, so this refuses outright rather
than reporting a finding nobody can act on.

THE SAFETY ASYMMETRY IS UNCHANGED, and it is the reason this is worth building at all:
who each caller IS comes from the OPERATOR (`Identity.subject_id`, Increment 6), and the
asserted owner comes from the TARGET. A target can cost itself a finding and cannot
manufacture one. The anonymous arm is what stops it calling published content a leak —
measured on Juice Shop, `/rest/products/1/reviews` returns every reviewer's email address
to anybody who asks.
"""
import json
import uuid

import pytest

from orchestrator.integrations.contracts import Identity


BASKET = "http://app.test/rest/basket/1"


def who(name, subject_id, **kw):
    return Identity.model_validate({
        "name": name, "target_origin": "http://app.test", "subject_id": subject_id,
        "check": {"url": "http://app.test/me", "method": "GET"}, **kw})


@pytest.fixture
async def lab(tmp_path, monkeypatch):
    """Two arms, one operation, with real evidence artifacts behind them."""
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    from orchestrator.integrations.security import SecretStore
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()

    store = SecretStore()
    handles = {}
    for name, subject in (("jim", "2"), ("admin", "1")):
        handle = store.put(who(name, subject).model_dump())
        handles[name] = handle
        await db.execute("INSERT INTO integration_identities VALUES(?,?,?)",
                         (handle, name, "http://app.test"))
    handles["anonymous"] = "anonymous"
    return {"db": db, "handles": handles}


async def arm(lab, identity, url=BASKET, body=None, status=200, case="WSTG-AUTHZ-04.2",
              parameter=""):
    """One stage's recorded run against one operation."""
    db = lab["db"]
    stage_id = uuid.uuid4().hex
    await db.execute(
        "INSERT INTO integration_stages(id,session_id,adapter,identity_id,status,result) "
        "VALUES(?,?,?,?,?,?)",
        (stage_id, "s", "testcases", identity, "completed", json.dumps({"status": "completed"})))
    await db.execute(
        "INSERT OR REPLACE INTO integration_endpoints"
        "(session_id,url,method,identity_id,sources,parameters) VALUES(?,?,?,?,?,?)",
        ("s", url, "GET", identity, json.dumps(["katana"]),
         json.dumps([parameter] if parameter else [])))
    run = {"test_case_id": case, "target": {"url": url, "parameter": parameter},
           "findings": [], "steps": [{
               "step": "read_as_caller", "command": f'curl -s -i "{url}"', "success": True,
               "duration_ms": 5, "exit_code": 0, "skipped": False, "error": None,
               "output": f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n"
                         + (body if body is not None else "")}],
           "chain_next": [], "stopped_early": False, "duration_ms": 5, "produced": {}}
    await db.evidence("s", stage_id, "testcase:" + case, json.dumps(run))


def owned_by(owner):
    return json.dumps({"status": "success", "data": {"id": 1, "UserId": owner}})


DENIED = json.dumps({"status": "error", "message": {}})


# --------------------------------------------------------------- the finding

async def test_a_cross_arm_violation_is_reported(lab):
    """jim (2) received an object the application attributes to 1; admin (1)
    corroborates it; anonymous was refused."""
    from orchestrator.integrations.inventory import cross_arm_authorization

    await arm(lab, lab["handles"]["jim"], body=owned_by(1))
    await arm(lab, lab["handles"]["admin"], body=owned_by(1))
    await arm(lab, "anonymous", body=DENIED, status=401)

    result = await cross_arm_authorization(
        "s", lab["handles"]["jim"], lab["handles"]["admin"], "data.UserId",
        anonymous="anonymous")
    assert result["refused_because"] == [], result
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["url"] == BASKET
    assert finding["asserted_owner"] == 1
    assert finding["caller_subject_id"] == "2"
    assert "anonymous" in finding["detail"]


# ------------------------------------------------------- the negative controls

async def test_the_caller_owning_it_is_not_a_finding(lab):
    from orchestrator.integrations.inventory import cross_arm_authorization

    await arm(lab, lab["handles"]["jim"], body=owned_by(2))
    await arm(lab, lab["handles"]["admin"], body=owned_by(2))
    await arm(lab, "anonymous", body=DENIED, status=401)
    result = await cross_arm_authorization("s", lab["handles"]["jim"],
                                           lab["handles"]["admin"], "data.UserId",
                                           anonymous="anonymous")
    assert result["findings"] == []


async def test_no_owner_asserted_is_not_a_finding(lab):
    """An absent object answers 200 with `{"data":null}` on Juice Shop, and a public list
    asserts no owner at all. Neither is a boundary being crossed."""
    from orchestrator.integrations.inventory import cross_arm_authorization

    for body in (json.dumps({"status": "success", "data": None}),
                 json.dumps({"status": "success", "data": [{"id": 1}]})):
        await arm(lab, lab["handles"]["jim"], body=body)
        await arm(lab, lab["handles"]["admin"], body=body)
        await arm(lab, "anonymous", body=DENIED, status=401)
        result = await cross_arm_authorization("s", lab["handles"]["jim"],
                                               lab["handles"]["admin"], "data.UserId",
                                               anonymous="anonymous")
        assert result["findings"] == [], body


async def test_content_anonymous_can_read_is_not_a_leak(lab):
    """The load-bearing clause. Measured on Juice Shop: /rest/products/1/reviews returns
    every reviewer's email address to anybody, so an ownership field on it would otherwise
    read as a critical finding."""
    from orchestrator.integrations.inventory import cross_arm_authorization

    await arm(lab, lab["handles"]["jim"], body=owned_by(1))
    await arm(lab, lab["handles"]["admin"], body=owned_by(1))
    await arm(lab, "anonymous", body=owned_by(1), status=200)
    result = await cross_arm_authorization("s", lab["handles"]["jim"],
                                           lab["handles"]["admin"], "data.UserId",
                                           anonymous="anonymous")
    assert result["findings"] == []


async def test_an_owner_that_cannot_corroborate_is_not_a_finding(lab):
    """A target printing `UserId: 1` at everybody while denying user 1 has leaked nothing
    to anybody."""
    from orchestrator.integrations.inventory import cross_arm_authorization

    await arm(lab, lab["handles"]["jim"], body=owned_by(1))
    await arm(lab, lab["handles"]["admin"], body=DENIED, status=403)
    await arm(lab, "anonymous", body=DENIED, status=401)
    result = await cross_arm_authorization("s", lab["handles"]["jim"],
                                           lab["handles"]["admin"], "data.UserId",
                                           anonymous="anonymous")
    assert result["findings"] == []


async def test_a_caller_who_was_refused_is_not_a_finding(lab):
    from orchestrator.integrations.inventory import cross_arm_authorization

    await arm(lab, lab["handles"]["jim"], body=DENIED, status=403)
    await arm(lab, lab["handles"]["admin"], body=owned_by(1))
    await arm(lab, "anonymous", body=DENIED, status=401)
    result = await cross_arm_authorization("s", lab["handles"]["jim"],
                                           lab["handles"]["admin"], "data.UserId",
                                           anonymous="anonymous")
    assert result["findings"] == []


# ------------------------------------------- it refuses rather than concluding

async def test_arms_that_are_not_comparable_are_refused_not_silently_clean(lab):
    """Composing on the isolation gate instead of repeating it.

    Comparing responses from arms that issued DIFFERENT requests measures the request.
    Here the arms reached the operation at different concrete URLs — the case the
    operation key introduces, which `compare_arms` already names — so this must refuse
    out loud rather than report no finding, because the two are not the same answer.
    """
    from orchestrator.integrations.inventory import cross_arm_authorization

    await arm(lab, lab["handles"]["jim"], url=BASKET + "?t=aaa", body=owned_by(1))
    await arm(lab, lab["handles"]["admin"], url=BASKET + "?t=bbb", body=owned_by(1))
    await arm(lab, "anonymous", body=DENIED, status=401)

    result = await cross_arm_authorization("s", lab["handles"]["jim"],
                                           lab["handles"]["admin"], "data.UserId",
                                           anonymous="anonymous")
    assert result["findings"] == []
    assert "per_arm_value_in_operation" in result["refused_because"], result


async def test_an_identity_without_a_declared_subject_is_refused(lab):
    """Without `subject_id` there is nothing operator-authored to compare the target's
    claim against, and taking the target's word on both sides is the forgery this design
    exists to prevent."""
    from orchestrator.integrations.inventory import cross_arm_authorization
    from orchestrator.integrations.security import SecretStore

    nameless = SecretStore().put(who("ghost", "").model_dump())
    await lab["db"].execute("INSERT INTO integration_identities VALUES(?,?,?)",
                            (nameless, "ghost", "http://app.test"))
    await arm(lab, nameless, body=owned_by(1))
    await arm(lab, lab["handles"]["admin"], body=owned_by(1))

    result = await cross_arm_authorization("s", nameless, lab["handles"]["admin"],
                                           "data.UserId")
    assert result["findings"] == []
    assert "caller_has_no_subject_id" in result["refused_because"]


async def test_a_missing_anonymous_arm_is_refused_not_assumed(lab):
    """The clause cannot be evaluated without the arm, and a clause nobody ran is not a
    clause that passed — the same rule the `ownership` evaluator applies."""
    from orchestrator.integrations.inventory import cross_arm_authorization

    await arm(lab, lab["handles"]["jim"], body=owned_by(1))
    await arm(lab, lab["handles"]["admin"], body=owned_by(1))

    result = await cross_arm_authorization("s", lab["handles"]["jim"],
                                           lab["handles"]["admin"], "data.UserId")
    assert result["findings"] == []
    assert "no_anonymous_arm" in result["refused_because"]


# ------------------------------------------------------------------ the route

async def test_the_route_reports_the_violation(lab):
    from orchestrator.integrations import service
    from orchestrator.integrations.api import authorization_check, AuthorizationCheck
    from orchestrator.integrations.contracts import AssessmentConfig

    await service.register("s", "http://app.test", AssessmentConfig(
        scope={"allow_hosts": ["app.test"], "allow_ports": [80]}))
    await arm(lab, lab["handles"]["jim"], body=owned_by(1))
    await arm(lab, lab["handles"]["admin"], body=owned_by(1))
    await arm(lab, "anonymous", body=DENIED, status=401)

    payload = await authorization_check("s", AuthorizationCheck(
        caller=lab["handles"]["jim"], owner=lab["handles"]["admin"],
        owner_field="data.UserId", anonymous="anonymous"))
    assert len(payload["findings"]) == 1
    assert payload["refused_because"] == []


async def test_the_route_says_a_refusal_is_not_a_clean_result(lab):
    from orchestrator.integrations import service
    from orchestrator.integrations.api import authorization_check, AuthorizationCheck
    from orchestrator.integrations.contracts import AssessmentConfig

    await service.register("s", "http://app.test", AssessmentConfig(
        scope={"allow_hosts": ["app.test"], "allow_ports": [80]}))
    await arm(lab, lab["handles"]["jim"], body=owned_by(1))
    await arm(lab, lab["handles"]["admin"], body=owned_by(1))

    payload = await authorization_check("s", AuthorizationCheck(
        caller=lab["handles"]["jim"], owner=lab["handles"]["admin"],
        owner_field="data.UserId"))
    assert payload["findings"] == []
    assert "no_anonymous_arm" in payload["refused_because"]
    assert "not a clean result" in payload["establishes"]


async def test_an_unknown_session_is_a_404(lab):
    from fastapi import HTTPException
    from orchestrator.integrations.api import authorization_check, AuthorizationCheck

    with pytest.raises(HTTPException) as exc:
        await authorization_check("nope", AuthorizationCheck(
            caller="a", owner="b", owner_field="data.UserId"))
    assert exc.value.status_code == 404
