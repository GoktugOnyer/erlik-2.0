"""What the cross-arm checks must not let the TARGET decide.

Both checks rest on one asymmetry: who a caller IS comes from the operator, and what a
response SAYS comes from the target — so a target can cost itself a finding and cannot
manufacture one. An adversarial pass over the foundation found four ways the target, or
an unlucky run, could manufacture one anyway. Each is reproduced here against real rows
and real evidence artifacts.

The evidence reader was the common cause. It keyed a response by the RUN's declared
`target.url` and took the FIRST step that had output, so the two bodies being compared
need not have come from the same request, the same step, or the same test case — and
nothing joined them to the endpoint rows the isolation gate actually looked at.
"""
import json
import uuid

import pytest

from orchestrator.integrations.contracts import Identity

URL = "http://app.test/rest/basket/1"
OWNED = 'HTTP/1.1 200 OK\r\n\r\n{"status":"success","data":{"id":1,"UserId":1}}'
REFUSED_403 = 'HTTP/1.1 403 Forbidden\r\n\r\n{"error":"no"}'
REFUSED_401 = 'HTTP/1.1 401 Unauthorized\r\n\r\nno'


@pytest.fixture
async def lab(tmp_path, monkeypatch):
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    from orchestrator.integrations.security import SecretStore
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    await db.execute("INSERT INTO integration_assessments(session_id,target,status,config) "
                     "VALUES(?,?,?,?)", ("s", "http://app.test", "completed", "{}"))
    store, handles = SecretStore(), {}
    for name, subject, role in (("jim", "2", "customer"), ("admin", "1", "admin")):
        identity = Identity.model_validate({
            "name": name, "target_origin": "http://app.test", "subject_id": subject,
            "role": role, "check": {"url": "http://app.test/me", "method": "GET"}})
        handles[name] = store.put(identity.model_dump())
        await db.execute("INSERT INTO integration_identities VALUES(?,?,?)",
                         (handles[name], name, "http://app.test"))
    handles["anonymous"] = "anonymous"
    return {"db": db, "h": handles}


async def stage(lab, identity, steps, url=URL, case="read", endpoint_url=None,
                parameter=""):
    """One stage, its endpoint row, and one run artifact with the given steps."""
    db = lab["db"]
    stage_id = uuid.uuid4().hex
    await db.execute("INSERT INTO integration_stages(id,session_id,adapter,identity_id,"
                     "status,result) VALUES(?,?,?,?,?,?)",
                     (stage_id, "s", "testcases", identity, "completed",
                      json.dumps({"status": "completed"})))
    await db.execute("INSERT OR REPLACE INTO integration_endpoints(session_id,url,method,"
                     "identity_id,sources,parameters) VALUES(?,?,?,?,?,?)",
                     ("s", endpoint_url or url, "GET", identity,
                      json.dumps(["katana"]), "[]"))
    run = {"test_case_id": case, "target": {"url": url, "parameter": parameter},
           "findings": [],
           "chain_next": [], "stopped_early": False, "duration_ms": 1, "produced": {},
           "steps": [{"step": name, "command": "curl", "success": True, "duration_ms": 1,
                      "exit_code": 0, "skipped": False, "error": None, "output": body}
                     for name, body in steps]}
    await db.evidence("s", stage_id, f"testcase:{case}", json.dumps(run))
    return stage_id


async def check(lab, anonymous="anonymous"):
    from orchestrator.integrations.inventory import cross_arm_authorization
    return await cross_arm_authorization("s", lab["h"]["jim"], lab["h"]["admin"],
                                         "data.UserId", anonymous)


# ----------------------------------------------------- the comparison is of one request

async def test_a_setup_step_cannot_stand_in_for_the_probe(lab):
    """The caller's run is [login 200 carrying the owner, read_as_caller 403]: the read
    was REFUSED and the 200 belongs to the login. Taking the first step with output read
    the login's body as the caller's access."""
    await stage(lab, lab["h"]["jim"], [("login", OWNED), ("read_as_caller", REFUSED_403)])
    await stage(lab, lab["h"]["admin"], [("read_as_caller", OWNED)])
    await stage(lab, "anonymous", [("read_as_caller", REFUSED_401)])
    result = await check(lab)
    assert result["findings"] == [], "the caller's actual read was refused"


async def test_bodies_from_different_test_cases_are_not_compared(lab):
    """The owner arm's body came from an injection probe against a different case. Two
    arms that issued different requests are not a differential, whatever they received."""
    await stage(lab, lab["h"]["jim"], [("read", OWNED)], case="WSTG-AUTHZ-04")
    await stage(lab, lab["h"]["admin"], [("sqli_probe", OWNED)], case="WSTG-INPV-05")
    await stage(lab, "anonymous", [("read", REFUSED_401)], case="WSTG-AUTHZ-04")
    result = await check(lab)
    assert result["findings"] == []


async def test_two_artifacts_for_one_request_are_dropped_not_ranked(lab):
    """One arm recorded the same (url, case, step, parameter) twice — a 403 and a 200. Row
    order used to decide, which both invents findings and loses them. Neither answer is the
    arm's answer, so the KEY is dropped and counted.

    Dropped rather than refusing the session, for the reason a real DVWA run forced: the
    key originally omitted the PARAMETER, so `WSTG-INPV-05.2:single_quote` probing `username`
    and probing `password` on one URL looked like one contradictory request and abandoned the
    whole comparison.
    """
    await stage(lab, lab["h"]["jim"], [("read", REFUSED_403)])
    await stage(lab, lab["h"]["jim"], [("read", OWNED)])
    await stage(lab, lab["h"]["admin"], [("read", OWNED)])
    await stage(lab, "anonymous", [("read", REFUSED_401)])
    result = await check(lab)
    assert result["findings"] == []
    assert result["ambiguous_evidence"] >= 1, result


async def test_two_probes_of_DIFFERENT_parameters_are_not_contradictory(lab):
    """Measured on the first real DVWA run: `WSTG-INPV-05.2` runs once per (endpoint,
    parameter) pair, so one URL legitimately carries several captures. Without the parameter
    in the key they collapsed into one, the differing captures read as self-contradiction,
    and `ambiguous_evidence` refused all 29 comparable operations."""
    from orchestrator.integrations.inventory import arm_responses

    await stage(lab, lab["h"]["jim"], [("probe", OWNED)], parameter="username")
    await stage(lab, lab["h"]["jim"], [("probe", REFUSED_403)], parameter="password")
    out, ambiguous, artifacts = await arm_responses("s", lab["h"]["jim"])
    assert ambiguous == set(), "two different parameters are two different requests"
    assert len(out) == 2


async def test_a_url_the_isolation_gate_never_compared_is_not_reported(lab):
    """The endpoint rows say both arms share `/rest/basket/1`; the evidence targets
    `/admin/export?all=1`. `compare_arms` ran on the rows and knows nothing about that
    URL, so a finding there is a finding nothing gated."""
    other = "http://app.test/admin/export?all=1"
    await stage(lab, lab["h"]["jim"], [("read", OWNED)], url=other, endpoint_url=URL)
    await stage(lab, lab["h"]["admin"], [("read", OWNED)], url=other, endpoint_url=URL)
    await stage(lab, "anonymous", [("read", REFUSED_401)], url=other, endpoint_url=URL)
    result = await check(lab)
    assert result["findings"] == []


# ------------------------------------------------- the anonymous arm has to have run

async def test_a_named_anonymous_arm_that_never_ran_is_refused(lab):
    """`service.register` creates an anonymous stage only via
    `config.identity_ids or ["anonymous"]`, so a two-identity run has NO anonymous arm —
    and an operator passing the lane's own literal name for it got findings with the
    load-bearing clause never evaluated."""
    await stage(lab, lab["h"]["jim"], [("read", OWNED)])
    await stage(lab, lab["h"]["admin"], [("read", OWNED)])
    result = await check(lab)
    assert result["findings"] == []
    assert "anonymous_arm_did_not_run" in result["refused_because"]


async def test_an_anonymous_arm_that_probed_something_else_is_not_a_denial(lab):
    await stage(lab, lab["h"]["jim"], [("read", OWNED)])
    await stage(lab, lab["h"]["admin"], [("read", OWNED)])
    await stage(lab, "anonymous", [("read", REFUSED_401)],
                url="http://app.test/rest/basket/9", endpoint_url=URL)
    result = await check(lab)
    assert result["findings"] == []


async def test_an_empty_anonymous_name_is_not_an_anonymous_arm(lab):
    await stage(lab, lab["h"]["jim"], [("read", OWNED)])
    await stage(lab, lab["h"]["admin"], [("read", OWNED)])
    await stage(lab, "anonymous", [("read", OWNED)])       # it PUBLISHED the object
    result = await check(lab, anonymous="")
    assert result["findings"] == []


def test_the_route_refuses_an_empty_anonymous_name():
    """`anonymous: str | None = None` with no `min_length` accepted `""`, which named no
    arm and then passed the presence check."""
    import pydantic
    from orchestrator.integrations.api import AuthorizationCheck

    with pytest.raises(pydantic.ValidationError):
        AuthorizationCheck(caller="a", owner="b", owner_field="data.UserId", anonymous="")


@pytest.mark.parametrize("artifact,why", [
    (b"not json at all", "a valid digest over something that is not a run"),
    (b'{"target":{"url":"' + URL.encode() + b'"},"steps":[]}', "a run with zero steps"),
])
async def test_an_unreadable_anonymous_artifact_is_not_a_denial(lab, artifact, why):
    """An arm whose evidence cannot be read did not answer. Scoring that as "refused"
    turns a read failure into the clause that makes a finding."""
    await stage(lab, lab["h"]["jim"], [("read", OWNED)])
    await stage(lab, lab["h"]["admin"], [("read", OWNED)])
    stage_id = uuid.uuid4().hex
    db = lab["db"]
    await db.execute("INSERT INTO integration_stages(id,session_id,adapter,identity_id,"
                     "status,result) VALUES(?,?,?,?,?,?)",
                     (stage_id, "s", "testcases", "anonymous", "completed",
                      json.dumps({"status": "completed"})))
    await db.execute("INSERT OR REPLACE INTO integration_endpoints(session_id,url,method,"
                     "identity_id,sources,parameters) VALUES(?,?,?,?,?,?)",
                     ("s", URL, "GET", "anonymous", json.dumps(["katana"]), "[]"))
    await db.evidence("s", stage_id, "testcase:read", artifact.decode())
    result = await check(lab)
    assert result["findings"] == [], why


# --------------------------------------- publication is about receipt, not about a value

@pytest.mark.parametrize("anonymous_body,why", [
    ('{"status":"success","data":{"id":1,"UserId":"1"}}', "owner retyped as a string"),
    ('{"status":"success","data":{"id":1}}', "owner field simply omitted"),
    ('{"status":"success","data":{"id":1,"UserId":99}}', "owner replaced"),
])
async def test_anonymous_receiving_the_object_suppresses_it_however_it_is_labelled(
        lab, anonymous_body, why):
    """Comparing the anonymous arm's owner VALUE let the target escape the clause by
    retyping or omitting the field — a no-privilege-needed way to manufacture a high
    finding on fully public data. What matters is that anonymous RECEIVED it."""
    await stage(lab, lab["h"]["jim"], [("read", OWNED)])
    await stage(lab, lab["h"]["admin"], [("read", OWNED)])
    await stage(lab, "anonymous", [("read", f"HTTP/1.1 200 OK\r\n\r\n{anonymous_body}")])
    result = await check(lab)
    assert result["findings"] == [], why


async def test_the_real_violation_still_reports(lab):
    """The positive control. Without it every assertion above is satisfied by a check
    that reports nothing at all."""
    await stage(lab, lab["h"]["jim"], [("read", OWNED)])
    await stage(lab, lab["h"]["admin"], [("read", OWNED)])
    await stage(lab, "anonymous", [("read", REFUSED_401)])
    result = await check(lab)
    assert result["refused_because"] == []
    assert len(result["findings"]) == 1
    assert result["findings"][0]["asserted_owner"] == 1
