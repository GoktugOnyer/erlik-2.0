"""Nine increments of authorization work produced JSON and persisted nothing.

`cross_arm_authorization` and `cross_arm_privileged_function` are the strongest evidence the
lane produces: a three-arm differential against an operator declaration, measured at two true
positives and zero false positives on a real Juice Shop assessment. And they existed only as the
body of an API response. Measured on that run:

    integration_findings            9 rows, every one from a catalogue case
    the checks reported             /api/Users and /api/Users/1

So `GET /sessions/{id}/findings` omitted them, the DefectDojo export omitted them, triage could
not mark them, and `coverage()` never credited those operations as `verified`. The lane threw away
the only findings it was most sure of.

THE MARKER MUST NOT TRAVEL. It names the application's private data — a real address, an internal
identifier — and a finding goes into an export. The check already records only a 12-character
digest; the finding does the same, and its evidence states what each arm RECEIVED rather than
quoting any of it. The obvious evidence string would quote the response around the marker, which
IS the private data.
"""
import json
import uuid

import pytest

from orchestrator.integrations.inventory import AUTHORIZATION_RULES, authorization_findings

TARGET = "http://app.test/"

FUNCTION_RESULT = {
    "refused_because": [],
    "findings": [{
        "url": "http://app.test/api/Users",
        "privileged": "handle-admin", "privileged_role": "admin",
        "unprivileged": "handle-jim", "unprivileged_role": "customer",
        "marker_sha256": "c5c79a1df019",
        "detail": "both arms received the marked data and an anonymous arm did not",
    }],
}

OBJECT_RESULT = {
    "refused_because": [],
    "findings": [{
        "url": "http://app.test/rest/basket/1",
        "caller": "handle-jim", "caller_subject_id": "2",
        "owner": "handle-admin", "asserted_owner": 1, "owner_field": "data.UserId",
        "detail": "the caller is declared to be '2' and the application attributed this to '1'",
    }],
}


# --------------------------------------------------------- what the finding says

@pytest.mark.parametrize("check,result,rule,cwe", [
    ("function", FUNCTION_RESULT, "erlik:authorization:privileged-function", "285"),
    ("object", OBJECT_RESULT, "erlik:authorization:object", "639"),
])
def test_a_check_result_becomes_a_finding(check, result, rule, cwe):
    findings = authorization_findings(TARGET, check, result)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule == rule == AUTHORIZATION_RULES[check]
    assert finding.severity == "high"
    assert finding.source == "cross-arm"
    assert finding.methodology == ["WSTG-AUTHZ-04"]
    assert finding.cwe == cwe, "a bare number, which is what DefectDojo's Finding.cwe is"


def test_the_finding_is_attributed_to_the_arm_that_crossed():
    """Not to the privileged arm. The violation is that the UNPRIVILEGED identity reached it, and
    `identity` is part of the fingerprint."""
    assert authorization_findings(TARGET, "function", FUNCTION_RESULT)[0].identity == "handle-jim"
    assert authorization_findings(TARGET, "object", OBJECT_RESULT)[0].identity == "handle-jim"


def test_the_evidence_carries_the_three_arm_differential():
    evidence = authorization_findings(TARGET, "function", FUNCTION_RESULT)[0].evidence
    assert "privileged arm" in evidence and "unprivileged arm" in evidence
    assert "anonymous arm" in evidence
    assert "c5c79a1df019" in evidence, "the digest says which declaration this was"


def test_the_object_level_evidence_says_whose_claim_is_whose():
    """The safety asymmetry, in the text a client reads: the subject id is the operator's and the
    asserted owner is the target's."""
    evidence = authorization_findings(TARGET, "object", OBJECT_RESULT)[0].evidence
    assert "operator-supplied" in evidence
    assert "data.UserId" in evidence and "'2'" in evidence


# ------------------------------------------------------ what must never travel

@pytest.mark.parametrize("marker", [
    '"email":"admin@juice-sh.op"',
    '"password":"hunter2"',
    '"totpSecret":"JBSWY3DPEHPK3PXP"',
])
def test_the_marker_never_reaches_the_finding(marker):
    """The check is given the marker; the finding is given its digest. A finding travels into an
    export, and the marker names the application's private data.

    The result dict here carries the marker under several plausible keys, because the structural
    reason this holds is that `authorization_findings` copies only the digest — so a future
    change that reached for the marker itself has to fail here.
    """
    import hashlib

    result = {"refused_because": [], "findings": [{
        **FUNCTION_RESULT["findings"][0],
        "marker": marker, "private_object_marker": marker, "forbidden_marker": marker,
        "marker_sha256": hashlib.sha256(marker.encode()).hexdigest()[:12]}]}
    blob = authorization_findings(TARGET, "function", result)[0].model_dump_json()
    assert marker not in blob
    assert "admin@juice-sh.op" not in blob and "hunter2" not in blob
    assert "JBSWY3DPEHPK3PXP" not in blob
    # ...and the digest IS there, so the reader can tell which declaration this was.
    assert hashlib.sha256(marker.encode()).hexdigest()[:12] in blob


def test_a_refused_check_records_nothing():
    """A refusal means the comparison did not run. Turning that into zero rows would be
    indistinguishable from a clean result — the caller is expected to read the reason."""
    refused = {"refused_because": ["no_anonymous_arm"], "findings": []}
    assert authorization_findings(TARGET, "function", refused) == []
    # ...and a refusal alongside findings, which should not happen, is still refused.
    assert authorization_findings(
        TARGET, "function",
        {**FUNCTION_RESULT, "refused_because": ["ambiguous_evidence"]}) == []


# ------------------------------------------------------------ the fingerprint

def test_the_same_violation_has_one_fingerprint():
    first = authorization_findings(TARGET, "function", FUNCTION_RESULT)[0]
    second = authorization_findings(TARGET, "function", FUNCTION_RESULT)[0]
    assert first.fingerprint == second.fingerprint


def test_the_two_checks_do_not_collide_on_one_url():
    """Both can fire on the same URL, and they are different claims about it. `persist_result`
    writes INSERT OR REPLACE on (session_id, fingerprint), and this codebase has already recorded
    one case where that silently replaced a finding."""
    url = "http://app.test/api/Users/1"
    one = authorization_findings(
        TARGET, "function",
        {"refused_because": [], "findings": [{**FUNCTION_RESULT["findings"][0], "url": url}]})[0]
    two = authorization_findings(
        TARGET, "object",
        {"refused_because": [], "findings": [{**OBJECT_RESULT["findings"][0], "url": url}]})[0]
    assert one.fingerprint != two.fingerprint


def test_two_urls_do_not_collide():
    a = authorization_findings(TARGET, "function", FUNCTION_RESULT)[0]
    b = authorization_findings(TARGET, "function", {"refused_because": [], "findings": [
        {**FUNCTION_RESULT["findings"][0], "url": "http://app.test/api/Users/1"}]})[0]
    assert a.fingerprint != b.fingerprint


# --------------------------------------------- and they reach the product

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


async def test_persisting_is_idempotent(lane):
    findings = authorization_findings(TARGET, "function", FUNCTION_RESULT)
    await lane.persist_findings("s", findings)
    await lane.persist_findings("s", authorization_findings(TARGET, "function", FUNCTION_RESULT))
    rows = await lane.rows("SELECT COUNT(*) n FROM integration_findings WHERE session_id='s'")
    assert rows[0]["n"] == 1


async def test_persisting_preserves_triage(lane):
    """An operator who marked one of these a false positive must not have that undone by running
    the check again."""
    await lane.persist_findings("s", authorization_findings(TARGET, "function", FUNCTION_RESULT))
    row = (await lane.rows("SELECT fingerprint,payload FROM integration_findings "
                           "WHERE session_id='s'"))[0]
    payload = json.loads(row["payload"])
    payload.update(triage_state="false_positive", triage_note="the marker was mine")
    await lane.execute("UPDATE integration_findings SET payload=? WHERE session_id='s' AND "
                       "fingerprint=?", (json.dumps(payload), row["fingerprint"]))

    await lane.persist_findings("s", authorization_findings(TARGET, "function", FUNCTION_RESULT))
    again = json.loads((await lane.rows("SELECT payload FROM integration_findings "
                                        "WHERE session_id='s'"))[0]["payload"])
    assert again["triage_state"] == "false_positive"
    assert again["triage_note"] == "the marker was mine"


async def test_the_finding_reaches_the_export_payload(lane):
    from orchestrator.integrations.defectdojo import finding_payload

    await lane.persist_findings("s", authorization_findings(TARGET, "function", FUNCTION_RESULT))
    stored = json.loads((await lane.rows("SELECT payload FROM integration_findings "
                                         "WHERE session_id='s'"))[0]["payload"])
    payload = finding_payload(stored)
    assert payload["severity"] == "High"
    assert payload["verified"] is True, "a three-arm differential is confirmed-grade"
    assert payload["endpoints"] == ["http://app.test/api/Users"]
    assert payload["cwe"] == 285
    assert "anonymous arm" in payload["description"], "the differential travels with the claim"


def test_the_cwe_reaches_the_export_at_all():
    """It was stored and never sent. Findings have carried a cwe since the ZAP adapter began
    recording `alert["cweid"]`, and the export payload dropped it — so DefectDojo's own CWE
    reporting was empty for every erlik import."""
    from orchestrator.integrations.defectdojo import finding_payload

    base = {"title": "t", "basis": "b", "severity": "high", "fingerprint": "f",
            "url": "http://a/x", "confidence": "confirmed", "evidence": ""}
    assert finding_payload({**base, "cwe": "89"})["cwe"] == 89
    # Not guessed at when it is not a bare number.
    assert "cwe" not in finding_payload({**base, "cwe": "CWE-89"})
    assert "cwe" not in finding_payload(base)


async def test_the_route_records_what_it_finds(lane, monkeypatch):
    """The route used to return these and keep nothing. An operator who called it saw JSON and the
    product was unchanged: no report, no export, no triage."""
    from orchestrator.integrations import api

    async def check(session_id, privileged, unprivileged, marker, anonymous=None):
        return FUNCTION_RESULT

    import orchestrator.integrations.inventory as inv
    monkeypatch.setattr(inv, "cross_arm_privileged_function", check)

    body = api.PrivilegedFunctionCheck(privileged="handle-admin", unprivileged="handle-jim",
                                       marker='"email":"admin@app.test"', anonymous="anonymous")
    response = await api.privileged_function_check("s", body)

    assert response["recorded"], "the route did not say what it recorded"
    rows = await lane.rows("SELECT payload FROM integration_findings WHERE session_id='s'")
    assert len(rows) == 1
    stored = json.loads(rows[0]["payload"])
    assert stored["rule"] == "erlik:authorization:privileged-function"
    assert stored["fingerprint"] == response["recorded"][0]
    # The route's own payload still answers the question it was asked.
    assert response["findings"] == FUNCTION_RESULT["findings"]


async def test_the_object_level_route_records_too(lane, monkeypatch):
    from orchestrator.integrations import api
    import orchestrator.integrations.inventory as inv

    async def check(session_id, caller, owner, owner_field, anonymous=None):
        return OBJECT_RESULT

    monkeypatch.setattr(inv, "cross_arm_authorization", check)
    body = api.AuthorizationCheck(caller="handle-jim", owner="handle-admin",
                                  owner_field="data.UserId", anonymous="anonymous")
    response = await api.authorization_check("s", body)
    assert response["recorded"]
    rows = await lane.rows("SELECT payload FROM integration_findings WHERE session_id='s'")
    assert json.loads(rows[0]["payload"])["rule"] == "erlik:authorization:object"


async def test_a_refused_route_call_records_nothing(lane, monkeypatch):
    from orchestrator.integrations import api
    import orchestrator.integrations.inventory as inv

    async def check(session_id, privileged, unprivileged, marker, anonymous=None):
        return {"refused_because": ["no_anonymous_arm"], "findings": []}

    monkeypatch.setattr(inv, "cross_arm_privileged_function", check)
    body = api.PrivilegedFunctionCheck(privileged="a", unprivileged="b", marker="m")
    response = await api.privileged_function_check("s", body)
    assert response["recorded"] == []
    assert await lane.rows("SELECT 1 FROM integration_findings WHERE session_id='s'") == []


async def test_coverage_credits_a_pair_no_catalogue_case_probed(lane):
    """`verified` used to be reachable only from `answered` — only when a catalogue case had
    probed the pair and got bytes back. A cross-arm finding does not come out of a case, so
    measured on a real run the operation carrying a HIGH `confirmed` privilege crossing was
    reported `not_run`: outstanding work, on the pair the lane was most sure about. A finding on
    a pair now outranks every other state."""
    from orchestrator.integrations.inventory import coverage

    url = "http://app.test/api/Users"
    arm = "handle-jim"
    await lane.execute("INSERT INTO integration_stages(id,session_id,adapter,identity_id,status,"
                       "result) VALUES(?,?,?,?,?,?)",
                       ("st", "s", "testcases", arm, "completed",
                        json.dumps({"status": "completed", "observations": []})))
    await lane.execute("INSERT OR REPLACE INTO integration_endpoints(session_id,url,method,"
                       "identity_id,sources,parameters) VALUES(?,?,?,?,?,?)",
                       ("s", url, "GET", arm, json.dumps(["katana"]), "[]"))

    before = {r["url"]: r["state"] for r in await coverage("s")}
    assert before[url] == "not_attempted", before

    await lane.persist_findings("s", authorization_findings(TARGET, "function", FUNCTION_RESULT))
    after = [r for r in await coverage("s") if r["url"] == url][0]
    assert after["state"] == "verified", after
    assert "erlik:authorization:privileged-function" in after["reason"]
    assert "without a catalogue check running" in after["reason"], (
        "and it must say so, or a reader would think a case probed it")


async def test_a_finding_outranks_a_case_that_did_not_run(lane):
    """The other branch: a catalogue case DID produce an observation for this pair, and it says
    the case never ran (budget truncation). The finding is the stronger fact and must win — a
    pair carrying a HIGH confirmed violation cannot be reported as untested work."""
    from orchestrator.integrations.inventory import coverage

    url = "http://app.test/api/Users"
    arm = "handle-jim"
    await lane.execute("INSERT INTO integration_stages(id,session_id,adapter,identity_id,status,"
                       "result) VALUES(?,?,?,?,?,?)",
                       ("st", "s", "testcases", arm, "completed", json.dumps({
                           "status": "partial",
                           "observations": [{"type": "test_case_not_run",
                                             "test_case_id": "WSTG-INPV-05.2", "url": url,
                                             "steps": [], "reason": "budget"}]})))
    await lane.execute("INSERT OR REPLACE INTO integration_endpoints(session_id,url,method,"
                       "identity_id,sources,parameters) VALUES(?,?,?,?,?,?)",
                       ("s", url, "GET", arm, json.dumps(["katana"]), "[]"))

    before = [r for r in await coverage("s") if r["url"] == url][0]
    assert before["state"] == "not_run", before

    await lane.persist_findings("s", authorization_findings(TARGET, "function", FUNCTION_RESULT))
    after = [r for r in await coverage("s") if r["url"] == url][0]
    assert after["state"] == "verified", after
    assert "erlik:authorization:privileged-function" in after["reason"]
