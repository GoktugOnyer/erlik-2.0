"""E-034: whether a `partial` arm should refuse, decided by sweep rather than by argument.

A cross-arm comparison answers in three ways, and the rule is "could this have invented a
finding, or only lost one?" A `partial` arm — one that read part of the surface — is currently
REPORTED rather than refused, on the strength of one data point: a finding surviving a
60-of-117 truncation with all three cited artifacts checking out. The plan says the line moves
if a real run is found where a `partial` arm produces a finding inspection cannot stand
behind, and that the measurement to redo is the sweep, not the reasoning.

This is the sweep. The falsifiable form of "a missing capture cannot manufacture one" is:
truncating any arm's evidence must never ADD a finding. It could, in principle — the ANONYMOUS
arm's capture is what REFUSES a finding, since content an unauthenticated caller received is
published rather than crossed. Delete that capture and the refusal has nothing to fire on.

It does not, and the reason is a named clause rather than luck. `cross_arm_privileged_function`
clause 3:

    # `get` with a default would read "the anonymous arm never probed this" as "the
    # anonymous arm was refused", which is the unrun-clause defect this project keeps removing
    if key not in anonymous_saw:
        continue

and the object-level check has its twin. Measured below across every arm and every truncation
level: the finding set only ever shrinks.
"""
import json
import uuid

import pytest

from orchestrator.integrations.contracts import Identity
from orchestrator.integrations.security import SecretStore

MARKER = "admin@app.test"
CROSSINGS = [f"http://app.test/api/Users/{n}" for n in range(1, 9)]
PUBLIC = [f"http://app.test/rest/products/{n}/reviews" for n in range(1, 5)]
ALL_URLS = CROSSINGS + PUBLIC


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


async def seed(db):
    """Twelve operations: eight the anonymous arm is refused, four it can read."""
    store = SecretStore()
    handles = {}
    for name, subject, role in (("jim", "2", "customer"), ("admin", "1", "admin")):
        handles[name] = store.put(Identity.model_validate({
            "name": name, "target_origin": "http://app.test", "subject_id": subject,
            "role": role, "check": {"url": "http://app.test/me", "method": "GET"}
        }).model_dump())
    handles["anonymous"] = "anonymous"
    await db.execute("INSERT INTO integration_assessments(session_id,target,status,config) "
                     "VALUES(?,?,?,?)", ("s", "http://app.test/", "completed", "{}"))
    marked = json.dumps({"data": {"id": 1, "UserId": "1", "email": MARKER}})
    denied = json.dumps({"status": "error", "message": {}})
    artifacts = {}
    for arm in handles.values():
        stage = uuid.uuid4().hex
        await db.execute(
            "INSERT INTO integration_stages(id,session_id,adapter,identity_id,status,result)"
            " VALUES(?,?,?,?,?,?)",
            (stage, "s", "testcases", arm, "completed", json.dumps({"status": "completed"})))
        for url in ALL_URLS:
            await db.execute(
                "INSERT OR REPLACE INTO integration_endpoints"
                "(session_id,url,method,identity_id,sources,parameters) VALUES(?,?,?,?,?,?)",
                ("s", url, "GET", arm, json.dumps(["katana"]), json.dumps([])))
            if arm == "anonymous" and url in CROSSINGS:
                body, status = denied, 401
            else:
                body, status = marked, 200
            artifact = await db.evidence("s", stage, "testcase:WSTG-AUTHZ-04.2", json.dumps({
                "test_case_id": "WSTG-AUTHZ-04.2", "target": {"url": url, "parameter": ""},
                "findings": [], "chain_next": [], "stopped_early": False, "duration_ms": 5,
                "produced": {}, "steps": [{
                    "step": "read", "command": f'curl -s -i "{url}"', "success": True,
                    "duration_ms": 5, "exit_code": 0, "skipped": False, "error": None,
                    "output": f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n"
                              + body}]}))
            artifacts[(arm, url)] = (stage, artifact)
    return handles, artifacts


async def both_checks(handles):
    """Every finding either cross-arm check makes, as a set of (check, url)."""
    from orchestrator.integrations.inventory import (
        cross_arm_authorization, cross_arm_privileged_function)

    out = set()
    function = await cross_arm_privileged_function(
        "s", handles["admin"], handles["jim"], MARKER, "anonymous")
    out |= {("function", f["url"]) for f in function.get("findings") or []}
    obj = await cross_arm_authorization(
        "s", handles["jim"], handles["admin"], "data.UserId", "anonymous")
    out |= {("object", f["url"]) for f in obj.get("findings") or []}
    return out


async def truncate(db, artifacts, arm, keep):
    """Leave `keep` of this arm's captures. Deterministic: sorted url order."""
    urls = sorted(u for (a, u) in artifacts if a == arm)
    for url in urls[keep:]:
        await db.execute("DELETE FROM integration_evidence WHERE id=?",
                         (artifacts[(arm, url)][1],))
    stage = artifacts[(arm, urls[0])][0]
    await db.execute("UPDATE integration_stages SET status='partial' WHERE id=?", (stage,))


# ------------------------------------------------------------------------ the sweep


async def test_the_complete_run_finds_the_crossings_and_refuses_the_public(lane):
    """The baseline every assertion below is relative to. Without it the sweep would be
    comparing empty sets and proving nothing."""
    handles, _ = await seed(lane)
    found = await both_checks(handles)
    urls = {url for _, url in found}
    assert urls, "the complete run found nothing; the sweep would be vacuous"
    assert urls <= set(CROSSINGS), (
        f"the complete run reported content the anonymous arm can read: "
        f"{sorted(urls - set(CROSSINGS))}")


@pytest.mark.parametrize("arm", ["anonymous", "jim", "admin"])
@pytest.mark.parametrize("keep", [11, 8, 6, 4, 2, 1, 0])
async def test_truncating_any_arm_to_any_level_never_adds_a_finding(lane, arm, keep):
    """The sweep. 3 arms x 7 levels, against a 12-operation surface.

    A missing capture must only ever LOSE a finding. The anonymous arm is the one that could
    break it — its capture is what refuses — and it is swept at every level like the others.
    """
    handles, artifacts = await seed(lane)
    baseline = await both_checks(handles)
    await truncate(lane, artifacts, handles[arm] if arm != "anonymous" else "anonymous", keep)
    after = await both_checks(handles)
    gained = after - baseline
    assert not gained, (
        f"truncating {arm} to {keep} of {len(ALL_URLS)} captures ADDED {sorted(gained)} — "
        f"a missing capture manufactured a finding, so a `partial` arm must refuse")


async def test_deleting_exactly_the_capture_that_refuses_adds_nothing(lane):
    """The sharpest single case, and the one the sweep exists to cover: remove the anonymous
    arm's read of PUBLIC content, so the clause that calls it published has nothing to read."""
    handles, artifacts = await seed(lane)
    baseline = await both_checks(handles)
    for url in PUBLIC:
        await lane.execute("DELETE FROM integration_evidence WHERE id=?",
                           (artifacts[("anonymous", url)][1],))
    after = await both_checks(handles)
    assert after - baseline == set(), sorted(after - baseline)
    assert not {url for _, url in after} & set(PUBLIC), (
        "an operation became a finding because nobody recorded the anonymous arm reading it")


async def test_the_clause_that_makes_this_true_is_still_there():
    """The property above holds because of ONE line in each check. A `get` with a default
    would read "never probed" as "was refused", and the sweep would go the other way."""
    import inspect

    from orchestrator.integrations import inventory

    for check in (inventory.cross_arm_privileged_function,
                  inventory.cross_arm_authorization):
        source = inspect.getsource(check)
        assert "key not in anonymous_saw" in source, (
            f"{check.__name__} no longer distinguishes an unprobed operation from a refused "
            f"one, which is what stops a truncation manufacturing a finding")


async def test_losing_every_capture_refuses_rather_than_reports(lane):
    """The far end of the sweep, and where E-034's line actually sits: an arm with NOTHING
    has no comparison to interpret, and that is a refusal rather than a quiet zero."""
    from orchestrator.integrations.inventory import cross_arm_privileged_function

    handles, artifacts = await seed(lane)
    await truncate(lane, artifacts, "anonymous", 0)
    result = await cross_arm_privileged_function(
        "s", handles["admin"], handles["jim"], MARKER, "anonymous")
    assert result["refused_because"], (
        "an arm with no evidence at all produced a bare zero, which reads as clean")
    assert result["findings"] == []
