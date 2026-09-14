"""E-011's acceptance, in one place: three violation classes and three negative controls.

The entry reads: "recover seeded cross-user, cross-tenant, and privileged-function access
violations; reject public content, generic error pages, and expected shared access as
negative controls." Two of the three violation classes had recovery tests. CROSS-TENANT had
only a LABEL test — `compare_arms` reports `cross_tenant: True` when both arms declare a
tenant and the two differ — and a label is not a demonstration that the product recovers the
violation.

It does, measured here. What the suite also found is a negative control that was NOT rejected:
one error document carrying the operator's marker, served 200 at five URLs and refused to the
anonymous arm, produced FIVE high findings — five copies of one document reported as five
privilege crossings. The status clause catches an error page that comes with an error STATUS;
an application answering 200 with an error body walked past it.

`indistinct_urls` already answers that and the cross-arm checks were not asking it. The most
canonical spelling survives and is still reported, so a real leak at one URL is not lost; its
repeats are listed under `skipped_indistinct_response`. On both recorded real runs the clause
prunes nothing: 34 and 38 operations checked, 0 skipped.

What remains undecidable is a generic document at ONE url. Whether a string is privileged data
is the operator's declaration, and no recorded response can overturn it — so that finding
stands and carries `declaration_that_would_suppress`, which is the cheap dismissal.
"""
import json
import uuid

import pytest

from orchestrator.integrations.contracts import Identity
from orchestrator.integrations.inventory import (
    compare_arms, cross_arm_authorization, cross_arm_privileged_function)
from orchestrator.integrations.security import SecretStore

MARKER = "admin-console-token"
DENIED = json.dumps({"status": "error", "message": {}})
ERROR_PAGE = json.dumps({"error": "internal", "support": MARKER})
CROSS_USER = "http://app.test/api/baskets/5"
CROSS_TENANT = "http://app.test/api/orders/77"
PRIVILEGED = "http://app.test/api/admin/console"
PUBLIC = "http://app.test/rest/products/1/reviews"
SHARED = "http://app.test/api/teams/9"
ERRORS = [f"http://app.test/api/thing/{n}" for n in range(1, 6)]


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


def owned_by(subject, object_id):
    # Each object carries its OWN id. An earlier version of this seed gave three distinct
    # objects one body, and the indistinct clause below correctly grouped them — a seed
    # artifact that would have read as a defect in the clause.
    return json.dumps({"data": {"id": object_id, "UserId": subject}})


def marked():
    return json.dumps({"data": {"console": MARKER}})


def public_marked():
    # Different content that ALSO contains the marker. Distinct bytes, because two unrelated
    # documents are not the same document — an earlier version of this seed reused `marked()`
    # and the indistinct clause grouped them, which is right and made the test read wrong.
    return json.dumps({"data": {"reviews": [{"note": MARKER}]}})


@pytest.fixture
async def seeded(lane):
    """One application, six seeded situations, three arms."""
    store = SecretStore()
    arms = {
        "caller": store.put(Identity.model_validate({
            "name": "acme-user", "target_origin": "http://app.test", "subject_id": "10",
            "role": "customer", "tenant": "acme", "may_access": [f"/api/teams/9"],
            "check": {"url": "http://app.test/me", "method": "GET"}}).model_dump()),
        "owner": store.put(Identity.model_validate({
            "name": "globex-admin", "target_origin": "http://app.test", "subject_id": "20",
            "role": "admin", "tenant": "globex",
            "check": {"url": "http://app.test/me", "method": "GET"}}).model_dump()),
        "anonymous": "anonymous",
    }
    await lane.execute("INSERT INTO integration_assessments(session_id,target,status,config) "
                       "VALUES(?,?,?,?)", ("s", "http://app.test/", "completed", "{}"))
    reads = {
        CROSS_USER: {"caller": (owned_by("20", 5), 200), "owner": (owned_by("20", 5), 200),
                     "anonymous": (DENIED, 401)},
        CROSS_TENANT: {"caller": (owned_by("20", 77), 200), "owner": (owned_by("20", 77), 200),
                       "anonymous": (DENIED, 401)},
        PRIVILEGED: {"caller": (marked(), 200), "owner": (marked(), 200),
                     "anonymous": (DENIED, 401)},
        # Negative control: everyone can read it, including nobody at all.
        PUBLIC: {"caller": (public_marked(), 200), "owner": (public_marked(), 200),
                 "anonymous": (public_marked(), 200)},
        # Negative control: the operator declared this identity entitled to it.
        SHARED: {"caller": (owned_by("20", 9), 200), "owner": (owned_by("20", 9), 200),
                 "anonymous": (DENIED, 401)},
        # Negative control: one error document, 200, at five urls.
        **{url: {"caller": (ERROR_PAGE, 200), "owner": (ERROR_PAGE, 200),
                 "anonymous": (DENIED, 401)} for url in ERRORS},
    }
    stages = {}
    for name, handle in arms.items():
        stage = uuid.uuid4().hex
        stages[name] = stage
        await lane.execute(
            "INSERT INTO integration_stages(id,session_id,adapter,identity_id,status,result)"
            " VALUES(?,?,?,?,?,?)",
            (stage, "s", "testcases", handle, "completed", json.dumps({"status": "completed"})))
    for url, per_arm in reads.items():
        for name, (body, status) in per_arm.items():
            await lane.execute(
                "INSERT OR REPLACE INTO integration_endpoints"
                "(session_id,url,method,identity_id,sources,parameters) VALUES(?,?,?,?,?,?)",
                ("s", url, "GET", arms[name], json.dumps(["katana"]), json.dumps([])))
            await lane.evidence("s", stages[name], "testcase:WSTG-AUTHZ-04.2", json.dumps({
                "test_case_id": "WSTG-AUTHZ-04.2", "target": {"url": url, "parameter": ""},
                "findings": [], "chain_next": [], "stopped_early": False, "duration_ms": 5,
                "produced": {}, "steps": [{
                    "step": "read", "command": f'curl -s -i "{url}"', "success": True,
                    "duration_ms": 5, "exit_code": 0, "skipped": False, "error": None,
                    "output": f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n"
                              + body}]}))
    return arms


async def object_check(arms):
    return await cross_arm_authorization("s", arms["caller"], arms["owner"],
                                         "data.UserId", "anonymous")


async def function_check(arms):
    return await cross_arm_privileged_function("s", arms["owner"], arms["caller"],
                                               MARKER, "anonymous")


def urls_of(result):
    return {f["url"] for f in result.get("findings") or []}


# ------------------------------------------------------------- the three violations


async def test_a_cross_user_violation_is_recovered(seeded):
    assert CROSS_USER in urls_of(await object_check(seeded))


async def test_a_cross_tenant_violation_is_recovered(seeded):
    """The class that had only a label test. `compare_arms` saying `cross_tenant: True` is
    the LABEL; recovering the violation is the capability."""
    assert CROSS_TENANT in urls_of(await object_check(seeded))
    surfaces = await compare_arms("s", seeded["caller"], seeded["owner"])
    assert surfaces["cross_tenant"] is True
    assert sorted(surfaces["tenants"].values()) == ["acme", "globex"]


async def test_a_privileged_function_violation_is_recovered(seeded):
    assert PRIVILEGED in urls_of(await function_check(seeded))


# ------------------------------------------------------- the three negative controls


async def test_public_content_is_rejected(seeded):
    """The anonymous arm received it, so it is published rather than crossed."""
    assert PUBLIC not in urls_of(await function_check(seeded))
    assert PUBLIC not in urls_of(await object_check(seeded))


async def test_expected_shared_access_is_rejected(seeded):
    """Declared through `Identity.may_access`, and named in the result so the suppression
    is visible."""
    result = await object_check(seeded)
    assert SHARED not in urls_of(result)
    assert "/api/teams/9" in json.dumps(result["suppressed_declared_access"])


async def test_a_generic_error_page_is_not_five_findings(seeded):
    """The control this suite found unmet. Before: five high findings, one per url."""
    result = await function_check(seeded)
    reported = urls_of(result) & set(ERRORS)
    assert len(reported) <= 1, (
        f"one error document was reported as {len(reported)} privilege crossings: "
        f"{sorted(reported)}")
    skipped = {entry["url"] for entry in result["skipped_indistinct_response"]}
    # Scoped to the error document. Asserting a total would make this brittle to any other
    # pair of operations the seed happens to give matching bodies.
    assert len(skipped & set(ERRORS)) == len(ERRORS) - 1, (
        result["skipped_indistinct_response"])
    assert all(entry["same_response_as"] in ERRORS
               for entry in result["skipped_indistinct_response"]
               if entry["url"] in ERRORS)


async def test_the_surviving_spelling_is_still_checked(seeded):
    """The clause must prune repeats, not the operation. A real leak at one url stays
    reportable — which is the difference between deduplicating and going blind."""
    result = await function_check(seeded)
    skipped = {entry["url"] for entry in result["skipped_indistinct_response"]}
    assert set(ERRORS) - skipped, "every spelling was pruned, including the survivor"


async def test_the_real_findings_are_untouched_by_the_new_clause(seeded):
    """The regression that would matter: pruning a genuine crossing because some other
    operation answered the same way."""
    result = await function_check(seeded)
    assert PRIVILEGED in urls_of(result)
    assert PRIVILEGED not in {e["url"] for e in result["skipped_indistinct_response"]}


# --------------------------------------------------------------- the whole acceptance


async def test_the_acceptance_recovers_every_violation_and_no_control(seeded):
    """E-011 in one assertion. Everything above is this, said separately so a failure names
    which half broke."""
    found = urls_of(await object_check(seeded)) | urls_of(await function_check(seeded))
    assert {CROSS_USER, CROSS_TENANT, PRIVILEGED} <= found, (
        f"a seeded violation was not recovered: "
        f"{sorted({CROSS_USER, CROSS_TENANT, PRIVILEGED} - found)}")
    assert PUBLIC not in found and SHARED not in found
    assert len(found & set(ERRORS)) <= 1, sorted(found & set(ERRORS))


async def test_two_objects_that_answer_identically_are_one_finding_naming_both(lane):
    """THE COST OF THE INDISTINCT CLAUSE, measured rather than assumed.

    Two genuinely distinct private objects that return byte-identical bodies collapse to one
    finding. That is a merge, not a loss — the surviving spelling is reported and the other
    is named beside it with `same_response_as` — and it is the same answer this lane already
    gives for a URL group: one finding per operation, naming every URL it covers.

    It is also the honest limit. If an application really does return identical bytes for two
    different objects, no reader could tell the two findings apart anyway; what they need is
    to know both URLs, and they do.
    """
    store = SecretStore()
    arms = {
        "caller": store.put(Identity.model_validate({
            "name": "c", "target_origin": "http://app.test", "subject_id": "10",
            "role": "customer", "check": {"url": "http://app.test/me", "method": "GET"}
        }).model_dump()),
        "owner": store.put(Identity.model_validate({
            "name": "o", "target_origin": "http://app.test", "subject_id": "20",
            "role": "admin", "check": {"url": "http://app.test/me", "method": "GET"}
        }).model_dump()),
        "anonymous": "anonymous",
    }
    await lane.execute("INSERT INTO integration_assessments(session_id,target,status,config) "
                       "VALUES(?,?,?,?)", ("s", "http://app.test/", "completed", "{}"))
    twins = ["http://app.test/api/secret/a", "http://app.test/api/secret/b"]
    for name, handle in arms.items():
        stage = uuid.uuid4().hex
        await lane.execute(
            "INSERT INTO integration_stages(id,session_id,adapter,identity_id,status,result)"
            " VALUES(?,?,?,?,?,?)",
            (stage, "s", "testcases", handle, "completed", json.dumps({"status": "completed"})))
        for url in twins:
            await lane.execute(
                "INSERT OR REPLACE INTO integration_endpoints"
                "(session_id,url,method,identity_id,sources,parameters) VALUES(?,?,?,?,?,?)",
                ("s", url, "GET", handle, json.dumps(["katana"]), json.dumps([])))
            body, status = ((marked(), 200) if name != "anonymous" else (DENIED, 401))
            await lane.evidence("s", stage, "testcase:WSTG-AUTHZ-04.2", json.dumps({
                "test_case_id": "WSTG-AUTHZ-04.2", "target": {"url": url, "parameter": ""},
                "findings": [], "chain_next": [], "stopped_early": False, "duration_ms": 5,
                "produced": {}, "steps": [{
                    "step": "read", "command": f'curl -s -i "{url}"', "success": True,
                    "duration_ms": 5, "exit_code": 0, "skipped": False, "error": None,
                    "output": f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n"
                              + body}]}))

    result = await cross_arm_privileged_function("s", arms["owner"], arms["caller"],
                                                 MARKER, "anonymous")
    reported = urls_of(result)
    assert len(reported) == 1, f"expected one merged finding, got {sorted(reported)}"
    named = {e["url"]: e["same_response_as"] for e in result["skipped_indistinct_response"]}
    assert set(twins) == reported | set(named), (
        f"an operation vanished: reported={reported} named={named}")
    assert set(named.values()) <= reported, (
        "the skipped operation points at something that was not reported, so a reader "
        "following `same_response_as` finds nothing")
