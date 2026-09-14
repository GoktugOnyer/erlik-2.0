"""E-032: `may_access` works, and using it correctly was left to guesswork.

The clause is right and stays: entitlement is the one thing no response can express, so an
object the operator says this caller may read is not a crossing. What was missing is
everything around it. The plan records that the operator must name exact paths out of 189
gated operations, that the object id is not derivable from `subject_id` (jim's is 2 while his
address ids are 4 and 5), and that they can only learn which after reading the false finding.

Two of those are inherent and one is not. Measured on `_entitled`'s three shapes against four
object URLs:

    /api/Users/2   suppresses 1 of 4    exact, and what an operator means
    /api/Users/    suppresses 3 of 4    the whole collection — visible, because
                                        `suppressed_declared_access` lists what it took
    /api/Users     suppresses 0 of 4    SILENTLY

The third is the one that costs an afternoon. It is the spelling a person reaches for —
"this identity may read users" — and `_entitled` matches it against `/api/Users` and
`/api/Users/` only, never `/api/Users/2`. The false finding stays, the declaration looks
applied, and nothing relates the two. A declaration that matched nothing must not read as one
that was honoured.

And the loop is cheaper than the plan implies: both checks are POST routes over a FINISHED
assessment's stored evidence, and both read `may_access` live from the secret store. So
declaring and re-checking is one PUT and one POST — no new assessment. Measured here rather
than assumed, because "re-run to apply a suppression" is the reading that makes the clause
sound unusable.
"""
import json
import uuid

import pytest

from orchestrator.integrations.inventory import (
    _entitled, _suppressing_declaration, _unmatched_declarations)

OBJECTS = ["http://localhost:3000/api/Users/1",
           "http://localhost:3000/api/Users/2",
           "http://localhost:3000/api/Users/3",
           "http://localhost:3000/api/Addresss/4"]


# --------------------------------------------------------------- the three shapes


@pytest.mark.parametrize("declaration,expected", [
    pytest.param("/api/Users/2", 1, id="exact — what an operator means"),
    pytest.param("/api/Users/", 3, id="trailing slash — the whole collection"),
    pytest.param("/api/Users", 0, id="no slash — the spelling that matches nothing"),
])
def test_what_each_spelling_actually_suppresses(declaration, expected):
    """The measurement the rest of this file rests on. If `_entitled` changes, these numbers
    change with it and the reasoning below has to be redone rather than quietly kept."""
    assert sum(_entitled(url, (declaration,)) for url in OBJECTS) == expected


def test_a_declaration_that_covers_nothing_is_named(_=None):
    """The silent one. Reported, so "I declared it and the finding is still there" has an
    answer that is not "read the matching rule"."""
    assert _unmatched_declarations(("/api/Users",), OBJECTS) == ["/api/Users"]


def test_a_declaration_that_covers_something_is_not_named():
    """The report must not cry wolf on a declaration that is doing its job — an operator who
    learns to ignore this line has lost the one above it too."""
    assert _unmatched_declarations(("/api/Users/2", "/api/Users/"), OBJECTS) == []


def test_each_declaration_is_judged_on_its_own(_=None):
    """One working declaration must not vouch for a broken one beside it."""
    assert _unmatched_declarations(
        ("/api/Users/2", "/api/Orders", "/api/Addresss/4"), OBJECTS) == ["/api/Orders"]


def test_the_declaration_a_finding_names_is_the_one_that_suppresses_it():
    """Not a hint: the exact string, matched by the same rule that will read it back."""
    for url in OBJECTS:
        declaration = _suppressing_declaration(url)
        assert _entitled(url, (declaration,)), (url, declaration)
        others = [u for u in OBJECTS if u != url]
        assert not any(_entitled(u, (declaration,)) for u in others), (
            f"{declaration!r} also suppresses {[u for u in others if _entitled(u, (declaration,))]}")


def test_the_declaration_ignores_the_query_the_probe_chose():
    """`_entitled` says entitlement is to an operation and cannot depend on a value the probe
    picked. The named declaration has to agree, or copying it in would not match."""
    url = "http://localhost:3000/api/Users/2?page=3"
    assert _suppressing_declaration(url) == "/api/Users/2"
    assert _entitled(url, (_suppressing_declaration(url),))


# ----------------------------------------------------- and the checks report both


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


URL = "http://app.test/api/Users/1"


async def seed(db, *, caller_may_access=()):
    """Three arms, one operation, real evidence artifacts — the shape the check reads.

    Mirrors `tests/test_cross_arm_authorization.py`: the check reads `testcase:` artifacts
    holding a full run, not bare captures, and an arm with no artifact is refused outright.
    """
    from orchestrator.integrations.contracts import Identity
    from orchestrator.integrations.security import SecretStore

    store = SecretStore()
    handles = {}
    # `role` because the function-level twin refuses `role_not_declared` without one, and a
    # test that skips is a test that proves nothing.
    for name, subject, extra in (
            ("jim", "2", {"may_access": list(caller_may_access), "role": "customer"}),
            ("admin", "1", {"role": "admin"})):
        handles[name] = store.put(Identity.model_validate({
            "name": name, "target_origin": "http://app.test", "subject_id": subject,
            "check": {"url": "http://app.test/me", "method": "GET"}, **extra}).model_dump())
    await db.execute("INSERT INTO integration_assessments(session_id,target,status,config) "
                     "VALUES(?,?,?,?)", ("s", "http://app.test/", "completed", "{}"))

    # The marker the function-level check is given is in both named arms and not in the
    # anonymous one — the shape that check exists for. `data.UserId` carries the object-level
    # claim alongside it, so one seeded session serves both twins.
    owned = json.dumps({"data": {"id": 1, "UserId": "1", "email": "admin@app.test"}})
    bodies = {handles["jim"]: owned, handles["admin"]: owned,
              "anonymous": json.dumps({"status": "error", "message": {}})}
    for arm, body in bodies.items():
        stage = uuid.uuid4().hex
        await db.execute(
            "INSERT INTO integration_stages(id,session_id,adapter,identity_id,status,result)"
            " VALUES(?,?,?,?,?,?)",
            (stage, "s", "testcases", arm, "completed", json.dumps({"status": "completed"})))
        await db.execute(
            "INSERT OR REPLACE INTO integration_endpoints"
            "(session_id,url,method,identity_id,sources,parameters) VALUES(?,?,?,?,?,?)",
            ("s", URL, "GET", arm, json.dumps(["katana"]), json.dumps([])))
        status = 200 if arm != "anonymous" else 401
        await db.evidence("s", stage, "testcase:WSTG-AUTHZ-04.2", json.dumps({
            "test_case_id": "WSTG-AUTHZ-04.2", "target": {"url": URL, "parameter": ""},
            "findings": [], "chain_next": [], "stopped_early": False, "duration_ms": 5,
            "produced": {}, "steps": [{
                "step": "read_as_caller", "command": f'curl -s -i "{URL}"', "success": True,
                "duration_ms": 5, "exit_code": 0, "skipped": False, "error": None,
                "output": f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n"
                          + body}]}))
    return handles["jim"], handles["admin"], URL


async def test_the_check_names_declarations_that_covered_nothing(lane):
    from orchestrator.integrations.inventory import cross_arm_authorization

    caller, owner, _ = await seed(lane, caller_may_access=("/api/Users",))
    result = await cross_arm_authorization("s", caller, owner, "data.UserId", "anonymous")
    assert result["declared_access_that_matched_nothing"] == ["/api/Users"], result


async def test_a_working_declaration_is_not_named_as_matching_nothing(lane):
    from orchestrator.integrations.inventory import cross_arm_authorization

    caller, owner, _ = await seed(lane, caller_may_access=("/api/Users/1",))
    result = await cross_arm_authorization("s", caller, owner, "data.UserId", "anonymous")
    assert result["declared_access_that_matched_nothing"] == [], result
    assert result["suppressed_declared_access"], (
        "the declaration suppressed nothing, so this test is not about a working one")


async def test_the_field_is_present_even_when_nothing_was_declared(lane):
    """An absent key and an empty list read the same to a person and differently to a
    script. `may_access` is empty on most assessments, which is exactly when a reader needs
    to be sure the report is not silent for a different reason."""
    from orchestrator.integrations.inventory import cross_arm_authorization

    caller, owner, _ = await seed(lane)
    result = await cross_arm_authorization("s", caller, owner, "data.UserId", "anonymous")
    assert result["declared_access_that_matched_nothing"] == []


async def test_a_finding_carries_the_declaration_that_would_suppress_it(lane):
    from orchestrator.integrations.inventory import cross_arm_authorization

    caller, owner, url = await seed(lane)
    result = await cross_arm_authorization("s", caller, owner, "data.UserId", "anonymous")
    assert result["findings"], f"no finding to carry it: {result}"
    named = result["findings"][0]["declaration_that_would_suppress"]
    assert named == "/api/Users/1", named


async def test_declaring_what_the_finding_named_suppresses_exactly_it(lane):
    """The loop, end to end and without a new assessment: read the finding, declare what it
    names, call the check again."""
    from orchestrator.integrations.inventory import cross_arm_authorization
    from orchestrator.integrations.security import SecretStore

    caller, owner, _ = await seed(lane)
    first = await cross_arm_authorization("s", caller, owner, "data.UserId", "anonymous")
    named = first["findings"][0]["declaration_that_would_suppress"]

    declaration = SecretStore().get(caller)
    SecretStore().put({**declaration, "may_access": [named]}, caller)

    second = await cross_arm_authorization("s", caller, owner, "data.UserId", "anonymous")
    assert second["findings"] == [], second["findings"]
    assert second["suppressed_declared_access"], second
    assert second["declared_access_that_matched_nothing"] == [], second


async def test_the_function_level_check_reports_the_same_two_things(lane):
    """The twin. A field on one check and not the other is how the two drifted before, and
    an operator reading one report has no reason to expect the other to be shaped
    differently."""
    from orchestrator.integrations.inventory import cross_arm_privileged_function

    caller, owner, _ = await seed(lane, caller_may_access=("/api/Users",))
    result = await cross_arm_privileged_function("s", owner, caller, "admin@app.test",
                                                 "anonymous")
    assert result["declared_access_that_matched_nothing"] == ["/api/Users"], result


async def test_the_function_level_check_names_the_declaration_on_its_findings(lane):
    """The per-finding half of the twin. Seeded so the marker the OPERATOR declares is what
    both privileged arms received and anonymous did not — the shape that check exists for."""
    from orchestrator.integrations.inventory import cross_arm_privileged_function

    caller, owner, url = await seed(lane)
    result = await cross_arm_privileged_function("s", owner, caller, "admin@app.test",
                                                 "anonymous")
    assert result["findings"], (
        f"no function-level finding to carry it: {result['refused_because']}, "
        f"checked={result['checked']}")
    assert result["findings"][0]["declaration_that_would_suppress"] == "/api/Users/1"
