"""Schema version diffs — E-012's remaining scope, and the last thing a digest cannot do.

`schema_sha256` answers "is this the same schema", and TWO places already compared it: the
retest comparison (E-017) and the cross-arm schema fork. Both could say only that it had
changed. That leaves the operator to diff two documents by hand — and when the schema was
supplied by URL they cannot, because `schema_file` fetches it at run time and nothing keeps
the bytes. Measured: `integration_assessments.config` stores inline `schema_input.content`,
so an inline schema survives, and a URL-supplied one leaves only its digest behind.

So the inventory is RECORDED per stage rather than reconstructed later.

ADDED AND REMOVED ARE NOT THE SAME FINDING. Added operations are surface the baseline never
assessed. A REMOVED operation is the more interesting half: withdrawn from the schema it
should be gone, and if it still answers it is a live endpoint the documentation no longer
admits to — which is a lead, not a diff line.

NOT `schema_endpoints`, which is GET-only, exists to find query parameters, and skips
templated paths because a template is not a URL. All three are right for parameter discovery
and wrong here: `DELETE /items/{id}` is an operation, and an inventory that drops it cannot
notice it being removed.
"""
import json

import pytest

from orchestrator.integrations.adapters import (
    declared_operations, graphql_operations, schema_diff, schema_endpoints)


BASE = {"paths": {
    "/items": {"post": {"operationId": "createItem"}},
    "/items/{id}": {"delete": {"operationId": "deleteItem"}},
    "/legacy": {"get": {"operationId": "legacy"}}}}

LATER = {"paths": {
    "/items": {"post": {"operationId": "createItem"},
               "get": {"operationId": "listItems",
                       "parameters": [{"name": "limit", "in": "query"}]}},
    "/items/{id}": {"delete": {"operationId": "deleteItem",
                               "parameters": [{"name": "force", "in": "query"}]}}}}


# ------------------------------------------------------------------ the inventory itself


def test_a_templated_path_is_an_operation():
    """The difference from `schema_endpoints`, which drops it. `DELETE /items/{id}` being
    removed is exactly the change worth noticing, and an inventory that never held it cannot
    report the removal."""
    ids = {o["id"] for o in declared_operations(BASE)}
    assert "DELETE /items/{id}" in ids
    assert all("{" not in e.url for e in schema_endpoints(BASE, "http://t/", "anon")), (
        "schema_endpoints is supposed to skip templates; if it stopped, this test is "
        "asserting a distinction that no longer exists")


def test_every_method_counts_not_only_reads():
    assert {o["id"] for o in declared_operations(BASE)} == {
        "POST /items", "DELETE /items/{id}", "GET /legacy"}


def test_path_level_parameters_belong_to_each_operation():
    """A `parameters` list beside the methods applies to all of them, and reading only the
    per-operation list would miss an input added once for the whole path."""
    document = {"paths": {"/x": {"parameters": [{"name": "tenant", "in": "query"}],
                                 "get": {"parameters": [{"name": "q", "in": "query"}]}}}}
    assert declared_operations(document)[0]["parameters"] == ["q", "tenant"]


def test_what_is_not_an_operation_is_not_counted():
    """`summary`, `description` and `parameters` sit beside the methods in a path item."""
    document = {"paths": {"/x": {"summary": "s", "description": "d",
                                 "parameters": [], "get": {"operationId": "g"}}}}
    assert [o["id"] for o in declared_operations(document)] == ["GET /x"]


def test_graphql_uses_the_same_shape():
    """One shape for both kinds, so the diff does not need to know which it is reading."""
    operations = graphql_operations(
        "type Query { a(x: Int): String }\ntype Mutation { b: Boolean }")
    inventory = declared_operations(graphql=operations)
    assert {o["id"] for o in inventory} == {"query a", "mutation b"}
    assert next(o for o in inventory if o["id"] == "query a")["parameters"] == ["x"]


# ------------------------------------------------------------------------- the diff


def test_added_and_removed_are_reported_separately():
    diff = schema_diff(declared_operations(BASE), declared_operations(LATER))
    assert [o["id"] for o in diff["added"]] == ["GET /items"]
    assert [o["id"] for o in diff["removed"]] == ["GET /legacy"]
    assert diff["changed"] is True


def test_a_new_parameter_on_an_existing_operation_is_a_change():
    """The operation set is identical and the surface is not: a new input on an operation
    that already existed is invisible to a set comparison."""
    diff = schema_diff(declared_operations(BASE), declared_operations(LATER))
    assert diff["parameters_added"] == [
        {"id": "DELETE /items/{id}", "parameters": ["force"]}]


def test_a_removed_parameter_is_not_reported_as_added():
    diff = schema_diff(declared_operations(LATER), declared_operations(BASE))
    assert diff["parameters_added"] == []
    assert [o["id"] for o in diff["added"]] == ["GET /legacy"]


def test_an_identical_schema_is_no_change():
    diff = schema_diff(declared_operations(BASE), declared_operations(BASE))
    assert diff == {"added": [], "removed": [], "parameters_added": [],
                    "unchanged": 3, "changed": False}


def test_an_empty_baseline_is_all_addition_rather_than_an_error():
    diff = schema_diff([], declared_operations(BASE))
    assert len(diff["added"]) == 3 and diff["removed"] == []


def test_the_unchanged_count_excludes_operations_that_gained_a_parameter():
    """An operation whose inputs changed is not unchanged, and counting it as such would
    overstate how much of the surface is the same as the baseline."""
    diff = schema_diff(declared_operations(BASE), declared_operations(LATER))
    assert diff["unchanged"] == 1, diff
    assert len(diff["parameters_added"]) == 1


# -------------------------------------------------------- it reaches the stage record


def test_both_adapters_record_the_inventory():
    """Asserted on the call sites. An inventory computed and not recorded cannot be diffed
    later, and for a URL-supplied schema there is no second chance — the document is fetched
    at run time and the bytes are not kept."""
    import inspect

    from orchestrator.integrations import adapters

    for adapter in (adapters.ZapAdapter, adapters.SchemathesisAdapter):
        source = inspect.getsource(adapter.run)
        assert 'result.metadata["declared_operations"] = declared_operations(' in source, (
            adapter.__name__)


def test_the_comparison_consumes_it():
    import inspect

    from orchestrator.integrations import inventory

    source = inspect.getsource(inventory)
    assert "schema_diff(first[\"_operations\"], second[\"_operations\"])" in source
    assert "live and undocumented" in source, (
        "the removed half no longer says why it is the interesting one")


# --------------------------------------------- end to end, through the real comparison


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


async def assessment(db, session, document, digest):
    """One session whose single stage recorded the inventory the adapters record."""
    import uuid

    await db.execute("INSERT INTO integration_assessments(session_id,target,status,config) "
                     "VALUES(?,?,?,?)",
                     (session, "http://app.test/", "completed",
                      json.dumps({"stages": ["schemathesis"]})))
    await db.execute(
        "INSERT INTO integration_stages(id,session_id,adapter,identity_id,status,result) "
        "VALUES(?,?,?,?,?,?)",
        (uuid.uuid4().hex, session, "schemathesis", "anonymous", "completed",
         json.dumps({"metadata": {"schema_sha256": digest,
                                  "declared_operations": declared_operations(document)}})))


async def schema_change(lane):
    from orchestrator.integrations.inventory import compare_assessments

    await assessment(lane, "base", BASE, "digest-one")
    await assessment(lane, "retest", LATER, "digest-two")
    result = await compare_assessments("base", "retest")
    return next(row for row in result["configuration_differences"]
                if row["field"] == "schema_sha256")


async def test_the_comparison_reports_the_operations_not_only_the_digest(lane):
    """The behaviour, not the source. The digest comparison already existed and said only
    that the schema changed; this asserts the operator is now told what did."""
    entry = await schema_change(lane)
    assert [o["id"] for o in entry["operations"]["added"]] == ["GET /items"]
    assert [o["id"] for o in entry["operations"]["removed"]] == ["GET /legacy"]
    assert entry["operations"]["parameters_added"] == [
        {"id": "DELETE /items/{id}", "parameters": ["force"]}]


async def test_a_withdrawn_operation_is_called_out_as_a_lead(lane):
    """The half worth acting on: an operation the schema no longer declares should be gone,
    and one that still answers is a live endpoint the documentation disowns."""
    entry = await schema_change(lane)
    assert "live and undocumented" in entry["why_it_matters"]
    assert "never assessed by it" in entry["why_it_matters"]


async def test_no_recorded_inventory_says_so_rather_than_showing_an_empty_diff(lane):
    """The blind spot this must not create. Assessments recorded before this existed carry a
    digest and no inventory, and an empty added/removed pair there means "not recorded", not
    "nothing changed" — reporting it as the latter would be the defect in new clothes."""
    from orchestrator.integrations.inventory import compare_assessments

    await assessment(lane, "old-one", {}, "digest-one")
    await assessment(lane, "old-two", {}, "digest-two")
    result = await compare_assessments("old-one", "old-two")
    entry = next(row for row in result["configuration_differences"]
                 if row["field"] == "schema_sha256")
    assert entry["operations"]["added"] == [] and entry["operations"]["removed"] == []
    assert "cannot be shown" in entry["why_it_matters"]


async def test_an_unchanged_schema_reports_no_difference_at_all(lane):
    """The comparison only lists fields that differ, so an identical digest must not produce
    a schema row carrying an empty diff."""
    from orchestrator.integrations.inventory import compare_assessments

    await assessment(lane, "same-one", BASE, "same-digest")
    await assessment(lane, "same-two", BASE, "same-digest")
    result = await compare_assessments("same-one", "same-two")
    assert not [row for row in result["configuration_differences"]
                if row["field"] == "schema_sha256"]
