"""What a GraphQL schema declares — E-012's "GraphQL query-operation inventory".

MEASURED BEFORE BUILDING. `schema_file` returned the parsed document only for OpenAPI
(`document if source.kind == "openapi" else None`), and `schema_endpoints` — which is paths
and query parameters — has nothing to say about a transport with one URL and no methods. So
`schema_endpoints(None, ...)` returned `[]` and a GraphQL assessment declared ZERO
operations. A six-operation schema and an empty one were indistinguishable, and nothing
anywhere enumerated GraphQL operations: the grep for a function that did came back empty.

That is the blind spot this file closes, and it is the recurring shape rather than a missing
feature — an empty inventory reads as "the schema declares nothing" when it meant "nothing
looked".

PARSED, NOT MATCHED. SDL carries block strings, descriptions, comments, directives,
interfaces and `extend type`. A regular expression that looked right on a tidy schema would
miss or invent operations on a real one, so graphql-core does it — the same library the
proxy already uses to tell a read-only query from a mutation.

THE INVENTORY NAMES WHAT WILL NOT RUN. With `state_changing` off the proxy refuses
mutations, so listing only what exists would leave the operator to infer the gap from an
absence in the results.
"""
import json

import pytest

from orchestrator.integrations.adapters import (
    STATE_CHANGING_OPERATIONS, graphql_inventory, graphql_operations)


SDL = """
"A registered user."
type User { id: ID!  email: String  isAdmin: Boolean }

type Query {
  user(id: ID!): User
  allUsers(limit: Int, offset: Int): [User]
  health: String
}

type Mutation {
  deleteUser(id: ID!): Boolean
  promote(id: ID!, role: String!): User
}

type Subscription { userChanged: User }
"""


# ------------------------------------------------------------------ what it enumerates


def test_every_root_operation_is_found():
    names = {(o["operation"], o["name"]) for o in graphql_operations(SDL)}
    assert names == {
        ("query", "user"), ("query", "allUsers"), ("query", "health"),
        ("mutation", "deleteUser"), ("mutation", "promote"),
        ("subscription", "userChanged")}


def test_arguments_and_types_come_with_the_operation():
    ops = {o["name"]: o for o in graphql_operations(SDL)}
    assert ops["allUsers"]["arguments"] == ["limit", "offset"]
    assert ops["health"]["arguments"] == []
    assert ops["promote"]["arguments"] == ["id", "role"]
    assert ops["allUsers"]["type"] == "[User]"
    assert ops["user"]["type"] == "User"


def test_a_schema_with_no_mutations_reports_none_rather_than_failing():
    ops = graphql_operations("type Query { ping: String }")
    assert [o["operation"] for o in ops] == ["query"]
    assert graphql_inventory(ops, state_changing=False)["state_changing_withheld"] == []


def test_descriptions_and_comments_do_not_become_operations():
    """The failure mode of matching instead of parsing: a description mentioning `type
    Query` is prose, and a commented-out field is not declared."""
    text = '''
    "This type Query description mentions type Query { fake: String } on purpose."
    type Query {
      real: String
      # notReal: String
    }
    '''
    assert [o["name"] for o in graphql_operations(text)] == ["real"]


def test_extend_type_contributes_its_fields():
    """`extend type Query` is ordinary in a stitched schema and a naive pattern misses it."""
    text = "type Query { a: String }\nextend type Query { b: String }"
    assert sorted(o["name"] for o in graphql_operations(text)) == ["a", "b"]


# ----------------------------------------------------------------- the two input shapes


def test_an_introspection_document_is_accepted_too():
    """An operator has SDL or an introspection response; both are what they have to hand."""
    from graphql import build_schema, get_introspection_query, graphql_sync

    result = graphql_sync(build_schema(SDL), get_introspection_query())
    payload = json.dumps({"data": result.data})
    assert {o["name"] for o in graphql_operations(payload)} == {
        o["name"] for o in graphql_operations(SDL)}


def test_an_unparseable_schema_raises_rather_than_reporting_an_empty_inventory():
    """The defect this file exists to prevent, in its own function: returning [] for a broken
    schema would say "declares nothing" about something that was never read."""
    with pytest.raises(ValueError) as bad_sdl:
        graphql_operations("type Query {{{ not valid")
    assert "could not be parsed" in str(bad_sdl.value)

    with pytest.raises(ValueError) as bad_json:
        graphql_operations('{"data": {"__schema": "not a schema"}}')
    assert "introspection" in str(bad_json.value)


def test_an_empty_schema_is_empty_rather_than_an_error():
    assert graphql_operations("") == []
    assert graphql_operations(None) == []


# ------------------------------------------------------- it says what will not be reached


def test_mutations_are_named_as_withheld_when_state_changing_is_off():
    report = graphql_inventory(graphql_operations(SDL), state_changing=False)
    assert report["total"] == 6
    assert report["by_operation"] == {"mutation": 2, "query": 3, "subscription": 1}
    assert report["state_changing_withheld"] == ["deleteUser", "promote", "userChanged"]
    assert "not exercised" in report["note"]


def test_nothing_is_withheld_when_state_changing_is_on():
    report = graphql_inventory(graphql_operations(SDL), state_changing=True)
    assert report["state_changing_withheld"] == []
    assert report["note"] is None
    assert report["total"] == 6, "the inventory still reports everything it found"


def test_the_withheld_set_matches_what_the_proxy_actually_refuses():
    """The claim is only worth something if it names the same operations the proxy blocks.
    `proxy_addon` allows a document through only when EVERY operation in it is a query, so
    mutations and subscriptions are exactly what does not run."""
    import pathlib

    # READ, not imported: `proxy_addon` imports mitmproxy at module level and that lives in
    # the proxy container, not here. Importing it to check a claim about it would make this
    # test unrunnable outside a container for no gain.
    source = (pathlib.Path(__file__).resolve().parents[1] / "orchestrator" / "integrations"
              / "proxy_addon.py").read_text()
    assert "OperationType.QUERY" in source
    assert "all(node.operation == OperationType.QUERY" in source, (
        "the proxy no longer allows only query-ONLY documents; the withheld set may be wrong")
    assert set(STATE_CHANGING_OPERATIONS) == {"mutation", "subscription"}


# --------------------------------------------------------------------- it reaches a stage


async def test_the_inventory_reaches_the_stage_record():
    """Asserted on the call site: an inventory computed and never recorded is invisible, and
    the operator's answer to "what does this schema declare" is the stage row."""
    import inspect

    from orchestrator.integrations import adapters

    for adapter in (adapters.ZapAdapter, adapters.SchemathesisAdapter):
        source = inspect.getsource(adapter.run)
        assert 'graphql_inventory(operations, ctx.config.state_changing)' in source, adapter.__name__


async def test_schema_file_hands_back_the_inventory_for_graphql():
    from orchestrator.integrations.adapters import Context, schema_file
    from orchestrator.integrations.contracts import AssessmentConfig

    class _Sandbox:
        def write(self, name, content):
            assert name == "schema.graphql", name
            return "/input/" + name

    cfg = AssessmentConfig(scope={"allow_hosts": ["app.test"], "allow_ports": [80]},
                           schema_input={"kind": "graphql", "content": SDL})
    _, digest, document, operations = await schema_file(
        Context("s", "stage", "http://app.test/graphql", cfg), _Sandbox())
    assert document is None, "GraphQL has no OpenAPI document and must not pretend to"
    assert digest, "the schema is still identified by its digest"
    assert len(operations) == 6


async def test_an_openapi_schema_carries_no_graphql_inventory():
    """The other direction: OpenAPI must not grow a phantom GraphQL inventory."""
    from orchestrator.integrations.adapters import Context, schema_file
    from orchestrator.integrations.contracts import AssessmentConfig

    class _Sandbox:
        def write(self, name, content):
            return "/input/" + name

    cfg = AssessmentConfig(
        scope={"allow_hosts": ["app.test"], "allow_ports": [80]},
        schema_input={"kind": "openapi", "content": json.dumps(
            {"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": {}})})
    _, _, document, operations = await schema_file(
        Context("s", "stage", "http://app.test/", cfg), _Sandbox())
    assert document is not None
    assert operations == []
