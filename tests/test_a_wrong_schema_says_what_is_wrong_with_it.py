"""E-012: "missing or incompatible schemas should not disappear into a generic scanner
failure."

Two readers parsed the same bytes and disagreed. `adapters.schema_file` validated the
document; `service.operation_routes` did not, and went straight to `doc.get("paths", {})`.
Measured on the committed code, for the five ways a schema can be wrong:

                            operation_routes                          schema_file
    malformed YAML          raw multi-line yaml.ParserError           the same dump
    a YAML scalar           AttributeError: 'str' has no 'get'        invalid OpenAPI document
    a YAML list             AttributeError: 'list' has no 'get'       invalid OpenAPI document
    an HTML error page      AttributeError: 'str' has no 'get'        invalid OpenAPI document
    JSON, not a spec        "selected operation IDs are missing"      invalid OpenAPI document

Those reasons reach the operator: the stage row carries `redact(str(exc))`. The last one is
the worst, and it is not generic — it is WRONG. It sends someone to check the operation IDs
they typed when the document is not a specification at all.

One validator now, because two copies of one fact is the defect this codebase names about its
own catalogue lists. The HTML case is named separately because it is the common one: a schema
URL that answers 200 with a login page, an error page, or documentation ABOUT the API.
"""
import pytest

from orchestrator.integrations.adapters import load_openapi_document
from orchestrator.integrations.contracts import AssessmentConfig

GOOD = """
openapi: 3.0.0
info: {title: t, version: "1"}
paths:
  /orders:
    post: {operationId: createOrder}
"""
WRONG = {
    "malformed": "openapi: 3.0.0\npaths:\n  - [unclosed\n",
    "a scalar": "just a string",
    "a list": "- one\n- two\n",
    "not a specification": '{"title": "not a spec", "paths": {}}',
    "markup": "<html><body>404 Not Found</body></html>",
}


def config(content):
    return AssessmentConfig(
        scope={"allow_hosts": ["app.test"], "allow_ports": [80]},
        state_changing=True, active=True,
        schema_input={"kind": "openapi", "content": content},
        workflow={"operations": ["createOrder"],
                  "fixtures": [{"url": "http://app.test/seed"}],
                  "cleanup": [{"url": "http://app.test/undo"}]})


# ------------------------------------------------------------ it says what is wrong


def test_a_valid_specification_loads():
    """The positive control. Every assertion below is only meaningful because this passes."""
    document = load_openapi_document(GOOD, "the schema")
    assert document["openapi"] == "3.0.0"
    assert "/orders" in document["paths"]


@pytest.mark.parametrize("label", sorted(WRONG))
def test_every_wrong_schema_names_its_own_problem(label):
    """No AttributeError, no raw parser dump, and the source named in every one."""
    with pytest.raises(ValueError) as raised:
        load_openapi_document(WRONG[label], "the schema at https://api.test/openapi.json")
    message = str(raised.value)
    assert "https://api.test/openapi.json" in message, message
    assert "has no attribute" not in message, f"a generic failure survived: {message}"
    assert message == " ".join(message.split()), (
        f"the reason spans lines; a stage `reason` renders it as noise: {message!r}")


def test_a_document_that_is_not_a_specification_is_not_blamed_on_the_operator():
    """The misleading one. "selected operation IDs are missing from schema" sends someone to
    check what they typed; the document has no `openapi` key at all."""
    with pytest.raises(ValueError) as raised:
        load_openapi_document(WRONG["not a specification"], "the schema")
    message = str(raised.value)
    assert "operation ID" not in message, message
    assert "`openapi` or `swagger` key" in message
    assert "'paths', 'title'" in message.replace('"', "'"), (
        f"the reason does not say what the document DOES contain: {message}")


def test_markup_is_called_out_by_name():
    """The common one in practice, and the one whose cause is least obvious from a type."""
    with pytest.raises(ValueError) as raised:
        load_openapi_document(WRONG["markup"], "the schema")
    assert "markup" in str(raised.value)
    assert "login page" in str(raised.value)


def test_a_parser_failure_keeps_the_position_it_reported():
    """One line, but not a shorter answer: the line and column are what locate the typo."""
    with pytest.raises(ValueError) as raised:
        load_openapi_document(WRONG["malformed"], "the schema")
    message = str(raised.value)
    assert "line 3" in message and "column" in message, message
    assert len(message) < 400, f"the dump was not bounded: {len(message)} chars"


# --------------------------------------------------------- and both readers agree


@pytest.mark.parametrize("label", sorted(WRONG))
async def test_both_schema_readers_give_the_same_answer(label):
    """`schema_file` and `operation_routes` read the same bytes and disagreed. A schema that
    is wrong is wrong in both lanes, and an operator who switches lanes to get a better error
    message is being told something about erlik rather than about their schema."""
    from orchestrator.integrations.adapters import Context, schema_file
    from orchestrator.integrations.service import operation_routes

    class _Sandbox:
        def write(self, name, content):
            return "/tmp/" + name

    settings = config(WRONG[label])
    with pytest.raises(ValueError) as from_routes:
        await operation_routes(settings, None, "http://app.test/")
    with pytest.raises(ValueError) as from_file:
        await schema_file(Context("s", "st", "http://app.test/", settings, "anonymous", None),
                          _Sandbox())
    # Same diagnosis; the source label differs because one is the workflow schema.
    def diagnosis(text):
        return str(text).split("schema", 1)[-1]

    assert diagnosis(from_routes.value) == diagnosis(from_file.value), (
        f"operation_routes says {from_routes.value!r}\n"
        f"schema_file says      {from_file.value!r}")


async def test_the_missing_operation_id_error_still_fires_on_a_real_specification():
    """The message that was misfiring is correct and must keep firing where it belongs."""
    from orchestrator.integrations.service import operation_routes

    settings = AssessmentConfig(
        scope={"allow_hosts": ["app.test"], "allow_ports": [80]},
        state_changing=True, active=True,
        schema_input={"kind": "openapi", "content": GOOD},
        workflow={"operations": ["noSuchOperation"],
                  "fixtures": [{"url": "http://app.test/seed"}],
                  "cleanup": [{"url": "http://app.test/undo"}]})
    with pytest.raises(ValueError) as raised:
        await operation_routes(settings, None, "http://app.test/")
    assert "operation ID" in str(raised.value)


def test_there_is_one_validator_and_both_readers_call_it():
    """Two copies of one fact is what put the two lanes out of step to begin with."""
    import inspect

    from orchestrator.integrations import adapters, service

    for reader in (adapters.schema_file, service.operation_routes):
        assert "load_openapi_document(" in inspect.getsource(reader), reader.__name__
    assert "yaml.safe_load" not in inspect.getsource(service.operation_routes), (
        "operation_routes parses the document itself again")


# ------------------------------------------- the digest is an identity, not a serialisation


REORDERED = """
paths:
  /orders:
    post: {operationId: createOrder}
info: {version: "1", title: t}
openapi: 3.0.0
"""


class _Sandbox:
    def __init__(self):
        self.written = {}

    def write(self, name, content):
        self.written[name] = content
        return "/tmp/" + name


def context(content, target="http://app.test/"):
    from orchestrator.integrations.adapters import Context

    return Context("s", "st", target, AssessmentConfig(
        scope={"allow_hosts": ["app.test"], "allow_ports": [80]},
        schema_input={"kind": "openapi", "content": content}), "anonymous", None)


async def test_the_same_schema_spelled_in_a_different_order_has_the_same_digest():
    """E-012's reproducibility handle, and the refusal that rests on it.

    `schema_sha256` is what `test_schema_fork` compares to decide that two arms were given
    DIFFERENT schemas — a refusal. Key order is not part of a schema's identity, and each arm
    fetches `schema_input.url` on its own request, so the order of a remote server's JSON is
    its business rather than ours.

    Measured on the committed code: these two hashed to d1ac2b39… and 90147ce6…, while the
    sibling `plan_sha256`, which was already canonical, hashed the pair alike.
    """
    from orchestrator.integrations.adapters import schema_file

    _, first, document, _ = await schema_file(context(GOOD), _Sandbox())
    _, second, reordered, _ = await schema_file(context(REORDERED), _Sandbox())
    assert document == reordered, "the fixtures are not the same document"
    assert first == second, (
        f"the same schema in a different key order hashed differently ({first[:12]} vs "
        f"{second[:12]}), so two arms would be refused as having different schemas")


async def test_a_genuinely_different_schema_still_differs():
    """The canonicalisation must not make the digest agree with everything — that would
    turn `test_schema_fork`'s refusal into a clause that cannot fire."""
    from orchestrator.integrations.adapters import schema_file

    other = GOOD.replace("createOrder", "cancelOrder")
    _, first, _, _ = await schema_file(context(GOOD), _Sandbox())
    _, second, _, _ = await schema_file(context(other), _Sandbox())
    assert first != second


async def test_the_digest_covers_the_bytes_the_scanner_was_given():
    """"Reproduces with the same schema digest" is only true if the digest identifies what
    was actually scanned — after bundling and after the target is pinned into `servers`."""
    import hashlib

    from orchestrator.integrations.adapters import schema_file

    sandbox = _Sandbox()
    _, digest, _, _ = await schema_file(context(GOOD), sandbox)
    written = sandbox.written["schema.json"]
    assert hashlib.sha256(written.encode()).hexdigest() == digest, (
        "the digest is not of the file handed to the scanner")
    assert '"servers"' in written and "http://app.test/" in written


async def test_the_target_is_part_of_the_schema_identity():
    """Two assessments of the same specification against different hosts are not the same
    scan, and the digest says so because the target is pinned into `servers` before hashing."""
    from orchestrator.integrations.adapters import schema_file

    _, here, _, _ = await schema_file(context(GOOD, "http://app.test/"), _Sandbox())
    _, there, _, _ = await schema_file(context(GOOD, "http://app.test/api/v2"), _Sandbox())
    assert here != there


def test_the_reproduction_handle_is_recorded_with_the_run():
    """E-012: "a seeded failure reproduces with the same schema digest and seed."

    Both halves are on the stage the fuzzer produced, and they are read from the same
    config field the command line is built from, so the recorded seed IS the seed used.

    WHAT THIS DOES NOT ESTABLISH: that Schemathesis is itself deterministic under a fixed
    seed. That is a property of the tool, needs a lab run to check, and is deliberately not
    asserted here — claiming the acceptance on the strength of a recorded number would be
    the confident-output-from-an-unrun-path defect this project keeps removing.
    """
    import inspect

    from orchestrator.integrations.adapters import SchemathesisAdapter

    source = inspect.getsource(SchemathesisAdapter.run)
    assert '"--seed", str(ctx.config.seed)' in source
    assert '"seed": ctx.config.seed' in source, "the recorded seed is not the one passed"
    assert '"schema_sha256": digest' in source
