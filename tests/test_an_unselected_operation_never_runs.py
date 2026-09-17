"""E-012's "unselected mutations never execute", and why it was not yet demonstrated.

THE CLAUSE WAS TESTED AGAINST A SCHEMA THAT COULD NOT VIOLATE IT. The container fixture's
OpenAPI document declared exactly ONE mutation, `createItem`, and
`test_workflow_selection_and_cleanup_failure` — the test that looks like the demonstration —
SELECTS that operation and then asserts the target saw no mutation outside the selected set.
With no unselected mutation in the schema, the assertion had nothing to exclude and could not
have failed. Reporting exclusion without exercising it is not the same as excluding.

The fixture now declares `promoteUser` (POST /admin/promote), which no workflow selects, and
that test asserts it never reached the target. This file covers the same rule at the policy
level, where a case can be written per refusal reason rather than per container run.

THE REFUSAL HAS A NAME AND NOTHING USED IT. `EgressPolicy` answers "operation not selected",
and no test in the suite mentioned that string — so a refusal arriving for a DIFFERENT reason
(scope, port, an excluded path, state-changing disabled) was indistinguishable from this one,
and a rule that stopped working for its own reason while another rule happened to catch the
same request would have looked identical.
"""
import json

import pytest

from orchestrator.integrations.contracts import AssessmentConfig
from orchestrator.integrations.egress_policy import EgressPolicy


SCHEMA = {"openapi": "3.0.0", "info": {"title": "t", "version": "1"},
          "paths": {"/items": {"post": {"operationId": "createItem"}},
                    "/admin/promote": {"post": {"operationId": "promoteUser"}},
                    "/items/{id}": {"delete": {"operationId": "deleteItem"}}}}


def config(**overrides):
    return AssessmentConfig(scope={"allow_hosts": ["app.test"], "allow_ports": [443]},
                            **overrides)


async def routes_for(selected, target="https://app.test"):
    from orchestrator.integrations.service import operation_routes

    cfg = config(stages=["schemathesis"], active=True, state_changing=True,
                 schema_input={"content": json.dumps(SCHEMA)},
                 workflow={"operations": selected,
                           "fixtures": [{"url": "https://app.test/setup", "method": "POST"}],
                           "cleanup": [{"url": "https://app.test/cleanup", "method": "POST"}]})
    settings = cfg.model_dump()
    settings["operation_routes"] = await operation_routes(cfg, None, target)
    return settings


# ------------------------------------------------------- the selected one, and only it


async def test_the_selected_operation_is_permitted():
    policy = EgressPolicy(await routes_for(["createItem"]))
    assert policy.check("https://app.test/items", "POST")[0]


async def test_an_unselected_mutation_is_refused_for_being_unselected():
    """The negative control, and the reason it names the REASON. A refusal that arrived
    because the host was out of scope would satisfy a bare `not allowed` assertion while
    saying nothing about operation selection."""
    allowed, reason = EgressPolicy(await routes_for(["createItem"])).check(
        "https://app.test/admin/promote", "POST")
    assert not allowed
    assert reason == "operation not selected", reason


async def test_selecting_the_other_operation_moves_the_refusal():
    """Neither URL is special. Swap the selection and the permitted and refused swap with
    it, which is what shows the decision follows the workflow rather than the path."""
    settings = await routes_for(["promoteUser"])
    policy = EgressPolicy(settings)
    assert policy.check("https://app.test/admin/promote", "POST")[0]
    allowed, reason = policy.check("https://app.test/items", "POST")
    assert not allowed and reason == "operation not selected"


async def test_the_method_is_part_of_the_selection():
    """`deleteItem` is a DELETE on a path whose POST is selected. Matching the path alone
    would let a delete through on the strength of a create."""
    policy = EgressPolicy(await routes_for(["createItem"]))
    allowed, reason = policy.check("https://app.test/items", "DELETE")
    assert not allowed and reason == "operation not selected"


# ------------------------------------------------------------- the empty-selection floor


def test_the_contract_refuses_state_changing_without_a_workflow():
    """The floor sits EARLIER than the policy, which is worth knowing before relying on the
    policy for it: state-changing testing cannot be configured without operations, fixtures
    and cleanup, so "no workflow, mutations permitted" is not a reachable configuration.

    Written after the first draft of this file assumed it was reachable and the validator
    said otherwise.
    """
    with pytest.raises(Exception) as refused:
        config(active=True, state_changing=True)
    assert "operations, fixtures, and cleanup" in str(refused.value)


def _proxy_settings(**over):
    """The policy receives a DICT, not a validated model — `runtime.Sandbox` builds it and
    the proxy reads it in another process. Testing the dict directly is the only way to
    reach a state the contract refuses to construct, and the proxy is where a malformed one
    would actually land."""
    base = config(active=True).model_dump()
    base.update(state_changing=True, operation_routes=[])
    base.update(over)
    return base


def test_no_routes_reaching_the_policy_permits_no_mutation():
    """`any()` over an empty list is False, so an empty route set refuses everything rather
    than permitting everything. That is one character away from a permit-all and the proxy
    is the last gate before the target, so it gets its own assertion."""
    allowed, reason = EgressPolicy(_proxy_settings()).check("https://app.test/items", "POST")
    assert not allowed and reason == "operation not selected"


def test_reads_are_unaffected_by_selection():
    """Selection governs mutations. A GET is not a state change and is not gated on a
    workflow, or an assessment without one could read nothing."""
    settings = _proxy_settings()
    assert EgressPolicy(settings).check("https://app.test/items", "GET")[0]
    assert EgressPolicy(settings).check("https://app.test/anything", "HEAD")[0]


def test_state_changing_disabled_refuses_before_selection_is_consulted():
    """Two different refusals, and the order matters for the operator reading it: with
    state-changing off the answer is that mutations are disabled, not that this particular
    operation was left out of a workflow."""
    settings = _proxy_settings(state_changing=False, operation_routes=[
        {"method": "POST", "origin": "https://app.test", "path_regex": "/items"}])
    allowed, reason = EgressPolicy(settings).check("https://app.test/items", "POST")
    assert not allowed
    assert reason == "state-changing requests disabled", reason


# ------------------------------------------------- the fixture keeps the control honest


def test_the_container_fixture_declares_a_mutation_no_workflow_selects():
    """A guard on the guard. If `promoteUser` is removed from the fixture the container test
    silently returns to asserting exclusion against a schema with nothing to exclude — which
    is the state this increment found it in, and nothing would have said so."""
    import pathlib
    import re

    source = (pathlib.Path(__file__).resolve().parents[0] / "fixtures"
              / "integration_target.py").read_text()
    assert '"operationId": "promoteUser"' in source
    assert '"/admin/promote"' in source
    mutations = re.findall(r'"operationId": "(\w+)"', source)
    assert "createItem" in mutations and "promoteUser" in mutations
