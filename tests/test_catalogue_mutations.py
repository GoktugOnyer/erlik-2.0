"""E-003: the catalogue must not perform a write it cannot undo.

docs/future-plan.md, R0: "V1 catalogue follow-up refuses all mutation steps, or
an explicit per-case fixture/cleanup wrapper handles them; no leftover probe
artifact in the lab."

`step_policy` refused a non-safe method only when the egress policy said no — and
once an operator selects `state_changing`, the policy says yes for any route they
declared. So a mutating catalogue step ran, wrote to the client's server, and
nothing recorded that a write had happened or undid it.

Nine catalogue steps use a non-safe method. Two cases carrying them are runnable
in the assessment lane:

    WSTG-CONF-06  put_probe    PUT /erlik_put_test.txt   — leaves a file behind
    WSTG-INPV-07  four steps   POST <xml document>       — effect unknowable

V1 takes the first branch of the acceptance: refuse. The cost is stated rather
than hidden — see test_what_refusing_costs.
"""
import pytest

from orchestrator.integrations.deterministic import curl_request
from orchestrator.testcase.loader import find_by_id, load_catalog
from orchestrator.testcase.runner import _render

TARGET = {"url": "https://app.test/x", "parameter": "q", "cookie": "", "auth_header": "",
          "origin": "https://app.test:443", "origin_host": "app.test", "submit": "",
          "url_template": "https://app.test/x", "method": "GET"}


def mutating_steps():
    out = []
    for case_id, tc in sorted(load_catalog().items()):
        for step in tc.steps:
            try:
                _, url, method = curl_request(_render(step.command, TARGET))
            except Exception:
                continue
            if method not in ("GET", "HEAD", "OPTIONS"):
                out.append((case_id, step.name, method, url))
    return out


def test_the_mutating_steps_are_the_ones_we_think_they_are():
    """Pinned, so a new mutating step cannot be added without this failing and
    the decision being made again."""
    found = {(c, s) for c, s, _, _ in mutating_steps()}
    assert found == {
        ("WSTG-CONF-06", "put_probe"),
        ("WSTG-INPV-07", "classic_file_read"),
        ("WSTG-INPV-07", "php_wrapper_read"),
        ("WSTG-INPV-07", "windows_file_read"),
        ("WSTG-INPV-07", "entity_parser_signature"),
        ("WSTG-INPV-11", "php_object_probe"),
        ("WSTG-INPV-11", "java_stream_probe"),
        ("WSTG-INPV-11", "python_pickle_probe"),
        ("WSTG-INPV-11", "dotnet_ruby_probe"),
    }, found


@pytest.mark.parametrize("case_id,step_name,method,url", mutating_steps())
async def test_no_mutating_step_runs_in_the_catalogue_lane(case_id, step_name, method, url):
    """The acceptance, directly: with state_changing SELECTED and a route that
    permits the method, the step is still refused.

    The egress policy is what used to say yes. Here it says yes too — and the
    step policy has to say no anyway, because the policy governs SCOPE and this
    governs whether erlik writes to someone's server."""
    from orchestrator.integrations.deterministic import CatalogueAdapter

    policy = {"scope": {"allow_hosts": ["app.test"], "allow_ports": [443], "deny_hosts": []},
              "state_changing": True,
              "operation_routes": [{"method": method, "origin": "https://app.test",
                                    "path_regex": ".*"}]}
    decide = CatalogueAdapter._v1_step_policy
    step = next(s for s in find_by_id(case_id).steps if s.name == step_name)
    reason = decide(policy, step, _render(step.command, TARGET))
    assert reason, f"{case_id}/{step_name} would write to the target"
    assert "mutate the target" in reason, reason

    # ...and the egress policy, which used to be the only gate, says yes here.
    from orchestrator.integrations.egress_policy import EgressPolicy
    assert EgressPolicy(policy).check(url, method)[0], (
        "this test no longer exercises the defect: the scope policy already refuses")


def test_a_safe_step_is_untouched():
    from orchestrator.integrations.deterministic import CatalogueAdapter
    policy = {"scope": {"allow_hosts": ["app.test"], "allow_ports": [443], "deny_hosts": []}}
    step = next(s for s in find_by_id("WSTG-INPV-05.2").steps if s.name == "single_quote")
    assert CatalogueAdapter._v1_step_policy(policy, step, _render(step.command, TARGET)) is None


def test_what_refusing_costs():
    """Stated, not buried. WSTG-CONF-06 keeps its medium detection from the
    Allow header and loses only the high confirmation that writes a file.
    WSTG-INPV-07 loses EVERYTHING: all four of its steps are POST and all four
    emit findings, so XXE becomes undetectable in this lane until a fixture and
    cleanup wrapper exists (E-012).

    If that ever stops being true, this test should fail and the trade should be
    revisited rather than silently inherited."""
    conf06 = {s.name: [e.emit_finding for e in s.evaluators if e.emit_finding]
              for s in find_by_id("WSTG-CONF-06").steps}
    assert conf06["options"], "CONF-06 would lose its only detection, not just a confirmation"
    assert conf06["options"][0]["severity"] == "medium"
    assert conf06["put_probe"][0]["severity"] == "high"

    inpv07 = find_by_id("WSTG-INPV-07")
    emitting = [s.name for s in inpv07.steps if any(e.emit_finding for e in s.evaluators)]
    mutating = {s for c, s, _, _ in mutating_steps() if c == "WSTG-INPV-07"}
    assert set(emitting) <= mutating, (
        "XXE detection now has a non-mutating step — re-check whether refusing is still right")
