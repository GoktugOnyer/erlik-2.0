"""Required fixture data — E-012's last item, and what a failed setup was reporting.

E-012 models a workflow as setup -> operations -> assertions -> cleanup, and the setup is
`Workflow.fixtures`: the data the selected operations REQUIRE before they mean anything. The
worker already refused to scan without it — a fixture whose assertion fails raises before
`subprocess.run`, so the scan never starts.

WHAT IT REPORTED IS THE DEFECT. Measured against the lab, four combinations of setup and
cleanup:

    setup ok,   cleanup ok      completed   1 operation exercised
    setup FAIL, cleanup ok      partial     0 exercised   <-- no coverage, reported as partial
    setup ok,   cleanup FAIL    partial     1 exercised
    setup FAIL, cleanup FAIL    partial     0 exercised

The failing-setup rows had `exit_code: None` and not one operation exercised, and the missing
report had ALREADY set the stage to "failed". The workflow branch ran afterwards and
overwrote it with "partial" — the status a run earns when it scanned properly and cleanup
left residue. No coverage at all was reported more reassuringly than a run that worked, under
one reason naming both causes and committing to neither.

They are opposite instructions. No coverage means run it again. Residue means go and look at
what was left on the client's system.

AND THE FIRST FIX WORKED BY ACCIDENT. It read a `setup_ok` flag added to the worker — which
arrived as None, because the worker runs from the copy baked into the container image and
nothing rebuilt it. The fallback happened to be right for the three cases measured and would
have been WRONG for the fourth: a scan that TIMES OUT sets the same `error` with setup
perfectly fine, and would have been reported as never having started. `workflow_setup_ok`
computes the answer from the fixture responses the existing worker already sends.
"""
import os

import pytest

from orchestrator.integrations.adapters import workflow_outcome, workflow_setup_ok
from orchestrator.integrations.contracts import RequestSpec

from tests.test_integration_docker import lab  # noqa: F401


SETUP = [RequestSpec(url="http://app.test/setup", method="POST", expected_status=200)]
DONE = {"fixtures": [{"status": 200, "body": "ok"}], "cleanup": [{"ok": True}],
        "exit_code": 0}


# --------------------------------------------------- did the required data get established


def test_a_matching_response_is_established_setup():
    assert workflow_setup_ok(DONE, SETUP) is True


def test_a_wrong_status_is_not():
    assert workflow_setup_ok({"fixtures": [{"status": 500, "body": ""}]}, SETUP) is False


def test_a_missing_body_marker_is_not():
    """`body_contains` is how an operator says "setup worked" when the status cannot: a 200
    carrying an error page is the case it exists for."""
    spec = [RequestSpec(url="http://app.test/s", expected_status=200, body_contains="token")]
    assert workflow_setup_ok({"fixtures": [{"status": 200, "body": "no marker here"}]}, spec) is False
    assert workflow_setup_ok({"fixtures": [{"status": 200, "body": "a token: x"}]}, spec) is True


def test_a_short_list_is_a_failure_not_a_pass():
    """The worker stops at the first fixture that fails, so fewer recorded responses than
    declared specs means one never returned. Zipping without checking the length would walk
    the pairs that DID succeed and call the setup good."""
    two = SETUP + [RequestSpec(url="http://app.test/s2", method="POST", expected_status=201)]
    assert workflow_setup_ok({"fixtures": [{"status": 200, "body": ""}]}, two) is False


def test_no_recorded_fixtures_is_not_success():
    assert workflow_setup_ok({}, SETUP) is False


# ------------------------------------------------------------ the four outcomes, separated


def test_everything_worked_leaves_the_status_alone():
    """Returning None rather than "completed": the caller has already decided what a clean
    scan is, and asserting it here would let a workflow stage overwrite a failure the report
    parsing found."""
    assert workflow_outcome(DONE, SETUP) is None


def test_failed_setup_is_failed_and_says_there_is_no_coverage():
    status, reason = workflow_outcome(
        {"fixtures": [{"status": 500, "body": ""}], "cleanup": [{"ok": True}],
         "error": "fixture assertion failed", "exit_code": None}, SETUP)
    assert status == "failed", "no coverage must not be reported as partial"
    assert "NO coverage" in reason and "never ran" in reason


def test_failed_cleanup_after_a_real_scan_is_partial():
    status, reason = workflow_outcome(
        {**DONE, "cleanup": [{"ok": False}]}, SETUP)
    assert status == "partial"
    assert "state may be left on the target" in reason
    assert "NO coverage" not in reason, "a scan that ran must not read as one that did not"


def test_both_failing_says_both():
    status, reason = workflow_outcome(
        {"fixtures": [{"status": 500, "body": ""}], "cleanup": [{"ok": False}],
         "error": "fixture assertion failed", "exit_code": None}, SETUP)
    assert status == "failed"
    assert "NO coverage" in reason and "state left behind" in reason


def test_a_scan_that_timed_out_is_partial_not_no_coverage():
    """The case the first fix would have got wrong. Setup succeeded and the SCAN stopped, so
    there is partial coverage — the opposite instruction from a setup that never established
    the data. Both set the worker's `error`, which is why that field cannot decide this."""
    status, reason = workflow_outcome(
        {**DONE, "error": "Command timed out after 45 seconds", "exit_code": None}, SETUP)
    assert status == "partial"
    assert "did not finish" in reason and "coverage is incomplete" in reason
    assert "NO coverage" not in reason


def test_the_setup_verdict_does_not_depend_on_the_workers_own_flag():
    """The worker runs from the image, not from this tree, so a field added here may simply
    not arrive — measured: it came back None against a current lab. The verdict is computed
    from the responses, and a stale flag claiming success cannot override them."""
    lying = {"fixtures": [{"status": 500, "body": ""}], "cleanup": [],
             "setup_ok": True, "error": "fixture assertion failed"}
    assert workflow_setup_ok(lying, SETUP) is False
    assert workflow_outcome(lying, SETUP)[0] == "failed"


def test_the_adapter_uses_the_extracted_decision():
    import inspect

    from orchestrator.integrations import adapters

    source = inspect.getsource(adapters.SchemathesisAdapter.run)
    assert "workflow_outcome(detail, workflow.fixtures)" in source


# ----------------------------------------------------------------- against the real lab


@pytest.mark.docker
@pytest.mark.skipif(os.environ.get("ERLIK_DOCKER_TESTS") != "1",
                    reason="set ERLIK_DOCKER_TESTS=1 for Docker lab tests")
@pytest.mark.asyncio
async def test_a_failed_fixture_reports_no_coverage_against_the_lab(lab):
    """End to end, because the unit cases above take the worker's report on trust and this is
    where that report is actually produced."""
    from orchestrator.integrations.adapters import ADAPTERS, Context
    from orchestrator.integrations.runtime import Sandbox
    from orchestrator.integrations.service import operation_routes
    from tests.test_integration_docker import config

    cfg = config(stages=["schemathesis"], active=True, state_changing=True,
                 schema_input={"url": "http://target:8080/openapi.json"},
                 workflow={"operations": ["createItem"],
                           # The target answers 200; demanding 299 makes the assertion fail.
                           "fixtures": [{"url": "http://target:8080/setup", "method": "POST",
                                         "expected_status": 299}],
                           "cleanup": [{"url": "http://target:8080/cleanup",
                                        "method": "POST"}]})
    async with Sandbox(cfg) as discovery:
        routes = await operation_routes(cfg, discovery, "http://target:8080")
    ctx = Context("w", "workflow", "http://target:8080", cfg)
    async with Sandbox(cfg, operation_routes=routes) as sandbox:
        result = await ADAPTERS["schemathesis"].run(ctx, sandbox)

    assert result.status == "failed", result.model_dump()
    assert "NO coverage" in result.reason
    assert not [o for o in result.observations if o.get("type") == "api_contract_failure"], (
        "the scan is supposed to have been skipped entirely")
    workflow = next(o for o in result.observations if o.get("type") == "workflow")
    assert workflow["exit_code"] is None, "the scan subprocess should never have started"
