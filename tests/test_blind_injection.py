"""WSTG-INPV-05.3 and 05.4 against a really injectable app, and six that are not.

Both cases decide by COMPARING responses rather than reading one, so the thing
that has to be got right is not the payload — it is when the comparison is
admissible. tests/fixtures/blind_injection_app.py serves one real SQL engine
behind routes that are injectable and routes that only look it, and this drives
the real cases through the real runner against each.

The negative routes are the whole point: a reflecting endpoint, an unstable
one, a filter that refuses every payload identically, and two that are slow for
reasons that have nothing to do with a database.
"""
import shlex
import shutil
import subprocess
import threading
from http.server import HTTPServer

import pytest

from orchestrator.testcase.loader import find_by_id
from orchestrator.testcase.runner import (
    Evaluator, StepResult, _comparable, _run_evaluator, run_test_case)

from fixtures import blind_injection_app

pytestmark = pytest.mark.skipif(shutil.which("curl") is None, reason="needs a real curl")

# A KERNEL-CHOSEN PORT, NOT A FIXED ONE. These fixtures bound a hard-coded number, and two
# full-suite runs inside the TIME_WAIT window left it in `TIME_WAIT` from the first — so the
# second errored every test in the file with `OSError: [Errno 48] Address already in use`, and
# a third minutes later passed. Measured three times in one sitting, once on a fresh clone
# where it read as a product regression and was a socket. `SO_REUSEADDR` does not help: the
# listening socket is gone and what remains are the closed connections to it.
#
# Binding 0 asks for a free one; `server.server_address[1]` is what was given.
BOOLEAN, TIMING = "WSTG-INPV-05.3", "WSTG-INPV-05.4"


@pytest.fixture(scope="module")
def app():
    server = HTTPServer(("127.0.0.1", 0), blind_injection_app.Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://localhost:{port}"
    server.shutdown()


async def real_curl(command, **kwargs):
    result = subprocess.run(shlex.split(command), capture_output=True, text=True, timeout=40)
    return {"success": result.returncode == 0, "exit_code": result.returncode,
            "output": result.stdout, "error": result.stderr or None}


async def probe(case, route, base):
    return await run_test_case(
        find_by_id(case),
        {"url": f"{base}/{route}", "parameter": "id", "scope": {"allow_hosts": ["localhost"]}},
        executor=real_curl, allow_llm=False)


# --------------------------------------------------------------- boolean

@pytest.mark.parametrize("route", ["quoted", "unquoted"])
async def test_a_blind_injection_is_detected_in_either_sink(route, app):
    """One sink quotes the parameter and one does not, and a payload that
    closes the wrong one is inert. Both families have to be present for the
    case to reach either."""
    run = await probe(BOOLEAN, route, app)
    assert run.findings, f"{route}: a real blind injection went unreported"
    assert run.findings[0].severity == "high"


async def test_the_finding_carries_the_comparison_as_its_evidence(app):
    """The true condition's response is an ordinary page. A reader handed only
    that cannot tell why it was reported, so the evidence is the difference."""
    finding = (await probe(BOOLEAN, "quoted", app)).findings[0]
    assert "first difference" in finding.evidence
    assert "User is MISSING" in finding.evidence and "User exists" in finding.evidence
    assert finding.confidence == "confirmed"
    assert "controls agreed" in finding.basis


@pytest.mark.parametrize("route", [
    "safe",            # parameterised — nothing to find
    "reflect",         # echoes the parameter, so any two probes differ
    "unstable",        # changes on its own, so any two probes differ
    "rejects_quotes",  # refuses every payload with the same page
])
async def test_the_boolean_case_reports_nothing_without_an_injection(route, app):
    run = await probe(BOOLEAN, route, app)
    assert not run.findings, (
        f"{route}: a HIGH finding for a request that proved nothing")


async def test_an_endpoint_that_reflects_is_declined_not_guessed_at(app):
    """A reflecting endpoint differs between ANY two probes, so the difference
    the case looks for is there without an injection. The control pair is what
    turns that from a finding into no verdict — and the case must still have
    run its payloads, not skipped the route."""
    run = await probe(BOOLEAN, "reflect", app)
    assert not run.findings
    steps = {s.step for s in run.steps}
    assert {"true_string", "true_numeric"} <= steps
    outputs = {s.step: s.output for s in run.steps}
    assert _comparable(outputs["control_a"]) != _comparable(outputs["control_b"])


async def test_the_warm_up_absorbs_a_one_shot_banner(app):
    """Measured on DVWA: the first response after login carries a flash the
    next one does not. Landing on control_a, it makes the controls disagree and
    a KNOWN vulnerable target report nothing. The fixture serves the same
    banner once per process, so this fails if the warm-up step is removed."""
    blind_injection_app.Handler.served = 0
    run = await probe(BOOLEAN, "quoted", app)
    assert run.findings, "the one-shot banner defeated the comparison"
    assert run.steps[0].step == "warm_up"
    assert "Welcome back" in run.steps[0].output
    assert not any("Welcome back" in s.output for s in run.steps[1:])


# ---------------------------------------------------------------- timing

@pytest.mark.parametrize("route", ["quoted_sleep", "unquoted_sleep"])
async def test_a_caused_delay_is_detected(route, app):
    run = await probe(TIMING, route, app)
    assert run.findings, f"{route}: a caused delay went unreported"
    assert "margin over the required" in run.findings[0].basis


async def test_a_timing_finding_is_never_graded_confirmed(app):
    """One measurement cannot rule out a single spike, and `confirmed` is what
    marks a finding verified in the client's tracker."""
    finding = (await probe(TIMING, "quoted_sleep", app)).findings[0]
    assert finding.confidence == "suspected"
    assert "ONE measurement" in finding.basis


@pytest.mark.parametrize("route", [
    "slow",            # uniformly slow: the controls are slow too
    "slow_by_length",  # slower for longer input, which equal-length pairs defeat
    "safe",
])
async def test_a_delay_that_was_not_caused_is_not_a_finding(route, app):
    run = await probe(TIMING, route, app)
    assert not run.findings, f"{route}: a delay was reported as an injection"


def test_every_sleep_payload_pair_is_the_same_length():
    """The short and long probes differ only in the number inside the sleep. An
    endpoint whose latency tracks input length therefore moves both equally,
    which is what makes /slow_by_length a non-finding rather than a lucky one."""
    steps = {s.name: s.command for s in find_by_id(TIMING).steps}
    for name in [n for n in steps if n.endswith("_short")]:
        assert len(steps[name]) == len(steps[name[:-6] + "_long"]), name


def test_no_payload_uses_or():
    """Measured on DVWA: `nosuchid' OR SLEEP(1) AND '1'='1` took 5025ms for a
    five-row table — MySQL evaluates the WHERE clause per row and the left side
    is false for every one. The same shape against a table of any real size is
    a denial of service delivered by a scanner."""
    for case in (BOOLEAN, TIMING):
        for step in find_by_id(case).steps:
            assert " OR " not in step.command.upper().replace("CURL", ""), step.name


# ------------------------------------------------- the timed-out step

def _step(name, output="body", ms=0, ok=True):
    return StepResult(step=name, command="curl", success=ok, output=output,
                      duration_ms=ms, exit_code=0 if ok else 28)


async def _verdict(ev, step, prior):
    finding, _, _, _ = await _run_evaluator(
        ev, step, find_by_id(BOOLEAN), {}, None, None, prior)
    return finding


async def test_a_timed_out_step_is_not_a_boolean_finding():
    """curl gives up with an empty body, which differs from every control — so
    a hung request looks exactly like a true condition."""
    ev = Evaluator(type="boolean_differential", control=["a", "b"],
                   differs_from="f", emit_finding={})
    prior = [_step("a"), _step("b"), _step("f")]
    dead = _step("t", output="", ms=20000, ok=False)
    assert await _verdict(ev, dead, prior + [dead]) is None


async def test_a_timed_out_step_is_not_a_timing_finding():
    """--max-time makes duration_ms the whole budget, so a hung request looks
    exactly like a successful SLEEP(20)."""
    ev = Evaluator(type="timing", control=["a", "b"], delay_ms=3000, emit_finding={})
    prior = [_step("a", ms=10), _step("b", ms=10)]
    dead = _step("t", output="", ms=20000, ok=False)
    assert await _verdict(ev, dead, prior + [dead]) is None


async def test_a_missing_control_is_no_verdict_rather_than_a_weaker_one():
    """A control named but never run — skipped by `when`, or renamed in the
    YAML — must not silently degrade the comparison to the remaining steps."""
    ev = Evaluator(type="boolean_differential", control=["a", "gone"],
                   differs_from="f", emit_finding={})
    prior = [_step("a"), _step("f")]
    assert await _verdict(ev, _step("t", output="different"), prior) is None


async def test_controls_that_disagree_stop_the_comparison():
    ev = Evaluator(type="boolean_differential", control=["a", "b"],
                   differs_from="f", emit_finding={})
    prior = [_step("a", output="one"), _step("b", output="two"), _step("f")]
    assert await _verdict(ev, _step("t", output="different"), prior) is None


async def test_a_false_condition_off_the_baseline_is_graded_down():
    """The full claim is that BOTH conditions behaved as SQL. When only the
    true side moved, the difference is real but the reading of it is a lead."""
    ev = Evaluator(type="boolean_differential", control=["a", "b"],
                   differs_from="f", emit_finding={})
    prior = [_step("a"), _step("b"), _step("f", output="something else")]
    finding = await _verdict(ev, _step("t", output="different"), prior)
    assert finding is not None and finding.confidence == "suspected"


def test_both_cases_run_where_the_findings_are():
    from orchestrator.integrations.inventory import executable_test_cases
    runnable = executable_test_cases()
    assert {BOOLEAN, TIMING} <= set(runnable)
    assert "WSTG-INPV-05" not in runnable, "unchanged: it still needs a shell"
