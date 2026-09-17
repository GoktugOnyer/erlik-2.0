"""WSTG-BUSL-04 had never been run against anything — E-013's two controls.

The case ships. It appears in the capability index, `capabilities.CLASSES` claims it for the
`logic` attack class, and the only test mentioning it asserted that the id exists. Nothing
executed it. So neither half of E-013's acceptance had ever been shown: "detect one seeded
invariant violation and reject a correctly enforced control under the same bounded schedule".

BOTH HALVES MATTER AND THE SECOND ONE IS THE HARD ONE. A race detector that fires on every
endpoint detects nothing — it just reports. The control is what separates "found a race" from
"fired N requests and saw N responses", and a case with only the positive half can pass while
being exactly that.

THE LAB CARRIES BOTH COUPONS. `/redeem` is check-then-act with a real gap; `/redeem-safe`
does identical work holding a mutex. Measured directly against the fixture before erlik was
pointed at it, because a test of a detector against an unverified target measures nothing:

    /redeem        8 concurrent -> 8 redeemed, 0 refused
    /redeem-safe   8 concurrent -> 1 redeemed, 7 refused

The gap is a real sleep rather than a hopeful one. A race that is won one run in five is a
flaky test, and a flaky negative control is indistinguishable from a working control.
"""
import pathlib
import re
import socket
import subprocess
import sys
import time

import pytest

from orchestrator.testcase.loader import load_catalog

CASE_ID = "WSTG-BUSL-04"
FIXTURE = pathlib.Path(__file__).resolve().parents[0] / "fixtures" / "integration_target.py"


@pytest.fixture
def lab_host(tmp_path):
    """The container fixture, run as a LOCAL process on a free port.

    Not Docker-gated, deliberately. `run_test_case` executes curl on this host rather than
    inside the sandbox, so a container reachable only on its own Docker network is the wrong
    shape — and the fixture is plain stdlib, so a subprocess is the whole requirement. The
    effect is that both controls run everywhere the suite runs, including the network-free
    CI job, instead of only where a daemon happens to be.

    127.0.0.1 throughout: this is a local lab and nothing here may leave the machine.
    """
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    source = FIXTURE.read_text().replace('("0.0.0.0", 8080)', f'("127.0.0.1", {port})')
    script = tmp_path / "target.py"
    script.write_text(source)
    process = subprocess.Popen([sys.executable, str(script)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    host = f"127.0.0.1:{port}"
    for _ in range(100):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.05)
    else:
        process.kill()
        pytest.fail("the lab fixture never came up")
    try:
        yield host
    finally:
        process.kill()
        process.wait(timeout=5)


def case():
    loaded = load_catalog().get(CASE_ID)
    assert loaded is not None, f"{CASE_ID} vanished from the catalogue"
    return loaded


def target(path, host):
    """The operator-supplied half. BUSL-04 fires `request_template` verbatim."""
    url = f"http://{host}{path}"
    return {
        "url": url,
        "request_template": f"curl -s -X POST {url}",
        "success_marker": "REDEEMED",
        "parallel_n": 8,
        "scope": {"allow_hosts": [host.split(":")[0]], "allow_ports": [int(host.split(":")[1])]},
    }


async def _local(command, *args, **kwargs):
    """Run the case's own rendered command here instead of in the kali-tools container.

    THE FLOORS STILL APPLY. `run_test_case` checks safe mode and write confinement BEFORE it
    calls an executor — that is what makes them a floor rather than something `execute_tool`
    happens to do — so supplying one swaps the transport and not the policy. What is under
    test is the CASE: whether BUSL-04's evaluators can tell a race from an enforced control.

    Local only, and the command is one this file rendered against 127.0.0.1.
    """
    import asyncio
    import time

    started = time.monotonic()
    process = await asyncio.create_subprocess_shell(
        command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    stdout, _ = await process.communicate()
    return {"success": process.returncode == 0, "output": stdout.decode(errors="replace"),
            "duration_ms": int((time.monotonic() - started) * 1000),
            "error": None, "exit_code": process.returncode}


async def run_against(path, host):
    from orchestrator.testcase.runner import run_test_case

    return await run_test_case(case(), target(path, host), executor=_local, allow_llm=False)


# ------------------------------------------------------------------ the two controls


@pytest.mark.asyncio
async def test_the_seeded_race_is_detected(lab_host):
    """The positive half. A single-use coupon that eight concurrent callers all redeem is
    the invariant violation, and the count evaluator is what sees it — `allow_llm=False`, so
    this is the deterministic path and not a model's opinion."""
    result = await run_against("/redeem", lab_host)
    assert result.findings, (
        f"the seeded race produced no finding: {result.model_dump()}")
    assert any("Race Condition" in (f.vuln_type or "") for f in result.findings), result.findings


@pytest.mark.asyncio
async def test_a_correctly_enforced_coupon_is_not_a_finding(lab_host):
    """The negative half, and the one that makes the positive half mean something. The same
    case, the same eight-way burst, against an endpoint that enforces the invariant."""
    result = await run_against("/redeem-safe", lab_host)
    assert not result.findings, (
        f"the enforced control was reported as a race: "
        f"{[f.model_dump() for f in result.findings]}")


@pytest.mark.asyncio
async def test_the_control_actually_took_the_same_burst(lab_host):
    """A negative control that was never exercised is not a control. This asserts the
    enforced endpoint really did receive the concurrent requests and really did refuse all
    but one — otherwise a case that silently failed to fire would pass the test above."""
    result = await run_against("/redeem-safe", lab_host)
    output = "".join(step.output or "" for step in result.steps)
    assert output.count("REDEEMED") == 1, (
        f"expected exactly one redemption under the lock, saw {output.count('REDEEMED')}")
    assert "already used" in output, "the other callers were not refused"


@pytest.mark.asyncio
async def test_the_two_endpoints_differ_only_in_the_lock(lab_host):
    """The controls are a PAIR: same case, same burst, same marker, opposite verdicts. If
    they ever start differing in something else, this is the test that should be rewritten
    rather than the conclusion that should be kept."""
    racy = await run_against("/redeem", lab_host)
    safe = await run_against("/redeem-safe", lab_host)
    assert bool(racy.findings) and not safe.findings
    assert racy.steps[0].command == safe.steps[0].command.replace("/redeem-safe", "/redeem")


# ------------------------------------------------- the finding says how badly it was lost


@pytest.mark.asyncio
async def test_the_finding_records_how_many_succeeded(lab_host):
    """E-013: "confidence records timing variability and does not infer impact from response
    counts alone". The count decides the finding, and it used to vanish — `basis` fell back
    to "count evaluator matched captured tool output", so two-of-eight and eight-of-eight
    were the same finding. `basis` is what the integration report renders as the
    description, so this is the sentence a client reads."""
    result = await run_against("/redeem", lab_host)
    finding = next(f for f in result.findings if "Race Condition" in (f.vuln_type or ""))
    assert "8 times" in finding.basis, finding.basis
    assert "across 8 parallel attempts" in finding.basis
    assert "at most 1 should have succeeded" in finding.basis


@pytest.mark.asyncio
async def test_the_finding_records_the_burst_duration(lab_host):
    """What says the requests actually overlapped. A burst taking as long as eight
    sequential requests raced nothing, and no count can show that."""
    result = await run_against("/redeem", lab_host)
    finding = next(f for f in result.findings if "Race Condition" in (f.vuln_type or ""))
    assert re.search(r"burst completed in \d+ms", finding.basis), finding.basis


@pytest.mark.asyncio
async def test_the_generic_fallback_is_not_what_a_race_reports(lab_host):
    """The specific thing that was there before, asserted absent."""
    result = await run_against("/redeem", lab_host)
    finding = next(f for f in result.findings if "Race Condition" in (f.vuln_type or ""))
    assert "count evaluator matched captured tool output" not in finding.basis


@pytest.mark.asyncio
async def test_a_race_finding_is_still_only_suspected(lab_host):
    """Recording the evidence is not the same as upgrading the claim. A burst shows the
    application allowed it twice; it does not show what that is worth, and `confirmed` in
    this lane is reserved for a differential. E-014's rule applies here too."""
    result = await run_against("/redeem", lab_host)
    finding = next(f for f in result.findings if "Race Condition" in (f.vuln_type or ""))
    assert finding.confidence == "suspected", finding.confidence
