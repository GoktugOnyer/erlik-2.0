"""WSTG-BUSL-05, and the proof that it is not WSTG-BUSL-04 with fewer threads.

A single-use function used twice, SEQUENTIALLY. That is the whole distinction from the race
case, and the distinction is load-bearing: an application can fail either one alone. Measured
on the lab fixture before either case was pointed at it:

    /redeem       8 concurrent -> 8 succeed     sequential -> 1 of 2    race-unsafe, replay-SAFE
    /apply        8 concurrent -> 8 succeed     sequential -> 2 of 2    no limit at all
    /redeem-safe  8 concurrent -> 1 succeeds    sequential -> 1 of 2    both enforced

So BUSL-05 must stay QUIET on /redeem — the endpoint BUSL-04 reports — because /redeem does
enforce its limit, just not atomically. A case that flagged it too would be the race case with
extra steps, and two cases that always agree are one case and a maintenance cost.

THAT DISAGREEMENT IS ASSERTED HERE rather than assumed. It is the only test in this file that
could not be written by looking at BUSL-05 alone.
"""
import pathlib
import socket
import subprocess
import sys
import time

import pytest

from orchestrator.testcase.loader import load_catalog

FIXTURE = pathlib.Path(__file__).resolve().parents[0] / "fixtures" / "integration_target.py"


@pytest.fixture
def lab_host(tmp_path):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    script = tmp_path / "target.py"
    script.write_text(FIXTURE.read_text().replace('("0.0.0.0", 8080)',
                                                  f'("127.0.0.1", {port})'))
    process = subprocess.Popen([sys.executable, str(script)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
        yield f"127.0.0.1:{port}"
    finally:
        process.kill()
        process.wait(timeout=5)


async def _local(command, *args, **kwargs):
    import asyncio

    started = time.monotonic()
    process = await asyncio.create_subprocess_shell(
        command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    stdout, _ = await process.communicate()
    return {"success": process.returncode == 0, "output": stdout.decode(errors="replace"),
            "duration_ms": max(1, int((time.monotonic() - started) * 1000)),
            "error": None, "exit_code": process.returncode}


async def run_case(case_id, path, host, **extra):
    from orchestrator.testcase.runner import run_test_case

    url = f"http://{host}{path}"
    marker = "APPLIED" if path == "/apply" else "REDEEMED"
    target = {"url": url, "request_template": f"curl -s -X POST {url}",
              "success_marker": marker,
              "scope": {"allow_hosts": ["127.0.0.1"],
                        "allow_ports": [int(host.split(":")[1])]}, **extra}
    case = load_catalog().get(case_id)
    assert case is not None, f"{case_id} vanished from the catalogue"
    return await run_test_case(case, target, executor=_local, allow_llm=False)


# ------------------------------------------------------------------ the two controls


@pytest.mark.asyncio
async def test_a_function_with_no_limit_is_detected(lab_host):
    result = await run_case("WSTG-BUSL-05", "/apply", lab_host)
    assert result.findings, f"the unlimited function produced no finding: {result.steps}"
    assert any("Usage Limit Not Enforced" in (f.vuln_type or "") for f in result.findings)


@pytest.mark.asyncio
async def test_an_enforced_limit_is_not_a_finding(lab_host):
    result = await run_case("WSTG-BUSL-05", "/redeem-safe", lab_host)
    assert not result.findings, [f.model_dump() for f in result.findings]


@pytest.mark.asyncio
async def test_the_enforced_limit_actually_refused_the_second_use(lab_host):
    """A negative control that was never exercised is not a control."""
    result = await run_case("WSTG-BUSL-05", "/redeem-safe", lab_host)
    output = "".join(step.output or "" for step in result.steps)
    assert output.count("REDEEMED") == 1, output
    assert "already used" in output, "the second use was not refused"


# --------------------------------------------- the two cases measure different things


@pytest.mark.asyncio
async def test_the_racy_endpoint_enforces_its_limit_sequentially(lab_host):
    """/redeem is race-unsafe and replay-SAFE. BUSL-05 must stay quiet on it: the limit IS
    enforced, just not atomically, and reporting it here would make this case a noisier
    duplicate of BUSL-04."""
    result = await run_case("WSTG-BUSL-05", "/redeem", lab_host)
    assert not result.findings, (
        f"BUSL-05 reported an endpoint whose limit holds under sequential use: "
        f"{[f.model_dump() for f in result.findings]}")


@pytest.mark.asyncio
async def test_the_race_case_does_report_that_same_endpoint(lab_host):
    """The other half of the disagreement, and the reason the pair is worth keeping. Same
    endpoint, same lab, two cases, opposite verdicts — because they ask different questions.
    If this ever agrees with the test above, one of the two cases has stopped earning its
    place."""
    racy = await run_case("WSTG-BUSL-04", "/redeem", lab_host, parallel_n=8)
    quiet = await run_case("WSTG-BUSL-05", "/redeem", lab_host)
    assert racy.findings, "BUSL-04 no longer finds the race it was built for"
    assert not quiet.findings
    assert "Race Condition" in (racy.findings[0].vuln_type or "")


@pytest.mark.asyncio
async def test_the_unlimited_endpoint_fails_both_and_that_is_not_a_contradiction(lab_host):
    """`/apply` has no limit at all, so both cases report it — concurrently and
    sequentially. Asserted because "the cases disagree" is a property of /redeem
    specifically, not a rule about the two cases."""
    both = await run_case("WSTG-BUSL-04", "/apply", lab_host, parallel_n=8)
    replay = await run_case("WSTG-BUSL-05", "/apply", lab_host)
    assert both.findings and replay.findings


# ------------------------------------------------------- the finding says what it saw


@pytest.mark.asyncio
async def test_the_finding_counts_the_uses_and_is_not_called_a_burst(lab_host):
    result = await run_case("WSTG-BUSL-05", "/apply", lab_host)
    basis = next(f for f in result.findings
                 if "Usage Limit" in (f.vuln_type or "")).basis
    assert "appeared 2 times" in basis, basis
    assert "at most 1 should have succeeded" in basis
    assert "burst" not in basis and "parallel attempts" not in basis
