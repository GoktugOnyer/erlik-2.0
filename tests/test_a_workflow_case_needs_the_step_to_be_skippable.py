"""WSTG-BUSL-06, with the same two controls E-013 asks for — and a third.

Workflow circumvention is a DIFFERENT invariant from the race in BUSL-04 and is checked
differently: no concurrency, one request, from a subject that never completed the
prerequisite. A burst would find concurrency bugs here and miss ordering entirely.

THE LAB CARRIES THE PAIR. `/shop/confirm` finalises an order whether or not it was ever paid
for; `/shop-strict/confirm` refuses until the cart is paid. Measured against the fixture
before the case was pointed at it:

    /shop/confirm          unpaid -> 200 {"status":"CONFIRMED"}
    /shop-strict/confirm   unpaid -> 409 {"error":"payment required"}

AND A THIRD CONTROL THE RACE PAIR DID NOT NEED. An endpoint that refuses EVERYTHING would
also pass the negative test, and would not be enforcing anything — it would be broken. So the
strict endpoint is also driven down its happy path: pay, then confirm, and the confirmation
must succeed. Without that, "no finding" cannot be told from "nothing works".
"""
import pathlib
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

import pytest

from orchestrator.testcase.loader import load_catalog

CASE_ID = "WSTG-BUSL-06"
FIXTURE = pathlib.Path(__file__).resolve().parents[0] / "fixtures" / "integration_target.py"


@pytest.fixture
def lab_host(tmp_path):
    """The lab fixture as a local process. Same reasoning as the race controls: the executor
    runs curl on this host, and 127.0.0.1 keeps it on this machine."""
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
    """Local transport; `run_test_case` still applies safe mode and write confinement first."""
    import asyncio

    started = time.monotonic()
    process = await asyncio.create_subprocess_shell(
        command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    stdout, _ = await process.communicate()
    return {"success": process.returncode == 0, "output": stdout.decode(errors="replace"),
            "duration_ms": max(1, int((time.monotonic() - started) * 1000)),
            "error": None, "exit_code": process.returncode}


async def run_against(prefix, host):
    """Confirm a cart that was NEVER paid for. A fresh id per run, so no earlier test can
    have paid for it — the case's own precondition, honoured by the test that checks it."""
    from orchestrator.testcase.runner import run_test_case

    cart = uuid.uuid4().hex[:12]
    url = f"http://{host}{prefix}/confirm?cart={cart}"
    target = {
        "url": url,
        "final_request": f"curl -s -X POST '{url}'",
        "success_marker": "CONFIRMED",
        "scope": {"allow_hosts": ["127.0.0.1"], "allow_ports": [int(host.split(":")[1])]},
    }
    case = load_catalog().get(CASE_ID)
    assert case is not None, f"{CASE_ID} vanished from the catalogue"
    return await run_test_case(case, target, executor=_local, allow_llm=False)


def post(host, path):
    try:
        response = urllib.request.urlopen(urllib.request.Request(
            f"http://{host}{path}", data=b"{}", method="POST"), timeout=5)
        return response.status, response.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


# ------------------------------------------------------------------ the two controls


@pytest.mark.asyncio
async def test_a_skippable_final_step_is_detected(lab_host):
    result = await run_against("/shop", lab_host)
    assert result.findings, f"the circumvented workflow produced no finding: {result.steps}"
    assert any("Workflow Circumvention" in (f.vuln_type or "") for f in result.findings)


@pytest.mark.asyncio
async def test_an_enforced_order_is_not_a_finding(lab_host):
    result = await run_against("/shop-strict", lab_host)
    assert not result.findings, [f.model_dump() for f in result.findings]


@pytest.mark.asyncio
async def test_the_enforced_endpoint_refused_rather_than_stayed_silent(lab_host):
    """A negative control that was never exercised is not a control."""
    result = await run_against("/shop-strict", lab_host)
    output = "".join(step.output or "" for step in result.steps)
    assert "payment required" in output, f"the control did not refuse anything: {output!r}"
    assert "CONFIRMED" not in output


@pytest.mark.asyncio
async def test_the_enforced_endpoint_still_works_when_the_order_is_followed(lab_host):
    """The third control. An endpoint that refuses EVERYTHING passes the negative test and
    enforces nothing — it is broken. Pay first, and the confirmation must succeed, or "no
    finding" cannot be told from "nothing works"."""
    cart = uuid.uuid4().hex[:12]
    assert post(lab_host, f"/shop-strict/pay?cart={cart}")[0] == 200
    status, body = post(lab_host, f"/shop-strict/confirm?cart={cart}")
    assert status == 200 and "CONFIRMED" in body, (status, body)


# ------------------------------------------------------- the finding says what it saw


@pytest.mark.asyncio
async def test_the_finding_says_the_request_should_not_have_succeeded_at_all(lab_host):
    """The count evaluator's basis, in this case's vocabulary. `min_count` is 1 here, so the
    threshold sentence is "should not have succeeded at all" rather than a count — and this
    is a single request, so it is not described as a burst."""
    result = await run_against("/shop", lab_host)
    basis = next(f for f in result.findings
                 if "Workflow Circumvention" in (f.vuln_type or "")).basis
    assert "appeared once" in basis, basis
    assert "should not have succeeded at all" in basis
    assert "parallel attempts" not in basis, "an ordering finding described as a burst"
    assert "burst" not in basis


@pytest.mark.asyncio
async def test_this_finding_is_suspected_like_the_race_one(lab_host):
    result = await run_against("/shop", lab_host)
    finding = next(f for f in result.findings
                   if "Workflow Circumvention" in (f.vuln_type or ""))
    assert finding.confidence == "suspected", finding.confidence
