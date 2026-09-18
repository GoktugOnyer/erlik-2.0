"""WSTG-AUTHZ-02: does access survive an ownership transfer? E-013's last invariant.

NOT the question AUTHZ-04 asks. That one, and the `ownership` evaluator beside it, ask whether
a caller can reach an object that was never theirs. This asks whether access SURVIVES a
legitimate transfer: alice owns the document, hands it to bob, and can still read it.

Nothing in the lane asked a before-and-after question about ONE identity. The cross-arm checks
compare two identities at one moment; `compare_assessments` compares two whole runs. This is a
differential in time, inside a single case.

THE REALISTIC SHAPE OF THE BUG IS TWO SOURCES OF TRUTH — an owner field and a grant list.
`/transfer` updates the owner and ADDS the recipient to the grants, leaving the previous owner
in place; `/transfer-strict` replaces them. Measured against the fixture before the case was
pointed at it:

    /transfer          alice before=200  after=200   bob=200    stale access
    /transfer-strict   alice before=200  after=403   bob=200    revoked

That third column is the control's own control. An endpoint that revoked EVERYBODY would also
stop alice reading, and would not be a working transfer.
"""
import pathlib
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest

from orchestrator.testcase.loader import load_catalog

CASE_ID = "WSTG-AUTHZ-02"
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


async def run_against(transfer_path, host, doc):
    """alice reads, hands the object to bob, reads again. A distinct document per run, so
    no earlier test can have transferred it already."""
    from orchestrator.testcase.runner import run_test_case

    read = f"curl -s -H 'Authorization: Bearer alice' 'http://{host}/object?id={doc}'"
    transfer = (f"curl -s -X POST -H 'Authorization: Bearer alice' "
                f"'http://{host}{transfer_path}?id={doc}&to=bob'")
    target = {
        "url": f"http://{host}/object?id={doc}",
        "read_request": read,
        "transfer_request": transfer,
        "success_marker": "OBJECT-BODY",
        "scope": {"allow_hosts": ["127.0.0.1"], "allow_ports": [int(host.split(":")[1])]},
    }
    case = load_catalog().get(CASE_ID)
    assert case is not None, f"{CASE_ID} vanished from the catalogue"
    return await run_test_case(case, target, executor=_local, allow_llm=False)


def get(host, doc, who):
    request = urllib.request.Request(f"http://{host}/object?id={doc}")
    request.add_header("Authorization", f"Bearer {who}")
    try:
        return urllib.request.urlopen(request, timeout=5).status
    except urllib.error.HTTPError as exc:
        return exc.code


# ------------------------------------------------------------------ the two controls


@pytest.mark.asyncio
async def test_access_surviving_the_transfer_is_detected(lab_host):
    result = await run_against("/transfer", lab_host, "lax-1")
    assert result.findings, f"stale access produced no finding: {result.steps}"
    assert any("Stale Access" in (f.vuln_type or "") for f in result.findings)


@pytest.mark.asyncio
async def test_a_transfer_that_revokes_is_not_a_finding(lab_host):
    result = await run_against("/transfer-strict", lab_host, "strict-1")
    assert not result.findings, [f.model_dump() for f in result.findings]


@pytest.mark.asyncio
async def test_the_first_read_succeeded_so_the_second_one_means_something(lab_host):
    """The reason min_count is 2 rather than 1. The first read is the control: it proves the
    subject really had access, without which "the second read failed" cannot be told from
    "this identity never had any". A case that sent only the post-transfer read would report
    clean against a target that refuses alice everything."""
    result = await run_against("/transfer-strict", lab_host, "strict-2")
    output = "".join(step.output or "" for step in result.steps)
    assert output.count("OBJECT-BODY") == 1, (
        f"expected exactly one successful read — before the transfer — saw "
        f"{output.count('OBJECT-BODY')}")
    assert "TRANSFERRED" in output, "the transfer itself did not happen"
    assert "forbidden" in output, "the second read was not refused"


@pytest.mark.asyncio
async def test_the_revoking_transfer_still_hands_the_object_over(lab_host):
    """The control's own control. An endpoint that revoked EVERYBODY would pass the negative
    test and would not be a working transfer — bob must be able to read what he now owns."""
    doc = "strict-3"
    assert get(lab_host, doc, "alice") == 200
    urllib.request.urlopen(urllib.request.Request(
        f"http://{lab_host}/transfer-strict?id={doc}&to=bob", data=b"{}", method="POST"),
        timeout=5)
    assert get(lab_host, doc, "alice") == 403, "the former owner kept access"
    assert get(lab_host, doc, "bob") == 200, "the transfer revoked everyone, including bob"


# ----------------------------------------------- it is a different question from AUTHZ-04


@pytest.mark.asyncio
async def test_this_asks_about_one_identity_over_time(lab_host):
    """AUTHZ-04 and the `ownership` evaluator compare identities at one moment. This case
    sends the SAME request twice as the SAME identity and reads the change between them —
    asserted on the rendered command, because that is where the shape lives."""
    result = await run_against("/transfer", lab_host, "lax-2")
    command = result.steps[0].command
    assert command.count("Authorization: Bearer alice") == 3, command
    assert "Bearer bob" not in command, "the case compared two identities, not two moments"


@pytest.mark.asyncio
async def test_the_finding_counts_the_reads(lab_host):
    result = await run_against("/transfer", lab_host, "lax-3")
    basis = next(f for f in result.findings if "Stale Access" in (f.vuln_type or "")).basis
    assert "appeared 2 times" in basis, basis
    assert "at most 1 should have succeeded" in basis
    assert "burst" not in basis and "parallel attempts" not in basis
