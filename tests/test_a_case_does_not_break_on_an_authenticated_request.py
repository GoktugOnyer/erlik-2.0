"""A case that only works on targets needing no authentication finds nothing worth finding.

MEASURED, on a lab endpoint with NO usage limit at all — the most blatant violation the
business-logic cases exist to catch:

    template                                        BUSL-04            BUSL-05
    curl -s -X POST -H 'Authorization: Bearer tok'  0 findings, 0 hits  0 findings, 0 hits
    curl -s -X POST http://host/apply               1 finding,  4 hits  1 finding,  2 hits

The difference is a single quote. Both cases wrapped the operator's template in
`bash -c '...'`, and `tool_executor._sync_docker_exec` ALREADY runs the command through
`bash -c` — so the wrapper was a second shell whose quotes closed the operator's. The
rendered command became:

    bash -c 'curl -s -H 'Authorization: Bearer alice' 'http://...''

which the shell reads as three words, none of them a URL. curl errors, the success marker
never appears, and the case reports CLEAN.

Every realistic business-logic target needs authentication. A coupon, a checkout, a transfer
— all of them are behind a session, and a session is passed with a quoted header. So these
cases worked on exactly the targets where the flaws do not matter.

THE TEMPLATE IS NO LONGER INSIDE THE WRAPPER. Escaping would have needed the renderer to
know which shell it was quoting for, so two cases drop the wrapper entirely -- BUSL-05 and
AUTHZ-02 write no shell of their own and need none.

BUSL-04 CANNOT drop it, and that is the whole reason this file states its rule the way it
does now. Its step is a shell program -- a burst, a count, a three-way verdict -- and
`_command_segments` reads `case` and `for` as program names, so an unwrapped version is
refused by the admission guard before any request goes out (see test_shell_steps.py). It
keeps `bash -c '...'` and passes the operator's request POSITIONALLY, after the quoted
script: the outer shell parses it once, where the operator wrote it, and the inner shell
runs `("$@")` without re-parsing anything.

So the rule is not "no wrapper". It is that the operator's request is never INTERPOLATED
into a string the case quotes, which is what the guard below checks and what the two
behavioural tests at the bottom measure.
"""
import asyncio
import pathlib
import socket
import subprocess
import sys
import time

import pytest

from orchestrator.testcase.loader import load_catalog

FIXTURE = pathlib.Path(__file__).resolve().parents[0] / "fixtures" / "integration_target.py"

# Every case that renders an operator-supplied request into a shell command.
TEMPLATED_CASES = ("WSTG-BUSL-04", "WSTG-BUSL-05", "WSTG-AUTHZ-02")


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
    process = await asyncio.create_subprocess_shell(
        command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    stdout, _ = await process.communicate()
    return {"success": process.returncode == 0, "output": stdout.decode(errors="replace"),
            "duration_ms": 5, "error": None, "exit_code": process.returncode}


# ---------------------------------- no case interpolates the template into its own quoting


# The fields that hold a WHOLE operator-written command rather than a value. These are
# the ones whose quoting is the operator's and not the case's.
TEMPLATE_FIELDS = ("request_template", "read_request", "transfer_request", "final_request")


def _single_quoted_spans(command: str):
    """Every [start, end) region of `command` that a single-quoted string covers."""
    spans, opened = [], None
    for i, ch in enumerate(command):
        if ch != "'":
            continue
        if opened is None:
            opened = i
        else:
            spans.append((opened, i + 1))
            opened = None
    return spans


@pytest.mark.parametrize("case_id", TEMPLATED_CASES)
def test_no_case_interpolates_the_operators_template_into_its_own_quoting(case_id):
    """The structural guard, stated as the defect rather than as one way of avoiding it.

    `_sync_docker_exec` runs `bash -c command`, so a case that writes the operator's
    request INSIDE a `bash -c '...'` of its own has put a string it does not control
    inside quotes it does -- and the operator's own quotes end them early. Measured:
    `-H 'Authorization: Bearer tok'` turned the whole command into three words, none a
    URL, and the case reported clean.

    Passing the request positionally, after the quoted script, is not that: the outer
    shell parses it once and the inner one receives argv. So this checks WHERE the
    placeholder sits, not whether a wrapper exists.
    """
    case = load_catalog()[case_id]
    for step in case.steps:
        spans = _single_quoted_spans(step.command)
        for field in TEMPLATE_FIELDS:
            token = "{{" + field + "}}"
            start = step.command.find(token)
            while start != -1:
                inside = next(((a, b) for a, b in spans if a < start < b), None)
                assert inside is None, (
                    f"{case_id} step {step.name!r} interpolates {token} inside its own "
                    f"quoted string {step.command[inside[0]:inside[1]][:80]!r} — the "
                    f"operator's quotes will close it early and the request is never made")
                start = step.command.find(token, start + 1)


def test_the_executor_is_what_supplies_the_shell():
    """Asserted so the fix above cannot be undone by the other end. If the executor stopped
    running commands through a shell, every case unwrapped here would break — the two facts
    belong together and nothing else pairs them."""
    import inspect

    from orchestrator import tool_executor

    source = inspect.getsource(tool_executor._sync_docker_exec)
    assert '"bash", "-c", command' in source, (
        "the executor no longer supplies a shell; the unwrapped cases now need one")


# --------------------------------------------- and an authenticated template still works


@pytest.mark.asyncio
async def test_a_quoted_header_finds_the_same_flaw_as_an_unquoted_request(lab_host):
    """The behavioural guard, on the endpoint with no limit at all. Before the fix the
    quoted form found nothing here; the unquoted form found it. They must now agree."""
    from orchestrator.testcase.runner import run_test_case

    catalog = load_catalog()
    for case_id, expected in (("WSTG-BUSL-04", 4), ("WSTG-BUSL-05", 2)):
        results = {}
        for label, template in (
            ("quoted", f"curl -s -X POST -H 'Authorization: Bearer tok' "
                       f"'http://{lab_host}/apply'"),
            ("plain", f"curl -s -X POST http://{lab_host}/apply"),
        ):
            target = {"url": f"http://{lab_host}/apply", "request_template": template,
                      "success_marker": "APPLIED", "parallel_n": 4,
                      "scope": {"allow_hosts": ["127.0.0.1"],
                                "allow_ports": [int(lab_host.split(":")[1])]}}
            result = await run_test_case(catalog[case_id], target,
                                         executor=_local, allow_llm=False)
            results[label] = ((result.steps[0].output or "").count("APPLIED"),
                              len(result.findings))
        assert results["quoted"] == results["plain"] == (expected, 1), (
            f"{case_id}: quoted={results['quoted']} plain={results['plain']}")


@pytest.mark.asyncio
async def test_a_quoted_header_reaches_the_target_at_all(lab_host):
    """The narrowest statement of the defect: the request was never made. Asserted on the
    shell's own complaint rather than on a finding count, because a finding count of zero has
    many innocent explanations and "curl: no URL specified" has one."""
    from orchestrator.testcase.runner import run_test_case

    target = {"url": f"http://{lab_host}/apply",
              "request_template": f"curl -s -X POST -H 'Authorization: Bearer tok' "
                                  f"'http://{lab_host}/apply'",
              "success_marker": "APPLIED", "parallel_n": 2,
              "scope": {"allow_hosts": ["127.0.0.1"],
                        "allow_ports": [int(lab_host.split(":")[1])]}}
    result = await run_test_case(load_catalog()["WSTG-BUSL-04"], target,
                                 executor=_local, allow_llm=False)
    output = result.steps[0].output or ""
    assert "no URL specified" not in output, output[:200]
    assert "command not found" not in output, output[:200]
    assert "APPLIED" in output
