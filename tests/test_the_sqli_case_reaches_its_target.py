"""WSTG-INPV-05 against DVWA — the case's own documented gate, executed.

INPV-05 is one of the nineteen catalogue cases nothing had ever run. Its header records a
defect that is worth a test rather than a paragraph:

    "a 302 to /login.php means 'you are not authenticated', and it matched the reachability
     gate below — so every later step probed an empty redirect body, found nothing, and the
     case reported CLEAN on a page it never reached."

That is the whole shape this project keeps removing: a confident verdict from a path that did
nothing. The gate was added by hand; nothing held it.

MEASURED against the running lab, and note what is NOT here:

    no session                302 -> ../../login.php, empty body    must NOT report clean
    session + security=low    200, 583 bytes, SQL error present     error-based FINDING
    session + security=impossible  200, 389 bytes, PHP warning
                              "Undefined array key user_token"      NOT a negative control

THE THIRD ROW IS THE INTERESTING ONE AND IT IS DELIBERATELY UNUSED. At `impossible` DVWA
demands a CSRF token the case does not send, so the probe receives a PHP warning rather than a
hardened query — it tested nothing. `no finding` there would be a vacuous pass, and
`COVERAGE_STATES` already names this exact trap: "a probe missing its CSRF token answers HTTP
200 with 389 bytes of PHP warnings, so the emptiness-only detector does not fire and nothing
was tested all the same."

A real negative control needs an endpoint that answers normally and is not injectable, which
sends the case on to its `sqlmap_scan` step. That is minutes of scanning per run, so it is
named here as missing rather than faked with the `impossible` row.

NON-GET REQUESTS: one POST to DVWA /login.php for a session. Nothing else.
"""
import asyncio
import os

import pytest

from orchestrator.testcase.loader import load_catalog

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(os.environ.get("ERLIK_DOCKER_TESTS") != "1",
                       reason="set ERLIK_DOCKER_TESTS=1 for the local DVWA lab"),
]

DVWA = "http://localhost:8081"
SQLI = f"{DVWA}/vulnerabilities/sqli/"
SIGNATURE = "You have an error in your SQL syntax"


async def _local(command, *args, **kwargs):
    process = await asyncio.create_subprocess_shell(
        command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    stdout, _ = await process.communicate()
    return {"success": process.returncode == 0, "output": stdout.decode(errors="replace"),
            "duration_ms": 5, "error": None, "exit_code": process.returncode}


async def dvwa_session():
    """A DVWA session. The POST is the only non-GET this file makes.

    A FRESH CLIENT, and the cookies passed per request deliberately once. httpx warns that
    per-request cookies are ambiguous about persistence, and it is right: a first draft of
    this measurement reused one client across an unauthenticated and an authenticated
    request, the first request's jar leaked into the second, and the SQL error signature
    read as absent at security=low. The documented behaviour was correct and the
    measurement was not.
    """
    import httpx

    from orchestrator.login import hidden_fields

    async with httpx.AsyncClient(follow_redirects=False, timeout=10) as client:
        page = await client.get(f"{DVWA}/login.php")
        jar = dict(page.cookies)
        token = hidden_fields(page.text).get("user_token", "")
        done = await client.post(f"{DVWA}/login.php", cookies=jar,
                                 data={"username": "admin", "password": "password",
                                       "user_token": token, "Login": "Login"})
        session = done.cookies.get("PHPSESSID") or jar.get("PHPSESSID")
    assert session, "could not obtain a DVWA session"
    return session


async def run_sqli(cookie):
    from orchestrator.testcase.runner import run_test_case

    target = {"url": SQLI, "parameter": "id", "submit": "Submit=Submit",
              "cookie": cookie,
              "scope": {"allow_hosts": ["localhost"], "allow_ports": [8081]}}
    return await run_test_case(load_catalog()["WSTG-INPV-05"], target,
                               executor=_local, allow_llm=False)


def steps_run(result):
    return [step.step for step in result.steps]


# --------------------------------------------------- the gate the header was written for


@pytest.mark.asyncio
async def test_an_unauthenticated_run_does_not_report_clean():
    """The documented defect. Without a session DVWA answers 302 to ../../login.php with an
    empty body; every later probe then finds nothing, and "no finding" is indistinguishable
    from a clean application. The gate must STOP the case at the baseline."""
    result = await run_sqli("")
    assert not result.findings, (
        f"an unauthenticated run reported {[f.vuln_type for f in result.findings]}")
    assert result.stopped_early, (
        f"the case ran on past a login redirect: steps={steps_run(result)}. That is the "
        f"defect this gate exists for — every later step probes an empty body and the "
        f"case reports CLEAN on a page it never reached")
    assert steps_run(result) == ["baseline"], steps_run(result)


@pytest.mark.asyncio
async def test_the_baseline_saw_the_redirect_rather_than_nothing():
    """The guard on the guard. `stopped_early` with an empty baseline would also satisfy the
    test above, and would mean the case stopped because it reached nothing at all."""
    result = await run_sqli("")
    baseline = result.steps[0].output or ""
    assert baseline.strip(), "the baseline received nothing; this proves neither gate nor bug"
    assert baseline.startswith("30"), baseline[:80]
    assert "login" in baseline.lower(), baseline[:80]


# ------------------------------------------------------------------ the positive control


@pytest.mark.asyncio
async def test_an_authenticated_run_finds_the_injection():
    """security=low, with a session and the Submit token DVWA requires before it runs the
    query at all. The error-based probe is what fires; `sqlmap_scan` is `when:
    no_finding_yet` and therefore never runs, which is why this test costs a second."""
    session = await dvwa_session()
    result = await run_sqli(f"PHPSESSID={session}; security=low")
    assert result.findings, (
        f"no finding at security=low. steps={steps_run(result)}, "
        f"baseline={(result.steps[0].output or '')[:60]!r}")
    assert any("SQL Injection" in (f.vuln_type or "") for f in result.findings)
    assert "sqlmap_scan" not in steps_run(result), (
        "the error probe should have satisfied `no_finding_yet` before sqlmap was needed")


@pytest.mark.asyncio
async def test_the_finding_rests_on_the_database_saying_so():
    """Not on a status code or a length. The signature is the application's own error text,
    which is what separates this from `the page changed when I added a quote`."""
    session = await dvwa_session()
    result = await run_sqli(f"PHPSESSID={session}; security=low")
    probe = next(s for s in result.steps if s.step == "error_based_probe")
    assert SIGNATURE in (probe.output or ""), (probe.output or "")[:200]


@pytest.mark.asyncio
async def test_the_submit_token_is_what_makes_the_query_run():
    """The header's other claim: "DVWA runs its query only when isset($_GET['Submit']), so a
    request without that token renders the page and touches the database not at all — which
    reads as CLEAN." Asserted by withholding it."""
    from orchestrator.testcase.runner import run_test_case

    session = await dvwa_session()
    target = {"url": SQLI, "parameter": "id", "cookie": f"PHPSESSID={session}; security=low",
              "scope": {"allow_hosts": ["localhost"], "allow_ports": [8081]}}
    result = await run_test_case(load_catalog()["WSTG-INPV-05"], target,
                                 executor=_local, allow_llm=False)
    probe = next((s for s in result.steps if s.step == "error_based_probe"), None)
    if probe is not None:
        assert SIGNATURE not in (probe.output or ""), (
            "the query ran without Submit; the header's reason for carrying it is stale")
