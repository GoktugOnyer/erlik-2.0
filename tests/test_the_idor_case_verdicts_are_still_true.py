"""AUTHZ-04's documented verdict tables, executed instead of read.

The case header carries two measured tables — one for DVWA at four security levels, one for
Juice Shop — and no test held either. The header says why that matters, about its own earlier
row:

    "a verdict table that was true when written, and was not re-measured after the behaviour
     it describes was changed one commit later"

It was corrected by hand once. Nothing would have caught it a second time.

MEASURED HERE, against the running lab, and matching the header exactly:

    DVWA security=low         arms 273/273/273   no finding
    DVWA security=medium      arms 273/273/273   no finding
    DVWA security=high        arms 273/41/41     no finding
    DVWA security=impossible  arms 273/41/41     no finding
    Juice Shop /api/Users     admin 200, jim 200, anonymous 401   FINDING

THE POSITIVE CONTROL IS NOT DECORATION. Four negative results are exactly what a case that
has stopped working produces, and this case spent a long time being unable to conclude
anything — the header lists three separate reasons it could never have fired. Without Juice
Shop firing, this file would assert that a broken case is a correct one.

THE ARM SIZES ARE ASSERTED, not just the verdicts. "No finding" on DVWA is only the right
answer because of WHY: at low and medium every arm including the anonymous one receives the
273-byte table, which is missing authentication rather than broken authorization; at high and
impossible the low-privilege arm drops to the 41-byte refusal. A case that fetched nothing at
all would also report no finding.

NON-GET REQUESTS: this test POSTs to DVWA's /login.php and Juice Shop's /rest/user/login to
obtain sessions. Nothing else is non-GET, and nothing here writes to either application.
"""
import asyncio
import os

import pytest

from tests.lab import requires_dvwa

from orchestrator.testcase.loader import load_catalog

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(os.environ.get("ERLIK_DOCKER_TESTS") != "1",
                       reason="set ERLIK_DOCKER_TESTS=1 for the local DVWA/Juice Shop lab"),
    # The lab is not started by this file, so its absence is a skip and not a
    # failure -- twelve tests went red in CI saying 'connection refused', which
    # is a fact about the runner rather than about the case under test.
    requires_dvwa,
]

DVWA = "http://localhost:8081"
JUICE = "http://localhost:3000"
USER_DATA = f"{DVWA}/vulnerabilities/authbypass/get_user_data.php"


async def _local(command, *args, **kwargs):
    process = await asyncio.create_subprocess_shell(
        command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    stdout, _ = await process.communicate()
    return {"success": process.returncode == 0, "output": stdout.decode(errors="replace"),
            "duration_ms": 5, "error": None, "exit_code": process.returncode}


async def dvwa_session(user, password):
    """A DVWA session. The POST is the only non-GET this file makes against DVWA."""
    import httpx

    from orchestrator.login import hidden_fields

    async with httpx.AsyncClient(follow_redirects=False, timeout=10) as client:
        page = await client.get(f"{DVWA}/login.php")
        jar = dict(page.cookies)
        token = hidden_fields(page.text).get("user_token", "")
        done = await client.post(f"{DVWA}/login.php", cookies=jar,
                                 data={"username": user, "password": password,
                                       "user_token": token, "Login": "Login"})
        session = done.cookies.get("PHPSESSID") or jar.get("PHPSESSID")
    assert session, f"could not obtain a DVWA session for {user}"
    return session


async def juice_token(email, password):
    import httpx

    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.post(f"{JUICE}/rest/user/login",
                                     json={"email": email, "password": password})
    assert response.status_code == 200, (email, response.status_code)
    token = response.json().get("authentication", {}).get("token")
    assert token, email
    return token


async def run_case(target):
    return await run_test_case_for(load_catalog()["WSTG-AUTHZ-04"], target)


async def run_test_case_for(case, target):
    from orchestrator.testcase.runner import run_test_case

    return await run_test_case(case, target, executor=_local, allow_llm=False)


def body_sizes(result):
    """Each arm's response body length, in step order: high, anonymous, low."""
    return [len((step.output or "").split("\r\n\r\n", 1)[-1]) for step in result.steps]


def arms(result):
    """What each arm actually got, for a failure message that explains itself.

    ADDED AFTER A FAILURE THAT COULD NOT EXPLAIN ITSELF. This file failed once inside a full
    gated run — `test_the_finding_names_both_arms_and_the_anonymous_exclusion` — and passed
    in isolation, in combination with the other Juice Shop suites, and under 25 rapid
    logins. The cause is not established. What IS established is that the test said nothing
    useful when it went: the assertion reached `findings[0]` on an empty list, so the report
    was an IndexError rather than which arm misbehaved.

    A finding that does not appear has three ordinary explanations here — an arm that never
    answered, an arm that answered without the marker, an anonymous arm that was served the
    object — and they are distinguishable from the captures. So the next occurrence says
    which.
    """
    detail = []
    for step in result.steps:
        capture = step.output or ""
        status = capture.split("\r\n", 1)[0][:40] if capture else "(no output)"
        body = capture.split("\r\n\r\n", 1)[-1]
        detail.append(f"{step.step}: {status!r} {len(body)}b")
    return " | ".join(detail)


def unanswered(result):
    """Arms that received ZERO bytes, which is the lab not answering rather than a verdict."""
    return [step.step for step in result.steps if not (step.output or "").strip()]


def the_finding(result, marker):
    """The single finding, or a failure that says why there is not one."""
    assert result.findings, (
        f"no finding. arms -> {arms(result)}. marker {marker!r} present per arm: "
        + ", ".join(f"{s.step}={marker in (s.output or '')}" for s in result.steps))
    assert len(result.findings) == 1, [f.model_dump() for f in result.findings]
    return result.findings[0]


async def run_until_the_lab_answers(target, attempts=3):
    """Run the case, retrying while an ARM RECEIVES NOTHING.

    MEASURED: 4 failures in 12 consecutive runs, each one an arm returning zero bytes in
    about a millisecond — `fetch_as_high_priv` three times, `fetch_as_low_priv` once. Juice
    Shop intermittently refuses the connection when driven hard, and the full gated suite
    drives it hard.

    An arm that received nothing establishes NOTHING, in either direction. Failing on it
    reports a product defect that is not there; passing on it would be worse. This is the
    rule the catalogue already states in INPV-05's own gate — "a case that cannot reach its
    target must say so, not return a verdict" — applied to the test rather than the case.

    So: retry, and if the lab still will not answer, SKIP with the arm named. A real
    regression, where every arm answers and the verdict is wrong, is untouched by this.
    """
    for attempt in range(attempts):
        result = await run_case(target)
        if not unanswered(result):
            return result
        if attempt + 1 < attempts:
            await asyncio.sleep(0.5)
    pytest.skip(f"the lab did not answer after {attempts} attempts: "
                f"{unanswered(result)} received zero bytes — arms: {arms(result)}")


# ------------------------------------------------ the positive control, first and loudest


@pytest.mark.asyncio
async def test_the_case_still_finds_the_violation_it_was_built_for():
    """Juice Shop `GET /api/Users`: admin 200, jim 200, anonymous 401 — `low == high` and
    `low != anon`, which is the finding. If this stops firing, every negative result below
    means nothing."""
    admin = await juice_token("admin@juice-sh.op", "admin123")
    jim = await juice_token("jim@juice-sh.op", "ncc-1701")
    result = await run_until_the_lab_answers({
        "url_template": f"{JUICE}/api/Users",
        "private_object_marker": "admin@juice-sh.op",
        "high_priv_token": admin, "low_priv_token": jim,
        "scope": {"allow_hosts": ["localhost"], "allow_ports": [3000]}})
    finding = the_finding(result, "admin@juice-sh.op")
    assert "Broken Access Control" in finding.vuln_type
    assert finding.confidence == "confirmed", (
        "this is the one evaluator graded `confirmed`; the grade is the claim")


@pytest.mark.asyncio
async def test_the_finding_names_both_arms_and_the_anonymous_exclusion():
    """A differential claim needs both sides. The evidence — not the one-line basis — is
    where the comparison lives, and a reader deciding whether to believe a `confirmed`
    finding is reading it."""
    admin = await juice_token("admin@juice-sh.op", "admin123")
    jim = await juice_token("jim@juice-sh.op", "ncc-1701")
    result = await run_until_the_lab_answers({
        "url_template": f"{JUICE}/api/Users",
        "private_object_marker": "admin@juice-sh.op",
        "high_priv_token": admin, "low_priv_token": jim,
        "scope": {"allow_hosts": ["localhost"], "allow_ports": [3000]}})
    evidence = the_finding(result, "admin@juice-sh.op").evidence
    assert "the private object is identified by" in evidence
    assert "as the privileged identity" in evidence
    assert "as the low-privilege identity" in evidence
    assert "anonymous did NOT receive it" in evidence


# --------------------------------------- the DVWA table, all four levels, sizes and all


@pytest.mark.asyncio
@pytest.mark.parametrize("level,expected_sizes", [
    ("low", [273, 273, 273]),
    ("medium", [273, 273, 273]),
    ("high", [273, 41, 41]),
    ("impossible", [273, 41, 41]),
])
async def test_dvwa_reports_nothing_and_for_the_documented_reason(level, expected_sizes):
    """The header's table, executed. The SIZES are the point: at low and medium the
    anonymous arm receives the same 273-byte table, which is missing authentication rather
    than broken authorization, and the anonymous clause is what declines to call it an IDOR.
    Asserting only "no finding" would pass against a case that fetched nothing."""
    admin = await dvwa_session("admin", "password")
    gordon = await dvwa_session("gordonb", "abc123")
    result = await run_until_the_lab_answers({
        "url_template": USER_DATA, "private_object_marker": "Gordon",
        "high_priv_cookie": f"PHPSESSID={admin}",
        "low_priv_cookie": f"PHPSESSID={gordon}",
        "config_cookie": f"security={level}",
        "scope": {"allow_hosts": ["localhost"], "allow_ports": [8081]}})
    assert body_sizes(result) == expected_sizes, (
        f"security={level}: arms {body_sizes(result)}, header documents {expected_sizes}")
    assert not result.findings, (
        f"security={level} now reports {[f.vuln_type for f in result.findings]}; the header "
        f"documents no finding, and says why: the endpoint serves the table to anybody who "
        f"sets a cookie, which is missing authentication rather than broken authorization")


@pytest.mark.asyncio
async def test_the_privileged_arm_always_got_the_object():
    """The guard on the table above. Every row expects 273 bytes for the privileged arm; if
    that ever became 41, all four rows would still say "no finding" and would be measuring a
    broken session rather than a working control."""
    admin = await dvwa_session("admin", "password")
    gordon = await dvwa_session("gordonb", "abc123")
    for level in ("low", "medium", "high", "impossible"):
        result = await run_until_the_lab_answers({
            "url_template": USER_DATA, "private_object_marker": "Gordon",
            "high_priv_cookie": f"PHPSESSID={admin}",
            "low_priv_cookie": f"PHPSESSID={gordon}",
            "config_cookie": f"security={level}",
            "scope": {"allow_hosts": ["localhost"], "allow_ports": [8081]}})
        assert body_sizes(result)[0] == 273, (
            f"security={level}: the privileged arm got {body_sizes(result)[0]} bytes, so the "
            f"admin session is not working and this row proves nothing")
