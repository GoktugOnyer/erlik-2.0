"""WSTG-INPV-05.2 against real database errors, and against text that only reads like one.

The case is driven through the real runner, so what is being tested is the
detector as it will run: payload, request, response, evaluator.

The benign side is the point. `juice_shop_bundle` is the exact text that made
the INPV-05 pattern fire eleven times during the 2026-09-09 baseline — a
challenge description inside Juice Shop's own JavaScript, served from a `.js`
file that is a discovered endpoint like any other. A HIGH-severity SQL
injection finding on that is worse than missing a real one.
"""
import shlex
import shutil
import subprocess
import threading
from http.server import HTTPServer

import pytest

from orchestrator.testcase.loader import find_by_id
from orchestrator.testcase.runner import run_test_case

from fixtures import sql_error_pages

pytestmark = pytest.mark.skipif(shutil.which("curl") is None, reason="needs a real curl")

PORT = 9093


@pytest.fixture(scope="module")
def pages():
    server = HTTPServer(("127.0.0.1", PORT), sql_error_pages.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://localhost:{PORT}"
    server.shutdown()


async def real_curl(command, **kwargs):
    result = subprocess.run(shlex.split(command), capture_output=True, text=True, timeout=20)
    return {"success": result.returncode == 0, "exit_code": result.returncode,
            "output": result.stdout, "error": result.stderr or None}


async def probe(route, base):
    return await run_test_case(
        find_by_id("WSTG-INPV-05.2"),
        {"url": f"{base}/{route}", "parameter": "id", "scope": {"allow_hosts": ["localhost"]}},
        executor=real_curl, allow_llm=False)


@pytest.mark.parametrize("engine", sorted(sql_error_pages.DATABASE_ERRORS))
async def test_a_real_database_error_is_detected(engine, pages):
    run = await probe(engine, pages)
    assert run.findings, f"{engine}: a real database error went unreported"
    assert "SQL Injection" in (run.findings[0].vuln_type or "")
    assert run.findings[0].severity == "high"


@pytest.mark.parametrize("page", sorted(sql_error_pages.BENIGN_PAGES))
async def test_a_page_that_merely_mentions_databases_is_not_a_finding(page, pages):
    run = await probe(page, pages)
    assert not run.findings, (
        f"{page}: false positive — a HIGH finding for a request that proved nothing")


async def test_it_stops_at_the_first_payload_that_answers(pages):
    """Three payloads chained on no_finding_yet, so a vulnerable parameter
    costs one request and a clean one costs three."""
    run = await probe("mysql_php", pages)
    assert len(run.steps) == 1 and run.steps[0].step == "single_quote"
    clean = await probe("sql_tutorial", pages)
    assert len(clean.steps) == 3


def test_the_pattern_carries_no_unbounded_wildcard():
    """An evaluator reads a whole response, so `Warning.*mysqli_` can join a
    warning in one place to a driver name in another and call the pair an
    error. Measured on the baseline corpus: that alternative in INPV-05 fired
    on exactly such a pairing."""
    for step in find_by_id("WSTG-INPV-05.2").steps:
        for evaluator in step.evaluators:
            assert ".*" not in (evaluator.pattern or ""), step.name


def test_the_case_runs_where_the_findings_are():
    """INPV-05 runs `bash -c` and sqlmap, so the assessment lane cannot execute
    it — which is why DVWA's SQL injection went unreported by anything looking
    for a database error."""
    from orchestrator.integrations.inventory import executable_test_cases
    runnable = executable_test_cases()
    assert "WSTG-INPV-05.2" in runnable
    assert "WSTG-INPV-05" not in runnable, "unchanged: it still needs a shell"
