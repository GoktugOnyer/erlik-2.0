"""WSTG-CLNT-04's payloads, against validators written independently of them.

A payload proved only against the case's own regex proves nothing about the
technique. tests/fixtures/open_redirect_validators.py implements one naive
check per route — startswith, contains, scheme-block, leading-slash, and a
hardcoded remote allowlist — and this drives the real case through the real
runner against each.

The last route is here to STAY undefeated: a scanner cannot guess a hardcoded
remote allowlist, and a battery that appeared to beat it would mean the fixture
was wrong rather than the payloads good.
"""
import shlex
import shutil
import subprocess
import threading
from http.server import HTTPServer

import pytest

from orchestrator.testcase.loader import find_by_id
from orchestrator.testcase.runner import run_test_case
from orchestrator.testcase.scope import ScopeViolation, check_command, from_target
from orchestrator.testcase.runner import _render

from fixtures import open_redirect_validators as validators

pytestmark = pytest.mark.skipif(shutil.which("curl") is None, reason="needs a real curl")

PORT = 9094


@pytest.fixture(scope="module")
def naive_app():
    validators.OWN_ORIGIN = f"http://localhost:{PORT}"
    server = HTTPServer(("127.0.0.1", PORT), validators.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://localhost:{PORT}"
    server.shutdown()


async def real_curl(command, **kwargs):
    result = subprocess.run(shlex.split(command), capture_output=True, text=True, timeout=20)
    return {"success": result.returncode == 0, "exit_code": result.returncode,
            "output": result.stdout, "error": result.stderr or None}


async def probe(route, base):
    return await run_test_case(
        find_by_id("WSTG-CLNT-04"),
        {"url": f"{base}/{route}", "parameter": "to", "scope": {"allow_hosts": ["localhost"]}},
        executor=real_curl, allow_llm=False)


@pytest.mark.parametrize("route,step", [
    ("scheme", "declared_parameter_probe"),
    ("contains", "allowlisted_string_in_query"),
])
async def test_the_payloads_defeat_the_validator_classes_they_target(route, step, naive_app):
    run = await probe(route, naive_app)
    assert run.findings, f"no finding against a {route} validator"
    assert run.findings[0].step == step


@pytest.mark.parametrize("route", ["startswith", "leadingslash"])
async def test_two_classes_are_documented_as_out_of_reach(route, naive_app):
    """Reaching these needs a payload beginning with a scheme'd URL or a
    backslash, and check_command refuses any step naming an out-of-scope host
    in a shape it recognises. The guard is right — it cannot tell a payload
    from a destination — so this is a scope-model decision, not a payload one.
    If someone widens it, this test should start failing and be updated."""
    run = await probe(route, naive_app)
    assert not run.findings


async def test_a_hardcoded_remote_allowlist_stays_undefeated(naive_app):
    """Juice Shop's shape. Measured against the real application: only its own
    `https://github.com/juice-shop/juice-shop` entry gets a 302, and neither
    the app's origin nor any off-site link it publishes is on the list."""
    run = await probe("allowlist", naive_app)
    assert not run.findings


def test_every_step_passes_the_scope_guard():
    """The two payloads that would reach `startswith` name an out-of-scope host
    in a shape check_command recognises, and were dropped for that reason. If a
    step ever regresses to that shape it fails here rather than in the field."""
    scope = from_target({"url": "http://app.test/r", "scope": {"allow_hosts": ["app.test"]}})
    derived = {"origin": "http://app.test:80", "origin_host": "app.test"}
    for step in find_by_id("WSTG-CLNT-04").steps:
        command = _render(step.command, {**derived, "url": "http://app.test/r", "parameter": "to"})
        check_command(command, scope, primary_url="http://app.test/r")


def test_the_runner_derives_the_origin_for_every_caller():
    """`origin` and `origin_host` are derived from the endpoint rather than
    supplied, so the case runs from the sweep and Test Lab too — not only from
    the assessment lane that happens to know about them."""
    import inspect
    from orchestrator.testcase import runner
    source = inspect.getsource(runner.run_test_case)
    assert "_origin_fields(endpoint_of(target))" in source
    assert set(runner._origin_fields("https://app.test:8443/x")) == {"origin", "origin_host"}
    assert runner._origin_fields("https://app.test:8443/x")["origin"] == "https://app.test:8443"
