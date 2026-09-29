import json
from pathlib import Path
from unittest.mock import AsyncMock
import pytest
from pydantic import ValidationError
from orchestrator.integrations.contracts import AssessmentConfig, StageResult, Endpoint
from orchestrator.integrations.adapters import Context, ZapAdapter
from orchestrator.integrations.deterministic import CatalogueAdapter, curl_request
from orchestrator.integrations.inventory import seeds
from orchestrator.integrations.runtime import JobOutput
from orchestrator.testcase.scope import ScopeViolation
from test_integrations import database


def config(**kw):
    return AssessmentConfig(scope={"allow_hosts": ["app.test"], "allow_ports": [443]}, **kw)


def _clnt07_origin() -> str:
    """The attacker origin WSTG-CLNT-07's step sends, read off the case itself."""
    import re

    from orchestrator.testcase.loader import find_by_id
    command = find_by_id("WSTG-CLNT-07").steps[0].command
    found = re.search(r'Origin:\s*([^"\'\s]+)', command)
    assert found, f"WSTG-CLNT-07 no longer sends an Origin header: {command!r}"
    return found.group(1)


CLNT07_ORIGIN = _clnt07_origin()


@pytest.mark.parametrize("command", [
    'curl https://app.test https://outside.test',
    'curl --noproxy "*" https://app.test',
    'curl -s https://app.test;cat /input/ca.pem',
    'curl -X POST --data @/input/profile.json https://app.test',
    'curl -H "Host: outside.test" https://app.test',
    'sh -c "curl https://app.test"',
])
def test_catalogue_execution_rejects_unsupported_paths(command):
    with pytest.raises(ScopeViolation):
        curl_request(command)


def test_origin_header_is_data_not_a_scan_destination():
    _, url, method = curl_request('curl -s -i -H "Origin: https://evil.oast.test" "https://app.test"')
    assert url == "https://app.test" and method == "GET"


def test_active_catalogue_checks_require_selection():
    with pytest.raises(ValidationError):
        config(test_cases=["WSTG-CLNT-07"])
    with pytest.raises(ValidationError):
        config(active=True, test_cases=["WSTG-INPV-19"])
    assert config().test_cases == []  # Existing saved configurations stay unchanged.


@pytest.mark.asyncio
async def test_inventory_is_filtered_deduplicated_and_identity_specific(database):
    cfg = config()
    ctx = Context("s", "zap", "https://app.test", cfg, "reader")
    await database.persist_result("s", "discovery", StageResult(endpoints=[
        Endpoint(url="https://app.test/hidden#fragment", method="GET", source="katana", identity="reader"),
        Endpoint(url="https://app.test/hidden", method="GET", source="playwright", identity="reader"),
        Endpoint(url="https://app.test/admin", method="GET", source="katana", identity="admin"),
        Endpoint(url="https://outside.test", method="GET", source="katana", identity="reader"),
        Endpoint(url="https://app.test/logout", method="GET", source="katana", identity="reader"),
        Endpoint(url="https://app.test/create", method="POST", source="katana", identity="reader"),
    ]))
    found = await seeds(ctx, cfg.model_dump())
    assert found == ["https://app.test", "https://app.test/hidden"]
    plan = ZapAdapter().plan(ctx, inventory=found)
    assert plan["jobs"][0] == {"type": "requestor", "requests": [{"url": url, "method": "GET"} for url in found]}
    assert not any(job["type"] == "activeScan" for job in plan["jobs"])


@pytest.mark.asyncio
async def test_catalogue_uses_sandbox_and_preserves_skipped_steps(database, tmp_path):
    """WSTG-SESS-02 and WSTG-CONF-06 USED TO BE HERE and are no longer lane-runnable.

    Both had a step rewritten into a `bash -c '...'` shell program, which
    `curl_request` refuses, and the rule is all steps or none -- see
    test_curl_dialect.TestWhatTheLaneCannotRunIsDeclared, which pins the three cases
    that left and why. CONF-06 mattered twice over: its `put_probe` was the only
    mutating step in any lane-runnable case, so the skip this test used to observe
    was a refused PUT and there is no longer a refused write to observe anywhere.

    The skip below is WSTG-CLNT-04's `client_side_sink_review`, whose only evaluator
    is an llm and which this lane runs with allow_llm=False. Same requirement --
    a step that did not run is recorded rather than dropped -- reached through the
    only kind of skip the catalogue can still produce here.
    """
    cfg = config(active=True, test_cases=["WSTG-CLNT-07", "WSTG-CLNT-04"])
    # A discovered parameter, so CLNT-04's steps are eligible and the one skip the
    # catalogue can still produce here actually happens. Without it CLNT-04 is
    # recorded `test_case_not_run` with no steps at all, which is a different
    # property (and the test below covers it).
    await database.execute(
        "INSERT OR REPLACE INTO integration_endpoints"
        "(session_id,url,method,identity_id,sources,parameters) VALUES(?,?,?,?,?,?)",
        ("s", "https://app.test/r", "GET", "anonymous",
         json.dumps(["katana"]), json.dumps(["next"])))
    class Sandbox:
        policy = cfg.model_dump()
        directory = tmp_path
        output = tmp_path / "output"
        images = {}
        proxy_url = "http://proxy:8080"
        async def run(self, argv):
            assert argv[0] == "curl" and "--proxy" in argv and "-X" not in argv or "OPTIONS" in argv
            # THE ORIGIN WSTG-CLNT-07 ACTUALLY SENDS. This said `evil.oast.test`,
            # which the case stopped sending when its payload host moved to the only
            # spelling `_scope_allows` permits -- and the evaluator had the same
            # stale constant, so the mock and the evaluator agreed with each other
            # and neither agreed with the case. Read from the catalogue, so a third
            # copy cannot drift: what is under test here is the adapter, not which
            # hostname the case picked.
            return JobOutput(0, "HTTP/1.1 200 OK\r\nSet-Cookie: session=canary\r\n"
                             f"Access-Control-Allow-Origin: {CLNT07_ORIGIN}\r\n"
                             "Access-Control-Allow-Credentials: true\r\n\r\nOK", "")
    sandbox = Sandbox()
    sandbox.output.mkdir()
    sandbox.run = AsyncMock(side_effect=sandbox.run)
    result = await CatalogueAdapter().run(Context("s", "tests", "https://app.test", cfg), sandbox)
    # Both are CLNT-07, one per in-scope URL -- the mocked response reflects an
    # Origin and allows credentials. CLNT-04 finds nothing and should not: the
    # response carries no Location header, so there is no redirect to report.
    assert len(result.findings) == 2
    assert all("CORS" in f.title for f in result.findings), [f.title for f in result.findings]
    # CLNT-07's one step on each of the two URLs, plus CLNT-04's six on the single
    # (url, parameter) pair, less its llm-only step which is skipped. It was 3 when
    # SESS-02 and CONF-06 were still selectable here.
    assert sandbox.run.await_count == 7
    assert all(f.confidence == "suspected" and f.evidence_ids for f in result.findings)
    assert any(step["skipped"] for row in result.observations for step in row["steps"])
    assert result.status == "completed"
