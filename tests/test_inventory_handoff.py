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
async def test_catalogue_uses_sandbox_and_preserves_skipped_mutations(database, tmp_path):
    cfg = config(active=True, test_cases=["WSTG-SESS-02", "WSTG-CLNT-07", "WSTG-CONF-06"])
    class Sandbox:
        policy = cfg.model_dump()
        directory = tmp_path
        output = tmp_path / "output"
        images = {}
        proxy_url = "http://proxy:8080"
        async def run(self, argv):
            assert argv[0] == "curl" and "--proxy" in argv and "-X" not in argv or "OPTIONS" in argv
            return JobOutput(0, "HTTP/1.1 200 OK\r\nSet-Cookie: session=canary\r\nAccess-Control-Allow-Origin: https://evil.oast.test\r\nAccess-Control-Allow-Credentials: true\r\n\r\nOK", "")
    sandbox = Sandbox()
    sandbox.output.mkdir()
    sandbox.run = AsyncMock(side_effect=sandbox.run)
    result = await CatalogueAdapter().run(Context("s", "tests", "https://app.test", cfg), sandbox)
    assert len(result.findings) == 2
    assert sandbox.run.await_count == 3
    assert all(f.confidence == "suspected" and f.evidence_ids for f in result.findings)
    assert any(step["skipped"] for row in result.observations for step in row["steps"])
    assert result.status == "completed"
