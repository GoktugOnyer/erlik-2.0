import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock
import pytest
from pydantic import ValidationError
from orchestrator.integrations.contracts import AssessmentConfig, Identity, StageResult, fingerprint
from orchestrator.integrations.egress_policy import EgressPolicy
from orchestrator.integrations.security import SecretStore, redact, secret_values
from orchestrator.integrations.adapters import Context, parse_zap, json_lines, ZapAdapter
from orchestrator.integrations.interactsh import correlate


def config(**overrides):
    return AssessmentConfig(scope={"allow_hosts": ["app.test"], "allow_ports": [443]}, **overrides)


@pytest.mark.parametrize("url,method,allowed", [
    ("https://app.test/", "GET", True), ("https://app.test/x", "POST", False),
    ("https://other.test/", "GET", False), ("https://app.test.evil.test/", "GET", False),
    ("http://app.test/", "GET", False), ("https://127.0.0.1/", "GET", False),
    ("https://169.254.169.254/", "GET", False), ("https://app.test:8443/", "GET", False),
    ("https://user@app.test/", "GET", False), ("file:///etc/passwd", "GET", False),
    ("https://app.test/logout", "GET", False), ("https://evil.oast.test/", "GET", False),
])
def test_scope_policy(url, method, allowed):
    cfg = config()
    assert EgressPolicy(cfg.model_dump()).check(url, method)[0] is allowed


def test_services_never_expand_assessment_scope():
    cfg = config().model_dump()
    cfg["services"] = ["https://dojo.test"]
    assert not EgressPolicy(cfg).check("https://dojo.test")[0]
    cfg["service_only"] = True
    assert EgressPolicy(cfg).check("https://dojo.test/api", "POST")[0]
    assert not EgressPolicy(cfg).check("https://app.test")[0]


def test_mutation_routes_are_explicit():
    cfg = config().model_dump()
    cfg.update(state_changing=True, operation_routes=[{"method": "POST", "origin": "https://app.test", "path_regex": "/items"}])
    policy = EgressPolicy(cfg)
    assert policy.check("https://app.test/items", "POST")[0]
    assert not policy.check("https://app.test/admin", "POST")[0]
    assert not policy.check("https://app.test/items", "DELETE")[0]


@pytest.mark.asyncio
async def test_workflow_routes_bind_base_path_origin_and_single_segment():
    from orchestrator.integrations.service import operation_routes
    cfg = config(stages=["schemathesis"], active=True, state_changing=True,
                 schema_input={"content": json.dumps({"paths": {"/items/{id}": {"post": {"operationId": "update"}}}})},
                 workflow={"operations": ["update"],
                           "fixtures": [{"url": "https://app.test/setup", "method": "POST"}],
                           "cleanup": [{"url": "https://app.test/cleanup", "method": "POST"}]})
    settings = cfg.model_dump()
    settings["scope"]["allow_hosts"].append("other.test")
    settings["operation_routes"] = await operation_routes(cfg, None, "https://app.test/api/v1")
    policy = EgressPolicy(settings)
    assert policy.check("https://app.test/api/v1/items/42", "POST")[0]
    assert policy.check("https://app.test/setup", "POST")[0]
    for url in ("https://other.test/api/v1/items/42", "https://other.test/setup",
                "https://app.test/items/42", "https://app.test/api/v1/items/42/delete"):
        assert not policy.check(url, "POST")[0]


@pytest.mark.parametrize("overrides", [
    {"stages": ["schemathesis"]}, {"stages": ["interactsh"], "active": True},
    {"state_changing": True}, {"active": True, "state_changing": True}, {"stages": ["zap", "zap"]},
    {"stages": []}, {"budget": {"concurrency": 0}},
])
def test_config_fail_closed(overrides):
    with pytest.raises(ValidationError):
        config(**overrides)


def test_explicit_ports_required():
    with pytest.raises(ValidationError):
        AssessmentConfig(scope={"allow_hosts": ["app.test"]})


def test_identity_origin_and_check():
    with pytest.raises(ValidationError):
        Identity(name="reader", target_origin="https://app.test", check={"url": "https://evil.test/me"})


def test_secret_storage_and_redaction(tmp_path, monkeypatch):
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path))
    store = SecretStore()
    key = store.put({"headers": {"Authorization": "Bearer supersecret"}})
    assert store.path(key).stat().st_mode & 0o777 == 0o600
    assert store.get(key)["headers"]["Authorization"] == "Bearer supersecret"
    with pytest.raises(ValueError):
        store.get("../../etc/passwd")
    value = redact({"output": "credential=supersecret", "headers": {"Authorization": "Bearer supersecret"}}, ("supersecret",))
    assert "supersecret" not in json.dumps(value)


def test_fingerprints_stable_and_identity_sensitive():
    a = fingerprint("https://app.test", "zap:123", "get", "https://app.test/item?token=old")
    b = fingerprint("https://APP.test/", "zap:123", "GET", "https://app.test/item?token=new")
    assert a == b
    assert a != fingerprint("https://app.test", "zap:123", "GET", "https://app.test/item?token=new", identity="admin")
    assert a != fingerprint("https://app.test", "nuclei:123", "GET", "https://app.test/item?token=new")


def test_zap_parser_preserves_every_instance():
    ctx = Context("session", "stage", "https://app.test", config())
    data = {"site": [{"alerts": [{"pluginid": "123", "name": "Missing header", "riskcode": "1",
                                   "instances": [{"uri": f"https://app.test/{i}", "method": "GET"} for i in range(150)]}]}]}
    result = parse_zap(data, ctx)
    assert len(result.findings) == 150
    assert all(f.confidence == "suspected" for f in result.findings)
    assert "activeScan" not in [j["type"] for j in ZapAdapter().plan(ctx)["jobs"]]


def test_malformed_jsonl_is_not_clean_scan():
    with pytest.raises((ValueError, json.JSONDecodeError)):
        json_lines('{"request":{}}\nnot json')


def test_callback_correlation_is_exact():
    ctx = Context("s", "i", "https://app.test", config())
    events = [{"full-id": "abc.callback.test", "protocol": "dns", "timestamp": "now"},
              {"full-id": "abc.callback.test.attacker.test", "protocol": "http"},
              {"full-id": "unrelated.callback.test", "protocol": "dns"}]
    result = correlate(events, {"abc.callback.test": {"url": "https://app.test/fetch", "parameter": "url"}}, ctx)
    assert len(result.findings) == 1
    assert result.findings[0].confidence == "likely"


@pytest.fixture
async def database(tmp_path, monkeypatch):
    import orchestrator.database as original
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    from orchestrator.integrations import persistence
    await original.init_db()
    await persistence.migrate()
    return persistence


@pytest.mark.asyncio
async def test_additive_migrations_and_evidence(database):
    await database.migrate()
    key = await database.evidence("s", "stage", "output", "Bearer secret", ("secret",))
    rows = await database.rows("SELECT * FROM integration_evidence WHERE id=?", (key,))
    assert rows[0]["size"] > 0
    from orchestrator.integrations.security import runtime_root
    assert "secret" not in (runtime_root() / "evidence" / key).read_text()


@pytest.mark.asyncio
async def test_restart_marks_interrupted_without_replay(database, monkeypatch):
    from orchestrator.integrations import service
    await service.register("s", "https://app.test", config(stages=["zap"]))
    await database.execute("UPDATE integration_stages SET status='running'")
    monkeypatch.setattr(service, "recover_orphans", AsyncMock(return_value=True))
    await service.recover()
    stages = await database.rows("SELECT * FROM integration_stages")
    assert stages[0]["status"] == "partial"
    assert "restart" in stages[0]["reason"]


@pytest.mark.asyncio
async def test_defectdojo_repeated_export_no_duplicate(database, monkeypatch):
    from orchestrator.integrations import service, defectdojo
    await service.register("s", "https://app.test", config(stages=["zap"]))
    class FakeSandbox:
        def __init__(self, *a, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): pass
    request = AsyncMock(return_value={"status": 200, "body": '{"test":42}'})
    monkeypatch.setattr(defectdojo, "Sandbox", FakeSandbox)
    monkeypatch.setattr(defectdojo, "rpc", request)
    secret = SecretStore().put({"token": "private"})
    cfg = defectdojo.ExportConfig(server="https://dojo.test", secret_id=secret, test_id=42)
    first = await defectdojo.export("s", cfg)
    second = await defectdojo.export("s", cfg)
    assert first["id"] == second["id"]
    assert request.await_count == 1
    assert request.call_args.args[1]["fields"]["close_old_findings"] == "false"


@pytest.mark.asyncio
async def test_defectdojo_uncertain_write_is_not_retried(database, monkeypatch):
    from orchestrator.integrations import service, defectdojo
    await service.register("s", "https://app.test", config(stages=["zap"]))
    class BrokenSandbox:
        def __init__(self, *a, **kw): pass
        async def __aenter__(self): raise RuntimeError("connection lost")
        async def __aexit__(self, *a): pass
    monkeypatch.setattr(defectdojo, "Sandbox", BrokenSandbox)
    secret = SecretStore().put({"token": "private"})
    cfg = defectdojo.ExportConfig(server="https://dojo.test", secret_id=secret, test_id=42)
    with pytest.raises(RuntimeError):
        await defectdojo.export("s", cfg)
    assert (await defectdojo.export("s", cfg))["status"] == "uncertain"


def test_http_and_websocket_require_same_token(monkeypatch):
    from fastapi import FastAPI, WebSocket
    from fastapi.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect
    from orchestrator.integrations.access import AccessMiddleware
    app = FastAPI()
    app.add_middleware(AccessMiddleware)
    @app.get("/api/report")
    def report(): return {"secret": "evidence"}
    @app.get("/api/integrations/report")
    def assessment_report(): return {"secret": "evidence"}
    @app.websocket("/ws/session")
    async def socket(ws: WebSocket):
        await ws.accept()
        await ws.close()
    monkeypatch.setenv("ERLIK_API_TOKEN", "test-token")
    client = TestClient(app)
    assert client.get("/api/report").status_code == 401
    assert client.get("/api/report", headers={"X-API-Token": "test-token"}).status_code == 200
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/session"): pass
    # Unsetting the token returns the BASE api to its documented default-off
    # posture (SECURITY.md, and test_security_doc pins it), so /api/report opens
    # again. Assessment data does not: it holds credential handles and client
    # evidence, there is no token left to authenticate with, and the only
    # correct answer is a refusal.
    monkeypatch.delenv("ERLIK_API_TOKEN")
    assert client.get("/api/report").status_code == 200
    assert client.get("/api/integrations/report").status_code == 401


@pytest.mark.asyncio
async def test_local_triage_preserved_and_reported(database):
    from orchestrator.integrations import service, api
    from orchestrator.integrations.contracts import IntegrationFinding
    await service.register("s", "https://app.test", config(stages=["zap"]))
    stage = (await database.rows("SELECT id FROM integration_stages"))[0]["id"]
    finding = IntegrationFinding(fingerprint="stable", title="Finding", url="https://app.test/private", rule="test", source="test", basis="Observed response")
    await database.persist_result("s", stage, StageResult(findings=[finding]))
    await api.triage("s", "stable", api.TriageInput(state="false_positive", note="Public content, no security impact"))
    assert (await service.report("s"))["findings"] == []
    await database.persist_result("s", stage, StageResult(findings=[finding]))
    restored = (await api.list_findings("s"))[0]
    assert restored["triage_state"] == "false_positive"
    assert restored["triage_note"]


@pytest.mark.asyncio
async def test_workflow_secrets_not_stored_in_database(database):
    from orchestrator.integrations import service
    cfg = config(stages=["schemathesis"], active=True, state_changing=True,
        schema_input={"content": '{"openapi":"3.0.3","info":{"title":"Test","version":"1"},"paths":{}}'},
        workflow={"operations": ["create"], "fixtures": [{"url": "https://app.test/setup", "method": "POST", "body": {"password": "fixture-secret"}}],
                  "cleanup": [{"url": "https://app.test/cleanup", "method": "POST"}]})
    await service.register("s", "https://app.test", cfg)
    row = (await database.rows("SELECT * FROM integration_assessments"))[0]
    assert "fixture-secret" not in row["config"]
    assert SecretStore().get(row["config_secret_id"])["assessment_config"]["workflow"]["fixtures"][0]["body"]["password"] == "fixture-secret"
