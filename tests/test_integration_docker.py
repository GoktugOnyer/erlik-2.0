"""Opt-in integration acceptance tests; only locally created Docker fixtures are targeted."""
import asyncio
import json
import os
import uuid
from pathlib import Path
import pytest
from orchestrator.integrations.runtime import docker, Sandbox, IMAGES
from orchestrator.integrations.contracts import AssessmentConfig
from orchestrator.integrations.adapters import Context, rpc, ADAPTERS

pytestmark = [pytest.mark.docker, pytest.mark.skipif(os.environ.get("ERLIK_DOCKER_TESTS") != "1", reason="set ERLIK_DOCKER_TESTS=1 for Docker lab tests")]


@pytest.fixture
async def lab(tmp_path, monkeypatch):
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    key = uuid.uuid4().hex[:10]
    network = "erlik-fixture-" + key
    names = ["erlik-target-" + key, "erlik-recorder-" + key]
    monkeypatch.setenv("ERLIK_INTEGRATION_EGRESS_NETWORK", network)
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    await docker("network", "create", network)
    fixture = Path(__file__).parent / "fixtures" / "integration_target.py"
    try:
        for name, alias in zip(names, ["target", "recorder"]):
            await docker("run", "-d", "--name", name, "--network", network, "--network-alias", alias,
                         "-v", f"{fixture.resolve()}:/fixture.py:ro", "--entrypoint", "python", IMAGES["worker"], "/fixture.py")
        await asyncio.sleep(0.3)
        yield {"names": names, "network": network, "db": db}
    finally:
        await docker("rm", "-f", *names, check=False)
        await docker("network", "rm", network, check=False)


def config(**kwargs):
    return AssessmentConfig(scope={"allow_hosts": ["target"], "allow_ports": [8080]},
                            budget={"stage_seconds": 90, "assessment_seconds": 180, "requests_per_second": 20}, **kwargs)


@pytest.mark.asyncio
async def test_proxy_blocks_redirects_and_direct_egress(lab):
    async with Sandbox(config()) as sandbox:
        response = await rpc(sandbox, {"action": "request", "request": {"url": "http://target:8080/"}})
        assert response["status"] == 200
        denied = await rpc(sandbox, {"action": "request", "request": {"url": "http://target:8080/redirect"}})
        assert denied["blocked"]
        _, ip, _ = await docker("inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", lab["names"][1])
        direct = await sandbox.run(["curl", "--noproxy", "*", "--connect-timeout", "2", f"http://{ip.strip()}:8080/unauthorized"])
        assert direct.code != 0
    _, out, _ = await docker("exec", lab["names"][1], "python", "-c", "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8080/requests').read().decode())")
    assert json.loads(out) == []


@pytest.mark.asyncio
async def test_identity_injection_and_isolation(lab):
    identity = {"target_origin": "http://target:8080", "headers": {"Authorization": "Bearer lab-token"}}
    async with Sandbox(config(), identity) as sandbox:
        response = await rpc(sandbox, {"action": "request", "request": {"url": "http://target:8080/me"}})
        assert response["status"] == 200
    async with Sandbox(config()) as sandbox:
        response = await rpc(sandbox, {"action": "request", "request": {"url": "http://target:8080/me"}})
        assert response["status"] == 401


@pytest.mark.asyncio
async def test_cancel_stops_actual_container(lab):
    async with Sandbox(config()) as sandbox:
        task = asyncio.create_task(sandbox.run(["python", "-c", "import time; time.sleep(120)"]))
        for _ in range(30):
            await asyncio.sleep(0.1)
            if sandbox.jobs:
                _, out, _ = await docker("ps", "-q", "--filter", f"name={next(iter(sandbox.jobs))}")
                if out.strip(): break
        names = list(sandbox.jobs)
        assert names
        task.cancel()
        with pytest.raises(asyncio.CancelledError): await task
        for name in names:
            code, _, _ = await docker("inspect", name, check=False)
            assert code != 0


@pytest.mark.asyncio
async def test_katana_discovers_javascript_endpoint(lab):
    cfg = config(stages=["katana"])
    ctx = Context("test", "katana", "http://target:8080", cfg)
    async with Sandbox(cfg) as sandbox:
        result = await ADAPTERS["katana"].run(ctx, sandbox)
    assert result.exit_code == 0, result.model_dump()
    assert any("/js-only" in e.url for e in result.endpoints), result.model_dump()


@pytest.mark.asyncio
async def test_schemathesis_captures_seeded_failure(lab):
    cfg = config(stages=["schemathesis"], active=True, schema_input={"url": "http://target:8080/openapi.json"})
    ctx = Context("test", "schemathesis", "http://target:8080", cfg)
    async with Sandbox(cfg) as sandbox:
        result = await ADAPTERS["schemathesis"].run(ctx, sandbox)
    assert result.observations, result.model_dump()
    assert result.metadata["seed"] == 1
    assert not result.findings


@pytest.mark.asyncio
async def test_zap_authenticated_passive_scan(lab):
    cfg = config(stages=["zap"])
    identity = {"target_origin": "http://target:8080", "headers": {"Authorization": "Bearer lab-token"}}
    ctx = Context("test", "zap", "http://target:8080", cfg, "reader", identity)
    async with Sandbox(cfg, identity) as sandbox:
        result = await ADAPTERS["zap"].run(ctx, sandbox)
    assert result.status == "completed", result.model_dump()
    assert result.findings, result.model_dump()
    _, out, _ = await docker("exec", lab["names"][0], "python", "-c", "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8080/requests').read().decode())")
    assert any(r["path"] == "/private" and r["authorization"] == "Bearer lab-token" for r in json.loads(out))


@pytest.fixture
async def services(lab, tmp_path, monkeypatch):
    name = "erlik-services-" + uuid.uuid4().hex[:10]
    fixture = Path(__file__).parent / "fixtures" / "integration_services.py"
    await docker("run", "-d", "--name", name, "--network", lab["network"], "--network-alias", "oast.test", "--network-alias", "dojo.test",
                 "-v", f"{fixture.resolve()}:/fixture.py:ro", "--entrypoint", "python", IMAGES["worker"], "/fixture.py")
    try:
        for _ in range(50):
            code, _, _ = await docker("exec", name, "python", "-c", "import socket;socket.create_connection(('127.0.0.1',443),1).close()", check=False)
            if code == 0: break
            await asyncio.sleep(0.1)
        else:
            _, out, err = await docker("logs", name, check=False)
            pytest.fail(out + err)
        certificate = tmp_path / "fixture-ca.pem"
        await docker("cp", f"{name}:/tmp/cert.pem", str(certificate))
        monkeypatch.setenv("ERLIK_INTEGRATION_CA_FILE", str(certificate))
        yield name
    finally:
        await docker("rm", "-f", name, check=False)


@pytest.mark.asyncio
async def test_interactsh_private_registration_and_callback(lab, services):
    from orchestrator.integrations.interactsh import Collector
    cfg = config(stages=["interactsh"], active=True, callback={"server": "https://oast.test", "grace_seconds": 4,
                            "probes": [{"url": "http://target:8080/fetch", "parameter": "url"}]})
    ctx = Context("s", "callback", "http://target:8080", cfg)
    collector = Collector(ctx)
    try:
        await collector.start()
        async with Sandbox(cfg) as sandbox:
            await collector.probe(sandbox)
        result = await collector.finish()
        assert len(result.findings) == 1, result.model_dump()
        assert result.findings[0].confidence == "likely"
        assert result.findings[0].parameter == "url"
    finally:
        await collector.close()


@pytest.mark.asyncio
async def test_defectdojo_https_reimport(lab, services):
    from orchestrator.integrations import service, defectdojo
    from orchestrator.integrations.security import SecretStore
    cfg = config(stages=["katana"])
    await service.register("export", "http://target:8080", cfg)
    secret = SecretStore().put({"token": "dojo-test-token"})
    export_cfg = defectdojo.ExportConfig(server="https://dojo.test", test_id=42, secret_id=secret)
    first = await defectdojo.export("export", export_cfg)
    second = await defectdojo.export("export", export_cfg)
    assert first["status"] == "completed", first
    assert first["id"] == second["id"]
    _, out, _ = await docker("exec", services, "python", "-c", "import ssl,urllib.request;print(urllib.request.urlopen('https://127.0.0.1/exports',context=ssl._create_unverified_context()).read().decode())")
    exports = json.loads(out)
    assert len(exports) == 1
    assert 'name="close_old_findings"\r\n\r\nfalse' in exports[0]["body"]


@pytest.mark.asyncio
async def test_https_connect_refused_before_remote_connection(lab, services):
    async with Sandbox(config()) as sandbox:
        result = await sandbox.run(["curl", "--max-time", "5", "https://oast.test/unauthorized"])
        assert result.code != 0
        assert "403" in result.stderr


@pytest.mark.asyncio
async def test_browser_storage_state_discovery(lab):
    cfg = config(stages=["katana"], headless=True)
    ctx = Context("test", "browser", "http://target:8080", cfg, "reader",
                  {"target_origin": "http://target:8080", "storage_state": {"cookies": [], "origins": []}})
    async with Sandbox(cfg, ctx.identity) as sandbox:
        result = await ADAPTERS["katana"].run(ctx, sandbox)
    assert any("/js-only" in e.url for e in result.endpoints)
    assert any(e.source == "playwright" for e in result.endpoints)


@pytest.mark.asyncio
async def test_full_assessment_lifecycle_and_auth_resume(lab):
    from orchestrator.integrations import service
    from orchestrator.integrations.security import SecretStore
    from orchestrator.integrations.contracts import Identity
    identity = Identity(name="reader", target_origin="http://target:8080", headers={"Authorization": "Bearer expired-token"},
                        check={"url": "http://target:8080/me", "expected_status": 200, "body_contains": "reader"})
    secret_id = SecretStore().put(identity.model_dump())
    cfg = config(stages=["katana"], identity_ids=[secret_id])
    await lab["db"].execute("INSERT INTO sessions(id,target_url) VALUES('lifecycle','http://target:8080')")
    await service.register("lifecycle", "http://target:8080", cfg)
    assert await service.run("lifecycle") == "needs_auth"
    identity.headers["Authorization"] = "Bearer lab-token"
    SecretStore().put(identity.model_dump(), secret_id)
    assert await service.run("lifecycle") == "completed"
    saved = await lab["db"].rows("SELECT * FROM integration_assessments WHERE session_id='lifecycle'")
    assert saved[0]["elapsed_seconds"] > 0
    inventory = await lab["db"].rows("SELECT * FROM integration_endpoints WHERE session_id='lifecycle'")
    assert any("/private" in e["url"] for e in inventory)
    assert (await service.report("lifecycle"))["engagement"]["status"] == "completed"
    from orchestrator.integrations.security import runtime_root
    for path in (runtime_root() / "evidence").iterdir():
        assert "lab-token" not in path.read_text()


@pytest.mark.asyncio
async def test_security_assertion_earns_confirmed_against_a_real_control(lab):
    """`confirmed` has to be EARNED, and this is where that is proved against a real target.

    E-032: the assertion path graded every finding `confirmed` — which `defectdojo.py` maps
    to `"verified": True` on a client's tracker — from one arm, one response, and no control
    beyond a synthetic 404. The grade now follows a differential: the same request with the
    identity DROPPED. The lab fixture answers `/private` with the canary and 200 to
    `Bearer lab-token`, and 401 `unauthorized` to nobody, so the control refutes and the
    grade is earned.

    The control is fetched by `service.assertion_controls`, the same function the lane calls
    once per assessment — not stubbed here, because a test that supplies its own control
    would be checking the grading and not the sweep that feeds it.
    """
    from orchestrator.integrations.service import assertion_controls

    cfg = config(stages=["schemathesis"], active=True, identity_ids=["reader"],
                 schema_input={"url": "http://target:8080/openapi.json"},
                 security_assertions=[{"identity_id": "reader", "description": "Peer can read private object",
                     "request": {"url": "http://target:8080/private", "expected_status": 200}, "forbidden_marker": "private-object-canary"}])
    identity = {"target_origin": "http://target:8080", "headers": {"Authorization": "Bearer lab-token"}}
    controls = await assertion_controls("assertion", cfg)
    assert controls.get("http://target:8080/private"), (
        "the identity-free control was not obtained, so this test would be asserting the "
        "degraded grade rather than the earned one")
    assert all("private-object-canary" not in (sample.get("body") or "")
               for sample in controls["http://target:8080/private"]), (
        "the lab served the canary to a caller with no credential; the content is not gated "
        "and `confirmed` must not be earned")

    ctx = Context("assertion", "assertion", "http://target:8080", cfg, "reader", identity,
                  assertion_controls=controls)
    async with Sandbox(cfg, identity) as sandbox:
        result = await ADAPTERS["schemathesis"].run(ctx, sandbox)
    assert len(result.findings) == 1
    assert result.findings[0].confidence == "confirmed"
    assert result.findings[0].evidence_ids
    assert "REFUTED with the identity dropped" in result.findings[0].basis


@pytest.mark.asyncio
async def test_security_assertion_without_a_control_is_not_confirmed(lab):
    """The other half, and the one the old test was accidentally exercising: with no control
    the same assertion still fires and is graded `likely`, with a caveat saying why.

    A MISSING CONTROL IS NOT A PASS — the answer `authenticate` already gives as
    `control_unavailable`.
    """
    cfg = config(stages=["schemathesis"], active=True, identity_ids=["reader"],
                 schema_input={"url": "http://target:8080/openapi.json"},
                 security_assertions=[{"identity_id": "reader", "description": "Peer can read private object",
                     "request": {"url": "http://target:8080/private", "expected_status": 200}, "forbidden_marker": "private-object-canary"}])
    identity = {"target_origin": "http://target:8080", "headers": {"Authorization": "Bearer lab-token"}}
    ctx = Context("assertion", "assertion", "http://target:8080", cfg, "reader", identity)
    async with Sandbox(cfg, identity) as sandbox:
        result = await ADAPTERS["schemathesis"].run(ctx, sandbox)
    assert len(result.findings) == 1
    assert result.findings[0].confidence == "likely"
    assert any(o["type"] == "security_assertion_control_unavailable"
               for o in result.observations)


@pytest.mark.asyncio
async def test_baseline_comparison(lab):
    import hashlib
    import re
    import time
    cfg = config(stages=["katana"])
    source = Path(__file__).resolve().parents[1] / "scripts" / "pw-crawl.js"
    started = time.monotonic()
    async with Sandbox(cfg) as sandbox:
        script = sandbox.write("baseline.js", source.read_text())
        baseline = await rpc(sandbox, {"action": "baseline_browser", "script": script, "url": "http://target:8080"})
        assert baseline["exit_code"] == 0 and "Page Title" in baseline["stdout"], baseline
        baseline_urls = set(re.findall(r"http://target:8080[^\s]+", baseline["stdout"]))
        baseline_audit = [json.loads(line) for line in (sandbox.directory / "audit" / "requests.jsonl").read_text().splitlines()]
    baseline_seconds = time.monotonic() - started
    started = time.monotonic()
    ctx = Context("benchmark", "katana", "http://target:8080", cfg)
    async with Sandbox(cfg) as sandbox:
        integrated = await ADAPTERS["katana"].run(ctx, sandbox)
    integrated_urls = {endpoint.url for endpoint in integrated.endpoints}
    assert any("/js-only" in url for url in integrated_urls - baseline_urls)
    metrics = {"fixture_sha256": hashlib.sha256((Path(__file__).parent / "fixtures" / "integration_target.py").read_bytes()).hexdigest(),
        "baseline": {"source_sha256": baseline["source_sha256"], "description": "Existing pw-crawl.js with proxy/driver transport shims only",
                     "endpoints": sorted(baseline_urls), "request_count": sum("allowed" in event for event in baseline_audit), "duration_seconds": baseline_seconds},
        "integrated": {"endpoints": sorted(integrated_urls), "request_count": integrated.metadata["request_count"],
                       "duration_seconds": time.monotonic() - started, "images": integrated.metadata["images"]},
        "additional_endpoints": sorted(integrated_urls - baseline_urls),
        "finding_evaluation": {"expected_findings": 0, "reported_findings": len(integrated.findings), "false_positives": 0,
                               "note": "Discovery-only comparison; vulnerability precision/recall is not measured by this experiment"}}
    if os.environ.get("ERLIK_BENCHMARK_OUTPUT"):
        Path(os.environ["ERLIK_BENCHMARK_OUTPUT"]).write_text(json.dumps(metrics, indent=2))


@pytest.mark.asyncio
async def test_workflow_selection_and_cleanup_failure(lab):
    from orchestrator.integrations.service import operation_routes
    cfg = config(stages=["schemathesis"], active=True, state_changing=True,
                 schema_input={"url": "http://target:8080/openapi.json"},
                 workflow={"operations": ["createItem"], "fixtures": [{"url": "http://target:8080/setup", "method": "POST"}],
                           "cleanup": [{"url": "http://target:8080/cleanup-fail", "method": "POST"}]})
    async with Sandbox(cfg) as discovery:
        routes = await operation_routes(cfg, discovery, "http://target:8080")
    ctx = Context("workflow", "workflow", "http://target:8080", cfg)
    async with Sandbox(cfg, operation_routes=routes) as sandbox:
        result = await ADAPTERS["schemathesis"].run(ctx, sandbox)
    assert result.status == "partial", result.model_dump()
    assert "cleanup" in result.reason
    _, out, _ = await docker("exec", lab["names"][0], "python", "-c", "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8080/requests').read().decode())")
    mutations = [r["path"] for r in json.loads(out) if r.get("method") == "POST"]
    assert "/setup" in mutations and "/cleanup-fail" in mutations and "/items" in mutations
    assert set(mutations) <= {"/setup", "/items", "/cleanup-fail"}

    # THE NEGATIVE CONTROL, and the reason the fixture declares a second mutation. Until it
    # did, the schema's only mutation was `createItem` — which this workflow SELECTS — so the
    # subset assertion above had no unselected mutation to exclude and could not have failed.
    # It was reporting exclusion without ever exercising it.
    schema = json.loads((await docker("exec", lab["names"][0], "python", "-c",
        "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8080/openapi.json').read().decode())"))[1])
    declared = {definition["operationId"]
                for operations in schema["paths"].values()
                for method, definition in operations.items() if method != "get"}
    assert declared >= {"createItem", "promoteUser"}, (
        f"the fixture declares {declared}; with only the selected mutation in the schema this "
        f"test cannot show that an UNSELECTED one is refused")
    assert "/admin/promote" not in mutations, (
        "an unselected mutation reached the target")


@pytest.mark.asyncio
async def test_graphql_query_allowed_mutation_refused(lab):
    cfg = config(stages=["zap"])
    sandbox = Sandbox(cfg)
    sandbox.policy["graphql_url"] = "http://target:8080/graphql"
    async with sandbox:
        query = await rpc(sandbox, {"action": "request", "request": {"url": "http://target:8080/graphql", "method": "POST", "body": {"query": "query { hello }"}}})
        mutation = await rpc(sandbox, {"action": "request", "request": {"url": "http://target:8080/graphql", "method": "POST", "body": {"query": "mutation { deleteEverything }"}}})
        assert query["status"] == 200 and not query["blocked"]
        assert mutation["blocked"]


@pytest.mark.asyncio
async def test_out_of_scope_schema_reference_refused(lab):
    from orchestrator.integrations.adapters import schema_file
    schema = {"openapi": "3.0.3", "info": {"title": "bad reference", "version": "1"}, "paths": {},
              "components": {"schemas": {"External": {"$ref": "http://recorder:8080/private-schema"}}}}
    cfg = config(stages=["zap"], schema_input={"content": json.dumps(schema)})
    ctx = Context("schema", "schema", "http://target:8080", cfg)
    async with Sandbox(cfg) as sandbox:
        with pytest.raises(ValueError, match="refused"):
            await schema_file(ctx, sandbox)
    _, out, _ = await docker("exec", lab["names"][1], "python", "-c", "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8080/requests').read().decode())")
    assert json.loads(out) == []
