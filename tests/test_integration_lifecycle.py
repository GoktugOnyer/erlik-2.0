"""Lifecycle acceptance against real pinned scanners and a local Docker target."""
import asyncio
import json
import os
from pathlib import Path
import signal
import sys
import uuid

import pytest

from orchestrator.integrations import persistence as db, runtime, service
from orchestrator.integrations.adapters import ADAPTERS, Context
from orchestrator.integrations.contracts import AssessmentConfig, Identity
from orchestrator.integrations.runtime import docker, IMAGES, Sandbox
from orchestrator.integrations.security import SecretStore, runtime_root


@pytest.fixture
async def lifecycle_lab(tmp_path, monkeypatch):
    import orchestrator.database as original
    key = uuid.uuid4().hex
    network = "erlik-lifecycle-" + key
    name = "erlik-lifecycle-target-" + key
    # Recovery from this test must never remove another concurrently running assessment.
    owner = "erlik.lifecycle-test=" + key
    monkeypatch.setattr(runtime, "OWNER", owner)
    monkeypatch.setenv("ERLIK_INTEGRATION_EGRESS_NETWORK", network)
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setenv("ERLIK_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    await docker("network", "create", network)
    fixture = Path(__file__).parent / "fixtures" / "integration_lifecycle_target.py"
    try:
        await docker("run", "-d", "--name", name, "--network", network, "--network-alias", "lifecycle-target",
                     "-v", f"{fixture.resolve()}:/fixture.py:ro", "--entrypoint", "python", IMAGES["worker"], "/fixture.py")
        for _ in range(40):
            code, _, _ = await docker("exec", name, "python", "-c",
                                     "import socket;socket.create_connection(('127.0.0.1',8080),1).close()", check=False)
            if code == 0:
                break
            await asyncio.sleep(0.1)
        else:
            pytest.fail("lifecycle target did not become ready")
        yield {"name": name, "owner": owner, "network": network}
    finally:
        await runtime.recover_orphans()
        await docker("rm", "-f", "-v", name, check=False)
        await docker("network", "rm", network, check=False)


def config(**kwargs):
    return AssessmentConfig(scope={"allow_hosts": ["lifecycle-target"], "allow_ports": [8080]},
                            budget={"stage_seconds": 180, "assessment_seconds": 420,
                                    "requests_per_second": 20}, **kwargs)


async def events(lab):
    _, out, _ = await docker("exec", lab["name"], "python", "-c",
                            "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8080/events').read().decode())")
    return json.loads(out)


async def wait_for_request(lab, prefix, timeout=60):
    async with asyncio.timeout(timeout):
        while True:
            if any(e["path"].startswith(prefix) for e in await events(lab)):
                return
            await asyncio.sleep(0.2)


async def register(session_id, target, cfg):
    await db.execute("INSERT INTO sessions(id,target_url) VALUES(?,?)", (session_id, target))
    await service.register(session_id, target, cfg)


@pytest.mark.asyncio
@pytest.mark.docker
@pytest.mark.skipif(os.environ.get("ERLIK_DOCKER_TESTS") != "1", reason="requires Docker lab")
async def test_mid_stage_auth_expiry_preserves_evidence_then_resumes(lifecycle_lab):
    origin = "http://lifecycle-target:8080"
    identity = Identity(name="reader", target_origin=origin,
                        headers={"Authorization": "Bearer expiring-lifecycle-token"},
                        check={"url": origin + "/expiry/me", "expected_status": 200, "body_contains": "reader"})
    secret_id = SecretStore().put(identity.model_dump())
    cfg = config(stages=["katana"], identity_ids=[secret_id])
    await register("expiry", origin + "/expiry/", cfg)

    assert await service.run("expiry") == "needs_auth"
    stage = (await db.rows("SELECT * FROM integration_stages WHERE session_id='expiry'"))[0]
    assert stage["status"] == "needs_auth" and "expired during stage" in stage["reason"]
    evidence = await db.rows("SELECT * FROM integration_evidence WHERE session_id='expiry'")
    auth_results = [json.loads((runtime_root() / "evidence" / item["id"]).read_text())
                    for item in evidence if item["kind"] == "authentication-check"]
    assert [item["status"] for item in auth_results] == [200, 401]
    assert any(item["kind"] == "requests" for item in evidence)
    old_ids = {item["id"] for item in evidence}

    identity.headers["Authorization"] = "Bearer renewed-lifecycle-token"
    SecretStore().put(identity.model_dump(), secret_id)
    assert await service.run("expiry") == "completed"
    assert (await db.rows("SELECT status FROM sessions WHERE id='expiry'"))[0]["status"] == "completed"
    saved = await db.rows("SELECT id FROM integration_evidence WHERE session_id='expiry'")
    assert old_ids < {item["id"] for item in saved}
    assert any(e["path"] == "/expiry/private" and e["authorization"] == "Bearer renewed-lifecycle-token"
               for e in await events(lifecycle_lab))
    for path in (runtime_root() / "evidence").iterdir():
        assert "expiring-lifecycle-token" not in path.read_text()
        assert "renewed-lifecycle-token" not in path.read_text()


@pytest.mark.asyncio
@pytest.mark.docker
@pytest.mark.skipif(os.environ.get("ERLIK_DOCKER_TESTS") != "1", reason="requires Docker lab")
async def test_zap_expected_passive_alert_has_authenticated_http_evidence(lifecycle_lab):
    origin = "http://lifecycle-target:8080"
    cfg = config(stages=["zap"])
    identity = {"target_origin": origin, "headers": {"Authorization": "Bearer zap-lifecycle-token"}}
    ctx = Context("passive", "passive", origin + "/zap/", cfg, "reader", identity)
    assert "activeScan" not in {job["type"] for job in ADAPTERS["zap"].plan(ctx)["jobs"]}
    async with Sandbox(cfg, identity) as sandbox:
        result = await ADAPTERS["zap"].run(ctx, sandbox)
    assert result.status == "completed", result.model_dump()
    expected = [finding for finding in result.findings if finding.rule == "zap:10010"
                and finding.parameter == "fixture_session" and "/zap/private" in finding.url]
    assert expected, result.model_dump()
    finding = expected[0]
    assert finding.confidence == "suspected" and finding.evidence_ids
    artifacts = await db.rows("SELECT * FROM integration_evidence WHERE session_id='passive' AND kind='zap.json'")
    assert artifacts
    report = json.loads((runtime_root() / "evidence" / artifacts[0]["id"]).read_text())
    instances = [instance for site in report["site"] for alert in site["alerts"]
                 if str(alert.get("pluginid")) == "10010" for instance in alert["instances"]
                 if "/zap/private" in instance["uri"]]
    assert instances
    assert any(instance.get("request-header", "").startswith("GET http://lifecycle-target:8080/zap/private ")
               and "Set-Cookie:" in instance.get("response-header", "")
               and "private-zap-canary" in instance.get("response-body", "") for instance in instances), instances
    received = await events(lifecycle_lab)
    assert any(e["path"] == "/zap/private" and e["authorization"] == "Bearer zap-lifecycle-token" for e in received)


@pytest.mark.asyncio
@pytest.mark.docker
@pytest.mark.skipif(os.environ.get("ERLIK_DOCKER_TESTS") != "1", reason="requires Docker lab")
async def test_zap_cancellation_stops_in_flight_scanner_and_retains_audit(lifecycle_lab):
    await register("cancel-zap", "http://lifecycle-target:8080/slow", config(stages=["zap"]))
    task = asyncio.create_task(service.run("cancel-zap"))
    try:
        await wait_for_request(lifecycle_lab, "/slow")
        _, running, _ = await docker("ps", "-q", "--filter", f"label={lifecycle_lab['owner']}",
                                     "--filter", f"ancestor={IMAGES['zap']}")
        assert running.strip(), "the real ZAP scanner must be running before cancellation"
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        for container in running.split():
            code, _, _ = await docker("inspect", container, check=False)
            assert code != 0
        assert (await db.rows("SELECT status FROM integration_stages WHERE session_id='cancel-zap'"))[0]["status"] == "cancelled"
        audits = await db.rows("SELECT id FROM integration_evidence WHERE session_id='cancel-zap' AND kind='requests'")
        assert any("/slow" in (runtime_root() / "evidence" / row["id"]).read_text() for row in audits)
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.docker
@pytest.mark.skipif(os.environ.get("ERLIK_DOCKER_TESTS") != "1", reason="requires Docker lab")
async def test_actual_process_crash_startup_stops_orphans_without_request_replay(lifecycle_lab):
    identity = Identity(name="crash-reader", target_origin="http://lifecycle-target:8080",
                        headers={"Authorization": "Bearer renewed-lifecycle-token"},
                        check={"url": "http://lifecycle-target:8080/expiry/me", "expected_status": 200,
                               "body_contains": "reader"})
    secret_id = SecretStore().put(identity.model_dump())
    await register("crash-zap", "http://lifecycle-target:8080/slow", config(stages=["zap"], identity_ids=[secret_id]))
    script = """
import asyncio, os
from orchestrator.integrations import runtime
runtime.OWNER = os.environ['ERLIK_TEST_OWNER']
from orchestrator.main import app, lifespan
from orchestrator.integrations import service
async def main():
    async with lifespan(app):
        if os.environ['ERLIK_TEST_MODE'] == 'run':
            await service.run('crash-zap')
        else:
            print('RECOVERED=' + str(app.state.integration_recovery_ok), flush=True)
asyncio.run(main())
"""
    env = {**os.environ, "ERLIK_TEST_OWNER": lifecycle_lab["owner"], "ERLIK_TEST_MODE": "run"}
    process = await asyncio.create_subprocess_exec(sys.executable, "-u", "-c", script, env=env,
                                                   start_new_session=True, stdout=asyncio.subprocess.PIPE,
                                                   stderr=asyncio.subprocess.PIPE)
    try:
        try:
            await wait_for_request(lifecycle_lab, "/slow")
        except TimeoutError:
            # The crashed-orchestrator subprocess is the thing under test; if it
            # never reached the target, its own stderr is the only account of
            # why, and discarding it leaves a bare TimeoutError to guess at.
            if process.returncode is None:
                process.kill()
            out, err = await asyncio.wait_for(process.communicate(), 10)
            raise AssertionError(
                "the orchestrator subprocess never reached /slow within the wait "
                f"(returncode={process.returncode}).\n"
                f"--- subprocess stdout ---\n{out.decode(errors='replace')}\n"
                f"--- subprocess stderr ---\n{err.decode(errors='replace')}") from None
        _, scanners, _ = await docker("ps", "-q", "--filter", f"label={lifecycle_lab['owner']}",
                                      "--filter", f"ancestor={IMAGES['zap']}")
        assert scanners.strip()
        os.killpg(process.pid, signal.SIGKILL)
        await asyncio.wait_for(process.communicate(), 10)
        for scanner in scanners.split():
            _, state, _ = await docker("inspect", "--format", "{{.State.Running}}", scanner)
            assert state.strip() == "true", "SIGKILL must leave a real orphan, unlike cooperative cancellation"
        before = await events(lifecycle_lab)
        replacement = await asyncio.create_subprocess_exec(sys.executable, "-u", "-c", script,
            env={**env, "ERLIK_TEST_MODE": "recover"}, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(replacement.communicate(), 30)
        assert replacement.returncode == 0, stderr.decode()
        assert b"RECOVERED=True" in stdout
        for scanner in scanners.split():
            code, _, _ = await docker("inspect", scanner, check=False)
            assert code != 0
        stage = (await db.rows("SELECT status,reason FROM integration_stages WHERE session_id='crash-zap'"))[0]
        assert stage["status"] == "partial" and "restart" in stage["reason"]
        assert (await db.rows("SELECT status FROM integration_assessments WHERE session_id='crash-zap'"))[0]["status"] == "partial"
        assert (await db.rows("SELECT status FROM sessions WHERE id='crash-zap'"))[0]["status"] == "partial"
        recovered = await db.rows("SELECT id,kind FROM integration_evidence WHERE session_id='crash-zap'")
        assert any(row["kind"] == "recovery" for row in recovered)
        assert any(row["kind"] == "recovered-requests" and "/slow" in
                   (runtime_root() / "evidence" / row["id"]).read_text() for row in recovered)
        assert any(row["kind"].endswith(".stdout") and "recovered" in row["kind"] for row in recovered)
        assert not list((runtime_root() / "jobs").iterdir()), "private orphan credentials must be removed"
        for path in (runtime_root() / "evidence").iterdir():
            assert "renewed-lifecycle-token" not in path.read_text()
        await asyncio.sleep(0.3)
        assert await events(lifecycle_lab) == before
    finally:
        if process.returncode is None:
            os.killpg(process.pid, signal.SIGKILL)
            await process.communicate()


@pytest.mark.asyncio
async def test_recovery_refuses_success_while_orphan_container_survives(monkeypatch):
    async def failed_cleanup(*args, **kwargs):
        if args[0] == "ps":
            return 0, "surviving-scanner\n", ""
        if args[:2] == ("rm", "-f"):
            return 1, "", "daemon refused removal"
        return 0, "", ""
    monkeypatch.setattr(runtime, "docker", failed_cleanup)
    assert await runtime.recover_orphans() is False


@pytest.mark.asyncio
async def test_recovery_preserves_redacted_artifacts_and_only_removes_owned_directories(tmp_path, monkeypatch):
    import orchestrator.database as original
    from orchestrator.integrations.security import private_write
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    own = runtime_root() / "jobs" / uuid.uuid4().hex
    other = runtime_root() / "jobs" / uuid.uuid4().hex
    private_write(own / "manifest.json", json.dumps({"owner": runtime.OWNER,
                  "assessment_context": {"session_id": "unit-crash", "stage_id": "unit-stage"},
                  "jobs": [], "images": {"scanner": "sha256:fixture"}}))
    private_write(own / "policy" / "policy.json", json.dumps({"identity": {
                  "headers": {"Authorization": "Bearer recovery-unit-secret"}}}))
    private_write(own / "output" / "result.txt", "Raw response contains recovery-unit-secret")
    private_write(own / "audit" / "requests.jsonl", '{"url":"http://fixture/private","allowed":true}\n')
    private_write(other / "manifest.json", json.dumps({"owner": "another-workspace"}))

    async def no_containers(*args, **kwargs):
        return 0, "", ""
    monkeypatch.setattr(runtime, "docker", no_containers)
    assert await runtime.recover_orphans() is True
    assert not own.exists() and other.exists()
    recovered = await db.rows("SELECT id,kind FROM integration_evidence WHERE session_id='unit-crash'")
    assert {row["kind"] for row in recovered} == {"recovered-result.txt", "recovered-requests", "recovery"}
    text = "\n".join((runtime_root() / "evidence" / row["id"]).read_text() for row in recovered)
    assert "recovery-unit-secret" not in text
    assert "[REDACTED]" in text and "sha256:fixture" in text
