"""Bounded deterministic SSRF hooks and optional real self-hosted OAST acceptance."""
import asyncio
import json
import os
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit
import uuid

import pytest

from orchestrator.integrations.adapters import Context
from orchestrator.integrations.contracts import AssessmentConfig
from orchestrator.integrations.interactsh import Collector, correlate
from orchestrator.testcase.loader import find_by_id


def configured():
    return AssessmentConfig(scope={"allow_hosts": ["target"], "allow_ports": [8080]},
        stages=["interactsh"], active=True, test_cases=["WSTG-INPV-19"],
        callback={"server": "https://oast.test", "grace_seconds": 4,
        "probes": [{"url": "http://target:8080/fetch?keep=yes&url=old", "parameter": "url"}]})


def collector():
    config = configured()
    instance = Collector(Context("session", "stage", "http://target:8080", config))
    instance.payloads = {"nucleione.oast.test": {**config.callback.probes[0], "engine": "nuclei", "probe_id": "nuclei-one"},
                         "caseone.oast.test": {**config.callback.probes[0], "engine": "testcase", "probe_id": "testcase-one",
                                               "test_case_id": "WSTG-INPV-19"}}
    instance.task = SimpleNamespace(done=lambda: False)
    return instance


@pytest.mark.asyncio
async def test_ssrf_case_uses_only_reserved_payload_and_keeps_query(monkeypatch):
    instance = collector()
    requests = []

    async def request(sandbox, data):
        requests.append(data)
        return {"status": 200, "body": "queued", "blocked": False}

    monkeypatch.setattr("orchestrator.integrations.interactsh.rpc", request)
    result = await instance.run_test_case(find_by_id("WSTG-INPV-19"), configured().callback.probes[0], object())
    assert len(requests) == 1
    query = parse_qs(urlsplit(requests[0]["request"]["url"]).query)
    assert query == {"keep": ["yes"], "url": ["https://caseone.oast.test"]}
    assert result.findings == []  # Target acceptance is not SSRF confirmation.
    assert "awaiting_callback" in result.steps[0].output
    assert instance.issued_payloads == {"caseone.oast.test"}
    assert instance.probe_evidence[0]["probe"]["test_case_id"] == "WSTG-INPV-19"
    with pytest.raises(ValueError, match="already issued"):
        await instance.run_test_case(find_by_id("WSTG-INPV-19"), configured().callback.probes[0], object())


@pytest.mark.asyncio
@pytest.mark.parametrize("target", [{"url": "http://outside:8080/fetch", "parameter": "url"},
                                  {"url": "http://target:8080/newly-discovered", "parameter": "url"},
                                  {"url": "http://target:8080/fetch?keep=yes&url=old", "parameter": "other"}])
async def test_ssrf_case_refuses_unselected_probe(target):
    with pytest.raises(ValueError, match="explicitly configured"):
        await collector().run_test_case(find_by_id("WSTG-INPV-19"), target, object())


@pytest.mark.asyncio
async def test_ssrf_case_unavailable_is_incomplete():
    instance = collector()
    instance.task = SimpleNamespace(done=lambda: True)
    with pytest.raises(RuntimeError, match="incomplete"):
        await instance.run_test_case(find_by_id("WSTG-INPV-19"), configured().callback.probes[0], object())


@pytest.mark.asyncio
async def test_ssrf_case_scope_is_rechecked_before_rpc(monkeypatch):
    from orchestrator.testcase.scope import ScopeViolation
    instance = collector()
    instance.ctx.config.scope.allow_hosts = ["other"]
    with pytest.raises(ScopeViolation):
        await instance.run_test_case(find_by_id("WSTG-INPV-19"), configured().callback.probes[0], object())
    assert not instance.issued_payloads


def test_engines_receive_separate_assignments_and_duplicates_fail():
    instance = collector()
    assignments = instance._assignments()
    assert {p["engine"] for p in assignments} == {"nuclei", "testcase"}
    instance.ctx.config.callback.probes *= 2
    with pytest.raises(ValueError, match="duplicate"):
        instance._assignments()


def test_callbacks_preserve_protocol_timestamps_without_duplicate_findings():
    instance = collector()
    events = [{"full-id": "caseone", "protocol": "dns", "timestamp": "2026-09-07T00:00:00Z"},
              {"full-id": "caseone.oast.test", "protocol": "dns", "timestamp": "2026-09-07T00:00:01Z"},
              {"full-id": "unrelated.oast.test", "protocol": "dns", "timestamp": "2026-09-07T00:00:02Z"}]
    result = correlate(events + [events[0]], instance.payloads, instance.ctx)
    assert len(result.observations) == 2
    assert len(result.findings) == 1
    assert result.findings[0].confidence == "likely"
    assert "does not prove SSRF" in result.findings[0].basis
    assert {o["probe"]["probe_id"] for o in result.observations} == {"testcase-one"}


@pytest.mark.asyncio
@pytest.mark.parametrize("poll_status,malformed,expected_status", [(200, False, "completed"), (503, False, "partial"), (200, True, "partial")])
async def test_finish_ignores_unissued_payloads_and_keeps_partial_evidence(tmp_path, monkeypatch, poll_status, malformed, expected_status):
    instance = collector()
    instance.sandbox = SimpleNamespace(output=tmp_path / "output", directory=tmp_path)
    instance.sandbox.output.mkdir()
    (tmp_path / "audit").mkdir()
    (tmp_path / "audit" / "requests.jsonl").write_text(json.dumps({"url": "https://oast.test/poll?id=example", "status": poll_status}) + "\n")
    event = {"full-id": "nucleione.oast.test", "protocol": "dns", "timestamp": "2026-09-08T00:00:00Z"}
    (instance.sandbox.output / "callbacks.jsonl").write_text(json.dumps(event) + "\n" + ("{broken\n" if malformed else ""))
    instance.task = asyncio.create_task(asyncio.Event().wait())

    async def record(ctx, sandbox, output, result):
        return result

    monkeypatch.setattr("orchestrator.integrations.interactsh.record", record)
    result = await instance.finish(wait=False)
    assert result.status == expected_status
    assert result.findings == []
    assert result.metadata["malformed_callback_records"] == int(malformed)
    if expected_status == "completed":
        assert "not proof of absence" in result.reason


@pytest.fixture
async def real_oast(tmp_path, monkeypatch):
    from orchestrator.integrations.runtime import docker, IMAGES
    from orchestrator.integrations import persistence as db
    import orchestrator.database as original
    key = uuid.uuid4().hex[:10]
    network, server, target = ("erlik-oast-" + key, "erlik-oast-server-" + key, "erlik-oast-target-" + key)
    monkeypatch.setenv("ERLIK_INTEGRATION_EGRESS_NETWORK", network)
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    await docker("network", "create", "--internal", network)
    try:
        await docker("run", "-d", "--name", server, "--network", network, "--network-alias", "oast.test",
                     "--memory=512m", "--cpus=1", "erlik-interactsh-lab:1")
        for _ in range(60):
            code, _, _ = await docker("exec", server, "python", "-c", "import socket;socket.create_connection(('127.0.0.1',443),1).close()", check=False)
            if code == 0:
                break
            await asyncio.sleep(0.2)
        else:
            _, out, err = await docker("logs", server, check=False)
            pytest.fail(out + err)
        certificate = tmp_path / "oast-ca.pem"
        await docker("cp", f"{server}:/tmp/interactsh/cert.pem", str(certificate))
        monkeypatch.setenv("ERLIK_INTEGRATION_CA_FILE", str(certificate))
        fixture = Path(__file__).resolve().parents[1] / "docker" / "interactsh-lab" / "target.py"
        await docker("run", "-d", "--name", target, "--network", network, "--network-alias", "target",
                     "-v", f"{fixture}:/lab/target.py:ro", "-v", f"{certificate}:/lab/ca.pem:ro",
                     "--entrypoint", "python", IMAGES["worker"], "/lab/target.py")
        yield {"network": network, "server": server, "target": target, "db": db}
    finally:
        await docker("rm", "-f", "-v", target, server, check=False)
        await docker("network", "rm", network, check=False)


@pytest.mark.docker
@pytest.mark.skipif(os.environ.get("ERLIK_DOCKER_TESTS") != "1" or os.environ.get("ERLIK_REAL_INTERACTSH_TESTS") != "1",
                    reason="set ERLIK_DOCKER_TESTS=1 and ERLIK_REAL_INTERACTSH_TESTS=1; build erlik-interactsh-lab:1")
@pytest.mark.asyncio
async def test_real_interactsh_dns_https_and_testcase_correlation(real_oast):
    from orchestrator.integrations.runtime import Sandbox, docker
    from orchestrator.integrations.security import SecretStore
    cfg = configured()
    cfg.callback.secret_id = SecretStore().put({"token": "erlik-isolated-lab-token"})
    cfg.budget.assessment_seconds = 120
    instance = Collector(Context("real-oast", "callback", "http://target:8080", cfg))
    try:
        await instance.start()
        assert len(instance.payloads) == 2
        async with Sandbox(cfg) as sandbox:
            await instance.probe(sandbox)
            case = await instance.run_test_case(find_by_id("WSTG-INPV-19"), cfg.callback.probes[0], sandbox)
            assert case.steps[0].success and not case.findings
        result = await instance.finish()
        assert result.status == "completed", result.model_dump()
        observations = [o for o in result.observations if o.get("type") == "oob_callback"]
        assert {o["protocol"] for o in observations} >= {"dns", "http"}, result.model_dump()
        assert {o["probe"]["engine"] for o in observations} == {"nuclei", "testcase"}
        assert len({o["probe"]["probe_id"] for o in observations}) == 2
        assert all(o["timestamp"] for o in observations)
        assert all(f.confidence == "likely" for f in result.findings)
        _, requests, _ = await docker("exec", real_oast["target"], "python", "-c",
                "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8080/requests').read().decode())")
        calls = [r for r in json.loads(requests) if r.startswith("/fetch?")]
        assert len(calls) == 2
        assert len({parse_qs(urlsplit(r).query)["url"][0] for r in calls}) == 2
    finally:
        await instance.close()


@pytest.mark.docker
@pytest.mark.skipif(os.environ.get("ERLIK_DOCKER_TESTS") != "1" or os.environ.get("ERLIK_REAL_INTERACTSH_TESTS") != "1",
                    reason="set ERLIK_DOCKER_TESTS=1 and ERLIK_REAL_INTERACTSH_TESTS=1; build erlik-interactsh-lab:1")
@pytest.mark.asyncio
async def test_real_interactsh_unavailable_polling_is_partial(real_oast):
    from orchestrator.integrations.runtime import Sandbox, docker
    from orchestrator.integrations.security import SecretStore
    cfg = configured()
    cfg.callback.secret_id = SecretStore().put({"token": "erlik-isolated-lab-token"})
    cfg.budget.assessment_seconds = 60
    instance = Collector(Context("real-oast-unavailable", "callback", "http://target:8080", cfg))
    try:
        await instance.start()
        async with Sandbox(cfg) as sandbox:
            await instance.probe(sandbox)
        await docker("stop", "-t", "1", real_oast["server"])
        result = await instance.finish()
        assert result.status == "partial", result.model_dump()
        assert "callback" in result.reason
    finally:
        await instance.close()
