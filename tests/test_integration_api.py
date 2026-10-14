import json
from unittest.mock import AsyncMock
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    import orchestrator.database as database
    import orchestrator.integrations.service as service
    from orchestrator.main import app
    monkeypatch.setattr(database, "DB_DIR", tmp_path)
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "api.db")
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setenv("ERLIK_API_TOKEN", "api-test-token")
    monkeypatch.setattr(service, "recover_orphans", AsyncMock(return_value=True))
    with TestClient(app) as test_client:
        yield test_client


def test_dashboard_login_cookie_and_read_protection(client):
    assert client.get("/integrations").status_code == 200
    assert client.get("/api/sessions").status_code == 401
    assert client.post("/api/auth", json={"token": "wrong"}).status_code == 401
    response = client.post("/api/auth", json={"token": "api-test-token"})
    assert response.status_code == 200
    assert "HttpOnly" in response.headers["set-cookie"]
    assert "SameSite=strict" in response.headers["set-cookie"]
    assert client.get("/api/sessions").status_code == 200


def test_identity_secret_never_returned(client):
    client.post("/api/auth", json={"token": "api-test-token"})
    profile = {"name": "reader", "target_origin": "https://app.test", "headers": {"Authorization": "Bearer private-secret"},
               "check": {"url": "https://app.test/me", "expected_status": 200, "body_contains": "reader"}}
    saved = client.post("/api/integrations/identities", json=profile)
    assert saved.status_code == 200
    assert "private-secret" not in saved.text
    assert "private-secret" not in client.get("/api/integrations/identities").text
    identity_id = saved.json()["id"]
    profile["headers"]["Authorization"] = "Bearer replacement"
    assert client.put("/api/integrations/identities/" + identity_id, json=profile).status_code == 200
    profile["target_origin"] = "https://other.test"
    assert client.put("/api/integrations/identities/" + identity_id, json=profile).status_code == 422


def test_create_integration_assessment_and_reports(client, monkeypatch):
    import orchestrator.integrations.service as service
    monkeypatch.setattr(service, "preflight", AsyncMock())
    client.post("/api/auth", json={"token": "api-test-token"})
    response = client.post("/api/sessions", json={"target_url": "https://app.test", "integration_config": {
        "scope": {"allow_hosts": ["app.test"], "allow_ports": [443]}, "stages": ["zap"]}})
    assert response.status_code == 200, response.text
    session_id = response.json()["id"]
    state = client.get(f"/api/integrations/sessions/{session_id}").json()
    assert state["status"] == "queued"
    assert state["stages"][0]["adapter"] == "zap"
    report = client.get(f"/api/sessions/{session_id}/report.json")
    assert report.status_code == 200, report.text
    assert report.json()["engagement"]["target"] == "https://app.test"
    assert client.get(f"/api/sessions/{session_id}/report.html").status_code == 200
    assert client.get(f"/api/sessions/{session_id}/report.sarif").status_code == 200


def test_missing_scope_or_policy_rejected_before_execution(client):
    client.post("/api/auth", json={"token": "api-test-token"})
    response = client.post("/api/sessions", json={"target_url": "https://app.test", "integration_config": {"stages": ["zap"]}})
    assert response.status_code == 422


def test_list_assessments_feeds_the_picker(client, monkeypatch):
    """GET /api/integrations/sessions is what the Authorization panel's picker reads.

    It must list every assessment with the one field the cross-arm checks gate on
    (status), and it must stay target-only: the config holds operator declarations and
    lives behind the secret store, so it never travels in this list.
    """
    import orchestrator.integrations.service as service
    monkeypatch.setattr(service, "preflight", AsyncMock())
    client.post("/api/auth", json={"token": "api-test-token"})
    assert client.get("/api/integrations/sessions").json() == []
    created = client.post("/api/sessions", json={"target_url": "https://app.test", "integration_config": {
        "scope": {"allow_hosts": ["app.test"], "allow_ports": [443]}, "stages": ["zap"]}})
    session_id = created.json()["id"]

    listed = client.get("/api/integrations/sessions")
    assert listed.status_code == 200
    rows = listed.json()
    assert [row["session_id"] for row in rows] == [session_id]
    assert rows[0]["target"] == "https://app.test"
    assert rows[0]["status"] == "queued"
    # Target-only: the config (and its secret handle) must not leak into the picker feed.
    assert "config" not in rows[0] and "config_secret_id" not in rows[0]
    # And the route is read-protected like every other /api/ route.
    client.cookies.clear()
    assert client.get("/api/integrations/sessions").status_code == 401
