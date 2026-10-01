"""Candidate-playbook review (learning loop, Track A PR-A2).

Approving a candidate lets its text -- derived from attacker-influenceable
finding evidence -- enter a shell-executing agent's prompt on a future run, so
review is ADMIN ONLY, the same bar as minting an operator. A pending candidate
is never injected; the read listing is what the dashboard renders for review.
"""

import asyncio
import importlib

import pytest
from fastapi.testclient import TestClient

SHARED = "root-secret"
SH = {"X-API-Token": SHARED}


@pytest.fixture
def mod(tmp_path, monkeypatch):
    monkeypatch.setenv("ERLIK_API_TOKEN", SHARED)
    monkeypatch.delenv("ERLIK_HOST", raising=False)
    import orchestrator.database as db_mod
    monkeypatch.setattr(db_mod, "DB_DIR", tmp_path)
    monkeypatch.setattr(db_mod, "DB_PATH", tmp_path / "pentest.db")
    asyncio.run(db_mod.init_db())
    import orchestrator.main as M
    importlib.reload(M)
    yield M, db_mod
    importlib.reload(M)


@pytest.fixture
def client(mod):
    return TestClient(mod[0].app)


def _seed(db_mod, **over):
    async def go():
        db = await db_mod.get_db()
        await db.execute(
            "INSERT INTO candidate_playbooks (target_key, vuln_class, title, body, "
            "source_session_id, source_finding_id, status) VALUES (?,?,?,?,?,?,?)",
            (over.get("target_key", "t.example:80"), over.get("vuln_class", "sqli"),
             over.get("title", "SQL Injection"), over.get("body", "### play"),
             over.get("source_session_id", "s1"), over.get("source_finding_id", 1),
             over.get("status", "pending")))
        await db.commit()
        row = await (await db.execute(
            "SELECT id FROM candidate_playbooks ORDER BY id DESC LIMIT 1")).fetchone()
        await db.close()
        return row["id"]
    return asyncio.run(go())


def _mint(client, name, role="operator"):
    r = client.post("/api/operators", json={"name": name, "role": role}, headers=SH)
    assert r.status_code == 200, r.text[:300]
    return {"X-API-Token": r.json()["token"]}


class TestListing:
    def test_lists_candidates_and_filters_by_status(self, client, mod):
        _, db_mod = mod
        _seed(db_mod, status="pending")
        _seed(db_mod, status="approved")
        allc = client.get("/api/candidate-playbooks", headers=SH).json()
        assert len(allc) == 2
        pend = client.get("/api/candidate-playbooks?status=pending", headers=SH).json()
        assert len(pend) == 1 and pend[0]["status"] == "pending"


class TestReviewIsAdminOnly:
    def test_a_regular_operator_cannot_review(self, client, mod):
        _, db_mod = mod
        cid = _seed(db_mod)
        bob = _mint(client, "bob@x")
        r = client.post(f"/api/candidate-playbooks/{cid}/review",
                        json={"status": "approved"}, headers=bob)
        assert r.status_code == 403 and "admin" in r.json()["detail"]
        # and the candidate stays pending -- a denied review changes nothing
        assert client.get("/api/candidate-playbooks",
                          headers=SH).json()[0]["status"] == "pending"

    def test_an_admin_can_approve_with_attribution(self, client, mod):
        _, db_mod = mod
        cid = _seed(db_mod)
        r = client.post(f"/api/candidate-playbooks/{cid}/review",
                        json={"status": "approved", "note": "looks right"}, headers=SH)
        assert r.status_code == 200
        row = r.json()
        assert row["status"] == "approved"
        assert row["reviewed_by"] and row["reviewed_at"]
        assert row["review_note"] == "looks right"

    def test_reject_sets_rejected(self, client, mod):
        _, db_mod = mod
        cid = _seed(db_mod)
        r = client.post(f"/api/candidate-playbooks/{cid}/review",
                        json={"status": "rejected"}, headers=SH)
        assert r.status_code == 200 and r.json()["status"] == "rejected"


class TestExportNeverLeaksCandidateBodies:
    """Default-deny: a candidate body is templated from finding evidence
    (attacker-influenceable), so it must never leave via the analysis export --
    whether the table is excluded (as it is now) or someone later includes it."""

    def test_a_candidate_body_secret_never_appears_in_the_export(self, client, mod):
        _, db_mod = mod
        # A distinctive marker, deliberately NOT shaped like a real provider key
        # (that would trip push-protection); the test checks the body never
        # reaches the export, so the string only needs to be unique.
        secret = "CANDIDATE_BODY_LEAK_MARKER_7f3a"
        _seed(db_mod, body=f"### play\nleaked: {secret}\n", status="approved")
        r = client.get("/api/thesis/export", headers=SH)
        assert r.status_code == 200
        assert secret not in r.text, "candidate body leaked into the thesis export"


class TestValidation:
    def test_an_invalid_status_is_refused(self, client, mod):
        _, db_mod = mod
        cid = _seed(db_mod)
        r = client.post(f"/api/candidate-playbooks/{cid}/review",
                        json={"status": "maybe"}, headers=SH)
        assert r.status_code == 400

    def test_an_unknown_candidate_is_404(self, client):
        r = client.post("/api/candidate-playbooks/9999/review",
                        json={"status": "approved"}, headers=SH)
        assert r.status_code == 404
