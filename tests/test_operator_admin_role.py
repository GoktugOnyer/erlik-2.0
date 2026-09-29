"""Minting an identity is privileged, and an instance cannot be stranded.

Until the role existed, ANY authenticated caller could create an operator. A
stolen operator token was therefore enough to mint a second identity and
attribute work to a name nobody recognises -- which undoes the attribution the
operator model exists to provide. Only an admin may now mint, revoke or
promote.

The other half is the failure mode a role model introduces: an admin who
demotes or revokes themselves while alone leaves an instance nobody can
administer. That is recoverable only by setting ERLIK_API_TOKEN again -- the
credential this whole design exists to let a deployment retire -- so both
paths refuse.

Two decisions worth stating, because both are load-bearing:

  * `opr_shared_token` is admin. ERLIK_API_TOKEN is the deployment's root
    secret; it has to be able to mint the FIRST admin or none can ever exist.
    Once one does, the secret can be unset and the bootstrap path closes.
  * it does NOT count toward the admin quorum. Counting it would let the last
    human admin be removed on the grounds that the shared secret could still
    act -- making the guard weakest exactly where the instance is most locked
    down.
"""

import asyncio
import importlib

import pytest
from fastapi.testclient import TestClient

from orchestrator import operators as O

SHARED = "root-secret"
SH = {"X-API-Token": SHARED}


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("ERLIK_API_TOKEN", SHARED)
    monkeypatch.delenv("ERLIK_HOST", raising=False)
    import orchestrator.database as db_mod
    monkeypatch.setattr(db_mod, "DB_DIR", tmp_path)
    monkeypatch.setattr(db_mod, "DB_PATH", tmp_path / "pentest.db")
    asyncio.run(db_mod.init_db())
    import orchestrator.main as M
    importlib.reload(M)
    yield M
    importlib.reload(M)


@pytest.fixture
def client(app):
    return TestClient(app.app)


def _mint(client, name, role="operator", headers=SH):
    r = client.post("/api/operators", json={"name": name, "role": role},
                    headers=headers)
    assert r.status_code == 200, r.text[:300]
    return r.json()


def _hdr(op):
    return {"X-API-Token": op["token"]}


class TestOnlyAnAdminMayMint:
    """The escalation this closes."""

    def test_a_regular_operator_cannot_mint(self, client):
        bob = _mint(client, "bob@x")
        r = client.post("/api/operators", json={"name": "mallory@x"},
                        headers=_hdr(bob))
        assert r.status_code == 403
        assert "admin" in r.json()["detail"]

    def test_a_regular_operator_cannot_revoke(self, client):
        bob, vic = _mint(client, "bob@x"), _mint(client, "victim@x")
        r = client.post(f"/api/operators/{vic['id']}/revoke", headers=_hdr(bob))
        assert r.status_code == 403

    def test_a_regular_operator_cannot_promote_themselves(self, client):
        """The obvious escalation if role changes were not gated."""
        bob = _mint(client, "bob@x")
        r = client.post(f"/api/operators/{bob['id']}/role",
                        json={"role": "admin"}, headers=_hdr(bob))
        assert r.status_code == 403
        assert client.get("/api/whoami", headers=_hdr(bob)).json()["role"] == "operator"

    def test_an_admin_can(self, client):
        """Negative control: minting stays possible, it does not just break."""
        alice = _mint(client, "alice@x", role="admin")
        r = client.post("/api/operators", json={"name": "carol@x"},
                        headers=_hdr(alice))
        assert r.status_code == 200

    def test_a_new_operator_is_not_an_admin_by_default(self, client):
        assert _mint(client, "dave@x")["role"] == "operator"

    def test_the_default_is_in_create_itself_not_just_the_endpoint(self, tmp_path):
        """Two defaults exist -- the endpoint's and `create()`'s -- and the
        endpoint always passes `role` explicitly, so its own default masks the
        function's. Flipping `create()` to ROLE_ADMIN left every test in this
        file green; a script or CLI calling it directly would have been handed
        admin. Asserted on the function, where the hazard is.
        """
        import asyncio
        import inspect

        import orchestrator.database as db_mod
        assert inspect.signature(O.create).parameters["role"].default == \
            O.ROLE_OPERATOR

        old = db_mod.DB_DIR, db_mod.DB_PATH
        db_mod.DB_DIR, db_mod.DB_PATH = tmp_path, tmp_path / "d.db"
        try:
            async def go():
                await db_mod.init_db()
                db = await db_mod.get_db()
                try:
                    made = await O.create(db, "scripted@x")
                    return made["role"]
                finally:
                    await db.close()
            assert asyncio.run(go()) == O.ROLE_OPERATOR
        finally:
            db_mod.DB_DIR, db_mod.DB_PATH = old

    def test_an_unknown_role_is_refused(self, client):
        r = client.post("/api/operators", json={"name": "x", "role": "superuser"},
                        headers=SH)
        assert r.status_code == 400


class TestTheBootstrapPath:
    def test_the_shared_token_is_admin(self, client):
        """It has to be, or the first admin can never be created."""
        assert client.get("/api/whoami", headers=SH).json()["role"] == "admin"

    def test_it_can_mint_the_first_admin(self, client):
        assert _mint(client, "alice@x", role="admin")["role"] == "admin"

    def test_it_is_still_not_a_person(self, client):
        """Admin does not make it attributable. A run stamped with it is
        authenticated and unattributed, whatever it is allowed to do."""
        me = client.get("/api/whoami", headers=SH).json()
        assert me["role"] == "admin"
        assert me["attributable"] is False

    def test_an_upgrade_does_not_hand_out_admin(self, client, tmp_path):
        """Rows that existed before the column default to 'operator'. Silently
        promoting them would give privileges nobody granted."""
        import sqlite3
        con = sqlite3.connect(tmp_path / "pentest.db")
        con.execute("INSERT INTO operators (id, name, token_hash) "
                    "VALUES ('opr_old', 'pre-existing', 'somehash')")
        con.commit()
        role = con.execute("SELECT role FROM operators WHERE id='opr_old'").fetchone()[0]
        assert role == "operator"


class TestTheInstanceCannotBeStranded:
    def test_the_last_admin_cannot_demote_themselves(self, client):
        alice = _mint(client, "alice@x", role="admin")
        r = client.post(f"/api/operators/{alice['id']}/role",
                        json={"role": "operator"}, headers=_hdr(alice))
        assert r.status_code == 409
        assert "last active admin" in r.json()["detail"]

    def test_the_last_admin_cannot_revoke_themselves(self, client):
        alice = _mint(client, "alice@x", role="admin")
        r = client.post(f"/api/operators/{alice['id']}/revoke", headers=_hdr(alice))
        assert r.status_code == 409

    def test_with_a_second_admin_both_are_allowed(self, client):
        """Negative control. The guard must be about the LAST admin, not about
        admins in general -- otherwise it is just a broken endpoint."""
        alice = _mint(client, "alice@x", role="admin")
        bob = _mint(client, "bob@x", role="admin")
        assert client.post(f"/api/operators/{alice['id']}/role",
                           json={"role": "operator"},
                           headers=_hdr(bob)).status_code == 200

    def test_the_shared_token_does_not_count_as_an_admin(self, client):
        """The load-bearing choice. If it counted, the last human admin could
        be removed because the shared secret could still act -- weakest
        exactly where a deployment has locked itself down most."""
        alice = _mint(client, "alice@x", role="admin")
        r = client.post(f"/api/operators/{alice['id']}/revoke", headers=SH)
        assert r.status_code == 409, (
            "the shared token was counted toward the admin quorum"
        )

    def test_a_revoked_admin_does_not_count_either(self, client):
        alice = _mint(client, "alice@x", role="admin")
        bob = _mint(client, "bob@x", role="admin")
        client.post(f"/api/operators/{bob['id']}/revoke", headers=SH)
        r = client.post(f"/api/operators/{alice['id']}/revoke", headers=SH)
        assert r.status_code == 409, "a revoked admin was counted as active"

    def test_a_regular_operator_is_freely_revokable(self, client):
        bob = _mint(client, "bob@x")
        assert client.post(f"/api/operators/{bob['id']}/revoke",
                           headers=SH).status_code == 200


class TestRoleChangesAreTraceable:
    def test_a_promotion_records_who_did_it(self, client):
        """The one action that changes who can create identities."""
        alice = _mint(client, "alice@x", role="admin")
        bob = _mint(client, "bob@x")
        client.post(f"/api/operators/{bob['id']}/role", json={"role": "admin"},
                    headers=_hdr(alice))
        row = [o for o in client.get("/api/operators", headers=SH).json()["operators"]
               if o["id"] == bob["id"]][0]
        assert row["role"] == "admin"
        assert row["role_changed_by"] == alice["id"]
        assert row["role_changed_at"]

    def test_minting_records_the_granting_admin(self, client):
        alice = _mint(client, "alice@x", role="admin")
        carol = _mint(client, "carol@x", role="admin", headers=_hdr(alice))
        row = [o for o in client.get("/api/operators", headers=SH).json()["operators"]
               if o["id"] == carol["id"]][0]
        assert row["created_by"] == alice["id"]
        assert row["role_changed_by"] == alice["id"]


class TestTheSyntheticIdentitiesAreNotAccounts:
    @pytest.mark.parametrize("sid", [O.SHARED_TOKEN_OPERATOR,
                                     O.UNAUTHENTICATED_OPERATOR])
    def test_their_role_cannot_be_changed(self, client, sid):
        r = client.post(f"/api/operators/{sid}/role", json={"role": "operator"},
                        headers=SH)
        assert r.status_code == 400

    @pytest.mark.parametrize("sid", [O.SHARED_TOKEN_OPERATOR,
                                     O.UNAUTHENTICATED_OPERATOR])
    def test_they_cannot_be_revoked(self, client, sid):
        assert client.post(f"/api/operators/{sid}/revoke",
                           headers=SH).status_code == 404


class TestListingStaysSafe:
    def test_the_roster_shows_roles_and_no_secrets(self, client):
        op = _mint(client, "alice@x", role="admin")
        blob = repr(client.get("/api/operators", headers=SH).json())
        assert '"role"' in blob or "'role'" in blob
        assert op["token"] not in blob
        assert "token_hash" not in blob
