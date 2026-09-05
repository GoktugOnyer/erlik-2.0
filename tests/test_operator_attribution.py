"""Who ran this test.

`ERLIK_API_TOKEN` is one shared secret. It authenticates a REQUEST and
identifies NOBODY, so nothing in the database could be attributed to a person.
`engagement_revisions` is the sharpest case: it exists to be an audit trail and
recorded the field, the old value, the new value and the timestamp -- every
column except the one an audit trail is for.

For a lab that is a shrug. For a paid engagement it is evidentiary: a client
asking "who ran this against our production estate, and who changed the
authorisation record" could not be answered from the data.

An operator is now a named row with their own token. These tests hold the two
properties that make that worth having -- the answer is recorded, and it is
never invented -- plus the one that separates it from a shared secret: access
can be withdrawn from one person without rotating everyone else's token.
"""

import asyncio
import importlib
import pathlib
import sqlite3

import pytest
from fastapi.testclient import TestClient

from orchestrator import operators as O

SHARED = "shared-bootstrap-secret"


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


SH = {"X-API-Token": SHARED}


def _new_engagement(client, headers) -> str:
    """The create endpoint nests the record under `engagement`; read it the way
    the API actually returns it rather than the way it would be convenient."""
    r = client.post("/api/engagements", json={"client_name": "Acme"},
                    headers=headers)
    assert r.status_code == 200, r.text[:300]
    return r.json()["engagement"]["id"]



def _mint(client, name="alice@pentest.example"):
    r = client.post("/api/operators", json={"name": name}, headers=SH)
    assert r.status_code == 200, r.text[:300]
    return r.json()


class TestTheSharedTokenIsHonestAboutItself:
    """It authenticates and identifies nobody, and must say so. Presenting it
    as an operator would be the interface describing something that did not
    happen."""

    def test_it_resolves_to_a_named_non_person(self, client):
        me = client.get("/api/whoami", headers=SH).json()
        assert me["operator_id"] == O.SHARED_TOKEN_OPERATOR
        assert me["attributable"] is False

    def test_its_label_does_not_read_like_a_name(self, client):
        me = client.get("/api/whoami", headers=SH).json()
        assert "not attributed" in me["name"]

    def test_an_edit_it_makes_is_recorded_as_unattributed(self, client):
        eid = _new_engagement(client, SH)
        client.put(f"/api/engagements/{eid}", json={"notes": "x"}, headers=SH)
        rev = client.get(f"/api/engagements/{eid}/revisions",
                         headers=SH).json()["revisions"][0]
        assert rev["operator_id"] == O.SHARED_TOKEN_OPERATOR
        assert O.is_attributable(rev["operator_id"]) is False


class TestAnOperatorIsRecorded:
    def test_whoami_names_them(self, client):
        op = _mint(client)
        me = client.get("/api/whoami",
                        headers={"X-API-Token": op["token"]}).json()
        assert me["operator_id"] == op["id"]
        assert me["name"] == "alice@pentest.example"
        assert me["attributable"] is True

    def test_an_engagement_edit_names_them(self, client):
        """The gap this closes. Before, this row had no actor column at all."""
        op = _mint(client)
        h = {"X-API-Token": op["token"]}
        eid = _new_engagement(client, h)
        client.put(f"/api/engagements/{eid}",
                   json={"authorised_by": "CISO, Acme"}, headers=h)
        rev = client.get(f"/api/engagements/{eid}/revisions",
                         headers=h).json()["revisions"][0]
        assert rev["field"] == "authorised_by"
        assert rev["operator_id"] == op["id"]
        assert rev["name"] == "alice@pentest.example"

    def test_two_operators_are_told_apart(self, client):
        """One shared secret cannot do this, which is the whole point."""
        a, b = _mint(client, "alice@x"), _mint(client, "bob@x")
        eid = _new_engagement(client, SH)
        client.put(f"/api/engagements/{eid}", json={"notes": "n1"},
                   headers={"X-API-Token": a["token"]})
        client.put(f"/api/engagements/{eid}", json={"authorised_by": "x"},
                   headers={"X-API-Token": b["token"]})
        revs = client.get(f"/api/engagements/{eid}/revisions",
                          headers=SH).json()["revisions"]
        by = {r["field"]: r["name"] for r in revs}
        assert by["notes"] == "alice@x"
        assert by["authorised_by"] == "bob@x"

    def test_a_session_records_its_operator(self, client, tmp_path):
        op = _mint(client)
        r = client.post("/api/sessions",
                        json={"target_url": "http://127.0.0.1:9000/"},
                        headers={"X-API-Token": op["token"]})
        assert r.status_code == 200, r.text[:300]
        con = sqlite3.connect(tmp_path / "pentest.db")
        got = con.execute("SELECT operator_id FROM sessions").fetchall()
        assert got == [(op["id"],)], got


class TestAccessCanBeWithdrawnFromOnePerson:
    """The difference between an account model and a shared secret."""

    def test_a_revoked_token_stops_working(self, client):
        op = _mint(client)
        h = {"X-API-Token": op["token"]}
        assert client.get("/api/whoami", headers=h).status_code == 200
        assert client.post(f"/api/operators/{op['id']}/revoke",
                           headers=SH).status_code == 200
        assert client.get("/api/whoami", headers=h).status_code == 401

    def test_everyone_else_is_unaffected(self, client):
        a, b = _mint(client, "alice@x"), _mint(client, "bob@x")
        client.post(f"/api/operators/{a['id']}/revoke", headers=SH)
        assert client.get("/api/whoami",
                          headers={"X-API-Token": b["token"]}).status_code == 200
        assert client.get("/api/whoami", headers=SH).status_code == 200

    def test_their_history_survives_revocation(self, client):
        """The row is never deleted. Deleting it would turn a run that IS
        attributable into one that reads as unattributed -- destroying the
        record instead of ending the access."""
        op = _mint(client)
        eid = _new_engagement(client, {"X-API-Token": op["token"]})
        client.put(f"/api/engagements/{eid}", json={"notes": "n"},
                   headers={"X-API-Token": op["token"]})
        client.post(f"/api/operators/{op['id']}/revoke", headers=SH)
        rev = client.get(f"/api/engagements/{eid}/revisions",
                         headers=SH).json()["revisions"][0]
        assert rev["name"] == "alice@pentest.example"

    def test_the_synthetic_identities_cannot_be_revoked(self, client):
        """They are not accounts. Revoking `opr_shared_token` would either do
        nothing or lock out the bootstrap path; neither is a coherent action."""
        for sid in (O.SHARED_TOKEN_OPERATOR, O.UNAUTHENTICATED_OPERATOR):
            assert client.post(f"/api/operators/{sid}/revoke",
                               headers=SH).status_code == 404


class TestTokensAreNotStoredOrLeaked:
    def test_the_token_is_never_returned_again(self, client):
        op = _mint(client)
        listing = client.get("/api/operators", headers=SH).json()["operators"]
        blob = repr(listing)
        assert op["token"] not in blob
        assert "token_hash" not in blob

    def test_the_plaintext_is_not_in_the_database(self, client, tmp_path):
        op = _mint(client)
        raw = (tmp_path / "pentest.db").read_bytes()
        assert op["token"].encode() not in raw

    def test_the_stored_form_is_a_hash_of_it(self, client, tmp_path):
        op = _mint(client)
        con = sqlite3.connect(tmp_path / "pentest.db")
        stored = con.execute("SELECT token_hash FROM operators WHERE id = ?",
                             (op["id"],)).fetchone()[0]
        assert stored == O.token_hash(op["token"])
        assert stored != op["token"]

    def test_a_token_in_free_text_is_redactable(self):
        """Tokens reach logs and step output by ordinary accident. The prefix
        is what makes that recoverable."""
        t = O.new_token()
        out = O.redact(f'curl -H "X-API-Token: {t}" http://target/')
        assert t not in out
        assert "<redacted>" in out

    def test_the_redactor_would_notice_if_the_format_changed(self):
        """Guard on the guard: if the token format drifts from the regex, the
        test above passes on a string it no longer needs to mask."""
        assert O.looks_like_token(O.new_token())
        assert O.redact("nothing here") == "nothing here"


class TestNothingIsInvented:
    def test_an_unknown_token_is_refused_not_guessed(self, client):
        r = client.get("/api/whoami", headers={"X-API-Token": O.new_token()})
        assert r.status_code == 401

    def test_rows_written_before_this_read_as_unattributed(self, client, tmp_path):
        """A NULL operator_id is real: those rows predate attribution. It must
        surface as unattributed, never as whoever happens to be first."""
        eid = _new_engagement(client, SH)
        con = sqlite3.connect(tmp_path / "pentest.db")
        con.execute("INSERT INTO engagement_revisions "
                    "(engagement_id, field, old_value, new_value, operator_id) "
                    "VALUES (?,?,?,?,NULL)", (eid, "notes", "a", "b"))
        con.commit()
        revs = client.get(f"/api/engagements/{eid}/revisions",
                          headers=SH).json()["revisions"]
        old = [r for r in revs if r["field"] == "notes"][0]
        assert old["operator_id"] is None
        assert old["name"] is None
        assert O.is_attributable(old["operator_id"]) is False

    def test_an_operator_records_who_created_it(self, client):
        """Any authenticated caller can mint one, so provenance is the only
        thing that makes a forged name traceable."""
        op = _mint(client)
        row = [o for o in client.get("/api/operators", headers=SH).json()["operators"]
               if o["id"] == op["id"]][0]
        assert row["created_by"] == O.SHARED_TOKEN_OPERATOR

    def test_a_nameless_operator_is_refused(self, client):
        assert client.post("/api/operators", json={"name": "  "},
                           headers=SH).status_code == 400
