"""The auth API and UI — the last mile that made credentials reachable.

`credentials.py` and `login.py` were complete, proven, and callable only by
running Python by hand. The engagement page rendered an auth badge over a store
nothing in the product could write to. Doing it by hand took the DVWA sweep
from 4 findings (all infrastructure) to 8.

THE SHAPE OF THE RISK, because it decides the design. Two things look alike:

  STORE with a hostile login_url — the caller supplies the password, so they
      exfiltrate a secret they already hold. Near worthless.
  EXECUTE an EXISTING credential against a caller-chosen URL — they obtain a
      password they do NOT hold, blind, without reading a response.

So the login route takes no URL at all.
"""

import asyncio
import inspect
import warnings

import pytest

warnings.filterwarnings("ignore", category=DeprecationWarning)

SECRET = "hunter2-must-never-appear"
T = "http://app.example"


@pytest.fixture
def client(tmp_path):
    """A real app over a real schema, with the DB globals RESTORED."""
    from fastapi.testclient import TestClient
    import orchestrator.database as db_mod
    import orchestrator.main as M
    old = db_mod.DB_DIR, db_mod.DB_PATH
    db_mod.DB_DIR = tmp_path
    db_mod.DB_PATH = str(tmp_path / "c.db")
    try:
        asyncio.run(db_mod.init_db())
        yield TestClient(M.app)
    finally:
        db_mod.DB_DIR, db_mod.DB_PATH = old


def _store(client, **over):
    body = {"target": T, "label": "ops", "username": "admin", "secret": SECRET,
            "role": "high", "login_url": "http://app.example/login"}
    body.update(over)
    return client.post("/api/v2/targets/credentials", json=body)


class TestTheSecretNeverComesBack:
    def test_the_store_response_does_not_echo_it(self, client):
        r = _store(client)
        assert r.status_code == 200, r.text
        assert SECRET not in r.text

    def test_the_listing_does_not_carry_it(self, client):
        _store(client)
        r = client.get(f"/api/v2/targets/credentials?target={T}")
        assert SECRET not in r.text
        c = r.json()["credentials"][0]
        assert c["has_secret"] is True
        for gone in ("secret_enc", "token_enc", "cookie_enc", "extra"):
            assert gone not in c, f"{gone} is exposed"

    def test_a_session_never_carries_its_material(self, client):
        """`latest_session` returns the RAW row. Anything serialising it
        straight to the page would ship encrypted session material into the
        DOM, so the session view drops those columns like `_view` does."""
        from orchestrator import credentials as C
        row = {"id": "s1", "status": "verified", "token_enc": "CIPHER",
               "cookie_enc": "CIPHER2", "header_name": "Authorization"}
        v = C.session_view(row)
        assert "token_enc" not in v and "cookie_enc" not in v
        assert v["has_token"] is True and v["has_cookie"] is True

    def test_a_validation_error_does_not_reflect_the_body(self, client):
        """FastAPI's DEFAULT 422 handler puts the request body in `input`.
        Verified on this stack before the fix: a list body and a bare JSON
        string both echoed the secret verbatim. App-wide, so every route had
        it — an error like that gets pasted into a ticket."""
        r = client.post("/api/v2/targets/credentials",
                        json=[{"secret": SECRET, "username": "admin"}])
        assert r.status_code == 422
        assert SECRET not in r.text, r.text
        r2 = client.post("/api/v2/targets/credentials",
                         content=f'"secret={SECRET}"',
                         headers={"content-type": "application/json"})
        assert SECRET not in r2.text, r2.text
        # and it must still say WHICH field and WHY
        assert "loc" in r.text and "msg" in r.text


class TestTheLoginRouteTakesNoUrl:
    """The load-bearing control. `authenticate` reads both destinations from
    the stored row; a URL parameter would let a caller send a password they do
    not know to a host they choose."""

    def test_authenticate_has_no_url_parameter(self):
        from orchestrator import login as L
        params = set(inspect.signature(L.authenticate).parameters)
        assert "verify_url" not in params, (
            "verify_url is back as a parameter — it carries the captured "
            "session to whatever host the caller names")
        assert "login_url" not in params
        assert params == {"db", "credential_id", "timeout"}

    def test_the_route_accepts_no_body(self):
        import orchestrator.main as M
        src = inspect.getsource(M.v2_credentials_login)
        assert "body" not in inspect.signature(M.v2_credentials_login).parameters
        assert "login_url" not in src.split('"""')[2], (
            "the route reads a URL from somewhere other than the stored row")

    def test_no_route_can_repoint_an_existing_credential(self):
        """A PATCH on login_url would be the worst route in the design: it
        repoints a secret the caller does not know."""
        import orchestrator.main as M
        paths = {(getattr(r, "path", ""), m)
                 for r in M.app.routes for m in (getattr(r, "methods", None) or [])}
        for p, m in paths:
            if "credential" in p and m in ("PATCH", "PUT"):
                pytest.fail(f"{m} {p} can change a stored credential in place")


class TestTheDestinationIsChecked:
    @pytest.mark.parametrize("url,fragment", [
        ("http://127.0.0.1@evil.test/login", "userinfo"),
        ("evil.test/login", "http:// or https://"),
        ("ftp://evil.test/", "http:// or https://"),
        ("http://a/`id`", "shell metacharacter"),
        ("", "is empty"),
    ])
    def test_refused(self, url, fragment):
        from orchestrator import credentials as C
        why = C.check_destination(url)
        assert why and fragment in why, f"{url!r} -> {why!r}"

    def test_a_different_host_from_the_target_is_allowed(self):
        """NOT same-host: tools address http://dvwa from inside the container
        while the login runs on the host at http://127.0.0.1:8081. Requiring
        identity would break the workflow this exists for."""
        from orchestrator import credentials as C
        assert C.check_destination("http://127.0.0.1:8081/login.php") == ""

    def test_the_route_refuses_with_a_named_reason(self, client):
        r = _store(client, login_url="http://127.0.0.1@evil.test/login")
        assert r.status_code == 400
        assert "userinfo" in r.json()["detail"]

    def test_it_is_rechecked_on_read(self):
        """A database is a trust boundary, and this row decides where a
        plaintext password is sent."""
        from orchestrator import login as L
        src = inspect.getsource(L.authenticate)
        assert "check_destination" in src, "the stored URL is trusted unchecked"


class TestRoleAndKindAreValidated:
    """ROLES existed and nothing consumed it. `role="Low"` stored happily, and
    auth_state then reported 'authenticated' with verified_roles ['Low'] while
    auth_inputs produced NO low_priv_token — so AUTHZ-04 kept skipping under a
    green badge."""

    def test_a_role_typo_is_refused(self, client):
        r = _store(client, role="Low")
        assert r.status_code == 400
        assert "role must be one of" in r.json()["detail"]

    def test_a_kind_typo_is_refused(self, client):
        r = _store(client, kind="saml")
        assert r.status_code == 400
        assert "kind must be one of" in r.json()["detail"]

    def test_the_valid_set_is_the_module_constant(self, client):
        from orchestrator import credentials as C
        for role in C.ROLES:
            assert _store(client, role=role, label=f"l-{role}").status_code == 200


class TestReStoringKeepsTheSessions:
    """A second store with the same label is just "the password changed". It
    was INSERT OR REPLACE with a fresh uuid, so it deleted the old row, minted
    a new id and ORPHANED every session — auth_state fell from 'authenticated'
    to 'credentials only' with no error, while the orphaned session went on
    resolving to the plaintext cookie forever, invisible to every read path."""

    def test_the_id_is_stable(self, client):
        a = _store(client).json()["credential_id"]
        b = _store(client, secret="new-password").json()["credential_id"]
        assert a == b, "re-storing minted a new id and orphaned the sessions"

    def test_no_session_is_orphaned(self, client, tmp_path):
        import orchestrator.database as db_mod
        from orchestrator import credentials as C
        cid = _store(client).json()["credential_id"]

        async def go():
            db = await db_mod.get_db()
            await C.save_session(db, cid, C.target_key(T), cookie="SECRET-COOKIE",
                                 status="verified")
            await db.commit()
            before = await C.auth_state(db, T)
            await C.store(db, T, "ops", "admin", "new-password", role="high",
                          login_url="http://app.example/login")
            await db.commit()
            orphans = await (await db.execute(
                "SELECT COUNT(*) FROM engagement_sessions s WHERE NOT EXISTS "
                "(SELECT 1 FROM engagement_credentials c WHERE c.id = s.credential_id)"
            )).fetchone()
            after = await C.auth_state(db, T)
            await db.close()
            return before, after, orphans[0]

        before, after, orphans = asyncio.run(go())
        assert before["state"] == "authenticated"
        assert orphans == 0, "a session points at a credential that no longer exists"
        # the old session is REVOKED, not left usable: a new password
        # invalidates what the old one bought
        assert after["state"] == "credentials only"


class TestRevokeAndDestroy:
    def test_revoke_keeps_the_row_and_stops_resolution(self, client):
        import orchestrator.database as db_mod
        from orchestrator import credentials as C
        cid = _store(client).json()["credential_id"]

        async def go():
            db = await db_mod.get_db()
            sid = await C.save_session(db, cid, C.target_key(T),
                                       cookie="SECRET-COOKIE", status="verified")
            await db.commit()
            live, _ = await C.resolve(db, C.handle(sid, "cookie"))
            await C.revoke_session(db, sid)
            await db.commit()
            dead, _ = await C.resolve(db, C.handle(sid, "cookie"))
            rows = await C.sessions_for(db, cid)
            await db.close()
            return live, dead, rows

        live, dead, rows = asyncio.run(go())
        assert "SECRET-COOKIE" in live
        assert "SECRET-COOKIE" not in dead, "a revoked session still resolves"
        assert len(rows) == 1 and rows[0]["status"] == "revoked", "the row was deleted"

    def test_destroy_removes_the_sessions_first(self, client):
        """`_plaintext` looks a session up BY ID with no join to its
        credential, so deleting the credential alone leaves the token and
        cookie fully resolvable while every read path has gone blind to
        them — strictly worse than doing nothing."""
        import orchestrator.database as db_mod
        from orchestrator import credentials as C
        cid = _store(client).json()["credential_id"]

        async def go():
            db = await db_mod.get_db()
            sid = await C.save_session(db, cid, C.target_key(T),
                                       cookie="SECRET-COOKIE", status="verified")
            await db.commit()
            await C.destroy(db, cid, by="tester")
            await db.commit()
            after, _ = await C.resolve(db, C.handle(sid, "cookie"))
            n = (await (await db.execute(
                "SELECT COUNT(*) FROM engagement_sessions")).fetchone())[0]
            tomb = await (await db.execute(
                "SELECT id, label, destroyed_by FROM destroyed_credentials")).fetchone()
            await db.close()
            return after, n, tuple(tomb) if tomb else None

        after, n, tomb = asyncio.run(go())
        assert "SECRET-COOKIE" not in after, "the session survived the destroy"
        assert n == 0
        assert tomb == (cid, "ops", "tester"), "the identifier was not kept"

    def test_the_tombstone_holds_no_ciphertext(self, client):
        """The identifier survives; the liability does not."""
        import orchestrator.database as db_mod

        async def go():
            db = await db_mod.get_db()
            cur = await db.execute("PRAGMA table_info(destroyed_credentials)")
            cols = [r[1] for r in await cur.fetchall()]
            await db.close()
            return cols

        cols = asyncio.run(go())
        assert cols, "the tombstone table is missing"
        assert not [c for c in cols if c.endswith("_enc")], cols


class TestTheBadgeDoesNotOverclaim:
    """Two verified DVWA sessions, one low one high, badge reading
    "access-control testing is possible" — and AUTHZ-04 STILL skipped with
    "needs two authenticated accounts".

    The case sends `-H "Authorization: Bearer {{low_priv_token}}"`, so it is
    bearer-only by construction, and `auth_inputs` correctly withholds those
    handles for a cookie session. DVWA — and most PHP/Rails/Django apps —
    authenticate by cookie. The badge was the thing that was wrong.
    """

    @staticmethod
    def _state(tmp_path, material):
        import orchestrator.database as db_mod
        from orchestrator import credentials as C
        old = db_mod.DB_DIR, db_mod.DB_PATH
        db_mod.DB_DIR = tmp_path
        db_mod.DB_PATH = tmp_path / "b.db"
        try:
            async def go():
                await db_mod.init_db()
                db = await db_mod.get_db()
                for role in ("low", "high"):
                    cid = await C.store(db, T, role, role, "p", role=role)
                    await C.save_session(db, cid, C.target_key(T),
                                         status="verified", **{material: "V"})
                await db.commit()
                out = await C.auth_state(db, T)
                ai = await C.auth_inputs(db, T)
                await db.close()
                return out, ai
            return asyncio.run(go())
        finally:
            db_mod.DB_DIR, db_mod.DB_PATH = old

    def test_cookie_sessions_do_not_claim_access_control_testing(self, tmp_path):
        st, ai = self._state(tmp_path, "cookie")
        assert st["verified_roles"] == ["high", "low"]
        assert st["access_control_ready"] is False
        assert "low_priv_token" not in ai, "the premise of this test moved"
        assert "COOKIE" in st["detail"] and "bearer" in st["detail"]

    def test_token_sessions_do(self, tmp_path):
        """The control: with material AUTHZ-04 can actually use, the claim is
        true and must still be made."""
        st, ai = self._state(tmp_path, "token")
        assert st["access_control_ready"] is True
        assert "access-control testing is possible" in st["detail"]
        assert "low_priv_token" in ai and "high_priv_token" in ai

    def test_the_badge_and_the_planner_agree(self, tmp_path):
        """The invariant behind both: the badge may claim access-control
        testing exactly when auth_inputs supplies what the case requires."""
        for material in ("cookie", "token"):
            st, ai = self._state(tmp_path / material, material)
            supplied = {"low_priv_token", "high_priv_token"} <= set(ai)
            assert st["access_control_ready"] is supplied, material


class TestTheUiIsWired:
    def test_the_panel_exists(self):
        from pathlib import Path
        html = Path("dashboard/templates/index.html").read_text()
        assert 'id="tl-cred-rows"' in html
        assert 'type="password"' in html, "the password field is not a password field"
        assert 'autocomplete="new-password"' in html

    def test_the_password_is_cleared_and_never_re_rendered(self):
        from pathlib import Path
        html = Path("dashboard/templates/index.html").read_text()
        i = html.index("async function tlCredStore")
        blk = html[i:i + 1800]
        assert "pass.value = ''" in blk, "the password stays in the DOM after a store"
        row = html[html.index("function tlCredRender"):][:2600]
        assert "secret" not in row.replace("secrets", ""), (
            "the row template references a secret field")

    def test_the_login_button_reports_usable_not_ok(self):
        """`authenticate` returns ok=True for a session it never verified, and
        such a session supplies nothing to a sweep."""
        from pathlib import Path
        html = Path("dashboard/templates/index.html").read_text()
        i = html.index("async function tlCredLogin")
        blk = html[i:i + 1200]
        assert "j.usable" in blk, "the button reads `ok`, which lies"
        assert "note_unverified" in blk
