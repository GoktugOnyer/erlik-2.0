"""Engagement scope — the legal boundary of a test.

Scope decides which assets someone is authorised to attack. Getting it wrong in
the permissive direction is not a wrong number in a report; it is scanning a
system nobody gave permission to scan. So the rules are tested exhaustively and
in the direction that matters: a mistake must fail CLOSED.

Three properties, each with its own failure story:

  DENY WINS — a customer who says "*.acme.com, but never prod.acme.com" has
  drawn a line no wildcard may cross.

  DISCOVERED IS NOT AUTHORISED — passive subdomain enumeration routinely
  returns shared hosting, CDN endpoints and parked names belonging to other
  people. A row nobody approved authorises nothing.

  NOTHING BY DEFAULT — an engagement with no scope rows authorises nothing.
"""

import asyncio

import aiosqlite
import pytest

from orchestrator import engagement as E


def ok(target, rows):
    return E.evaluate_scope(rows, target)[0]


DECLARED = {"source": "declared", "approved_at": "2026-08-18"}


class TestNothingIsInScopeByDefault:
    def test_empty_scope_authorises_nothing(self):
        allowed, why = E.evaluate_scope([], "https://acme.com")
        assert allowed is False
        assert "no in-scope rule" in why

    def test_unparseable_target_is_refused(self):
        assert ok("", [{"pattern": "acme.com", "kind": "domain", "in_scope": 1, **DECLARED}]) is False
        assert ok("   ", [{"pattern": "acme.com", "kind": "domain", "in_scope": 1, **DECLARED}]) is False


class TestDomainMatching:
    ROWS = [{"pattern": "acme.com", "kind": "domain", "in_scope": 1, **DECLARED}]

    @pytest.mark.parametrize("t", [
        "https://acme.com", "http://acme.com/path", "acme.com",
        "https://www.acme.com", "https://api.staging.acme.com", "acme.com:8443",
    ])
    def test_domain_and_its_subdomains_are_in_scope(self, t):
        assert ok(t, self.ROWS) is True

    @pytest.mark.parametrize("t", [
        "https://notacme.com",      # suffix match would wrongly allow this
        "https://acme.com.evil.net",
        "https://evilacme.com",
        "https://acme.org",
    ])
    def test_lookalike_domains_are_refused(self, t):
        """`notacme.com`.endswith(`acme.com`) is True. Matching by string
        suffix would place an unrelated company inside the customer's scope."""
        assert ok(t, self.ROWS) is False

    def test_trailing_dot_and_case_are_normalised(self):
        assert ok("https://WWW.Acme.COM.", self.ROWS) is True

    def test_host_kind_is_exact(self):
        rows = [{"pattern": "app.acme.com", "kind": "host", "in_scope": 1, **DECLARED}]
        assert ok("https://app.acme.com", rows) is True
        assert ok("https://other.acme.com", rows) is False
        assert ok("https://sub.app.acme.com", rows) is False


class TestDenyWins:
    ROWS = [
        {"pattern": "acme.com", "kind": "domain", "in_scope": 1, **DECLARED},
        {"pattern": "prod.acme.com", "kind": "domain", "in_scope": 0, **DECLARED},
    ]

    def test_exclusion_beats_the_wildcard(self):
        assert ok("https://staging.acme.com", self.ROWS) is True
        assert ok("https://prod.acme.com", self.ROWS) is False

    def test_exclusion_covers_subdomains_of_the_excluded_name(self):
        assert ok("https://db.prod.acme.com", self.ROWS) is False

    def test_deny_wins_regardless_of_row_order(self):
        """Order dependence here would be a coin flip over a legal boundary."""
        assert ok("https://prod.acme.com", list(reversed(self.ROWS))) is False

    def test_the_reason_names_the_rule(self):
        allowed, why = E.evaluate_scope(self.ROWS, "https://prod.acme.com")
        assert allowed is False and "prod.acme.com" in why


class TestDiscoveredIsNotAuthorised:
    def test_unapproved_discovery_is_refused_even_when_marked_in_scope(self):
        rows = [{"pattern": "vpn.acme.com", "kind": "host", "in_scope": 1,
                 "source": "discovered", "approved_at": None}]
        allowed, why = E.evaluate_scope(rows, "https://vpn.acme.com")
        assert allowed is False
        assert "approved" in why

    def test_approval_authorises_it(self):
        rows = [{"pattern": "vpn.acme.com", "kind": "host", "in_scope": 1,
                 "source": "discovered", "approved_at": "2026-08-18"}]
        assert ok("https://vpn.acme.com", rows) is True

    def test_a_declared_rule_still_covers_a_discovered_host(self):
        """If the customer authorised the whole domain, a host under it is
        allowed on the strength of the DECLARED rule."""
        rows = [{"pattern": "acme.com", "kind": "domain", "in_scope": 1, **DECLARED}]
        assert ok("https://vpn.acme.com", rows) is True


class TestIpAndCidr:
    def test_cidr_membership(self):
        rows = [{"pattern": "10.0.0.0/24", "kind": "cidr", "in_scope": 1, **DECLARED}]
        assert ok("http://10.0.0.5", rows) is True
        assert ok("http://10.0.1.5", rows) is False

    def test_malformed_cidr_refuses_rather_than_raises(self):
        rows = [{"pattern": "not-a-network", "kind": "cidr", "in_scope": 1, **DECLARED}]
        assert ok("http://10.0.0.5", rows) is False

    def test_hostname_against_cidr_does_not_crash(self):
        rows = [{"pattern": "10.0.0.0/8", "kind": "cidr", "in_scope": 1, **DECLARED}]
        assert ok("http://acme.com", rows) is False


class TestPersistence:
    @staticmethod
    def _db(tmp_path):
        async def go():
            import orchestrator.database as db_mod
            db_mod.DB_PATH = str(tmp_path / "e.db")
            await db_mod.init_db()
            return await db_mod.get_db()
        return asyncio.run(go())

    def test_create_declares_the_root_domain_as_scope(self, tmp_path, monkeypatch):
        import orchestrator.database as db_mod
        monkeypatch.setattr(db_mod, "DB_PATH", str(tmp_path / "e.db"))

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            eid = await E.create(db, "Acme Corp", "acme.com",
                                 authorised_by="J. Smith")
            allowed, _ = await E.check(db, eid, "https://api.acme.com")
            denied, _ = await E.check(db, eid, "https://notacme.com")
            rows = await E.scope_rows(db, eid)
            s = await E.summary(db, eid)
            await db.close()
            return allowed, denied, rows, s

        allowed, denied, rows, s = asyncio.run(go())
        assert allowed is True and denied is False
        assert rows and rows[0]["pattern"] == "acme.com"
        assert rows[0]["approved_at"], "a declared root domain must be authorised"
        assert s["engagement"]["client_name"] == "Acme Corp"
        assert s["counts"]["pending_scope"] == 0

    def test_discovered_host_lands_pending_and_needs_approval(self, tmp_path, monkeypatch):
        import orchestrator.database as db_mod
        monkeypatch.setattr(db_mod, "DB_PATH", str(tmp_path / "e2.db"))

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            eid = await E.create(db, "Acme", "")          # no root domain
            await E.add_scope(db, eid, "vpn.acme.com", kind="host",
                              source="discovered")
            await db.commit()
            before, why = await E.check(db, eid, "https://vpn.acme.com")
            pending = (await E.summary(db, eid))["pending_scope"]
            await E.approve_scope(db, eid, "vpn.acme.com", "operator")
            await db.commit()
            after, _ = await E.check(db, eid, "https://vpn.acme.com")
            await db.close()
            return before, why, pending, after

        before, why, pending, after = asyncio.run(go())
        assert before is False and "approved" in why
        assert len(pending) == 1
        assert after is True

    def test_existing_work_is_unassigned_not_misattributed(self, tmp_path, monkeypatch):
        """The 108 sessions recorded before engagements existed genuinely have
        no customer. Silently attaching them to one would put another client's
        data on a customer's page."""
        import orchestrator.database as db_mod
        monkeypatch.setattr(db_mod, "DB_PATH", str(tmp_path / "e3.db"))

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            await db.execute(
                "INSERT INTO sessions (id, target_url, scope_mode, system_prompt, "
                "model, enabled_tools, status) VALUES ('old','http://x','full','','m','','completed')")
            await db.commit()
            eid = await E.create(db, "Acme", "acme.com")
            s = await E.summary(db, eid)
            await db.close()
            return s

        s = asyncio.run(go())
        assert s["counts"]["sessions"] == 0, "pre-existing session was adopted"


class TestApiRefusesOutOfScope:
    """The API is where a scope mistake becomes an action. A target the
    engagement does not authorise must be refused at the boundary, not merely
    flagged in the UI."""

    @pytest.fixture(scope="class")
    def client(self, tmp_path_factory):
        """Against a TEMP database, not the live one.

        These tests drive the real API, and the API writes. Pointed at the
        production DB they created a real engagement per run — 32 rows of
        "Scope Test Co" and "Disc Co" had accumulated in the operator's
        customer list, which is both noise and, on a tool that holds client
        data, the wrong default entirely.

        get_db() reads DB_PATH at CALL time, so redirecting the module
        attribute is enough; the rest of this file already does it that way.
        """
        import warnings
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        from fastapi.testclient import TestClient
        import orchestrator.database as db_mod
        import orchestrator.main as M

        original = db_mod.DB_PATH
        db_mod.DB_PATH = str(tmp_path_factory.mktemp("api") / "t.db")
        asyncio.run(db_mod.init_db())
        try:
            yield TestClient(M.app)
        finally:
            # RESTORED, or the redirect leaks into every module that runs after
            # this one — which it did: the export tests passed alone and failed
            # in the full suite, reading an empty temp database.
            db_mod.DB_PATH = original

    def test_full_flow_and_refusal(self, client):
        r = client.post("/api/engagements",
                        json={"client_name": "Scope Test Co",
                              "root_domain": "scopetest.example",
                              "authorised_by": "tester"})
        assert r.status_code == 200, r.text
        eid = r.json()["engagement"]["id"]

        good = client.post(f"/api/engagements/{eid}/scope/check",
                           json={"target": "https://app.scopetest.example"}).json()
        assert good["allowed"] is True

        bad = client.post(f"/api/engagements/{eid}/scope/check",
                          json={"target": "https://notscopetest.example"}).json()
        assert bad["allowed"] is False

        # adding an out-of-scope target must be REFUSED, not recorded
        r = client.post(f"/api/engagements/{eid}/targets",
                        json={"base_url": "https://someoneelse.example"})
        assert r.status_code == 403, r.text
        assert "out of scope" in r.json()["detail"]

        r = client.post(f"/api/engagements/{eid}/targets",
                        json={"base_url": "https://app.scopetest.example"})
        assert r.status_code == 200
        assert r.json()["counts"]["targets"] == 1

    def test_discovered_scope_is_not_immediately_usable(self, client):
        eid = client.post("/api/engagements",
                          json={"client_name": "Disc Co"}).json()["engagement"]["id"]
        client.post(f"/api/engagements/{eid}/scope",
                    json={"pattern": "vpn.disc.example", "kind": "host",
                          "source": "discovered"})
        chk = client.post(f"/api/engagements/{eid}/scope/check",
                          json={"target": "https://vpn.disc.example"}).json()
        assert chk["allowed"] is False
        # and it must be REFUSED as a target while pending
        assert client.post(f"/api/engagements/{eid}/targets",
                           json={"base_url": "https://vpn.disc.example"}).status_code == 403
        client.post(f"/api/engagements/{eid}/scope/approve",
                    json={"pattern": "vpn.disc.example"})
        assert client.post(f"/api/engagements/{eid}/scope/check",
                           json={"target": "https://vpn.disc.example"}).json()["allowed"] is True

    def test_unknown_engagement_is_404(self, client):
        assert client.get("/api/engagements/nope").status_code == 404


class TestShellMetacharacterGate:
    """Values from a target dict are substituted into `bash -c '...'` command
    templates with no quoting of their own (runner._render is a raw string
    substitution). The gate must reject what can BREAK OUT of that quoting —
    and must not reject anything else.

    Every template in tests_catalog/wstg/ interpolates inside DOUBLE quotes
    within an outer single-quoted `bash -c`. So `&` and `;` are literal there
    and appear in ordinary URLs; refusing them would reject legitimate customer
    targets, which is a correctness failure wearing a security costume.
    """

    @pytest.mark.parametrize("url", [
        "https://app.acme.com",
        "https://app.acme.com/search?q=test&page=2&sort=desc",   # & is normal
        "https://app.acme.com/a;b/c",                            # ; is normal
        "https://acme.com:8443/path/to/thing",
        "https://acme.com/?filter=a|b",                          # | is literal
        "https://acme.com/?a=<b>",                               # < > literal
    ])
    def test_ordinary_urls_are_accepted(self, url):
        assert E.looks_injectable(url) == "", f"refused a legitimate URL: {url}"

    @pytest.mark.parametrize("bad,why", [
        ('https://acme.com/"; id; echo "', 'double quote closes the inner quote'),
        ("https://acme.com/'; id; echo '", "apostrophe closes the outer bash -c"),
        ("https://acme.com/$(id)", "command substitution"),
        ("https://acme.com/${HOME}", "parameter expansion"),
        ("https://acme.com/`id`", "backtick substitution"),
        ("https://acme.com/\\x", "backslash escape"),
        ("https://acme.com/\nid", "newline"),
    ])
    def test_breakout_characters_are_refused(self, bad, why):
        assert E.looks_injectable(bad), f"accepted a breakout payload ({why}): {bad!r}"

    def test_the_reason_names_the_character(self):
        r = E.looks_injectable("https://acme.com/$(id)")
        assert "$" in r

    def test_sweep_planner_refuses_rather_than_renders(self):
        """The planner must turn an injectable value into a NAMED SKIP, not a
        runnable case — the whole point of planning before executing."""
        from orchestrator.testcase import sweep as S
        case = {"id": "X", "name": "x", "category": "c", "severity": "low",
                "target_schema": {"required": ["url"], "optional": []}}
        tgt, why = S.build_target(case, 'https://acme.com/$(id)')
        assert tgt is None
        assert "url" in why and "$" in why

    def test_sweep_planner_still_builds_a_normal_target(self):
        """Guard on the guard: the gate must not refuse everything."""
        from orchestrator.testcase import sweep as S
        case = {"id": "X", "name": "x", "category": "c", "severity": "low",
                "target_schema": {"required": ["url"], "optional": []}}
        tgt, why = S.build_target(case, "https://acme.com/search?q=a&b=2")
        assert tgt is not None and why == ""


class TestUrlScopeKindChecksTheHost:
    """`kind='url'` matched by raw string prefix, so pattern
    "https://acme.com" authorised "https://acme.com.evil.net" — the same
    label-boundary mistake as a domain suffix match, pointing the other way."""

    ROWS = [{"pattern": "https://acme.com/app", "kind": "url", "in_scope": 1,
             **DECLARED}]

    def test_prefix_alone_no_longer_authorises_a_different_host(self):
        assert ok("https://acme.com.evil.net/app", self.ROWS) is False

    def test_the_intended_url_still_matches(self):
        assert ok("https://acme.com/app/page", self.ROWS) is True

    def test_a_different_path_on_the_same_host_is_refused(self):
        assert ok("https://acme.com/other", self.ROWS) is False



class TestTheSuiteDoesNotWriteToTheLiveDatabase:
    """Guard on the guard. An API test that writes to the operator's real
    database is a test that changes what it is measuring — and here it also put
    fictional customers in a list of real ones."""

    def test_api_tests_use_a_temp_database(self):
        import pathlib
        src = pathlib.Path(__file__).read_text()
        block = src[src.index("class TestApiRefusesOutOfScope"):]
        block = block[:block.index("\n\nclass ")] if "\n\nclass " in block else block
        assert "db_mod.DB_PATH = str(tmp_path_factory" in block, (
            "the API test client points at the live database")

    def test_no_fixture_client_names_leak_into_the_live_db(self):
        """Fails loudly if the live DB still holds test rows, so the cleanup is
        not silently forgotten."""
        import pathlib
        import sqlite3
        db = pathlib.Path(__file__).resolve().parents[1] / "data" / "pentest.db"
        if not db.exists():
            pytest.skip("no live database in this checkout")
        c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            n = c.execute(
                "SELECT COUNT(*) FROM engagements WHERE client_name IN "
                "('Scope Test Co', 'Disc Co')").fetchone()[0]
        except sqlite3.OperationalError:
            pytest.skip("engagements table not present")
        assert n == 0, f"{n} test-created engagement(s) still in the live database"


class TestAnEngagementReachesTheRunItOwns:
    """The gate existed and could never fire.

    `enforce_engagement_scope` and the `engagement_id` INSERT were both written
    and correct, and the dashboard never sent the field — so the engagements
    table had never held a row that mattered: 127 sessions, 0 with an
    engagement; 95 deterministic runs, 0 with an engagement. A boundary nothing
    can reach is not a boundary, and this is the shape of defect this project
    ships most often.
    """

    @pytest.fixture(scope="class")
    def client(self, tmp_path_factory):
        import warnings
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        from fastapi.testclient import TestClient
        import orchestrator.database as db_mod
        import orchestrator.main as M

        original = db_mod.DB_PATH
        db_mod.DB_PATH = str(tmp_path_factory.mktemp("engrun") / "t.db")
        asyncio.run(db_mod.init_db())
        try:
            yield TestClient(M.app)
        finally:
            db_mod.DB_PATH = original

    @pytest.fixture(scope="class")
    def engagement(self, client):
        r = client.post("/api/engagements",
                        json={"client_name": "Acme Corp", "root_domain": "acme.example"})
        assert r.status_code == 200, r.text
        return r.json()["engagement"]["id"]

    SESSION = {"scope_mode": "full", "model": "m", "enabled_tools": ["curl"], "max_turns": 1}
    CHAIN = {"scope_mode": "full", "model": "m", "enabled_tools": ["curl"],
             "max_turns_per_session": 1, "auto_progress": False}

    # ---- the session path -------------------------------------------------

    def test_an_in_scope_target_is_accepted_and_records_the_customer(
            self, client, engagement):
        r = client.post("/api/sessions", json={
            **self.SESSION, "target_url": "http://app.acme.example",
            "engagement_id": engagement, "authorization_ref": "SOW-2026-114"})
        assert r.status_code == 200, r.text
        import orchestrator.database as db_mod

        async def row():
            db = await db_mod.get_db()
            out = await (await db.execute(
                "SELECT engagement_id, authorization_ref FROM sessions WHERE id = ?",
                (r.json()["id"],))).fetchone()
            await db.close()
            return out

        got = asyncio.run(row())
        assert got[0] == engagement, "the run did not record its customer"
        assert got[1] == "SOW-2026-114"

    def test_an_out_of_scope_target_is_REFUSED(self, client, engagement):
        """THE point of the whole feature."""
        r = client.post("/api/sessions", json={
            **self.SESSION, "target_url": "http://not-acme.example",
            "engagement_id": engagement})
        assert r.status_code == 403, r.text
        assert "not in scope" in r.json()["detail"]

    def test_an_unknown_engagement_is_refused(self, client):
        r = client.post("/api/sessions", json={
            **self.SESSION, "target_url": "http://anywhere.example",
            "engagement_id": "no-such-engagement"})
        assert r.status_code == 404

    def test_a_run_with_no_engagement_still_works(self, client):
        """462 findings and 110 sessions predate engagements. Unassigned work
        must stay legal, or the feature is a breaking change."""
        r = client.post("/api/sessions", json={
            **self.SESSION, "target_url": "http://anywhere.example"})
        assert r.status_code == 200, r.text

    # ---- the chain path, which had NO engagement support at all ------------

    def test_a_chain_records_the_customer_and_its_children_inherit_it(
            self, client, engagement):
        """A chain is a run like any other. Before this, `engagement_id` was
        absent from ChainCreate, from the chains table and from the
        sub-session INSERT — so selecting a customer and choosing "chain" would
        have dropped it in silence."""
        r = client.post("/api/chains", json={
            **self.CHAIN, "target_url": "http://app.acme.example",
            "engagement_id": engagement, "authorization_ref": "SOW-2026-114"})
        assert r.status_code == 200, r.text
        chain_id = r.json()["id"]
        import orchestrator.database as db_mod

        async def rows():
            db = await db_mod.get_db()
            chain = await (await db.execute(
                "SELECT engagement_id, authorization_ref FROM chains WHERE id = ?",
                (chain_id,))).fetchone()
            kids = await (await db.execute(
                "SELECT engagement_id FROM sessions WHERE chain_id = ?",
                (chain_id,))).fetchall()
            await db.close()
            return chain, kids

        chain, kids = asyncio.run(rows())
        assert chain[0] == engagement
        assert chain[1] == "SOW-2026-114"
        assert kids, "the chain created no sub-session to check"
        for k in kids:
            assert k[0] == engagement, "a chain phase lost the customer"

    def test_a_chain_against_an_out_of_scope_target_is_REFUSED(
            self, client, engagement):
        r = client.post("/api/chains", json={
            **self.CHAIN, "target_url": "http://not-acme.example",
            "engagement_id": engagement})
        assert r.status_code == 403, r.text

    def test_both_paths_share_one_gate(self):
        """Two copies of a legal boundary is one copy that eventually stops
        matching the other."""
        import inspect
        import orchestrator.main as M
        for fn in (M.create_session, M.create_chain):
            assert "enforce_engagement_scope" in inspect.getsource(fn), fn.__name__

    def test_the_report_says_who_authorised_the_test(self):
        import orchestrator.main as M
        assert "SOW-2026-114" in "\n".join(
            M.render_authorization_block("SOW-2026-114"))
        assert "NOT RECORDED" in "\n".join(M.render_authorization_block(None))


class TestTheDashboardActuallySendsIt:
    """A backend field the UI never populates is the exact defect being fixed,
    so the UI wiring is asserted too."""

    @staticmethod
    def _html():
        from pathlib import Path
        return Path("dashboard/templates/index.html").read_text()

    def test_the_scanner_has_a_customer_selector_and_an_authorisation_input(self):
        html = self._html()
        assert 'id="session-engagement"' in html
        assert 'id="session-authref"' in html

    def test_the_selector_is_populated_from_the_api(self):
        html = self._html()
        assert "loadEngagementOptions" in html
        assert "'/api/engagements'" in html
        # ...and actually invoked at start-up, not merely defined.
        assert "\n        loadEngagementOptions();" in html, \
            "the loader is never called, so the selector stays empty"

    def test_both_start_paths_send_the_engagement(self):
        """/api/sessions AND /api/chains — missing either one drops the
        customer for that mode without any error."""
        html = self._html()
        assert html.count("engagement_id: engagementId") == 2, \
            "one of the two start paths does not send the engagement"
        assert html.count("authorization_ref: authorizationRef") == 2

    def test_the_values_come_from_the_inputs(self):
        html = self._html()
        assert "getElementById('session-engagement').value" in html
        assert "getElementById('session-authref').value" in html

    def test_a_refused_run_is_not_swallowed(self):
        """Both paths used to call resp.json() with no status check, so a 403
        set sessionId = undefined and the flow carried on. The gate fired and
        the operator saw nothing."""
        html = self._html()
        assert html.count("if (!resp.ok) throw new Error(await describeApiError(resp));") == 2
        assert "async function describeApiError" in html

    def test_the_test_lab_handoff_carries_the_customer(self):
        html = self._html()
        assert "function engToTestLab(url, engagementId)" in html
        assert "engToTestLab(b.dataset.engtestlab, engCurrent)" in html

    def test_the_scope_hint_follows_the_target(self):
        """The hint named the target captured when the CUSTOMER was picked, so
        it went stale the moment the operator edited the URL — telling them the
        wrong host would be checked."""
        html = self._html()
        assert 'oninput="onEngagementPicked()"' in html, \
            "editing the target no longer refreshes the scope hint"

    def test_a_client_name_cannot_inject_markup_into_the_selector(self):
        """Option text is set through new Option(), which assigns text, not
        markup — the dashboard has had an XSS through innerHTML before."""
        html = self._html()
        i = html.index("async function loadEngagementOptions")
        block = html[i:i + 1600]
        assert "new Option(" in block
        assert "innerHTML" not in block, "option list built with innerHTML"
