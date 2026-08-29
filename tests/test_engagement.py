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


def js_body(html, signature):
    """A JS function's actual body, by brace matching.

    Fixed character windows are brittle and were wrong twice: one test used
    2200 characters and the call sat at 2270; another used 2600 and a
    truncation note pushed the columns past it. Both failed on formatting
    rather than on behaviour, which trains you to widen the number instead of
    reading the diff.
    """
    i = html.index(signature)
    depth = 0
    for k in range(html.index("{", i), len(html)):
        if html[k] == "{":
            depth += 1
        elif html[k] == "}":
            depth -= 1
            if depth == 0:
                return html[i:k + 1]
    raise AssertionError(f"unbalanced braces after {signature!r}")


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


class TestTheExecutorEnforcesTheEngagementScope:
    """The API gate and the execution guard enforced DIFFERENT boundaries.

    `tool_executor._scope_violation` allowed any subdomain of the SESSION's
    target, never read `engagement_scope`, could be switched off with
    ERLIK_SCOPE_ENFORCE=0, and returned "no opinion" whenever `target_url` was
    falsy — which is exactly how recon.py calls it, so subdomain enumeration
    and liveness probing ran with no scope check at all.

    So the front door was locked (see TestAnEngagementReachesTheRunItOwns)
    while the tool that actually touches the customer was not.
    """

    DECLARED = [{"pattern": "acme.example", "kind": "domain", "in_scope": 1,
                 "source": "declared", "approved_at": "2026-08-28",
                 "approved_by": None}]
    EXCLUDED = DECLARED + [{"pattern": "vpn.acme.example", "kind": "host",
                            "in_scope": 0, "source": "declared",
                            "approved_at": "2026-08-28", "approved_by": None}]

    @staticmethod
    def _check(command, rows, target_url=None):
        from orchestrator.tool_executor import _scope_violation
        return _scope_violation(command, target_url, rows)

    def test_an_in_scope_host_is_allowed(self):
        assert self._check("curl http://app.acme.example/", self.DECLARED) is None

    def test_a_host_outside_the_engagement_is_refused(self):
        why = self._check("curl http://not-acme.example/", self.DECLARED)
        assert why and "outside the engagement" in why

    def test_an_EXCLUDED_host_is_refused_even_though_it_is_a_subdomain(self):
        """The old guard allowed any subdomain of the session target, so a host
        the customer explicitly carved OUT still ran."""
        why = self._check("curl http://vpn.acme.example/", self.EXCLUDED)
        assert why, "an explicitly excluded host was allowed"

    def test_a_discovered_but_unapproved_host_is_refused(self):
        """Recon writes candidates; approval is a human act. If the executor
        ignored that, the approval workflow would be decorative at the one
        point it matters."""
        rows = self.DECLARED + [{"pattern": "shared.acme.example", "kind": "host",
                                 "in_scope": 1, "source": "discovered",
                                 "approved_at": None, "approved_by": None}]
        # ...but it IS under the declared domain, so the declared rule covers
        # it. Use a host outside the domain, which only the candidate names.
        rows = [{"pattern": "cdn.other.example", "kind": "host", "in_scope": 1,
                 "source": "discovered", "approved_at": None, "approved_by": None}]
        assert self._check("curl http://cdn.other.example/", rows)

    def test_ERLIK_SCOPE_ENFORCE_0_CANNOT_disable_it(self, monkeypatch):
        """An engagement is a legal boundary; an environment variable must not
        be able to switch it off."""
        monkeypatch.setenv("ERLIK_SCOPE_ENFORCE", "0")
        from orchestrator.tool_executor import _scope_enforced
        assert _scope_enforced() is False, "fixture did not actually disable it"
        assert self._check("curl http://not-acme.example/", self.DECLARED), \
            "an env var switched off the customer's legal boundary"

    def test_a_missing_target_url_does_not_disable_it(self):
        """THE recon hole. `not target_url` returned None, and recon.py calls
        execute_tool without one."""
        assert self._check("httpx -u http://not-acme.example", self.DECLARED,
                           target_url=None), \
            "enumeration ran unchecked because no target_url was supplied"

    def test_with_no_engagement_behaviour_is_unchanged(self):
        """110 sessions predate engagements. None must mean "no opinion" —
        an empty list would mean "nothing is authorised" and refuse everything."""
        assert self._check("curl http://anything.example/", None) is None
        assert self._check("curl http://anything.example/", []) is None

    def test_out_of_band_callback_domains_are_still_allowed(self):
        """erlik's own detection infrastructure, not a customer asset. Blind
        SSRF/XXE detection is unusable without it."""
        assert self._check("curl http://abc.oast.fun/x", self.DECLARED) is None

    def test_both_guards_use_the_same_matcher(self):
        """Two implementations of one legal boundary is one implementation that
        eventually stops matching the other — which is what happened."""
        import inspect
        from orchestrator import tool_executor as T
        assert "evaluate_scope" in inspect.getsource(T._engagement_violation)


class TestTheEngagementRulesActuallyReachTheExecutor:
    """A guard nothing supplies rules to is another producer with no consumer."""

    def test_the_agent_loop_loads_and_passes_them(self):
        import inspect
        import orchestrator.main as M
        src = inspect.getsource(M.agent_loop)
        assert "engagement_rows_for_session" in src, \
            "the agent loop never loads the customer's scope"
        assert "engagement_rows=_eng_rows" in src, \
            "the loop loads the scope but never hands it to the executor"

    def test_recon_passes_them_on_both_active_paths(self):
        import inspect
        from orchestrator import recon as R
        run_src = inspect.getsource(R.run)
        assert "engagement_rows=_rows" in run_src
        assert "engagement_rows=rows" in run_src
        for fn in (R.enumerate_passive, R.probe_live):
            assert "engagement_rows=engagement_rows" in inspect.getsource(fn), fn.__name__

    def test_an_unassigned_session_yields_None_not_empty(self):
        """Returning [] would refuse every command on a run with no customer."""
        import inspect
        import orchestrator.main as M
        src = inspect.getsource(M.engagement_rows_for_session)
        assert "return None" in src
        assert "[]" not in src.split('"""')[2], "an empty list would deny everything"


class TestTheWorkspaceSidebar:
    """The dashboard was eight top tabs and nothing else: the operator could
    not see what a customer's engagement contained without opening a view and
    waiting for a fetch. These counts ARE the state of the work — what has been
    found, on whose assets, and what has actually been run.
    """

    @staticmethod
    def _html():
        from pathlib import Path
        return Path("dashboard/templates/index.html").read_text()

    def test_the_sidebar_exists_and_wraps_the_page(self):
        html = self._html()
        assert 'id="app-sidebar"' in html
        assert 'class="app-shell"' in html
        assert ".app-shell { display: flex" in html, "the shell has no layout"

    def test_navigation_moved_into_the_sidebar_without_losing_a_view(self):
        """switchView() is id-based, so every nav id must survive the move or
        that view becomes unreachable."""
        html = self._html()
        for view in ("scanner", "reports", "benchmark", "monitor",
                     "engagements", "testlab", "skills", "arsenal"):
            assert f'id="nav-{view}"' in html, view
        i = html.index('id="app-sidebar"')
        j = html.index("</aside>")
        sidebar = html[i:j]
        for view in ("scanner", "engagements", "testlab", "arsenal"):
            assert f'id="nav-{view}"' in sidebar, f"{view} nav is not in the sidebar"

    def test_the_sidebar_shows_assets_findings_and_activity(self):
        html = self._html()
        for el in ("side-assets", "side-findings", "side-activity"):
            assert f'id="{el}"' in html, el

    def test_the_counts_come_from_the_engagement_summary(self):
        html = self._html()
        assert "asset_counts" in html and "findings_by_severity" in html
        assert "/api/engagements/${encodeURIComponent(id)}" in html

    def test_the_sidebar_is_populated_at_start_up(self):
        assert "\n        sideLoadEngagements();" in self._html(), \
            "the sidebar loader is never called, so it stays empty"

    def test_customer_selection_is_two_way(self):
        """One customer, one run: the counts on screen must describe the
        engagement the next run will be recorded against."""
        html = self._html()
        assert "function sideEngagementPicked" in html
        assert "getElementById('session-engagement')" in html[html.index("function sideEngagementPicked"):][:900]
        i = html.index("function onEngagementPicked")
        assert "side-engagement" in html[i:i + 900], \
            "picking a customer in the Scanner does not update the sidebar"

    def test_a_client_name_cannot_inject_markup_into_the_sidebar(self):
        html = self._html()
        i = html.index("async function sideLoadEngagements")
        block = html[i:i + 1400]
        assert "new Option(" in block
        assert "innerHTML" not in block

    def test_counts_are_escaped_where_they_are_rendered(self):
        html = self._html()
        i = html.index("function sideCount")
        assert "tlEsc(label)" in html[i:i + 500]


class TestTheEngagementPageAnswersWhatHappened:
    """It listed run IDs and nothing else, so "what has actually happened for
    this customer" took reading a list of hex strings."""

    @staticmethod
    def _html():
        from pathlib import Path
        return Path("dashboard/templates/index.html").read_text()

    def test_there_are_count_cards(self):
        html = self._html()
        assert "function engStatCards" in html
        assert "${engStatCards(d)}" in html, "the cards are built but never rendered"
        assert ".stat-card {" in html

    def test_there_is_an_execution_table_with_status_and_duration(self):
        html = self._html()
        assert "function engRunTable" in html
        assert "${engRunTable(d)}" in html, "the table is built but never rendered"
        block = js_body(html, "function engRunTable(d) {")
        for col in ("Status", "Started", "Duration"):
            assert col in block, col

    def test_the_table_covers_BOTH_lanes(self):
        """A customer page that showed only agent runs would misrepresent the
        deterministic lane as idle."""
        block = js_body(self._html(), "function engRunTable(d) {")
        assert "d.sessions" in block and "d.v2_runs" in block

    def test_duration_is_formatted_not_raw_milliseconds(self):
        html = self._html()
        assert "function fmtDuration" in html
        i = html.index("function fmtDuration")
        assert "m " in html[i:i + 400]

    def test_the_summary_supplies_duration(self):
        """The table cannot show a duration the API does not return."""
        import inspect
        from orchestrator import engagement as E
        src = inspect.getsource(E.summary)
        assert "total_duration_ms" in src
        assert "duration_ms" in src

    def test_the_summary_query_only_selects_columns_that_exist(self):
        """`findings_count` was written into the v2_runs SELECT and does not
        exist on that table — it would have raised on every engagement page."""
        import asyncio
        import inspect
        import sqlite3
        import tempfile
        import os
        from orchestrator import engagement as E
        import orchestrator.database as db_mod

        src = inspect.getsource(E.summary)
        assert "findings_count" not in src

        old = db_mod.DB_PATH
        db_mod.DB_PATH = os.path.join(tempfile.mkdtemp(), "sum.db")
        try:
            async def go():
                await db_mod.init_db()
                db = await db_mod.get_db()
                eid = await E.create(db, "Acme", "acme.example")
                await db.commit()
                out = await E.summary(db, eid)   # raises if a column is wrong
                await db.close()
                return out
            out = asyncio.run(go())
            assert "counts" in out and "asset_counts" in out
        finally:
            db_mod.DB_PATH = old


class TestTheParityToolsetIsReachable:
    """Nine tools a working pentester expects that erlik did not have.

    A tool counts only when all three hold: registered with a timeout, enabled
    by default, and installed in the image. Two of the three is the shape that
    keeps biting — a tool declared but absent reports a failed scan, and a tool
    installed but undeclared can never be selected.
    """

    NEW = ["theHarvester", "dirsearch", "sslscan", "ssh-audit", "smbmap",
           "gitleaks", "cmseek", "joomscan", "searchsploit"]

    def test_every_new_tool_has_a_timeout(self):
        from orchestrator.tool_executor import TOOL_TIMEOUTS
        for t in self.NEW:
            assert t in TOOL_TIMEOUTS, f"{t} would fall back to the 60s default"

    def test_every_new_tool_is_enabled_by_default(self):
        from orchestrator.models import _DEFAULT_TOOLS
        for t in self.NEW:
            assert t in _DEFAULT_TOOLS, f"{t} can never be selected"

    def test_every_registered_tool_has_a_timeout(self):
        """Guard on the whole registry, not just the new rows."""
        from orchestrator.models import _DEFAULT_TOOLS
        from orchestrator.tool_executor import TOOL_TIMEOUTS
        missing = [t for t in _DEFAULT_TOOLS if t not in TOOL_TIMEOUTS]
        assert not missing, missing

    def test_the_image_installs_them(self):
        """Anchored to the apt-get INSTALL LINE, not the file.

        The first version searched the whole Dockerfile and passed with the
        package deleted from the install list, because every tool is also
        named in the comment block above it. A test that a comment satisfies
        is not a test."""
        import re
        from pathlib import Path
        docker = Path("Dockerfile.kali").read_text()
        m = re.search(r"apt-get install -y --no-install-recommends\s*\\\s*\n"
                      r"((?:\s+[a-z0-9.\-+ ]+\\?\s*\n)+?)\s*&&\s*echo \"\[erlik\] rekono-parity",
                      docker)
        assert m, "the parity install step is gone from Dockerfile.kali"
        packages = set(m.group(1).replace("\\", " ").split())
        for t in ("theharvester", "dirsearch", "sslscan", "gitleaks",
                  "ssh-audit", "smbmap", "cmseek", "joomscan", "exploitdb"):
            assert t in packages, (
                f"{t} is registered but is not in the apt install list "
                f"(found: {sorted(packages)})")

    def test_the_fixed_size_presets_were_not_grown(self):
        """core_10 / standard_20 / full_30 are experiment ARMS — their sizes
        are the independent variable in the action-space measurements, so
        adding tools to them would silently invalidate every recorded
        comparison."""
        from orchestrator.main import TOOLSET_PRESETS
        assert len(TOOLSET_PRESETS["core_10"]["tools"]) == 10
        assert len(TOOLSET_PRESETS["standard_20"]["tools"]) == 20
        assert len(TOOLSET_PRESETS["full_30"]["tools"]) == 30

    def test_metasploit_is_not_registered(self):
        """It is present in the base image. searchsploit answers "does an
        exploit exist" without handing an agent a working exploitation
        framework, which is a different decision from "can it look things up"."""
        from orchestrator.tool_executor import TOOL_TIMEOUTS
        from orchestrator.models import _DEFAULT_TOOLS
        for name in ("msfconsole", "metasploit", "msfvenom"):
            assert name not in TOOL_TIMEOUTS
            assert name not in _DEFAULT_TOOLS

    def test_the_agent_is_taught_the_working_gitleaks_form(self):
        """`detect --no-git` was REMOVED in gitleaks 8 and silently reports
        "no leaks found" — verified against a planted Slack token, which only
        `dir` finds. Teaching the dead form would produce a confident clean
        result from a scan that examined nothing."""
        import inspect
        import orchestrator.main as M
        src = inspect.getsource(M)
        i = src.index("TOOL USAGE EXAMPLES")
        block = src[i:i + 3000]
        assert "gitleaks dir" in block
        assert "detect --no-git" not in block.split("NOTE:")[0]

    def test_searchsploit_is_described_as_lookup_only(self):
        import inspect
        import orchestrator.main as M
        src = inspect.getsource(M)
        i = src.index("TOOL USAGE EXAMPLES")
        block = src[i:i + 3000]
        j = block.index("searchsploit")
        assert "LOOKUP ONLY" in block[j:j + 200]


class TestTheUrlDescribesWhatIsOnScreen:
    """Every piece of dashboard state lived in CSS classes and closure
    variables, so no screen could be linked to, bookmarked, reloaded into or
    pasted into a ticket, and every reload dumped the operator back on the
    Scanner form regardless of what they had been reading.

    `switchView` was already the single funnel every transition went through,
    so the URL is written there and read back on load.
    """

    @staticmethod
    def _html():
        from pathlib import Path
        return Path("dashboard/templates/index.html").read_text()

    def test_the_view_is_written_to_the_url(self):
        html = self._html()
        body = js_body(html, "function switchView(view) {")
        assert "urlWrite();" in body, "switchView does not record the view"

    def test_the_url_is_read_on_load(self):
        html = self._html()
        assert "function bootFromUrl" in html
        i = html.index("function bootFromUrl")
        assert "switchView(st.view || 'overview')" in html[i:i + 900], \
            "the URL is written but never read, so every reload lands on the default view"

    def test_a_hashchange_navigates(self):
        html = self._html()
        assert "addEventListener('hashchange'" in html
        i = html.index("addEventListener('hashchange'")
        assert "urlApply()" in html[i:i + 300]

    def test_the_write_loop_is_guarded(self):
        """Writing the hash fires hashchange, which would write the hash."""
        html = self._html()
        assert "__urlApplying" in html
        i = html.index("addEventListener('hashchange'")
        assert "if (__urlApplying) return" in html[i:i + 300]

    def test_only_known_keys_are_honoured(self):
        """The hash is attacker-supplied in the sense that anyone can send a
        link. Unknown keys are dropped rather than reflected."""
        html = self._html()
        assert "const URL_KEYS = [" in html
        i = html.index("function urlState()")
        assert "URL_KEYS.includes(k)" in html[i:i + 700]

    def test_the_selected_customer_is_in_the_url(self):
        """It is the scope the rest of the app is read through; a link without
        it shows the recipient a different application state."""
        html = self._html()
        i = html.index("function sideEngagementPicked")
        assert "urlSet({eng:" in html[i:i + 900]

    def test_typing_does_not_bury_the_back_button(self):
        html = self._html()
        i = html.index("function urlSet(")
        block = html[i:i + 1100]
        assert "replaceState" in block
        assert "replace = true" in block, "the default must not push a history entry"


class TestListsFilterSortAndTellTheTruth:
    """A view that silently shows 30 of 127 rows reads exactly like a complete
    one — the defect shape this project keeps hitting. Truncation is stated."""

    @staticmethod
    def _html():
        from pathlib import Path
        return Path("dashboard/templates/index.html").read_text()

    def test_the_count_states_the_truth_when_filtered(self):
        html = self._html()
        assert "function listCountLabel" in html
        i = html.index("function listCountLabel")
        block = html[i:i + 700]
        assert "shown === total" in block, "the label cannot distinguish filtered from complete"
        assert "of" in block

    def test_a_server_side_cap_is_reported_separately(self):
        """A server LIMIT is a second truncation and must not be folded into
        the same number."""
        i = self._html().index("function listCountLabel")
        assert "server returns at most" in self._html()[i:i + 700]

    def test_reports_has_a_search_box_and_sortable_headers(self):
        html = self._html()
        assert 'id="reports-search"' in html
        assert html.count('class="col-sort"') >= 6
        assert ".col-sort { cursor: pointer" in html

    def test_sorting_shows_which_column_and_direction(self):
        """A header that sorts and does not say so is a feature nobody finds."""
        html = self._html()
        assert "function listMarkSort" in html
        assert '.col-sort[data-active]::after' in html

    def test_the_two_empty_states_are_different(self):
        """"No sessions found" while a filter is active sends the operator
        hunting for a bug that is their own search box."""
        html = self._html()
        i = html.index("async function loadReportsList")
        block = html[i:i + 4200]
        assert "No sessions found" in block
        assert "No session matches" in block

    def test_filtering_does_not_refetch(self):
        html = self._html()
        assert "__reportsCache" in html
        i = html.index("async function loadReportsList")
        assert "opts.fromCache" in self._html()[i:i + 900]

    def test_the_search_input_is_the_source_of_truth(self):
        """An earlier version copied the URL back into the input on every
        render, so any change was reverted to a stale query and the list
        filtered on something the box no longer said."""
        html = self._html()
        i = html.index("async function loadReportsList")
        block = html[i:i + 4200]
        assert "document.activeElement !== searchEl" not in block, \
            "the URL is overwriting the input again"

    def test_reports_is_scoped_to_the_selected_customer(self):
        html = self._html()
        i = html.index("async function loadReportsList")
        block = html[i:i + 4200]
        assert "side-engagement" in block
        assert "engagement_id === eng" in block

    def test_scoping_refuses_to_filter_on_a_field_the_api_omits(self):
        """Filtering on a missing key does not error — it silently returns
        nothing, and an empty list reads as "this customer has done no work".
        /api/sessions did not send engagement_id when this was written."""
        html = self._html()
        i = html.index("async function loadReportsList")
        block = html[i:i + 4200]
        # The guard must be USED in the filter, not merely defined above it.
        # The first version checked only that the words appeared, and passed
        # with the filter reverted to the unguarded form.
        assert "(eng && scopable) ?" in block, \
            "the guard is defined but the filter does not consult it"
        assert "NOT scoped" in block, "a missing field would be silently indistinguishable"

    def test_the_sessions_api_actually_sends_it(self, tmp_path_factory):
        """BEHAVIOURAL. The first version searched the handler's source and
        passed with the column deleted from the SELECT, because the comment
        above it still said "engagement_id". A test a comment satisfies is not
        a test — the same trap as the Dockerfile check."""
        import asyncio
        import warnings
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        from fastapi.testclient import TestClient
        import orchestrator.database as db_mod
        import orchestrator.main as M

        original = db_mod.DB_PATH
        db_mod.DB_PATH = str(tmp_path_factory.mktemp("sess") / "s.db")
        try:
            asyncio.run(db_mod.init_db())
            client = TestClient(M.app)
            eid = client.post("/api/engagements",
                              json={"client_name": "Acme", "root_domain": "acme.example"}
                              ).json()["engagement"]["id"]
            r = client.post("/api/sessions", json={
                "target_url": "http://app.acme.example", "scope_mode": "full",
                "model": "m", "enabled_tools": ["curl"], "max_turns": 1,
                "engagement_id": eid})
            assert r.status_code == 200, r.text
            rows = client.get("/api/sessions").json()
            assert rows, "no session came back"
            assert "engagement_id" in rows[0], (
                "the UI scopes on a field the API does not return; the list "
                f"would silently empty. keys={sorted(rows[0])}")
            assert rows[0]["engagement_id"] == eid
        finally:
            db_mod.DB_PATH = original


class TestTruncationIsAlwaysStated:
    """A view that silently shows 30 of 127 rows reads exactly like a complete
    one. This project has shipped that shape repeatedly, so every cap between
    the database and the screen is now named and reported."""

    @staticmethod
    def _html():
        from pathlib import Path
        return Path("dashboard/templates/index.html").read_text()

    def test_the_summary_reports_true_totals_not_row_counts(self):
        """`counts.sessions` was len(rows) of a LIMIT 200 query, so an
        engagement with 4,000 sessions and one with 200 were indistinguishable."""
        import asyncio
        import os
        import tempfile
        import orchestrator.database as db_mod
        from orchestrator import engagement as E

        old = db_mod.DB_PATH
        db_mod.DB_PATH = os.path.join(tempfile.mkdtemp(), "cap.db")
        try:
            async def go():
                await db_mod.init_db()
                db = await db_mod.get_db()
                eid = await E.create(db, "Acme", "acme.example")
                await db.commit()
                for i in range(E.SUMMARY_ROW_LIMIT + 5):
                    await db.execute(
                        "INSERT INTO sessions (id, target_url, scope_mode, model, "
                        "enabled_tools, status, engagement_id) VALUES (?,?,?,?,?,?,?)",
                        (f"s{i:05d}", "http://a", "full", "m", "curl", "completed", eid))
                await db.commit()
                out = await E.summary(db, eid)
                await db.close()
                return out
            out = asyncio.run(go())
        finally:
            db_mod.DB_PATH = old

        assert out["counts"]["sessions"] == E.SUMMARY_ROW_LIMIT + 5, \
            "counts reports the returned rows, not the real total"
        assert out["returned"]["sessions"] == E.SUMMARY_ROW_LIMIT
        assert out["returned"]["row_limit"] == E.SUMMARY_ROW_LIMIT

    def test_the_cap_is_a_named_constant(self):
        from orchestrator import engagement as E
        assert isinstance(E.SUMMARY_ROW_LIMIT, int) and E.SUMMARY_ROW_LIMIT > 0

    def test_the_execution_table_states_both_caps(self):
        """Two caps sit between the database and that table: the server's
        row_limit and the table's own render cap."""
        block = js_body(self._html(), "function engRunTable(d) {")
        assert "TABLE_CAP" in block
        assert "Showing ${shown} of ${trueTotal}" in block
        assert "returns at most" in block, "the server cap is not mentioned"

    def test_the_capped_lists_on_the_engagement_page_say_so(self):
        html = self._html()
        assert "function engCapNote" in html
        assert html.count("engCapNote(") >= 3, "a capped list is unlabelled"

    def test_the_monitor_says_its_metrics_come_from_a_sample(self):
        """Not a display cap: every tier count is computed from those rows, so
        an unlabelled sample is a coverage number that describes the latest 30
        sessions and claims to describe the corpus."""
        html = self._html()
        assert "MONITOR_SAMPLE" in html
        assert 'id="mon-sample-note"' in html
        assert "not the full corpus" in html

    def test_no_bare_numeric_slice_caps_remain_in_list_rendering(self):
        """Guard on the guard: a new `.slice(0, 40)` on a rendered list is the
        same defect returning under a different literal."""
        import re
        html = self._html()
        allowed = {"TABLE_CAP", "MONITOR_SAMPLE", "MONITOR_ROWS"}
        offenders = []
        for m in re.finditer(r"\.slice\(0,\s*(\d+)\)", html):
            line = html[html.rfind("\n", 0, m.start()) + 1: html.find("\n", m.end())]
            # string truncation of a single value is display, not a hidden cap
            if any(x in line for x in (".id", "text()", "await r.text()", "r.url",
                                       "chainId", "run_id", "selected_for", "join")):
                continue
            offenders.append(line.strip()[:90])
        assert not offenders, (
            "list caps that are not named constants:\n  " + "\n  ".join(offenders))


class TestTheOverviewAnswersWhatIsGoingOn:
    """erlik opened on an empty Scanner form, which answers "what can I start"
    and never "what is already going on"."""

    @staticmethod
    def _html():
        from pathlib import Path
        return Path("dashboard/templates/index.html").read_text()

    def test_the_view_and_its_nav_entry_exist(self):
        html = self._html()
        assert 'id="view-overview"' in html
        assert 'id="nav-overview"' in html

    def test_it_is_registered_with_the_view_switcher(self):
        """A view the switcher does not know about can never be shown."""
        body = js_body(self._html(), "function switchView(view) {")
        assert "'overview'" in body
        assert "overview: document.getElementById('view-overview')" in body
        assert "loadOverview()" in body

    def test_it_is_the_landing_view(self):
        html = self._html()
        assert "switchView(st.view || 'overview')" in html
        assert "let __currentView = 'overview';" in html

    def test_the_tiles_are_links_not_just_numbers(self):
        """A number you cannot act on is a number you read once."""
        block = js_body(self._html(), "function ovTile(label, n, href, colour) {")
        assert "<a" in block and "href=" in block

    def test_the_tiles_carry_the_selected_customer(self):
        block = js_body(self._html(), "async function loadOverview() {")
        assert "&eng=${encodeURIComponent(eng)}" in block, \
            "tile links drop the customer, so they land unscoped"

    def test_only_the_first_unmet_rung_is_actionable(self):
        """Showing all five as a flat checklist offers five equally-plausible
        next actions, four of which are blocked."""
        block = js_body(self._html(), "function ovLadder(rungs) {")
        assert "blocked" in block
        assert "if (!r.done) blocked = true" in block

    def test_the_rungs_are_genuinely_ordered(self):
        """A first version listed "a target is recorded" as a rung and showed
        it blocking two rungs that were already complete — a target record is
        endpoint knowledge, not a gate. A ladder whose rungs are not really
        ordered names the wrong next action."""
        block = js_body(self._html(), "async function loadOverview() {")
        # EVERY ladder in the function, not just the first. loadOverview builds
        # two — the no-customer empty state and the scoped one — and checking
        # only `block.index("ovLadder([")` inspected the empty state, so a bad
        # rung added to the real ladder passed unnoticed.
        ladders, at = [], 0
        while True:
            i = block.find("ovLadder([", at)
            if i < 0:
                break
            j = block.index("]);", i)
            ladders.append(block[i:j])
            at = j
        assert len(ladders) >= 2, f"expected the empty-state and scoped ladders, got {len(ladders)}"

        for rungs in ladders:
            assert "A target is recorded" not in rungs, \
                "a non-blocking step is back in the dependency chain"

        scoped = ladders[-1]
        assert "Scope is declared" in scoped and "Work has been run" in scoped
        assert scoped.index("Scope is declared") < scoped.index("Work has been run"), \
            "scope must precede running: the gate refuses an unscoped run"

    def test_it_works_before_any_customer_exists(self):
        """The empty state is the one a new operator sees first."""
        block = js_body(self._html(), "async function loadOverview() {")
        assert "if (!eng) {" in block
        assert "A customer exists" in block

    def test_pending_scope_is_surfaced_as_needing_a_human(self):
        block = js_body(self._html(), "async function loadOverview() {")
        assert "pending_scope" in block
        assert "awaiting approval" in block


class TestBadgesCountOpenWork:
    """Two defects, both of which made a badge contradict the operator.

    The rollup grouped on the raw `severity` column, so someone could triage a
    critical down to low and the sidebar would keep saying critical for ever —
    `submission_policy.current_severity` was the one definition of what a
    report shows, and this rollup ignored it. And a finding marked a false
    positive still counted, so a triaged engagement displayed its original
    number until someone deleted rows, which is the opposite of what triage is
    for.
    """

    @staticmethod
    def _summary(tmp_path, rows):
        import asyncio
        import orchestrator.database as db_mod
        from orchestrator import engagement as E
        old = db_mod.DB_PATH
        db_mod.DB_PATH = str(tmp_path / "sev.db")
        try:
            async def go():
                await db_mod.init_db()
                db = await db_mod.get_db()
                eid = await E.create(db, "Acme", "acme.example")
                await db.execute(
                    "INSERT INTO sessions (id, target_url, scope_mode, model, enabled_tools, "
                    "status, engagement_id) VALUES ('s1','http://a','full','m','curl',"
                    "'completed',?)", (eid,))
                for vt, sev, override, triage in rows:
                    await db.execute(
                        "INSERT INTO findings (session_id, vuln_type, severity, url, "
                        "severity_override, triage_status) VALUES ('s1',?,?,?,?,?)",
                        (vt, sev, "http://a/x", override, triage))
                await db.commit()
                out = await E.summary(db, eid)
                await db.close()
                return out
            return asyncio.run(go())
        finally:
            db_mod.DB_PATH = old

    def test_a_rejected_finding_does_not_count_as_open(self, tmp_path):
        out = self._summary(tmp_path, [
            ("SQLi", "critical", None, None),
            ("XSS", "high", None, "rejected"),
        ])
        assert out["findings_by_severity"] == {"critical": 1}
        assert out["counts"]["findings"] == 1
        assert out["counts"]["findings_total"] == 2
        assert out["counts"]["findings_rejected"] == 1

    def test_a_severity_override_is_respected(self, tmp_path):
        """THE case: an operator downgrades a critical, and the badge must
        follow their decision rather than the detector's first guess."""
        out = self._summary(tmp_path, [("SQLi", "critical", "low", None)])
        assert out["findings_by_severity"] == {"low": 1}, out["findings_by_severity"]

    def test_the_total_is_still_reported_so_nothing_looks_deleted(self, tmp_path):
        out = self._summary(tmp_path, [
            ("A", "high", None, "rejected"), ("B", "high", None, "rejected"),
            ("C", "low", None, None),
        ])
        assert out["counts"]["findings"] == 1
        assert out["counts"]["findings_total"] == 3

    def test_it_uses_the_shared_definition_of_effective_severity(self):
        """Two implementations of "what severity is this" is one that
        eventually disagrees with the report."""
        import inspect
        from orchestrator import engagement as E
        assert "current_severity" in inspect.getsource(E.summary)

    def test_the_ui_says_how_many_were_triaged_out(self):
        from pathlib import Path
        html = Path("dashboard/templates/index.html").read_text()
        assert "triaged out" in html, \
            "the numbers just shrink, which reads as data loss rather than work done"


class TestTheSidebarCollapses:
    @staticmethod
    def _html():
        from pathlib import Path
        return Path("dashboard/templates/index.html").read_text()

    def test_there_is_a_toggle_and_a_collapsed_style(self):
        html = self._html()
        assert 'id="rail-toggle"' in html
        assert "body.rail #app-sidebar" in html

    def test_the_choice_persists_per_operator_not_in_the_url(self):
        """A link someone pastes must not impose their sidebar width on the
        person opening it."""
        html = self._html()
        assert "localStorage" in html and "erlik.sidebar.rail" in html
        assert "rail" not in "".join(
            html[html.index("const URL_KEYS = ["):html.index("]", html.index("const URL_KEYS = ["))])

    def test_storage_failure_does_not_break_the_page(self):
        """localStorage throws outright in a private window or with site data
        blocked, and a sidebar preference is not worth losing the page over."""
        html = self._html()
        i = html.index("function toggleRail")
        assert "try {" in html[i:i + 400] and "catch" in html[i:i + 400]
        j = html.index("function restoreRail")
        assert "try {" in html[j:j + 400] and "catch" in html[j:j + 400]

    def test_the_rail_is_disabled_on_narrow_screens(self):
        """Below 900px the sidebar is already a stacked strip; shrinking it to
        icons there hides the counts for no gain."""
        html = self._html()
        i = html.index("@media (max-width: 900px)", html.index("body.rail"))
        block = html[i:i + 700]
        assert "body.rail #app-sidebar" in block
        assert "#rail-toggle { display: none; }" in block


class TestTheEngagementRecordIsEditableAndKeepsHistory:
    """An engagement carries the AUTHORISATION for a test. Being able to
    silently rewrite who approved it, and from when, is the one edit that must
    not be possible — so edits are allowed and every previous value is kept."""

    @staticmethod
    def _client(tmp_path):
        import asyncio
        import warnings
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        from fastapi.testclient import TestClient
        import orchestrator.database as db_mod
        import orchestrator.main as M
        db_mod.DB_PATH = str(tmp_path / "ed.db")
        asyncio.run(db_mod.init_db())
        return TestClient(M.app)

    def test_an_edit_is_recorded_with_its_previous_value(self, tmp_path):
        import orchestrator.database as db_mod
        old = db_mod.DB_PATH
        try:
            c = self._client(tmp_path)
            eid = c.post("/api/engagements",
                         json={"client_name": "Acme Crop"}).json()["engagement"]["id"]
            r = c.put(f"/api/engagements/{eid}", json={"client_name": "Acme Corp"})
            assert r.status_code == 200
            assert r.json()["updated"]["changed"] == ["client_name"]
            revs = c.get(f"/api/engagements/{eid}/revisions").json()["revisions"]
            assert revs[0]["field"] == "client_name"
            assert revs[0]["old_value"] == "Acme Crop"
            assert revs[0]["new_value"] == "Acme Corp"
        finally:
            db_mod.DB_PATH = old

    def test_an_unknown_field_is_ignored_not_written(self, tmp_path):
        """A typo in a field name must not silently succeed."""
        import orchestrator.database as db_mod
        old = db_mod.DB_PATH
        try:
            c = self._client(tmp_path)
            eid = c.post("/api/engagements",
                         json={"client_name": "Acme"}).json()["engagement"]["id"]
            r = c.put(f"/api/engagements/{eid}", json={"nonsense": "x", "notes": "n"})
            assert r.json()["updated"]["ignored"] == ["nonsense"]
            assert r.json()["updated"]["changed"] == ["notes"]
        finally:
            db_mod.DB_PATH = old

    def test_a_noop_edit_records_no_revision(self, tmp_path):
        import orchestrator.database as db_mod
        old = db_mod.DB_PATH
        try:
            c = self._client(tmp_path)
            eid = c.post("/api/engagements",
                         json={"client_name": "Acme"}).json()["engagement"]["id"]
            c.put(f"/api/engagements/{eid}", json={"client_name": "Acme"})
            assert c.get(f"/api/engagements/{eid}/revisions").json()["revisions"] == []
        finally:
            db_mod.DB_PATH = old

    def test_archiving_never_deletes(self, tmp_path):
        """Sessions, findings, scope rules and assets all reference this row,
        and the project's rule is that an identifier is deprecated, not
        removed."""
        import orchestrator.database as db_mod
        old = db_mod.DB_PATH
        try:
            c = self._client(tmp_path)
            eid = c.post("/api/engagements",
                         json={"client_name": "Acme"}).json()["engagement"]["id"]
            a = c.post(f"/api/engagements/{eid}/archive", json={"archived": True})
            assert a.json()["engagement"]["status"] == "archived"
            assert c.get(f"/api/engagements/{eid}").status_code == 200
            back = c.post(f"/api/engagements/{eid}/archive", json={"archived": False})
            assert back.json()["engagement"]["status"] == "active"
            fields = [r["field"] for r in
                      c.get(f"/api/engagements/{eid}/revisions").json()["revisions"]]
            assert fields.count("status") == 2, "the archive transition was not recorded"
        finally:
            db_mod.DB_PATH = old

    def test_an_unknown_engagement_is_a_404(self, tmp_path):
        import orchestrator.database as db_mod
        old = db_mod.DB_PATH
        try:
            c = self._client(tmp_path)
            assert c.put("/api/engagements/nope", json={"notes": "x"}).status_code == 404
            assert c.post("/api/engagements/nope/archive", json={}).status_code == 404
        finally:
            db_mod.DB_PATH = old

    def test_the_ui_saves_explicitly_not_as_you_type(self):
        """A field that commits while you are still typing can store half an
        approval reference."""
        from pathlib import Path
        html = Path("dashboard/templates/index.html").read_text()
        assert 'onclick="engSave()"' in html
        i = html.index('id="eng-e-by"')
        assert "oninput=" not in html[i:i + 300] and "onchange=" not in html[i:i + 300]

    def test_the_ui_shows_the_edit_history(self):
        from pathlib import Path
        html = Path("dashboard/templates/index.html").read_text()
        assert "engLoadRevisions" in html
        assert "EDIT HISTORY" in html

    def test_the_confirmation_survives_the_re_render(self):
        """engRender replaces the panel, taking the status span with it.
        Setting the message first made a successful save look like a no-op."""
        from pathlib import Path
        html = Path("dashboard/templates/index.html").read_text()
        block = js_body(html, "async function engSave() {")
        assert block.index("engRender(d)") < block.index("engSaveMessage(")
