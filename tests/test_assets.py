"""The asset inventory: what findings are ABOUT.

Findings were keyed only by a URL string, so 167 Information Disclosure rows in
the corpus could describe a handful of facts about a handful of hosts with
nothing tying them together. A client asks "what did you find on our
infrastructure"; a flat list of 453 URLs does not answer that.

TWO RULES, and both are what these tests exist to hold.

CONSOLIDATE FOR PRESENTATION, NEVER DESTROY ROWS. `findings` rows stay exactly
as they were and are still counted the same way, so every recorded metric holds.
An earlier design elsewhere in this codebase removed rows and made the client
deliverable disagree with the measurement; this must not repeat.

AN ASSET MUST BE IN SCOPE. Creating an asset records that erlik touched a host
on this customer's engagement. A host they did not authorise must not silently
acquire a row in their inventory.
"""

import asyncio

import pytest

from orchestrator import assets as A


class TestDecomposeIsPureAndShallow:
    def test_host_and_port_always(self):
        assert A.decompose("https://app.acme.com/x")[:2] == [
            ("host", "app.acme.com"), ("port", "443")]

    def test_http_default_port(self):
        assert ("port", "80") in A.decompose("http://acme.com")

    def test_explicit_port_wins(self):
        assert ("port", "8443") in A.decompose("https://acme.com:8443/a")

    def test_endpoint_only_when_there_is_a_path(self):
        assert [k for k, _ in A.decompose("https://acme.com")] == ["host", "port"]
        assert [k for k, _ in A.decompose("https://acme.com/")] == ["host", "port"]
        assert ("endpoint", "/api/users") in A.decompose("https://acme.com/api/users")

    def test_no_guessed_service_or_technology(self):
        """Inventing a technology from a URL alone is a guess, and an inventory
        of guesses is worse than a short one. Those kinds are filled in by
        whatever actually observed them."""
        kinds = {k for k, _ in A.decompose("https://acme.com/app")}
        assert "technology" not in kinds and "service" not in kinds

    def test_garbage_yields_nothing_rather_than_a_bogus_asset(self):
        assert A.decompose("") == []
        assert A.decompose("   ") == []
        assert A.decompose("::::") == []

    def test_case_and_trailing_dot_normalised(self):
        assert ("host", "acme.com") in A.decompose("https://ACME.com./x")


def _fresh(tmp_path, monkeypatch):
    import orchestrator.database as db_mod
    monkeypatch.setattr(db_mod, "DB_PATH", str(tmp_path / "a.db"))
    return db_mod


class TestScopeGovernsTheInventory:
    def test_an_in_scope_url_builds_the_chain(self, tmp_path, monkeypatch):
        db_mod = _fresh(tmp_path, monkeypatch)
        from orchestrator import engagement as E

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            eid = await E.create(db, "Acme", "acme.com")
            leaf, why = await A.path_for_url(db, eid, "https://app.acme.com/api/users")
            await db.commit()
            t = await A.tree(db, eid)
            c = await A.counts(db, eid)
            await db.close()
            return leaf, why, t, c

        leaf, why, t, c = asyncio.run(go())
        assert leaf and why == "ok"
        assert c == {"host": 1, "port": 1, "endpoint": 1}
        assert t[0]["kind"] == "host" and t[0]["value"] == "app.acme.com"
        assert t[0]["children"][0]["kind"] == "port"
        assert t[0]["children"][0]["children"][0]["value"] == "/api/users"

    def test_an_out_of_scope_url_creates_nothing(self, tmp_path, monkeypatch):
        """The rule that matters. Creating an asset records that erlik touched
        this host on this engagement."""
        db_mod = _fresh(tmp_path, monkeypatch)
        from orchestrator import engagement as E

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            eid = await E.create(db, "Acme", "acme.com")
            leaf, why = await A.path_for_url(db, eid, "https://notacme.com/x")
            await db.commit()
            c = await A.counts(db, eid)
            await db.close()
            return leaf, why, c

        leaf, why, c = asyncio.run(go())
        assert leaf is None
        assert "no in-scope rule" in why
        assert c == {}, "an unauthorised host acquired an inventory row"

    def test_an_unapproved_discovered_host_creates_nothing(self, tmp_path, monkeypatch):
        db_mod = _fresh(tmp_path, monkeypatch)
        from orchestrator import engagement as E

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            eid = await E.create(db, "Acme", "")
            await E.add_scope(db, eid, "vpn.other.example", kind="host",
                              source="discovered")
            await db.commit()
            leaf, why = await A.path_for_url(db, eid, "https://vpn.other.example/")
            await db.commit()
            c = await A.counts(db, eid)
            await db.close()
            return leaf, why, c

        leaf, why, c = asyncio.run(go())
        assert leaf is None and "approved" in why and c == {}


class TestIdempotence:
    def test_the_same_url_twice_yields_one_chain(self, tmp_path, monkeypatch):
        """A scan that revisits a URL must not double the inventory."""
        db_mod = _fresh(tmp_path, monkeypatch)
        from orchestrator import engagement as E

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            eid = await E.create(db, "Acme", "acme.com")
            a, _ = await A.path_for_url(db, eid, "https://app.acme.com/api")
            b, _ = await A.path_for_url(db, eid, "https://app.acme.com/api")
            await db.commit()
            c = await A.counts(db, eid)
            await db.close()
            return a, b, c

        a, b, c = asyncio.run(go())
        assert a == b
        assert c == {"host": 1, "port": 1, "endpoint": 1}

    def test_sibling_endpoints_share_a_host_and_port(self, tmp_path, monkeypatch):
        db_mod = _fresh(tmp_path, monkeypatch)
        from orchestrator import engagement as E

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            eid = await E.create(db, "Acme", "acme.com")
            for u in ("https://app.acme.com/a", "https://app.acme.com/b",
                      "https://app.acme.com/c"):
                await A.path_for_url(db, eid, u)
            await db.commit()
            c = await A.counts(db, eid)
            await db.close()
            return c

        assert asyncio.run(go()) == {"host": 1, "port": 1, "endpoint": 3}

    def test_a_different_port_is_a_different_asset(self, tmp_path, monkeypatch):
        db_mod = _fresh(tmp_path, monkeypatch)
        from orchestrator import engagement as E

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            eid = await E.create(db, "Acme", "acme.com")
            await A.path_for_url(db, eid, "https://app.acme.com:8443/a")
            await A.path_for_url(db, eid, "https://app.acme.com/a")
            await db.commit()
            c = await A.counts(db, eid)
            await db.close()
            return c

        assert asyncio.run(go())["port"] == 2


class TestConsolidationDoesNotDestroyRows:
    def test_findings_are_grouped_on_read_not_deleted(self, tmp_path, monkeypatch):
        """Three identical findings stay three rows AND present as one line
        with count 3. Both numbers are correct; they no longer have to be the
        same number."""
        db_mod = _fresh(tmp_path, monkeypatch)
        from orchestrator import engagement as E

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            eid = await E.create(db, "Acme", "acme.com")
            await db.execute(
                "INSERT INTO sessions (id, target_url, scope_mode, system_prompt, "
                "model, enabled_tools, status, engagement_id) "
                "VALUES ('s1','https://app.acme.com','full','','m','','completed',?)",
                (eid,))
            leaf, _ = await A.path_for_url(db, eid, "https://app.acme.com/api")
            for _ in range(3):
                await db.execute(
                    "INSERT INTO findings (session_id, vuln_type, severity, url, "
                    "evidence, asset_id) VALUES ('s1','SQL Injection','high',"
                    "'https://app.acme.com/api','e',?)", (leaf,))
            await db.commit()
            raw = (await (await db.execute(
                "SELECT COUNT(*) FROM findings")).fetchone())[0]
            t = await A.tree(db, eid)
            sev = A.rollup(t)
            await db.close()
            return raw, t, sev

        raw, t, sev = asyncio.run(go())
        assert raw == 3, "consolidation deleted rows"
        ep = t[0]["children"][0]["children"][0]
        # `lane` distinguishes a detector-proved finding from a model-asserted
        # one — see the lane test below.
        assert ep["findings"] == [
            {"vuln_type": "SQL Injection", "severity": "high", "count": 3,
             "lane": "agent"}]
        assert sev == {"high": 3}, "rollup lost the count"

    def test_rollup_climbs_the_whole_subtree(self, tmp_path, monkeypatch):
        """A host must show what is beneath it, or the inventory is a list."""
        db_mod = _fresh(tmp_path, monkeypatch)
        from orchestrator import engagement as E

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            eid = await E.create(db, "Acme", "acme.com")
            await db.execute(
                "INSERT INTO sessions (id, target_url, scope_mode, system_prompt, "
                "model, enabled_tools, status, engagement_id) "
                "VALUES ('s1','https://app.acme.com','full','','m','','completed',?)",
                (eid,))
            for path, sev in (("/a", "high"), ("/b", "medium"), ("/c", "medium")):
                leaf, _ = await A.path_for_url(db, eid, f"https://app.acme.com{path}")
                await db.execute(
                    "INSERT INTO findings (session_id, vuln_type, severity, url, "
                    "evidence, asset_id) VALUES ('s1','X',?, ?,'e',?)",
                    (sev, f"https://app.acme.com{path}", leaf))
            await db.commit()
            t = await A.tree(db, eid)
            await db.close()
            return A.rollup(t)

        assert asyncio.run(go()) == {"high": 1, "medium": 2}


class TestWritePathIntegration:
    def test_record_finding_attaches_an_asset(self):
        """Wiring guard: the inventory is populated by the ONE finding writer,
        not by a second path that can drift from it."""
        import pathlib
        src = (pathlib.Path(__file__).resolve().parents[1]
               / "orchestrator" / "main.py").read_text()
        assert "path_for_url" in src
        assert "asset_id) VALUES" in src, "asset_id is computed but not stored"

    def test_a_session_with_no_engagement_still_records_findings(self, tmp_path,
                                                                 monkeypatch):
        """462 findings predate engagements. Requiring an asset would have made
        every one of them unwritable."""
        db_mod = _fresh(tmp_path, monkeypatch)

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            await db.execute(
                "INSERT INTO sessions (id, target_url, scope_mode, system_prompt, "
                "model, enabled_tools, status) "
                "VALUES ('s2','http://x','full','','m','','completed')")
            await db.commit()
            import orchestrator.main as M
            ok = await M._record_finding(
                "s2", {"vuln_type": "XSS", "severity": "high",
                       "url": "http://x/a", "evidence": "e"}, source="test", db=db)
            await db.commit()
            n = (await (await db.execute(
                "SELECT COUNT(*) FROM findings WHERE session_id='s2'")).fetchone())[0]
            aid = (await (await db.execute(
                "SELECT asset_id FROM findings WHERE session_id='s2'")).fetchone())[0]
            await db.close()
            return ok, n, aid

        ok, n, aid = asyncio.run(go())
        assert ok is True and n == 1
        assert aid is None, "invented an asset for a session with no customer"


class TestTheModelIsReachableFromARealRun:
    """The audit that prompted these: the asset model shipped complete and
    UNREACHABLE.

    `sessions.engagement_id` had no writer at all, so `_record_finding` read it,
    got NULL every time, and no real run could ever produce an asset. The demo
    only worked because the session row was inserted by hand. Two more of the
    same shape: `record_observation()` had zero callers, and `v2_findings.asset_id`
    existed as a column the deterministic lane never wrote.

    A capability nothing can reach is indistinguishable from one that does not
    exist, which is this codebase's signature defect.
    """

    def test_session_creation_accepts_an_engagement(self):
        from orchestrator.models import SessionCreate
        assert "engagement_id" in SessionCreate.model_fields

    def test_session_creation_persists_it(self):
        import pathlib
        src = (pathlib.Path(__file__).resolve().parents[1]
               / "orchestrator" / "main.py").read_text()
        assert "authorization_ref, engagement_id) " in src, (
            "engagement_id is accepted but never written to the row")
        assert "data.engagement_id)," in src

    def test_record_observation_is_called(self):
        """It was dead code — service/technology could never be populated."""
        import pathlib
        src = (pathlib.Path(__file__).resolve().parents[1]
               / "orchestrator" / "main.py").read_text()
        # The CALL SITE, not the substring: a rename to
        # `_dead_record_observation(` still contains "record_observation(",
        # which is exactly how this assertion passed against dead code when I
        # tested it.
        assert "await _A.record_observation(db," in src

    def test_the_deterministic_lane_links_assets(self):
        """The half erlik asks a client to trust contributed nothing to the
        inventory, and the column added for it stayed empty."""
        import pathlib
        src = (pathlib.Path(__file__).resolve().parents[1] / "orchestrator"
               / "testcase" / "persistence.py").read_text()
        assert "await _asset_for(db, _eid, f.url)" in src
        assert "evidence, source, detector, asset_id)" in src, (
            "asset_id is computed but not in the INSERT column list")

    def test_scope_is_enforced_when_a_run_names_a_customer(self, tmp_path,
                                                           monkeypatch):
        """The real payoff. An engagement's scope is the legal boundary, and it
        is now enforced at session CREATION — a session that should never have
        existed is not something a later gate can undo."""
        import warnings
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        from fastapi.testclient import TestClient
        import orchestrator.database as db_mod
        import orchestrator.main as M

        original = db_mod.DB_PATH
        db_mod.DB_PATH = str(tmp_path / "s.db")
        try:
            asyncio.run(db_mod.init_db())
            c = TestClient(M.app)
            eid = c.post("/api/engagements",
                         json={"client_name": "Bound", "root_domain": "bound.example"}
                         ).json()["engagement"]["id"]

            out = c.post("/api/sessions", json={
                "target_url": "http://notbound.example", "engagement_id": eid})
            assert out.status_code == 403, out.text
            assert "not in scope" in out.json()["detail"]

            ok = c.post("/api/sessions", json={
                "target_url": "http://app.bound.example", "engagement_id": eid})
            assert ok.status_code == 200, ok.text

            bad = c.post("/api/sessions", json={
                "target_url": "http://x.example", "engagement_id": "nope"})
            assert bad.status_code == 404
        finally:
            db_mod.DB_PATH = original

    def test_a_run_without_an_engagement_is_unaffected(self, tmp_path, monkeypatch):
        """110 sessions predate engagements. Requiring one would break every
        existing workflow."""
        import warnings
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        from fastapi.testclient import TestClient
        import orchestrator.database as db_mod
        import orchestrator.main as M

        original = db_mod.DB_PATH
        db_mod.DB_PATH = str(tmp_path / "s2.db")
        try:
            asyncio.run(db_mod.init_db())
            c = TestClient(M.app)
            r = c.post("/api/sessions", json={"target_url": "http://anything.example"})
            assert r.status_code == 200, r.text
        finally:
            db_mod.DB_PATH = original


class TestTheTreeShowsBothLanes:
    """It read only `findings` — the agent lane. A host the DETERMINISTIC lane
    found something on rendered with no findings at all, and `v2_findings` has
    carried an asset_id since the v2 run learned its engagement.

    `lane` is kept per row rather than merged away: "SQL Injection x3" means
    something different when a detector proved it than when a model asserted
    it, and a client table that flattens the two cannot be un-flattened later.
    """

    def test_a_deterministic_finding_appears_on_its_asset(self, tmp_path, monkeypatch):
        db_mod = _fresh(tmp_path, monkeypatch)
        from orchestrator import engagement as E

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            eid = await E.create(db, "Acme", "acme.com")
            leaf, _ = await A.path_for_url(db, eid, "https://app.acme.com/api")
            await db.execute(
                "INSERT INTO v2_runs (id, test_case_id, target_json, engagement_id) "
                "VALUES ('r1','WSTG-INPV-05','{}',?)", (eid,))
            await db.execute(
                "INSERT INTO v2_findings (run_id, test_case_id, step, vuln_type, "
                "severity, url, evidence, asset_id) VALUES ('r1','WSTG-INPV-05',"
                "'s','SQL Injection','high','https://app.acme.com/api','e',?)", (leaf,))
            await db.commit()
            t = await A.tree(db, eid)
            await db.close()
            return t

        t = asyncio.run(go())
        ep = t[0]["children"][0]["children"][0]
        assert ep["findings"], "a deterministic finding is invisible on its asset"
        assert ep["findings"][0]["lane"] == "deterministic"

    def test_the_two_lanes_stay_distinguishable(self, tmp_path, monkeypatch):
        db_mod = _fresh(tmp_path, monkeypatch)
        from orchestrator import engagement as E

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            eid = await E.create(db, "Acme", "acme.com")
            leaf, _ = await A.path_for_url(db, eid, "https://app.acme.com/api")
            await db.execute(
                "INSERT INTO sessions (id, target_url, scope_mode, system_prompt, "
                "model, enabled_tools, status, engagement_id) "
                "VALUES ('s1','https://app.acme.com','full','','m','','completed',?)",
                (eid,))
            await db.execute(
                "INSERT INTO findings (session_id, vuln_type, severity, url, evidence, "
                "asset_id) VALUES ('s1','SQL Injection','high','u','e',?)", (leaf,))
            await db.execute(
                "INSERT INTO v2_runs (id, test_case_id, target_json, engagement_id) "
                "VALUES ('r1','WSTG-INPV-05','{}',?)", (eid,))
            await db.execute(
                "INSERT INTO v2_findings (run_id, test_case_id, step, vuln_type, "
                "severity, url, evidence, asset_id) VALUES ('r1','WSTG-INPV-05','s',"
                "'SQL Injection','high','u','e',?)", (leaf,))
            await db.commit()
            t = await A.tree(db, eid)
            await db.close()
            return t

        ep = asyncio.run(go())[0]["children"][0]["children"][0]
        lanes = sorted(f["lane"] for f in ep["findings"])
        assert lanes == ["agent", "deterministic"], lanes
        assert A.rollup([{"findings": ep["findings"], "children": []}]) == {"high": 2}

    def test_severity_is_normalised_in_the_tree(self, tmp_path, monkeypatch):
        """The corpus contains '** CRITICAL' beside 'critical'. A tree showing
        both is not a summary."""
        db_mod = _fresh(tmp_path, monkeypatch)
        from orchestrator import engagement as E

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            eid = await E.create(db, "Acme", "acme.com")
            leaf, _ = await A.path_for_url(db, eid, "https://app.acme.com/api")
            await db.execute(
                "INSERT INTO v2_runs (id, test_case_id, target_json, engagement_id) "
                "VALUES ('r1','X','{}',?)", (eid,))
            await db.execute(
                "INSERT INTO v2_findings (run_id, test_case_id, step, vuln_type, "
                "severity, url, evidence, asset_id) VALUES ('r1','X','s','A',"
                "'** CRITICAL','u','e',?)", (leaf,))
            await db.commit()
            t = await A.tree(db, eid)
            await db.close()
            return t

        ep = asyncio.run(go())[0]["children"][0]["children"][0]
        assert ep["findings"][0]["severity"] == "critical", ep["findings"]
