"""The deliverable boundary — the one split between what a client report shows
and what it withholds.

Two problems this pins:

1. Four render points each iterated `findings` independently (the session-info
   count, the `## Vulnerabilities Found (N)` heading and detail loop, the
   summary tables, and the executive-summary prompt), so a filter added to one
   contradicted the other three inside the same file.

2. `_build_report_json` funnels only 5 of the 9 report-producing routes. The
   four it misses are the ones actually handed to a client. A hardcoded
   five-endpoint list is what let four separate designs miss the same four
   routes, so the control here is a DISCOVERY test over the live route table.
"""

import asyncio
import sqlite3

import pytest

import orchestrator.database as db_mod
import orchestrator.main as M


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db_mod, "DB_DIR", tmp_path)
    monkeypatch.setattr(db_mod, "DB_PATH", tmp_path / "t.db")
    asyncio.run(db_mod.init_db())

    async def seed():
        db = await db_mod.get_db()
        try:
            await db.execute(
                "INSERT INTO sessions (id, target_url, system_prompt) VALUES (?, ?, ?)",
                ("s1", "http://juice-shop:3000", "test"))
            await db.commit()
        finally:
            await db.close()
    asyncio.run(seed())
    return tmp_path / "t.db"


def _gen(monkeypatch, total_findings):
    """Run the real generator with the executive-summary model stubbed out."""
    async def fake_chat(*a, **k):
        return "stubbed executive summary"
    monkeypatch.setattr(M.llm_client, "chat", fake_chat)
    return asyncio.run(M._generate_report(
        "s1", "test-model", "http://juice-shop:3000", "cold", "general",
        total_steps=3, total_findings=total_findings, total_duration_ms=1000))


def _add(sid, vuln_type, source, url="http://juice-shop:3000/x"):
    asyncio.run(M._record_finding(sid, {
        "vuln_type": vuln_type, "severity": "medium", "url": url,
        "parameter": "", "evidence": "e"}, source=source))


class TestSplitIsSingleSourceOfTruth:
    def test_header_count_matches_section_count(self, tmp_db, monkeypatch):
        """The live bug: the session-info Findings count came from the agent
        loop's own counter, which by design excludes nettacker pre-scan
        findings — while the findings SELECT returns them. With nettacker
        enabled the header disagreed with the section directly beneath it.

        Here the agent counter says 1 while the table holds 3.
        """
        _add("s1", "XSS", "llm_reported")
        _add("s1", "Open Port 22", "nettacker", "http://juice-shop:22")
        _add("s1", "Open Port 80", "nettacker", "http://juice-shop:80")

        md, _summary, _ms = _gen(monkeypatch, total_findings=1)

        assert "| **Findings** | 3 |" in md
        assert "## Vulnerabilities Found (3)" in md
        assert "| **Findings** | 1 |" not in md

    def test_withholding_propagates_to_every_render_point(self, tmp_db, monkeypatch):
        """Mutation test: the seam must be load-bearing, not decorative.

        Force the split to withhold everything. If any render point still reads
        the unfiltered list, this fails — which is the whole point of routing
        them through one call.
        """
        _add("s1", "XSS", "llm_reported")
        _add("s1", "SQL Injection", "llm_reported")
        monkeypatch.setattr(M, "_deliverable_view", lambda fs: ([], list(fs)))

        md, _summary, _ms = _gen(monkeypatch, total_findings=2)

        assert "| **Findings** | 0 |" in md
        assert "## Vulnerabilities Found (0)" in md
        assert "SQL Injection" not in md

    def test_default_view_withholds_nothing(self):
        """Until the submission policy lands, the split must be a pass-through —
        so this commit provably moves no recorded number."""
        rows = [{"vuln_type": "XSS"}, {"vuln_type": "SQLi"}]
        included, withheld = M._deliverable_view(rows)
        assert included == rows
        assert withheld == []

    def test_view_does_not_alias_its_input(self):
        """Callers rebind `findings` to the included list; returning the same
        object would make a later mutation edit the caller's data too."""
        rows = [{"vuln_type": "XSS"}]
        included, _ = M._deliverable_view(rows)
        assert included is not rows


class TestEveryReportRouteIsAccountedFor:
    def test_no_unclassified_report_route(self):
        """Discovery control. Enumerates the LIVE route table rather than a
        hardcoded list, so adding a tenth report route fails this test until it
        is either routed through the boundary or explicitly declared ungated.
        """
        report_routes = {
            r.path for r in M.app.routes
            if "report" in getattr(r, "path", "")
        }
        # The four that serve a pre-generated artifact rather than assembling
        # live; the boundary applies at GENERATION time for these.
        generated_at_write_time = {
            "/api/sessions/{session_id}/report",
            "/api/sessions/{session_id}/report/download",
            "/api/chains/{chain_id}/report",
            "/api/chains/{chain_id}/report/download",
        }
        # The five that assemble live from the DB via _build_report_json.
        #
        # Listing them here USED TO BE the whole check: the assertion below only
        # required that no route be UNCLASSIFIED, so naming a route in this set
        # exempted it permanently. All five bypassed the submission policy for
        # as long as they existed. `test_the_shared_builder_is_where_the_gate_lives`
        # and the format tests below now assert they are actually gated —
        # membership of this set is a statement about HOW they are gated, not a
        # pass.
        assembled_live = {
            "/api/sessions/{session_id}/report.json",
            "/api/sessions/{session_id}/report.html",
            "/api/sessions/{session_id}/report.sarif",
            "/api/sessions/{session_id}/report.defectdojo.json",
            "/api/sessions/{session_id}/report.jira.csv",
        }
        known = generated_at_write_time | assembled_live | set(M.ALLOWED_UNGATED_REPORT_PATHS)
        unclassified = report_routes - known
        assert unclassified == set(), (
            f"unclassified report route(s): {sorted(unclassified)} — route through "
            f"_deliverable_view or declare in ALLOWED_UNGATED_REPORT_PATHS")

        # And the live-assembly category must actually BE gated, not merely
        # named. Without this, adding a route to `assembled_live` is enough to
        # ship it ungated — which is exactly what happened.
        import inspect
        assert "_policy_verdicts" in inspect.getsource(M._build_report_json), (
            "the five assembled_live routes derive from _build_report_json, "
            "which no longer applies the submission policy")

    def test_the_four_artifact_routes_still_exist(self):
        """Guards the assumption the classification above rests on. If one of
        these is renamed, the set-difference test would pass vacuously."""
        paths = {getattr(r, "path", "") for r in M.app.routes}
        for p in ("/api/sessions/{session_id}/report",
                  "/api/sessions/{session_id}/report/download",
                  "/api/chains/{chain_id}/report",
                  "/api/chains/{chain_id}/report/download"):
            assert p in paths, f"{p} disappeared — reclassify it"

    def test_every_ungated_path_has_a_stated_reason(self):
        for path, reason in M.ALLOWED_UNGATED_REPORT_PATHS.items():
            assert reason and len(reason) > 20, f"{path} needs a real justification"


class TestEveryExportPassesTheSubmissionPolicy:
    """The five machine-readable exports had never seen the submission policy.

    /report.json, .html, .sarif, .defectdojo.json and .jira.csv all derive from
    _build_report_json, which called neither _deliverable_view nor
    _policy_verdicts — so an operator clicking SARIF shipped a deliverable
    containing findings the policy says must never be submitted, while the
    markdown report for the same session withheld them. Two answers about one
    session.

    The test that should have caught it listed those five under `assembled_live`
    and asserted only that no route was UNCLASSIFIED — a permanent exemption
    dressed as a classification.

    Semantics match the markdown path: ANNOTATE, never remove. Every finding is
    still listed and the stored severity is unchanged.
    """

    # Real evidence, because the policy is evidence-based: a CORS finding is
    # only demoted when the wildcard header is actually present. Fixtures that
    # skip this pass while proving nothing — two earlier attempts at this test
    # did exactly that.
    BLOCKED = ("CORS Misconfiguration", "medium", "Access-Control-Allow-Origin: *")
    ALLOWED = ("SQL Injection", "critical", "You have an error in your SQL syntax")

    @staticmethod
    def _client(tmp_path, rows):
        import asyncio
        import warnings
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        from fastapi.testclient import TestClient
        import orchestrator.database as db_mod
        import orchestrator.main as M

        db_mod.DB_PATH = str(tmp_path / "exp.db")

        async def seed():
            await db_mod.init_db()
            db = await db_mod.get_db()
            await db.execute(
                "INSERT INTO sessions (id,target_url,scope_mode,model,enabled_tools,"
                "status) VALUES ('s1','http://a','full','m','curl','completed')")
            for vt, sev, ev in rows:
                await db.execute(
                    "INSERT INTO findings (session_id,vuln_type,severity,url,evidence) "
                    "VALUES ('s1',?,?,?,?)", (vt, sev, "http://a/x", ev))
            await db.commit()
            await db.close()

        asyncio.run(seed())
        return TestClient(M.app)

    def _both(self, tmp_path):
        return self._client(tmp_path, [self.BLOCKED, self.ALLOWED])

    def test_the_fixture_actually_triggers_a_rule(self, tmp_path):
        """Guard on the guard. Every assertion below is vacuous if the policy
        never fires, and it did not fire for two earlier fixtures — one used a
        severity above the rule's ceiling, one had evidence the rule does not
        match."""
        from orchestrator import submission_policy as SP
        rules, _ = SP.cached_rules()
        vt, sev, ev = self.BLOCKED
        d = SP.classify({"id": 1, "vuln_type": vt, "severity": sev, "evidence": ev}, rules)
        assert d.is_informational, f"fixture does not trigger any rule: {d}"
        vt, sev, ev = self.ALLOWED
        d2 = SP.classify({"id": 2, "vuln_type": vt, "severity": sev, "evidence": ev}, rules)
        assert not d2.is_informational, "the control finding is also demoted"

    def test_report_json_carries_the_verdict(self, tmp_path):
        import orchestrator.database as db_mod
        old = db_mod.DB_PATH
        try:
            j = self._both(tmp_path).get("/api/sessions/s1/report.json").json()
            by = {f["title"]: f for f in j["findings"]}
            assert by["CORS Misconfiguration"]["submittable"] is False
            assert by["CORS Misconfiguration"]["policy_rule"]
            assert by["SQL Injection"]["submittable"] is True
            assert j["statistics"]["not_submittable"] == 1
        finally:
            db_mod.DB_PATH = old

    def test_nothing_is_removed(self, tmp_path):
        """Annotate, never remove — the rule the markdown path states."""
        import orchestrator.database as db_mod
        old = db_mod.DB_PATH
        try:
            j = self._both(tmp_path).get("/api/sessions/s1/report.json").json()
            assert len(j["findings"]) == 2
            assert j["statistics"]["total"] == 2
        finally:
            db_mod.DB_PATH = old

    def test_sarif_carries_it(self, tmp_path):
        import orchestrator.database as db_mod
        old = db_mod.DB_PATH
        try:
            sar = self._both(tmp_path).get("/api/sessions/s1/report.sarif").json()
            props = [r.get("properties", {}) for r in sar["runs"][0]["results"]]
            flags = sorted(p.get("submittable") for p in props)
            assert flags == [False, True], flags
            assert any(p.get("policy_rule") for p in props)
        finally:
            db_mod.DB_PATH = old

    def test_defectdojo_marks_it_inactive(self, tmp_path):
        """`active` is what DefectDojo's triage views filter on.

        An earlier version set this key EARLIER in the same dict literal, where
        a later line silently shadowed it — the change looked applied and did
        nothing, and only reading the parsed payload caught it."""
        import orchestrator.database as db_mod
        old = db_mod.DB_PATH
        try:
            dd = self._both(tmp_path).get(
                "/api/sessions/s1/report.defectdojo.json").json()["findings"]
            by = {d["title"]: d for d in dd}
            assert by["CORS Misconfiguration"]["active"] is False
            assert by["SQL Injection"]["active"] is True
            assert "NOT SUBMITTABLE" in by["CORS Misconfiguration"]["description"]
        finally:
            db_mod.DB_PATH = old

    def test_the_defectdojo_payload_has_no_duplicate_keys(self):
        """The bug above is invisible in a dict literal. This reads the SOURCE
        for a repeated key inside the appended object."""
        import ast
        import inspect
        from orchestrator import reporting
        tree = ast.parse(inspect.getsource(reporting.report_to_defectdojo))
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                keys = [k.value for k in node.keys
                        if isinstance(k, ast.Constant) and isinstance(k.value, str)]
                dupes = {k for k in keys if keys.count(k) > 1}
                assert not dupes, f"duplicate keys silently shadowed: {sorted(dupes)}"

    def test_jira_csv_has_a_submittable_column(self, tmp_path):
        import csv
        import io
        import orchestrator.database as db_mod
        old = db_mod.DB_PATH
        try:
            text = self._both(tmp_path).get("/api/sessions/s1/report.jira.csv").text
            rows = list(csv.DictReader(io.StringIO(text)))
            assert "Submittable" in rows[0]
            by = {r["Summary"].split("] ", 1)[-1]: r for r in rows}
            assert by["CORS Misconfiguration"]["Submittable"] == "no"
            assert by["SQL Injection"]["Submittable"] == "yes"
        finally:
            db_mod.DB_PATH = old

    def test_html_shows_a_banner(self, tmp_path):
        import orchestrator.database as db_mod
        old = db_mod.DB_PATH
        try:
            html = self._both(tmp_path).get("/api/sessions/s1/report.html").text
            assert "NOT SUBMITTABLE" in html
        finally:
            db_mod.DB_PATH = old

    def test_the_shared_builder_is_where_the_gate_lives(self):
        """One place, so the five formats cannot drift apart."""
        import inspect
        import orchestrator.main as M
        assert "_policy_verdicts" in inspect.getsource(M._build_report_json)

    def test_report_statistics_use_normalised_severity(self, tmp_path):
        """`calibrated_severity` contains '** CRITICAL'. Upper-casing that
        leaves it unmatched by _SEV_STAT_KEY, so a CRITICAL finding was counted
        as informational in the statistics of a client report."""
        import orchestrator.database as db_mod
        old = db_mod.DB_PATH
        try:
            import asyncio
            from fastapi.testclient import TestClient
            import orchestrator.main as M
            db_mod.DB_PATH = str(tmp_path / "sev.db")

            async def seed():
                await db_mod.init_db()
                db = await db_mod.get_db()
                await db.execute(
                    "INSERT INTO sessions (id,target_url,scope_mode,model,enabled_tools,"
                    "status) VALUES ('s1','http://a','full','m','curl','completed')")
                await db.execute(
                    "INSERT INTO findings (session_id,vuln_type,severity,"
                    "calibrated_severity,url,evidence) "
                    "VALUES ('s1','Broken Access Control','high','** CRITICAL',"
                    "'http://a/z','e')")
                await db.commit()
                await db.close()

            asyncio.run(seed())
            j = TestClient(M.app).get("/api/sessions/s1/report.json").json()
            assert j["statistics"]["critical"] == 1, j["statistics"]
            assert j["statistics"]["informational"] == 0
        finally:
            db_mod.DB_PATH = old
