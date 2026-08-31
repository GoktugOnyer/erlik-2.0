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

    def test_an_untriaged_finding_is_never_withheld(self):
        """The default is to SHOW. Only an explicit operator verdict removes a
        finding, so a session nobody has triaged reports exactly what it found."""
        rows = [{"vuln_type": "XSS"}, {"vuln_type": "SQLi", "triage_status": None},
                {"vuln_type": "SSRF", "triage_status": "accepted"}]
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
        #
        # That sentence was FALSE for the two chain routes for as long as it
        # was written. Their generator, _generate_chain_report, called neither
        # _deliverable_view nor _policy_verdicts and carried its own second,
        # unnormalised definition of effective severity — the same "permanent
        # exemption dressed as a classification" this file condemns twenty
        # lines below for `assembled_live`. It is true now, and
        # TestTheChainReportIsAlsoADeliverable asserts it rather than
        # asserting the claim.
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


class TestOperatorTriageIsOneDefinition:
    """"The operator says this finding is not real" had FOUR spellings.

        five machine exports   triage_status == "rejected"
        chain report           triage_status == "rejected"
        findings API (SQL)     IN ('rejected','false_positive')
        engagement rollup      IN ('rejected','false_positive')
        markdown report        (nothing at all)

    So a `false_positive` was hidden from the operator's own findings view and
    excluded from the engagement severity rollup while still being shipped to
    SARIF, DefectDojo and Jira; and a `rejected` finding was excluded from all
    five exports while still appearing in full — and counted in the header — in
    the markdown report actually handed to the client.
    """

    def test_the_python_and_sql_predicates_agree(self):
        """Same discipline as SQL_NORMALISE: compare them, do not trust that
        they were written to match."""
        import sqlite3
        from orchestrator import submission_policy as SP
        db = sqlite3.connect(":memory:")
        db.execute("CREATE TABLE f (triage_status TEXT)")
        matrix = ["rejected", "REJECTED", " Rejected ", "false_positive",
                  "FALSE_POSITIVE", "accepted", "", None, "confirmed",
                  "rejected_by_mistake"]
        for v in matrix:
            db.execute("DELETE FROM f")
            db.execute("INSERT INTO f VALUES (?)", (v,))
            sql = bool(db.execute(
                "SELECT COUNT(*) FROM f WHERE "
                + SP.SQL_WITHHELD_TRIAGE.format(col="triage_status")).fetchone()[0])
            py = SP.is_withheld({"triage_status": v})
            assert sql == py, f"{v!r}: SQL={sql} python={py}"

    def test_both_verdicts_are_withheld(self):
        from orchestrator import submission_policy as SP
        assert SP.is_withheld({"triage_status": "rejected"})
        assert SP.is_withheld({"triage_status": "false_positive"})
        assert not SP.is_withheld({"triage_status": "accepted"})
        assert not SP.is_withheld({})

    def test_no_hand_rolled_predicate_survives(self):
        """The four spellings are gone, and a fifth cannot be added quietly."""
        import re
        from pathlib import Path
        pat = re.compile(r"""triage_status["']?\s*(\)\s*)?(or\s+["']{2}\s*\)\s*)?"""
                         r"""(\.lower\(\)\s*)?(==|\bin\b)\s*[\("']""")
        offenders = []
        for f in (Path("orchestrator/main.py"), Path("orchestrator/engagement.py")):
            for n, line in enumerate(f.read_text().splitlines(), 1):
                if line.lstrip().startswith("#"):
                    continue
                if pat.search(line):
                    offenders.append(f"{f}:{n}: {line.strip()}")
        assert not offenders, (
            "hand-rolled triage predicate — use submission_policy.is_withheld "
            "or SQL_WITHHELD_TRIAGE:\n" + "\n".join(offenders))


class TestTheMarkdownAgreesWithTheExports:
    """The defect the whole boundary exists to prevent, still live in the one
    artifact a client actually reads.

    Measured before the fix: one session, one rejected finding — report.md said
    2 findings and listed the rejected one with full evidence, while report.json
    and report.sarif for that same session said 1. The dashboard meanwhile tells
    the operator, at index.html, "rejected are excluded from the report +
    exports".
    """

    @staticmethod
    def _all_four(tmp_path):
        import asyncio
        import warnings
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        from fastapi.testclient import TestClient
        import orchestrator.database as db_mod
        import orchestrator.main as M
        old = db_mod.DB_PATH, db_mod.DB_DIR, M.REPORTS_DIR
        db_mod.DB_DIR = tmp_path
        db_mod.DB_PATH = tmp_path / "agree.db"
        M.REPORTS_DIR = tmp_path / "reports"
        try:
            async def seed():
                await db_mod.init_db()
                db = await db_mod.get_db()
                await db.execute(
                    "INSERT INTO chains (id,target_url) VALUES ('c1','http://a')")
                await db.execute(
                    "INSERT INTO sessions (id,target_url,system_prompt,status,"
                    "scope_mode,model,enabled_tools,chain_id,chain_phase,"
                    "chain_position,total_steps,total_findings) VALUES "
                    "('s1','http://a','p','completed','full','m','curl','c1',"
                    "'recon',0,2,2)")
                for vt, tri in (("Ghost XSS", "rejected"),
                                ("SQL Injection", "accepted")):
                    await db.execute(
                        "INSERT INTO findings (session_id,vuln_type,severity,url,"
                        "evidence,triage_status) VALUES ('s1',?,'high',"
                        "'http://a/x','ev',?)", (vt, tri))
                await db.commit()
                await db.close()

                async def fake_chat(*a, **k):
                    return "stub"
                M.llm_client.chat = fake_chat
                md, _s, _ms = await M._generate_report(
                    "s1", "m", "http://a", "cold", "general", 2, 2, 500)
                await M._generate_chain_report("c1", "http://a")
                return md, (M.REPORTS_DIR / "chain_c1.md").read_text()

            md, chain = asyncio.run(seed())
            c = TestClient(M.app)
            return {
                "markdown": md,
                "json": c.get("/api/sessions/s1/report.json").json(),
                "sarif": c.get("/api/sessions/s1/report.sarif").json(),
                "chain": chain,
            }
        finally:
            db_mod.DB_PATH, db_mod.DB_DIR, M.REPORTS_DIR = old

    def test_every_deliverable_reports_the_same_number(self, tmp_path):
        import re
        d = self._all_four(tmp_path)
        md_header = int(re.search(r"\| \*\*Findings\*\* \| (\d+) \|", d["markdown"]).group(1))
        md_section = int(re.search(r"## Vulnerabilities Found \((\d+)\)", d["markdown"]).group(1))
        counts = {
            "report.md header": md_header,
            "report.md section": md_section,
            "report.json": d["json"]["statistics"]["total"],
            "report.sarif": len(d["sarif"]["runs"][0]["results"]),
            "chain report.md": int(
                re.search(r"Unique findings:\*\* (\d+)", d["chain"]).group(1)),
        }
        assert set(counts.values()) == {1}, counts

    def test_the_rejected_finding_is_in_none_of_them(self, tmp_path):
        d = self._all_four(tmp_path)
        assert "Ghost XSS" not in d["markdown"]
        assert "Ghost XSS" not in str(d["json"])
        assert "Ghost XSS" not in str(d["sarif"])
        assert "Ghost XSS" not in d["chain"]

    def test_the_markdown_states_what_it_withheld(self, tmp_path):
        """Annotate, never silently shrink. A report that drops findings without
        saying so is indistinguishable from a run that found fewer, and the
        client has no way to know there is a question to ask."""
        d = self._all_four(tmp_path)
        assert "| **Withheld** | 1 (rejected in triage)" in d["markdown"]
        assert "withheld from this report by operator triage" in d["markdown"]

    def test_the_chain_report_states_it_too(self, tmp_path):
        """It dropped them silently for its entire existence."""
        d = self._all_four(tmp_path)
        assert "withheld by operator triage" in d["chain"]
        assert "1 rejected" in d["chain"]


class TestTheChainReportIsAlsoADeliverable:
    """The consolidated chain report is the MOST client-facing artifact erlik
    produces, and it was the only findings table that had never seen the
    submission policy or the shared severity function.

    `test_no_unclassified_report_route` classified both chain routes as gated
    "at GENERATION time". Their generator called neither gate.
    """

    @staticmethod
    def _render(tmp_path, rows):
        import asyncio
        import orchestrator.database as db_mod
        import orchestrator.main as M
        old = db_mod.DB_PATH, db_mod.DB_DIR, M.REPORTS_DIR
        db_mod.DB_DIR = tmp_path
        db_mod.DB_PATH = tmp_path / "ch.db"
        M.REPORTS_DIR = tmp_path / "reports"
        try:
            async def go():
                await db_mod.init_db()
                db = await db_mod.get_db()
                await db.execute(
                    "INSERT INTO chains (id,target_url) VALUES ('c1','http://a')")
                await db.execute(
                    "INSERT INTO sessions (id,target_url,system_prompt,chain_id,"
                    "chain_phase,chain_position,total_steps,total_findings) "
                    "VALUES ('s1','http://a','p','c1','recon',0,1,1)")
                for vt, sev, cal, ev in rows:
                    await db.execute(
                        "INSERT INTO findings (session_id,vuln_type,severity,"
                        "calibrated_severity,url,evidence) VALUES "
                        "('s1',?,?,?,'http://a/'||?,?)", (vt, sev, cal, vt, ev))
                await db.commit()
                await db.close()
                await M._generate_chain_report("c1", "http://a")
                return (M.REPORTS_DIR / "chain_c1.md").read_text()
            return asyncio.run(go())
        finally:
            db_mod.DB_PATH, db_mod.DB_DIR, M.REPORTS_DIR = old

    # `calibrated_severity` really holds this. 11 rows in the recorded corpus
    # carry a '** ' prefix, one of them '** CRITICAL'.
    STARRED = ("Broken Access Control", "high", "** CRITICAL", "admin reachable")
    PLAIN = ("Verbose Errors", "medium", None, "stack trace")

    def test_a_starred_critical_is_counted_as_critical(self, tmp_path):
        """It rendered as `** CRITICAL`, and the executive summary said
        "1 critical" for a report holding two."""
        md = self._render(tmp_path, [self.STARRED, self.PLAIN])
        assert "** CRITICAL" not in md
        assert "| CRITICAL |" in md
        assert "1 critical" in md and "1 medium" in md

    def test_a_starred_critical_sorts_above_a_medium(self, tmp_path):
        """'** critical' was not a key in the order map, so it fell through to
        the default and sorted BELOW info — the most severe finding in the
        report appeared last."""
        md = self._render(tmp_path, [self.PLAIN, self.STARRED])
        body = md[md.index("## Consolidated Findings"):]
        assert body.index("Broken Access Control") < body.index("Verbose Errors")

    def test_the_submission_policy_reaches_the_chain_table(self, tmp_path):
        """A finding the policy says must never be submitted appeared here as
        an ordinary medium, while the same session's SARIF marked it."""
        md = self._render(tmp_path, [
            ("CORS Misconfiguration", "medium", None, "Access-Control-Allow-Origin: *"),
            ("SQL Injection", "critical", None, "You have an error in your SQL syntax")])
        assert "Submittable" in md
        cors = next(l for l in md.splitlines() if "CORS" in l)
        sqli = next(l for l in md.splitlines() if "SQL Injection" in l and l.startswith("|"))
        assert cors.rstrip().endswith("|") and "no — " in cors, cors
        assert "| yes |" in sqli, sqli

    def test_it_uses_the_shared_severity_function(self, tmp_path):
        """One definition. A local re-spelling is how the '**' bug got in."""
        import inspect
        import orchestrator.main as M
        src = inspect.getsource(M._generate_chain_report)
        assert "_sp.current_severity" in src
        assert 'or f.get("calibrated_severity")' not in src, (
            "a second effective-severity definition is back")
