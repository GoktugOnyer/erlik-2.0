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
