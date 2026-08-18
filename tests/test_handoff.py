"""Deterministic results become the AI agent's starting point.

erlik had both lanes and no path between them:

    main.py mentions v2_findings :  0
    v2 lane writes recon_context :  0

A deterministic run produced facts no agent ever saw, and every agent run
started from a bare URL — rediscovering ports, endpoints and technologies a
scan had already established.
"""

import asyncio

import pytest

import orchestrator.database as db_mod
import orchestrator.main as M
from orchestrator import handoff as H


class F:
    def __init__(self, vt, url="", ev="", tc="WSTG-X"):
        self.vuln_type, self.url, self.evidence, self.test_case_id = vt, url, ev, tc


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(db_mod, "DB_DIR", tmp_path)
    monkeypatch.setattr(db_mod, "DB_PATH", tmp_path / "t.db")
    asyncio.run(db_mod.init_db())
    return tmp_path / "t.db"


def bridge(findings, url="http://juice-shop:3000", run="r1"):
    async def go():
        d = await db_mod.get_db()
        try:
            n = await H.bridge_run(d, run, url, findings)
            await d.commit()
            return n
        finally:
            await d.close()
    return asyncio.run(go())


class TestKeysMatchTheAgent:
    def test_target_key_is_identical_to_mains(self):
        """A different normalisation means the agent looks under a key the
        handoff never wrote — the bridge would silently reach nothing."""
        for u in ("http://juice-shop:3000", "https://x.test", "http://a.b/c?d=1",
                  "juice-shop:3000"):
            assert H.target_key(u) == M._target_key(u), u

    def test_unparseable_target_writes_nothing(self, db):
        assert bridge([F("X")], url="") == 0


class TestBridge:
    def test_findings_reach_recon_context(self, db):
        assert bridge([F("NoSQL Operator Injection", "http://t/s", "$ne")]) == 1

    def test_idempotent_on_rerun(self, db):
        f = [F("NoSQL Operator Injection", "http://t/s", "$ne")]
        assert bridge(f) == 1
        assert bridge(f) == 0, "a rerun multiplied the agent's context"

    def test_findings_without_a_type_are_skipped(self, db):
        assert bridge([F(None)]) == 0

    def test_dict_findings_work_too(self, db):
        assert bridge([{"vuln_type": "X", "url": "http://t/", "evidence": "e",
                        "test_case_id": "WSTG-Y"}]) == 1

    @pytest.mark.parametrize("vt,bucket", [
        ("Spring Actuator Environment Dump Exposed", "endpoint"),
        ("phpinfo() Page Exposed", "endpoint"),
        ("Technology Version Disclosed", "endpoint"),
        ("NoSQL Operator Injection", "finding"),
        ("LDAP Injection", "finding"),
    ])
    def test_classification(self, vt, bucket):
        """`endpoint` reads to the agent as somewhere to look; `finding` as
        already established."""
        assert H._classify(vt) == bucket


class TestAgentActuallySeesIt:
    def test_deterministic_results_appear_in_the_starting_context(self, db):
        bridge([F("Spring Actuator Environment Dump Exposed",
                  "http://juice-shop:3000/actuator/env", "datasource creds",
                  "WSTG-CONF-02")])
        ctx = asyncio.run(M._get_target_memory_context(
            "a-different-session", "http://juice-shop:3000"))
        assert ctx, "agent got no starting context"
        assert "Actuator" in ctx or "WSTG-CONF-02" in ctx

    def test_a_different_target_sees_nothing(self, db):
        """Context is keyed per target; a scan of one host must not leak into a
        run against another."""
        bridge([F("X", "http://a.test/", "e")], url="http://a.test")
        ctx = asyncio.run(M._get_target_memory_context("s2", "http://b.test"))
        assert "X" not in ctx


class TestRecallIsNotInflated:
    def test_bridge_does_not_write_to_findings(self, db):
        """`findings` is what recall and precision are computed from. Copying
        deterministic results there would count one finding twice and make
        agent-lane numbers incomparable with every run before it."""
        import sqlite3
        bridge([F("NoSQL Operator Injection", "http://t/s", "$ne")])
        con = sqlite3.connect(db)
        try:
            assert con.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0
        finally:
            con.close()

    def test_module_never_inserts_into_findings(self):
        import inspect
        src = inspect.getsource(H)
        assert "INSERT INTO findings" not in src


class TestBriefStaysShort:
    def test_empty_input_produces_nothing(self):
        assert H.format_for_agent([]) == ""

    def test_brief_is_facts_not_methodology(self):
        """Injected guidance costs recall dose-dependently, so this is evidence
        rather than instruction."""
        out = H.format_for_agent([{"context_type": "endpoint", "key": "k", "value": "v"}])
        assert "already confirmed" in out
        assert len(out) < 600

    def test_brief_is_capped(self):
        rows = [{"context_type": "endpoint", "key": f"k{i}", "value": "v" * 300}
                for i in range(100)]
        assert len(H.format_for_agent(rows)) < 4000


class TestFailureIsNonFatal:
    def test_persistence_guards_the_bridge(self):
        import inspect
        from orchestrator.testcase import persistence
        src = inspect.getsource(persistence)
        # Anchor on the CALL, not the import — src.index finds the import line
        # first and the guard sits ~600 chars past it.
        i = src.index("await bridge_run(")
        window = src[i:i + 600]
        assert "except Exception" in window, "the bridge is unguarded"
        assert "skipped:" in window, "a failed bridge must say so, not vanish"


class TestHandoffContextIsDeterministicOnly:
    """The gate must inject the WSTG lane's results and NOTHING else.

    `_get_target_memory_context` — the obvious thing to reuse — also replays
    every prior finding from every earlier session against the target: 436 rows
    across 102 sessions on the Juice Shop corpus. Gating an experiment arm on
    that would measure "hand the agent every answer anyone ever recorded", and
    shipping it would let one false positive re-enter every future run on that
    client as an established fact.
    """

    def test_only_wstg_sourced_rows_are_injected(self, tmp_path, monkeypatch):
        import aiosqlite
        import orchestrator.main as M

        db_file = tmp_path / "t.db"

        async def _seed():
            async with aiosqlite.connect(db_file) as db:
                await db.execute(
                    "CREATE TABLE recon_context (session_id TEXT, context_type TEXT, "
                    "key TEXT, value TEXT, source_tool TEXT, target_key TEXT)")
                await db.executemany(
                    "INSERT INTO recon_context VALUES (?,?,?,?,?,?)",
                    [("other", "finding", "WSTG-INPV-05:SQL Injection", "/search",
                      "wstg:WSTG-INPV-05", "juice-shop:3000"),
                     ("other", "directory", "/admin", "found", "ffuf", "juice-shop:3000"),
                     ("other", "endpoint", "/api", "found", "nuclei", "juice-shop:3000")])
                await db.commit()
        asyncio.run(_seed())

        async def fake_get_db():
            conn = await aiosqlite.connect(db_file)
            conn.row_factory = aiosqlite.Row
            return conn

        monkeypatch.setattr(M, "get_db", fake_get_db)
        out = asyncio.run(M._get_handoff_context("me", "http://juice-shop:3000"))
        assert "SQL Injection" in out, "the deterministic row was not injected"
        assert "ffuf" not in out and "/admin" not in out, out
        assert "nuclei" not in out, out

    def test_empty_when_the_lane_has_run_nothing(self, tmp_path, monkeypatch):
        """Must return "" rather than a header with no facts under it — an
        empty brief still costs prompt budget and implies a scan happened."""
        import aiosqlite
        import orchestrator.main as M
        db_file = tmp_path / "t.db"

        async def _seed():
            async with aiosqlite.connect(db_file) as db:
                await db.execute(
                    "CREATE TABLE recon_context (session_id TEXT, context_type TEXT, "
                    "key TEXT, value TEXT, source_tool TEXT, target_key TEXT)")
                await db.commit()
        asyncio.run(_seed())

        async def fake_get_db():
            conn = await aiosqlite.connect(db_file)
            conn.row_factory = aiosqlite.Row
            return conn
        monkeypatch.setattr(M, "get_db", fake_get_db)
        assert asyncio.run(M._get_handoff_context("me", "http://juice-shop:3000")) == ""

    def test_gate_is_off_by_default(self):
        from orchestrator import runconfig
        assert runconfig.resolve({"preset": "custom"})["handoff"] is False

    def test_gate_is_separate_from_target_memory(self):
        """Two levers, because they carry different kinds of claim."""
        from orchestrator import runconfig
        r = runconfig.resolve({"preset": "custom", "handoff": True})
        assert r["handoff"] is True and r["target_memory"] is False

    def test_agent_loop_reads_the_isolated_gate(self):
        """Wiring guard: the loop must branch on `handoff`, not target_memory."""
        import pathlib
        src = (pathlib.Path(__file__).resolve().parents[1]
               / "orchestrator" / "main.py").read_text()
        assert 'runcfg.get("handoff")' in src
        assert "_get_handoff_context(session_id, target_url)" in src


class TestEvidenceIsNotAnHtmlPage:
    """Error-based test cases capture whole HTML error pages. Injected verbatim
    that put multi-line markup into the prompt, and injected volume is the one
    variable measured to cost recall dose-dependently."""

    def test_tags_and_newlines_are_stripped(self):
        raw = "<html>\n  <head>\n    <title>Error: SQLITE_ERROR: near \"x\"</title>"
        out = H._evidence(raw)
        assert "<" not in out and "\n" not in out
        assert "SQLITE_ERROR" in out, "stripped the part that carries the signal"

    def test_entities_are_decoded(self):
        assert '"' in H._evidence("a &quot;b&quot; c")

    def test_bounded(self):
        assert len(H._evidence("x" * 5000)) <= 110

    def test_handles_none(self):
        assert H._evidence(None) == ""

    def test_rendered_block_has_one_line_per_row(self):
        rows = [{"context_type": "finding", "key": "WSTG-INPV-05:SQLi",
                 "value": "<html>\n<head>\n<title>Error: SQLITE_ERROR</title>"}]
        body = H.format_for_agent(rows)
        entry = [l for l in body.splitlines() if l.startswith("  [")]
        assert len(entry) == 1, body
