"""The single finding writer and its provenance stamp.

`INSERT INTO findings` used to appear in three bespoke inline blocks (nettacker,
auto-detect, LLM-reported), each carrying its own subset of the bookkeeping that
must happen alongside the write. Rows were also unattributable: a deterministic
detector finding and a model-reported one were byte-identical in the table.

Controls here are RUNTIME INVARIANTS, deliberately not source greps. A grep for
the literal `INSERT INTO findings` is defeated by `INSERT OR IGNORE` or an
f-string — both already used elsewhere in this codebase — so it would go green
against exactly the change it is meant to catch.
"""

import asyncio
import sqlite3

import pytest

import orchestrator.database as db_mod
import orchestrator.main as M
from orchestrator.detection import auto_detect_findings


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    """A real, migrated database at a throwaway path."""
    monkeypatch.setattr(db_mod, "DB_DIR", tmp_path)
    monkeypatch.setattr(db_mod, "DB_PATH", tmp_path / "t.db")
    asyncio.run(db_mod.init_db())
    asyncio.run(_mk_session("s1"))
    return tmp_path / "t.db"


async def _mk_session(sid):
    db = await db_mod.get_db()
    try:
        await db.execute(
            "INSERT INTO sessions (id, target_url, system_prompt) VALUES (?, ?, ?)",
            (sid, "http://juice-shop:3000", "test"))
        await db.commit()
    finally:
        await db.close()


def _rows(path, cols="vuln_type, source, detector"):
    con = sqlite3.connect(path)
    try:
        return [dict(zip([c.strip() for c in cols.split(",")], r))
                for r in con.execute(f"SELECT {cols} FROM findings ORDER BY id")]
    finally:
        con.close()


class TestProvenanceStamp:
    def test_content_discovery_carries_its_detector(self, tmp_db):
        """Positive control: a real gobuster block reaches the table attributed."""
        out = "/ftp    (Status: 200) [Size: 1]\n"
        found = auto_detect_findings("gobuster", out,
                                     "gobuster dir -u http://juice-shop:3000 -w /w.txt")
        assert found, "fixture must actually produce a finding"
        collected = []
        for f in found:
            asyncio.run(M._record_finding("s1", f, source="auto_detect",
                                          collected=collected))
        rows = _rows(tmp_db)
        assert len(rows) == 1
        assert rows[0]["source"] == "auto_detect"
        assert rows[0]["detector"] == "gobuster:_detect_content_discovery"

    def test_curl_rule_is_stamped_more_finely_than_its_tool(self):
        """curl dispatches 15 rules; `curl:curl` would be useless provenance."""
        out = ("HTTP/1.1 200 OK\r\n"
               "Access-Control-Allow-Origin: *\r\n"
               "Access-Control-Allow-Credentials: true\r\n\r\n")
        found = auto_detect_findings("curl", out, "curl -s -i http://juice-shop:3000/")
        assert found, "fixture must actually produce a finding"
        assert all(f["detector"].startswith("curl:_curl_") for f in found)

    def test_model_reported_finding_has_no_detector(self, tmp_db):
        """Negative control for the stamp: `detector` must NOT be blanket-filled.

        A model claim and a deterministic rule hit have to stay distinguishable,
        otherwise the column asserts a rule ran when none did.
        """
        asyncio.run(M._record_finding("s1", {
            "vuln_type": "SQL Injection", "severity": "high",
            "url": "http://juice-shop:3000/login", "parameter": "email",
            "evidence": "model said so",
        }, source="llm_reported", collected=[]))
        row = _rows(tmp_db)[0]
        assert row["source"] == "llm_reported"
        assert row["detector"] is None


class TestWriterInvariants:
    def test_every_row_is_attributable_to_a_writer(self, tmp_db):
        """The invariant that replaces the source grep.

        Exercises all three writers, then asserts no row reached the table
        without a `source`. A new inline INSERT added anywhere would fail this.
        """
        collected = []
        asyncio.run(M._record_finding("s1", {
            "vuln_type": "Open Port", "severity": "info", "url": "http://t/",
            "parameter": "", "evidence": "nettacker"}, source="nettacker"))
        for f in auto_detect_findings(
                "gobuster", "/ftp    (Status: 200) [Size: 1]\n",
                "gobuster dir -u http://juice-shop:3000 -w /w.txt"):
            asyncio.run(M._record_finding("s1", f, source="auto_detect",
                                          collected=collected))
        asyncio.run(M._record_finding("s1", {
            "vuln_type": "XSS", "severity": "medium", "url": "http://t/s",
            "parameter": "q", "evidence": "model"},
            source="llm_reported", collected=collected))

        con = sqlite3.connect(tmp_db)
        try:
            unattributed = con.execute(
                "SELECT COUNT(*) FROM findings WHERE source IS NULL").fetchone()[0]
            undetected = con.execute(
                "SELECT COUNT(*) FROM findings "
                "WHERE source = 'auto_detect' AND detector IS NULL").fetchone()[0]
            total = con.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        finally:
            con.close()
        assert unattributed == 0
        assert undetected == 0
        assert total == 3

    def test_collected_list_matches_the_table(self, tmp_db):
        """`findings_count` is derived from len(collected), so a divergence
        between the list and the table would put a wrong number in the report
        header while the table beneath it said something else."""
        collected = []
        for i in range(4):
            asyncio.run(M._record_finding("s1", {
                "vuln_type": "XSS", "severity": "medium",
                "url": f"http://t/{i}", "parameter": "q", "evidence": "e"},
                source="llm_reported", collected=collected))
        con = sqlite3.connect(tmp_db)
        try:
            n = con.execute("SELECT COUNT(*) FROM findings WHERE session_id='s1'").fetchone()[0]
        finally:
            con.close()
        assert n == len(collected) == 4

    def test_dedup_writes_nothing_and_reports_it(self, tmp_db):
        collected = []
        f = {"vuln_type": "CORS Misconfiguration", "severity": "high",
             "url": "http://t/api", "parameter": "", "evidence": "e"}
        assert asyncio.run(M._record_finding("s1", dict(f), source="auto_detect",
                                             collected=collected, dedup=True)) is True
        assert asyncio.run(M._record_finding("s1", dict(f), source="auto_detect",
                                             collected=collected, dedup=True)) is False
        assert len(collected) == 1
        assert len(_rows(tmp_db)) == 1

    def test_dedup_off_by_default(self, tmp_db):
        """The LLM path has its own validation and must not silently dedup."""
        collected = []
        f = {"vuln_type": "XSS", "severity": "medium", "url": "http://t/",
             "parameter": "q", "evidence": "e"}
        for _ in range(2):
            asyncio.run(M._record_finding("s1", dict(f), source="llm_reported",
                                          collected=collected))
        assert len(_rows(tmp_db)) == 2

    def test_evidence_is_truncated_at_the_writer(self, tmp_db):
        """Each inline INSERT applied [:2000] itself; one of four could have
        drifted. Now there is a single place it can be wrong."""
        asyncio.run(M._record_finding("s1", {
            "vuln_type": "XSS", "severity": "low", "url": "http://t/",
            "parameter": "", "evidence": "A" * 5000}, source="llm_reported"))
        con = sqlite3.connect(tmp_db)
        try:
            ev = con.execute("SELECT evidence FROM findings").fetchone()[0]
        finally:
            con.close()
        assert len(ev) == 2000

    def test_caller_owned_connection_is_not_closed(self, tmp_db):
        """The nettacker path holds one connection across a loop and commits
        once. Closing it per-finding would break the second iteration."""
        async def run():
            db = await db_mod.get_db()
            try:
                for i in range(3):
                    await M._record_finding("s1", {
                        "vuln_type": "Open Port", "severity": "info",
                        "url": f"http://t:{i}", "parameter": "", "evidence": "e"},
                        source="nettacker", db=db)
                await db.commit()
            finally:
                await db.close()
        asyncio.run(run())
        assert len(_rows(tmp_db)) == 3
