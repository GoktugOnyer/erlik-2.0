"""Refused commands must not count as coverage.

`tool_coverage`, `tools_used` and `phases_covered` are recomputed from
`steps.tool_called` in the DB long after a run ends. A command refused by the
scope guard, the toolset check, safe mode, the blocked-pattern list, or a
missing container is still WRITTEN as a step — it reached no shell, produced no
output, and told you nothing about the target.

Counting it inflates coverage with work that never happened, and safe mode
makes refusals routine rather than exceptional, so this stops being a rounding
error the moment safe mode is on.

Guarding the agent loop's in-memory `tools_executed` set does not fix it: that
set is discarded at session end, while the metrics are derived from the table.
Hence the column.
"""

import asyncio
import sqlite3

import pytest

import orchestrator.database as db_mod
import orchestrator.main as M


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(db_mod, "DB_DIR", tmp_path)
    monkeypatch.setattr(db_mod, "DB_PATH", tmp_path / "t.db")
    asyncio.run(db_mod.init_db())
    return tmp_path / "t.db"


def _seed(steps, enabled="curl,nmap,sqlmap,ffuf"):
    async def go():
        x = await db_mod.get_db()
        try:
            await x.execute(
                "INSERT INTO sessions (id,target_url,system_prompt,enabled_tools) "
                "VALUES (?,?,?,?)", ("s1", "http://t", "m", enabled))
            for i, (tool, phase, denied) in enumerate(steps, 1):
                await x.execute(
                    "INSERT INTO steps (session_id,phase,step_number,tool_called,"
                    "tool_input,tool_output,duration_ms,denied) VALUES (?,?,?,?,?,?,?,?)",
                    ("s1", phase, i, tool, f"{tool} http://t/",
                     "SCOPE: refused" if denied else "200 OK", 10, denied))
            await x.commit()
            cur = await x.execute("SELECT * FROM steps WHERE session_id='s1'")
            return [dict(r) for r in await cur.fetchall()]
        finally:
            await x.close()
    return asyncio.run(go())


class TestSchema:
    def test_denied_column_exists_and_defaults_to_zero(self, db):
        rows = _seed([("curl", "discovery", 0)])
        assert rows[0]["denied"] == 0

    def test_column_is_additive_on_an_existing_database(self, db):
        """The migration runs ALTER TABLE on a table that already exists, so an
        installed deployment picks it up without losing rows."""
        asyncio.run(db_mod.init_db())      # second run must be a no-op
        rows = _seed([("curl", "discovery", 0)])
        assert "denied" in rows[0]


class TestCoverageExcludesRefusals:
    def test_refused_tool_is_not_counted(self, db):
        """The concrete inflation: one real curl and one refused nmap reported
        two tools used and 0.50 coverage against a four-tool session."""
        rows = _seed([("curl", "discovery", 0), ("nmap", "recon", 1)])
        executed = [s for s in rows if not s.get("denied")]
        assert {s["tool_called"] for s in rows} == {"curl", "nmap"}
        assert {s["tool_called"] for s in executed} == {"curl"}
        assert len(executed) / 4 == 0.25

    def test_refused_step_does_not_cover_its_phase(self, db):
        """A refused nmap must not report the recon phase as covered — that is
        the feedback the agent needs to retry."""
        rows = _seed([("curl", "discovery", 0), ("nmap", "recon", 1)])
        phases = {s["phase"] for s in rows if not s.get("denied")}
        assert phases == {"discovery"}
        assert "recon" not in phases

    def test_all_refused_means_zero_coverage(self, db):
        rows = _seed([("nmap", "recon", 1), ("sqlmap", "exploitation", 1)])
        assert [s for s in rows if not s.get("denied")] == []

    def test_nothing_refused_is_unchanged(self, db):
        """The no-op control: a run with no refusals must measure exactly as it
        did before the column existed."""
        rows = _seed([("curl", "discovery", 0), ("nmap", "recon", 0)])
        executed = [s for s in rows if not s.get("denied")]
        assert len(executed) == len(rows)
        assert {s["tool_called"] for s in executed} == {"curl", "nmap"}


class TestEveryCoverageSiteIsGuarded:
    """Four sites derive coverage from steps. Missing one leaves the inflation
    in place on that path, which is exactly how the original design's
    agent-loop-only guard failed."""

    @staticmethod
    def _src():
        from pathlib import Path
        return (Path(__file__).resolve().parents[1] / "orchestrator" / "main.py").read_text()

    def test_session_metrics_filter_denied(self):
        assert 'executed_steps = [s for s in steps if not s.get("denied")]' in self._src()

    def test_chain_metrics_filter_denied(self):
        assert 'if s.get("tool_called") and not s.get("denied")' in self._src()

    def test_report_phase_coverage_filters_denied(self):
        assert '[s["tool_called"] for s in steps if not s.get("denied")]' in self._src()

    def test_agent_loop_tracker_filters_denied(self):
        """In-memory and discarded at session end, so it does not drive the
        recorded metric — but it DOES drive the phase feedback shown to the
        model mid-run, and telling the model it covered recon because a refused
        nmap 'ran' would suppress the retry."""
        src = self._src()
        i = src.index("tools_executed.add(tool_name)")
        assert 'if result.get("executed", True):' in src[i - 300:i]

    def test_denied_count_is_reported_not_just_subtracted(self):
        """An operator seeing lower coverage must be able to tell 'the agent did
        less' from 'the gate refused more'."""
        src = self._src()
        assert '"denied_steps": denied_steps,' in src
        assert '"denied_steps": all_chain_denied,' in src


class TestWriteSiteStampsIt:
    def test_step_insert_carries_the_flag(self):
        from pathlib import Path
        src = (Path(__file__).resolve().parents[1] / "orchestrator" / "main.py").read_text()
        i = src.index("INSERT INTO steps (session_id, phase, step_number, prompt_sent, "
                      "model_response, \"\n                        \"tool_called")
        block = src[i:i + 700]
        assert "denied" in block
        assert '0 if result.get("executed", True) else 1' in block
