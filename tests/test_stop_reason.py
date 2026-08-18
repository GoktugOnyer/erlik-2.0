"""Every way the agent loop can end must SAY so.

Diagnosing why 32 of 33 sessions stopped short of their cap required inferring
from the last parsed-action line — and that inference was WRONG: the stagnation
guard was not firing at all. A stop reason has to be a read, not a deduction.

Five exits, all instrumented: agent_done, stagnation, container_down,
max_turns, error.
"""

import asyncio
import inspect

import orchestrator.database as db_mod
import orchestrator.main as M
import pytest

SRC = inspect.getsource(M)
REASONS = ("agent_done", "stagnation", "container_down", "max_turns", "error")


class TestEveryExitIsInstrumented:
    @pytest.mark.parametrize("reason", ["container_down", "stagnation", "agent_done"])
    def test_break_sets_a_reason(self, reason):
        assert f'stop_reason = "{reason}"' in SRC

    def test_default_is_max_turns(self):
        """Falling out of the loop normally is itself a reason, not an absence."""
        assert 'stop_reason = "max_turns"' in SRC

    def test_error_path_records_its_own(self):
        """The post-loop persist is skipped when an exception escapes."""
        i = SRC.index("[AGENT CRASH]")
        assert "stop_reason = ?" in SRC[i - 900:i + 900]

    @pytest.mark.parametrize("reason", ["container_down", "stagnation",
                                        "agent_done", "max_turns"])
    def test_each_reason_is_printed(self, reason):
        """A broadcast goes to a websocket nobody records during a sweep."""
        assert f"STOP: {reason}" in SRC

    def test_every_break_in_the_loop_is_accounted_for(self):
        """Guard against a new exit landing without a reason."""
        lines = SRC.splitlines()
        start = next(i for i, l in enumerate(lines) if "for turn in range(max_turns)" in l)
        indent = len(lines[start]) - len(lines[start].lstrip())
        end = len(lines)
        for i in range(start + 1, len(lines)):
            l = lines[i]
            if l.strip() and (len(l) - len(l.lstrip())) <= indent and not l.lstrip().startswith("#"):
                end = i
                break
        unaccounted = []
        for i in range(start, end):
            if lines[i].strip() != "break":
                continue
            if not any('stop_reason = "' in lines[j] for j in range(max(start, i - 8), i)):
                unaccounted.append(i + 1)
        assert unaccounted == [], (
            f"break(s) at line(s) {unaccounted} exit the loop without setting a "
            f"stop_reason — the next diagnosis becomes a guess again")


class TestPersistence:
    @pytest.fixture
    def db(self, tmp_path, monkeypatch):
        monkeypatch.setattr(db_mod, "DB_DIR", tmp_path)
        monkeypatch.setattr(db_mod, "DB_PATH", tmp_path / "t.db")
        asyncio.run(db_mod.init_db())
        return tmp_path / "t.db"

    def test_column_exists_and_defaults_null(self, db):
        """Nullable on purpose: sessions recorded before this genuinely have no
        reason and must read as unknown, not be attributed to a default."""
        async def go():
            x = await db_mod.get_db()
            try:
                await x.execute("INSERT INTO sessions (id,target_url,system_prompt) "
                                "VALUES (?,?,?)", ("s1", "http://t", "m"))
                await x.commit()
                cur = await x.execute("SELECT stop_reason FROM sessions WHERE id='s1'")
                return (await cur.fetchone())[0]
            finally:
                await x.close()
        assert asyncio.run(go()) is None

    @pytest.mark.parametrize("reason", REASONS)
    def test_round_trips(self, db, reason):
        async def go():
            x = await db_mod.get_db()
            try:
                await x.execute("INSERT INTO sessions (id,target_url,system_prompt) "
                                "VALUES (?,?,?)", ("s1", "http://t", "m"))
                await x.execute("UPDATE sessions SET stop_reason = ? WHERE id = ?",
                                (reason, "s1"))
                await x.commit()
                cur = await x.execute("SELECT stop_reason FROM sessions WHERE id='s1'")
                return (await cur.fetchone())[0]
            finally:
                await x.close()
        assert asyncio.run(go()) == reason

    def test_persist_failure_does_not_break_a_run(self):
        i = SRC.index("UPDATE sessions SET stop_reason")
        assert "except Exception" in SRC[i:i + 400]
        assert "not recorded" in SRC[i:i + 500]
