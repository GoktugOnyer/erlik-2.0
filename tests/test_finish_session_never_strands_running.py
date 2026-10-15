"""`_finish_session` is the only transition out of 'running'.

If its status write raises and the exception escapes, the row is stranded in
'running' forever and every poller waits on a run that is already over. So the
write retries a transient failure and never propagates — a failed write must
still not skip the broadcast or crash the caller's cleanup.

Also guards that the agent loop's own hot-loop `get_db()` step-saves close their
connection through a finally (item 4's other half), so an exception at a step
write cannot leak the connection at the site.
"""

import inspect
import re

import pytest

import orchestrator.database as database
from orchestrator import main as M


@pytest.fixture
async def db_at(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_DIR", tmp_path)
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "test.db")
    await database.init_db()


async def _status(session_id):
    db = await M.get_db()
    try:
        row = await (await db.execute(
            "SELECT status FROM sessions WHERE id = ?", (session_id,))).fetchone()
        return row["status"] if row else None
    finally:
        await db.close()


async def _seed(session_id):
    db = await M.get_db()
    try:
        await db.execute("INSERT INTO sessions(id,target_url,status) VALUES(?,?,?)",
                         (session_id, "http://t/", "running"))
        await db.commit()
    finally:
        await db.close()


# ----------------------------------------------------------- the happy path

async def test_a_clean_finish_writes_the_terminal_status(db_at):
    await _seed("s-ok")
    await M._finish_session("s-ok", "completed")
    assert await _status("s-ok") == "completed"


# ------------------------------------------------- a transient failure retries

async def test_a_transient_write_failure_is_retried_to_success(db_at, monkeypatch):
    await _seed("s-flaky")
    real_get_db = M.get_db
    calls = {"n": 0}

    async def flaky_get_db():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("database is locked")   # transient
        return await real_get_db()

    monkeypatch.setattr(M, "get_db", flaky_get_db)
    await M._finish_session("s-flaky", "completed")
    assert calls["n"] >= 2, "the first failure must have been retried"
    assert await _status("s-flaky") == "completed", "the retry must have landed the write"


# -------------------------------------- a permanent failure does not propagate

async def test_a_permanent_write_failure_does_not_raise_or_skip_the_broadcast(
        db_at, monkeypatch):
    await _seed("s-dead")

    async def always_fail():
        raise RuntimeError("database is locked")

    monkeypatch.setattr(M, "get_db", always_fail)

    broadcasts = []

    async def record(session_id, message):
        broadcasts.append((session_id, message))

    monkeypatch.setattr(M.manager, "broadcast", record)

    # The property that matters: this returns rather than raising, so the
    # caller's finally (pop running_tasks, chain propagation) still runs.
    await M._finish_session("s-dead", "error")

    assert broadcasts and broadcasts[0][1]["status"] == "error", (
        "a failed status write must not also suppress the status broadcast")


# ------------------------------------------------- the hot-loop get_db wrapping

def test_every_hot_loop_get_db_in_the_agent_loop_closes_through_finally():
    """Each `db = await get_db()` inside agent_loop must be wrapped so the
    connection closes even when the step write raises. This fails if one of the
    three step-save wraps is reverted to a bare open/execute/close.
    """
    src = inspect.getsource(M.agent_loop).splitlines()
    offenders = []
    for i, line in enumerate(src):
        if re.match(r"\s*db = await get_db\(\)\s*$", line):
            # the very next non-blank line must open a try:
            nxt = next((s for s in src[i + 1:] if s.strip()), "")
            if nxt.strip() != "try:":
                offenders.append((i + 1, line.strip()))
    assert offenders == [], (
        f"a hot-loop get_db() in agent_loop is not wrapped in try/finally: {offenders}")
