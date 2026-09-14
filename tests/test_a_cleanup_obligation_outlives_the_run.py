"""E-012: "if the orchestrator dies, preserve cleanup obligations for operator review
rather than automatically repeating state changes after restart."

`TestStep.cleanup` runs the undo in a `finally`. That covers an exception and a cancellation.
It does NOT cover the process going away — a SIGKILL, a container stop, a machine losing
power — and `save_run` is called AFTER the run returns, so until this there was no row of any
kind: the file was on the client's server and nothing anywhere knew it existed.

Measured before: a run that wrote and then died left zero rows in the database.

The obligation is recorded IMMEDIATELY BEFORE the write, not beside the step policy. A first
version of this recorded it earlier and left an obligation for a step the safe-mode floor then
refused — a write that never happened, filed as an outstanding artifact. At the line it sits on
now, the step has passed the caller's policy, the floor and the scope check, so the next thing
that happens is the request.

AND IF IT CANNOT BE RECORDED, THE STEP DOES NOT RUN. That is `_v1_step_policy`'s own reasoning
— erlik cannot declare the undo, so it does not make the request — applied to the durable half.

NOTHING REPLAYS. Re-issuing a DELETE against a client's system from a record erlik cannot
re-verify is a state change nobody asked for a second time, and the target may have been
restored, reused or handed to someone else since. `outstanding_cleanups` reads; that is all.
"""
import asyncio
import json
import uuid

import pytest

import orchestrator.database as db_mod
from orchestrator.testcase.runner import outstanding_cleanups, run_test_case
from orchestrator.testcase.schema import TestCase as Case, TestStep as Step

SCOPE = {"allow_hosts": ["app.test"], "allow_ports": [80]}
WRITE = 'curl -s -i -X PUT "http://app.test/erlik_put_test.txt"'
UNDO = 'curl -s -i -X DELETE "http://app.test/erlik_put_test.txt"'


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(db_mod, "DB_DIR", tmp_path)
    monkeypatch.setattr(db_mod, "DB_PATH", tmp_path / "t.db")
    monkeypatch.setenv("ERLIK_SAFE_MODE", "0")
    asyncio.run(db_mod.init_db())
    return tmp_path / "t.db"


async def rows():
    db = await db_mod.get_db()
    try:
        return [dict(r) for r in await (await db.execute(
            "SELECT * FROM v2_cleanup_obligations ORDER BY created_at")).fetchall()]
    finally:
        await db.close()


async def run_case(*, die_before_cleanup=False, cleanup=UNDO, command=WRITE, fail_undo=False):
    sent = []

    async def recorder(cmd, *a, **kw):
        sent.append(cmd)
        if die_before_cleanup and cmd == command:
            # The process going away. `finally` does not run for a SIGKILL; BaseException
            # is the nearest thing a test can express, and it still runs `finally` — so the
            # obligation is checked while the run is IN FLIGHT instead, below.
            pass
        return {"success": not (fail_undo and cmd == cleanup), "output": "",
                "duration_ms": 1, "error": "remote refused" if fail_undo else None}

    case = Case(id="WSTG-CONF-06", name="methods", category="config", severity="medium",
                steps=[Step(name="put_probe", tool="curl", command=command, cleanup=cleanup)])
    result = await run_test_case(case, {"url": "http://app.test/u", "scope": SCOPE},
                                 executor=recorder, allow_llm=False)
    return sent, result


# ------------------------------------------------------------- the obligation is durable


async def test_the_obligation_exists_before_the_write_lands(store):
    """The whole point: it has to be on disk BEFORE the request, or a death between the two
    loses it. Asserted from inside the executor, which is the only moment that proves it."""
    seen = {}

    async def recorder(cmd, *a, **kw):
        seen[cmd] = await rows()
        return {"success": True, "output": "", "duration_ms": 1, "error": None}

    case = Case(id="WSTG-CONF-06", name="methods", category="config", severity="medium",
                steps=[Step(name="put_probe", tool="curl", command=WRITE, cleanup=UNDO)])
    await run_test_case(case, {"url": "http://app.test/u", "scope": SCOPE},
                        executor=recorder, allow_llm=False)
    at_write = seen[WRITE]
    assert len(at_write) == 1, (
        f"the write was issued with {len(at_write)} obligations recorded; a death here "
        f"would leave the artifact known to nobody")
    assert at_write[0]["command"] == UNDO
    assert at_write[0]["test_case_id"] == "WSTG-CONF-06"
    assert at_write[0]["step"] == "put_probe"
    assert at_write[0]["discharged_at"] is None


async def test_a_completed_undo_discharges_it(store):
    await run_case()
    recorded = await rows()
    assert len(recorded) == 1
    assert recorded[0]["discharged_at"] is not None
    assert recorded[0]["outcome"] == "succeeded"
    assert await outstanding_cleanups() == []


async def test_a_failed_undo_stays_outstanding_with_its_reason(store):
    """The row an operator most needs: the undo was attempted and the artifact is still
    there. Discharged, but recorded as failed — and `outstanding_cleanups` is for the ones
    nothing ever attempted, which is a different question."""
    await run_case(fail_undo=True)
    recorded = await rows()
    assert recorded[0]["outcome"] == "failed"
    assert "remote refused" in recorded[0]["detail"]


async def test_an_obligation_no_run_discharged_is_listed(store):
    """The death case, expressed the only way a test can: a row written and never closed,
    which is exactly what a SIGKILL between the write and the `finally` leaves."""
    db = await db_mod.get_db()
    try:
        await db.execute(
            "INSERT INTO v2_cleanup_obligations(id,test_case_id,step,command,target) "
            "VALUES (?,?,?,?,?)",
            (str(uuid.uuid4()), "WSTG-CONF-06", "put_probe", UNDO, "http://app.test/u"))
        await db.commit()
    finally:
        await db.close()
    outstanding = await outstanding_cleanups()
    assert len(outstanding) == 1
    assert outstanding[0]["command"] == UNDO
    assert outstanding[0]["target"] == "http://app.test/u"


async def test_a_discharged_obligation_is_not_listed_as_outstanding(store):
    """A list that includes what was already handled trains an operator to ignore it."""
    await run_case()
    assert await outstanding_cleanups() == []


# --------------------------------------------------- and what it refuses to do


async def test_a_write_whose_obligation_cannot_be_recorded_is_not_made(store, monkeypatch):
    """`_v1_step_policy`'s reasoning applied to the durable half: erlik cannot promise to
    remember the undo, so it does not make the request."""
    from orchestrator.testcase import runner

    async def broken(db, tc, step, command, target):
        raise RuntimeError("the store is unavailable")

    monkeypatch.setattr(runner, "_record_obligation", broken)
    sent, result = await run_case()
    assert sent == [], f"the write was made with no obligation recorded: {sent}"
    assert result.steps[0].skipped is True
    assert "could not be recorded" in result.steps[0].error
    assert "the write was not made" in result.steps[0].error


async def test_a_step_the_floor_refuses_records_no_obligation(store, monkeypatch):
    """The ordering bug this test exists for: recorded beside the step policy, an obligation
    was filed for a write the safe-mode floor then refused — an outstanding artifact for a
    request that never happened."""
    monkeypatch.setenv("ERLIK_SAFE_MODE", "1")
    sent, result = await run_case()
    assert sent == [] and result.steps[0].skipped is True
    assert result.steps[0].error.startswith("SAFE_MODE: ")
    assert await rows() == [], (
        "an obligation was recorded for a write the floor refused")


async def test_a_step_that_declares_no_cleanup_records_nothing(store):
    sent, _ = await run_case(cleanup=None, command='curl -s "http://app.test/x"')
    assert sent == ['curl -s "http://app.test/x"']
    assert await rows() == []


async def test_nothing_replays_an_obligation():
    """E-012 says review, not repeat. Re-issuing a DELETE from a record erlik cannot
    re-verify is a state change nobody asked for a second time — and the target may have
    been restored, reused, or handed to someone else since.

    Asserted against the module rather than by running a restart, because the claim is that
    NO code path does it: a behavioural test can only show that the paths it happens to
    exercise do not.
    """
    import inspect

    from orchestrator.testcase import runner

    source = inspect.getsource(runner)
    reads = source.count("FROM v2_cleanup_obligations")
    assert reads == 1, f"something else reads the obligations table ({reads} readers)"
    assert "outstanding_cleanups" in source
    body = inspect.getsource(runner.outstanding_cleanups)
    assert "execute_tool" not in body and "executor" not in body, (
        "the review path can issue a command, which makes it a replay path")
