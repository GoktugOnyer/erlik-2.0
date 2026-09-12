"""`recover()` rewrote the stage rows and left the assessment claiming it had finished.

It repairs `integration_stages` for EVERY session — `status='running'` becomes `partial`
"Interrupted by orchestrator restart" — and repairs `integration_assessments` only
`WHERE status='running'`. So a row that already said `completed` over a stage this function
just rewrote kept saying `completed`, and a restart is precisely when that would be noticed.

The write-time defect that produced the state is fixed (`service.run` degrades on any
exception and gives abandoned stages a terminal status), but fixing the writer does not repair
a store already holding one.

The rule is `run`'s own rollup, read from the one list both now share: any stage not
`completed` or `skipped` means the assessment is `partial`. It is scoped to rows that
currently claim `completed`, which is what keeps it from rewriting history — measured on both
recorded real stores, zero rows change.
"""
import pytest

from orchestrator.integrations.contracts import FINISHED_STAGE_STATUSES


@pytest.fixture
async def store(tmp_path, monkeypatch):
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db, service
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()

    async def no_orphans():
        return True

    monkeypatch.setattr(service, "recover_orphans", no_orphans)
    return db


async def session(store, name, assessment_status, *stage_statuses):
    import uuid
    await store.execute("INSERT INTO integration_assessments(session_id,target,status,config) "
                        "VALUES(?,?,?,?)", (name, "http://app.test/", assessment_status, "{}"))
    for status in stage_statuses:
        await store.execute(
            "INSERT INTO integration_stages(id,session_id,adapter,identity_id,status) "
            "VALUES(?,?,?,?,?)", (uuid.uuid4().hex, name, "testcases", "anonymous", status))


async def statuses(store):
    return {r["session_id"]: r["status"] for r in await store.rows(
        "SELECT session_id,status FROM integration_assessments")}


async def test_completed_over_an_unfinished_stage_becomes_partial(store):
    from orchestrator.integrations import service
    await session(store, "lying", "completed", "completed", "partial")
    await service.recover()
    assert (await statuses(store))["lying"] == "partial"


@pytest.mark.parametrize("status", FINISHED_STAGE_STATUSES)
async def test_a_genuinely_finished_assessment_is_left_alone(store, status):
    """The control that matters most: this runs at every startup over every session, so a
    false positive rewrites a record an operator has already reported on."""
    from orchestrator.integrations import service
    await session(store, "clean", "completed", "completed", status)
    await service.recover()
    assert (await statuses(store))["clean"] == "completed"


@pytest.mark.parametrize("assessment_status", ["needs_auth", "cancelled", "partial", "queued"])
async def test_a_row_that_does_not_claim_completed_keeps_its_own_word(store, assessment_status):
    """A `needs_auth` pause has non-finished stages BY DESIGN — it is the reason this is not
    applied to every row — and `cancelled` is more specific than `partial`."""
    from orchestrator.integrations import service
    await session(store, "paused", assessment_status, "needs_auth")
    await service.recover()
    assert (await statuses(store))["paused"] == assessment_status


async def test_it_repairs_the_state_the_restart_itself_creates(store):
    """End to end through the real sequence: a stage left `running` by a crash is rewritten to
    `partial` by the statement above, and the assessment must not survive that as `completed`.
    This is the case the gap existed in."""
    from orchestrator.integrations import service
    await session(store, "crashed", "completed", "running")
    await service.recover()
    assert (await statuses(store))["crashed"] == "partial"
    stage = (await store.rows("SELECT status,reason FROM integration_stages "
                              "WHERE session_id='crashed'"))[0]
    assert stage["status"] == "partial"
    assert "Interrupted by orchestrator restart" in stage["reason"]


async def test_the_session_row_is_repaired_too(store):
    """The repair stopped at `integration_assessments`, and the `sessions` table is what the
    dashboard list reads — so a repaired session still said `completed` there. Measured by an
    adversarial pass: 5 of 5 repaired sessions were left that way."""
    from orchestrator.integrations import service
    await store.execute("INSERT INTO sessions(id,status,target_url) VALUES(?,?,?)",
                        ("lying", "completed", "http://app.test/"))
    await session(store, "lying", "completed", "partial")
    await service.recover()
    row = (await store.rows("SELECT status FROM sessions WHERE id='lying'"))[0]
    assert row["status"] == "partial", "the dashboard would still say this run finished"


async def test_a_session_row_with_its_own_word_keeps_it(store):
    """`cancelled` is more specific than `partial`, and a repair must not flatten it."""
    from orchestrator.integrations import service
    await store.execute("INSERT INTO sessions(id,status,target_url) VALUES(?,?,?)",
                        ("cancelled-session", "cancelled", "http://app.test/"))
    await session(store, "cancelled-session", "completed", "partial")
    await service.recover()
    row = (await store.rows("SELECT status FROM sessions WHERE id='cancelled-session'"))[0]
    assert row["status"] == "cancelled"


async def test_one_session_does_not_drag_down_another(store):
    from orchestrator.integrations import service
    await session(store, "bad", "completed", "failed")
    await session(store, "good", "completed", "completed", "skipped")
    await service.recover()
    assert await statuses(store) == {"bad": "partial", "good": "completed"}


async def test_the_rule_comes_from_one_place(store):
    """`service.run`'s rollup and this one have to agree, and they did not exist together
    before — the list is shared so a future edit cannot move only one."""
    import inspect
    from orchestrator.integrations import inventory, service
    # NOT a count over the module, which a first draft used: the import line alone pushed it
    # past the threshold, so the assertion passed while `run`'s rollup still carried its own
    # literal tuple. Check the two FUNCTIONS, and that no literal survives beside them.
    for where in (service.run, service.recover, inventory.unfinished_stages):
        assert "FINISHED_STAGE_STATUSES" in inspect.getsource(where), where.__name__
    assert '("completed", "skipped")' not in inspect.getsource(service.run), (
        "the rollup is back to its own literal; the three places will drift")
