"""E-033: no test case could clean up after itself, across all 32 of them.

`TestCase` and `TestStep` had no `cleanup` or `teardown` field at either level. The only
`cleanup` in the system was `Workflow.cleanup` — the operator's declaration for the
Schemathesis lane, not the case author's for their own probe. BUSL-09's header tells a HUMAN
to run `find / -name 'erlik-upload-*'` afterwards, which is the honest admission that erlik
writes to a client's server on an authorised engagement and then forgets.

THIS PERMITS NOTHING NEW, and that is the point of the shape it has. A cleanup runs only
after a step that actually EXECUTED, and a mutating step executes only where safe mode
already allows it — `ERLIK_SAFE_MODE=0`, a deliberately authorised destructive engagement.
With safe mode on, the step is refused and the cleanup never runs, because there is nothing
to undo. The gate is untouched; what changes is what erlik leaves behind on the side of it
where it was already writing.

The cleanup is held to the same scope check and the same safe-mode floor as any other
command. That costs nothing — a legitimate cleanup follows a step safe mode already
permitted — and closes the obvious abuse: a plain GET step with `cleanup: curl -X DELETE …`
would otherwise smuggle a mutation past a gate its own step could not pass.

A FAILED cleanup is the one that matters. It is a file still sitting on a client's server,
and a run that stays silent about it is how BUSL-09 came to tell a human to go looking.
"""
import pytest

from orchestrator.testcase.runner import run_test_case
from orchestrator.testcase.schema import TestCase as Case, TestStep as Step

SCOPE = {"allow_hosts": ["app.test"], "allow_ports": [80]}


@pytest.fixture(autouse=True)
def store(tmp_path, monkeypatch):
    """Every cleanup needs somewhere to record its obligation.

    Not incidental: the runner refuses a writing step whose obligation it cannot record, so
    a test without a database is testing the refusal rather than the undo. Production always
    has one — see `test_a_cleanup_obligation_outlives_the_run` for the rule itself.
    """
    import asyncio

    import orchestrator.database as db_mod

    monkeypatch.setattr(db_mod, "DB_DIR", tmp_path)
    monkeypatch.setattr(db_mod, "DB_PATH", tmp_path / "t.db")
    asyncio.run(db_mod.init_db())
    return tmp_path / "t.db"
UPLOAD = 'curl -s -F "f=@-;filename=erlik-upload-canary.php" "http://app.test/u"'
UNDO = 'curl -s -X DELETE "http://app.test/uploads/erlik-upload-canary.php"'


async def run(steps, *, fail=(), raises=(), **kwargs):
    """Run a case with an executor that RECORDS and sends nothing."""
    sent = []

    async def recorder(cmd, *a, **kw):
        sent.append(cmd)
        if cmd in raises:
            raise RuntimeError("the container went away")
        return {"success": cmd not in fail, "output": "", "duration_ms": 1,
                "error": "remote refused" if cmd in fail else None}

    case = Case(id="T", name="t", category="business logic", severity="high", steps=steps)
    result = await run_test_case(case, {"url": "http://app.test/u", "scope": SCOPE},
                                 executor=recorder, allow_llm=False, **kwargs)
    return sent, result


def upload_step(cleanup=UNDO, command=UPLOAD, name="upload"):
    return Step(name=name, tool="curl", command=command, cleanup=cleanup)


# ------------------------------------------------------- it runs, where writing is allowed


async def test_a_step_that_ran_has_its_undo_issued(monkeypatch):
    monkeypatch.setenv("ERLIK_SAFE_MODE", "0")
    sent, result = await run([upload_step()])
    assert sent == [UPLOAD, UNDO], sent
    assert [c.success for c in result.cleanups] == [True], result.cleanups
    assert result.cleanups[0].step == "cleanup: upload"


async def test_a_failed_undo_is_reported_rather_than_swallowed(monkeypatch):
    """The whole reason the field exists. A file is still on the client's server."""
    monkeypatch.setenv("ERLIK_SAFE_MODE", "0")
    _, result = await run([upload_step()], fail=(UNDO,))
    assert len(result.cleanups) == 1
    assert result.cleanups[0].success is False
    assert result.cleanups[0].error == "remote refused"


async def test_an_undo_that_raises_is_reported_rather_than_losing_the_run(monkeypatch):
    """A cleanup that throws must not take the findings with it — and must not be silent."""
    monkeypatch.setenv("ERLIK_SAFE_MODE", "0")
    _, result = await run([upload_step()], raises=(UNDO,))
    assert result.cleanups[0].success is False
    assert "RuntimeError" in result.cleanups[0].error


async def test_undos_run_in_reverse_order(monkeypatch):
    """A later step can depend on what an earlier one created, so undoing forwards can
    remove the thing the next undo needs."""
    monkeypatch.setenv("ERLIK_SAFE_MODE", "0")
    first = 'curl -s -X PUT "http://app.test/a"'
    second = 'curl -s -X PUT "http://app.test/b"'
    sent, _ = await run([
        upload_step(command=first, cleanup='curl -s -X DELETE "http://app.test/a"', name="a"),
        upload_step(command=second, cleanup='curl -s -X DELETE "http://app.test/b"', name="b")])
    assert sent == [first, second,
                    'curl -s -X DELETE "http://app.test/b"',
                    'curl -s -X DELETE "http://app.test/a"'], sent


async def test_the_undo_runs_even_when_the_case_is_cut_short(monkeypatch):
    """`finally`, because the artifact exists whether or not the case finished — and a run
    cut short mid-probe is when something is most likely left behind."""
    monkeypatch.setenv("ERLIK_SAFE_MODE", "0")
    sent = []

    async def recorder(cmd, *a, **kw):
        sent.append(cmd)
        return {"success": True, "output": "", "duration_ms": 1, "error": None}

    def explode(cmd, scope, primary_url=None):
        # Only the SECOND step. A checker that also raised for the cleanup would be testing
        # the fake rather than the product — which an earlier version of this did.
        if cmd == 'curl -s "http://app.test/x"':
            raise KeyboardInterrupt("operator stopped the run")
        return None

    case = Case(id="T", name="t", category="business logic", severity="high",
                steps=[upload_step(), Step(name="next", tool="curl",
                                           command='curl -s "http://app.test/x"')])
    with pytest.raises(KeyboardInterrupt):
        await run_test_case(case, {"url": "http://app.test/u", "scope": SCOPE},
                            executor=recorder, allow_llm=False, command_checker=explode)
    assert UNDO in sent, f"the undo did not run when the case was cut short: {sent}"


# --------------------------------------------------------- and it permits nothing new


async def test_nothing_is_undone_for_a_step_that_never_ran():
    """Safe mode ON. The mutating step is refused, so there is nothing to undo, and issuing
    a DELETE to a client's server for a file erlik never created would be its own defect."""
    sent, result = await run([upload_step()])
    assert sent == [], sent
    assert result.cleanups == [], result.cleanups
    assert result.steps[0].skipped is True


async def test_a_harmless_step_cannot_smuggle_a_mutation_through_its_cleanup():
    """A plain GET passes every gate; its `cleanup` must not therefore inherit permission."""
    sent, result = await run([upload_step(command='curl -s "http://app.test/x"')])
    assert sent == ['curl -s "http://app.test/x"'], sent
    assert len(result.cleanups) == 1
    assert result.cleanups[0].skipped is True
    assert result.cleanups[0].error.startswith("SAFE_MODE: "), result.cleanups[0].error


async def test_an_undo_is_scope_checked_like_any_other_command(monkeypatch):
    """The undo is a request to a host, and the case author chose the host."""
    monkeypatch.setenv("ERLIK_SAFE_MODE", "0")
    sent, result = await run([upload_step(
        cleanup='curl -s -X DELETE "http://elsewhere.test/f"')])
    assert sent == [UPLOAD], sent
    assert result.cleanups[0].skipped is True
    assert "scope violation" in result.cleanups[0].error


async def test_a_case_declaring_no_cleanup_is_unchanged(monkeypatch):
    """32 cases declare none, and nothing about them should move."""
    monkeypatch.setenv("ERLIK_SAFE_MODE", "0")
    sent, result = await run([Step(name="probe", tool="curl",
                                   command='curl -s "http://app.test/x"')])
    assert sent == ['curl -s "http://app.test/x"']
    assert result.cleanups == []


async def test_the_undo_is_rendered_from_the_same_context_as_its_step(monkeypatch):
    """`{{url}}` in a cleanup has to mean what it means in the command beside it, or an
    author writes an undo for a URL the step never touched."""
    monkeypatch.setenv("ERLIK_SAFE_MODE", "0")
    sent, _ = await run([upload_step(command='curl -s -X PUT "{{url}}/f"',
                                     cleanup='curl -s -X DELETE "{{url}}/f"')])
    assert sent == ['curl -s -X PUT "http://app.test/u/f"',
                    'curl -s -X DELETE "http://app.test/u/f"'], sent


def test_the_field_exists_on_the_step_rather_than_the_case():
    """Per STEP, because a case's steps do not all write, and a case-level undo would have
    to guess which of them left something."""
    from orchestrator.testcase.schema import TestCase, TestStep

    assert "cleanup" in TestStep.model_fields
    assert "cleanup" not in TestCase.model_fields
    assert TestStep(name="n", tool="curl", command="c").cleanup is None


async def test_one_failed_undo_does_not_strand_the_others(monkeypatch):
    """The lesson `service.release` already learned about collectors, and it applies harder
    here: what is stranded is a file on a client's server. Found by an earlier version of
    the cut-short test above, whose fake checker raised for the cleanup as well."""
    monkeypatch.setenv("ERLIK_SAFE_MODE", "0")
    first = 'curl -s -X PUT "http://app.test/a"'
    second = 'curl -s -X PUT "http://app.test/b"'
    undo_a = 'curl -s -X DELETE "http://app.test/a"'
    undo_b = 'curl -s -X DELETE "http://app.test/b"'

    def checker(cmd, scope, primary_url=None):
        if cmd == undo_b:
            raise ValueError("the checker itself fell over")
        return None

    sent, result = await run(
        [upload_step(command=first, cleanup=undo_a, name="a"),
         upload_step(command=second, cleanup=undo_b, name="b")],
        command_checker=checker)
    assert undo_a in sent, f"the surviving undo was abandoned: {sent}"
    failed = [c for c in result.cleanups if c.step == "cleanup: b"]
    assert failed and "could not be checked" in failed[0].error, result.cleanups


# ------------------------------------------------------ and the case that needed it


def test_the_one_case_that_can_name_what_it_wrote_declares_the_undo():
    """A mechanism nothing uses is a protection that is not there.

    CONF-06's `put_probe` writes `erlik_put_test.txt` to a URL erlik CHOSE, so unlike an
    upload it can name what it created. It is the only step in the catalogue that can, and
    the catalogue is read here rather than the filename asserted, so a rename cannot leave
    this passing against nothing.
    """
    from orchestrator.testcase.loader import load_catalog

    catalog = load_catalog()
    declared = [(case_id, step.name) for case_id, case in catalog.items()
                for step in case.steps if step.cleanup]
    assert ("WSTG-CONF-06", "put_probe") in declared, declared

    step = next(s for s in catalog["WSTG-CONF-06"].steps if s.name == "put_probe")
    written = step.command.rsplit("/", 1)[-1].strip('"')
    assert written and written in step.cleanup, (
        f"the undo does not name what the step wrote ({written!r}): {step.cleanup!r}")
    assert "-X DELETE" in step.cleanup


def test_a_case_that_cannot_name_what_it_wrote_does_not_pretend_to():
    """BUSL-09 uploads a file and the server decides where it lands, so erlik cannot form
    the URL to remove it. Declaring a guessed one would issue a DELETE against a path it
    invented on a client's server. Its header still tells a human where to look, and that
    remains the honest answer until an upload case can read back its own location."""
    import pathlib

    from orchestrator.testcase.loader import load_catalog

    case = load_catalog()["WSTG-BUSL-09"]
    assert all(step.cleanup is None for step in case.steps), (
        "BUSL-09 declares an undo; the upload location is the server's choice, not erlik's")
    header = pathlib.Path("tests_catalog/wstg/BUSL-09_file_upload.yaml").read_text()
    assert "find / -name 'erlik-upload-*'" in header, (
        "the human-cleanup instruction was removed without an undo replacing it")
