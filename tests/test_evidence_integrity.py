"""E-004: a stored digest that is never checked is not an integrity guarantee.

docs/future-plan.md, R0: "Every referenced artifact exists and passes its digest
check; each finding has substantive supporting evidence; empty diagnostic files
are valid attachments."

Two of those three clauses were not met, and the plan recorded E-004 as closed on
the strength of the third.

  CLAUSE 1  persistence.evidence() computes a sha256 at WRITE time and stores it.
            Nothing ever recomputes it. The download route fetches the row only
            to prove the id is known, discards its sha256, and streams whatever
            is on disk. defectdojo.reconcile reads an artifact and DECIDES from
            its contents whether a remote export matches. And the benchmark's own
            "resolvable" predicate reads `size` from the DATABASE ROW rather than
            the file — so it checks the row against itself.

  CLAUSE 3  record() drops an empty attachment entirely rather than retaining it
            as a valid-but-empty one. Those are different things, and the clause
            asks for the second.
"""
import hashlib

import pytest

from orchestrator.integrations.security import runtime_root


@pytest.fixture
async def database(tmp_path, monkeypatch):
    import orchestrator.database as original
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    from orchestrator.integrations import persistence
    await original.init_db()
    await persistence.migrate()
    return persistence


# ------------------------------------------------------- clause 1: the digest

async def test_a_substituted_artifact_is_refused_rather_than_served(database):
    """The bytes on disk are what a reader, an exporter and a reconciliation all
    act on. If one is swapped, every consumer acts on the wrong content and the
    stored digest — which would have caught it — is never consulted."""
    key = await database.evidence("s", "stage", "output", "the response we captured")
    assert await database.evidence_bytes(key) == b"the response we captured"

    (runtime_root() / "evidence" / key).write_text("something else entirely")
    with pytest.raises(database.EvidenceIntegrityError, match="digest"):
        await database.evidence_bytes(key)


async def test_a_missing_artifact_is_an_integrity_answer_not_a_crash(database):
    key = await database.evidence("s", "stage", "output", "content")
    (runtime_root() / "evidence" / key).unlink()
    with pytest.raises(database.EvidenceIntegrityError, match="missing"):
        await database.evidence_bytes(key)


async def test_an_unknown_id_is_distinguishable_from_a_corrupt_one(database):
    """A finding citing an id that was never stored and a finding whose artifact
    was tampered with are different defects with different fixes."""
    with pytest.raises(KeyError):
        await database.evidence_bytes("0" * 32)


async def test_the_download_route_verifies_before_it_serves(database):
    from fastapi import HTTPException
    from orchestrator.integrations import api

    key = await database.evidence("s", "stage", "output", "captured bytes")
    served = await api.evidence_file(key)
    assert b"captured bytes" in bytes(served.body)

    (runtime_root() / "evidence" / key).write_text("tampered")
    with pytest.raises(HTTPException) as raised:
        await api.evidence_file(key)
    assert raised.value.status_code == 404
    assert "digest" in str(raised.value.detail)


# --------------------------------------------- clause 3: an empty attachment

async def test_an_empty_diagnostic_file_is_retained_as_an_attachment(database, tmp_path):
    """An empty stderr from a clean scanner is a valid attachment: it says the
    scanner said nothing. Dropping it entirely and citing it as evidence are both
    wrong — the first loses the fact, the second was the original defect."""
    from orchestrator.integrations.adapters import record
    from orchestrator.integrations.contracts import StageResult
    from orchestrator.integrations.runtime import JobOutput

    out = tmp_path / "out"
    out.mkdir()
    (out / "scanner.log").write_text("")
    (out / "report.json").write_text('{"alerts": []}')

    class _Sandbox:
        images = {}
        output = out
        directory = tmp_path

    class _Ctx:
        session_id = "s"
        stage_id = "stage"
        known = ()

    result = StageResult()
    await record(_Ctx, _Sandbox, JobOutput(0, "", ""), result)

    rows = await database.rows("SELECT kind, size FROM integration_evidence WHERE session_id='s'")
    kinds = {r["kind"]: r["size"] for r in rows}
    assert "scanner.log" in kinds, "an empty diagnostic file was dropped instead of attached"
    assert kinds["scanner.log"] == 0
    assert kinds["report.json"] > 0
    # ...and an empty STREAM still writes nothing: a scanner that printed nothing
    # on stderr has no artifact to attach, which is not the same as a file.
    assert "stderr" not in kinds and "stdout" not in kinds


async def test_a_retained_empty_attachment_is_intact_not_dangling(database, tmp_path):
    """The half that makes clause 3 safe to satisfy: once an empty file is
    stored, its digest must verify, or the validator would call it broken."""
    key = await database.evidence("s", "stage", "scanner.log", "")
    assert await database.evidence_bytes(key) == b""
    row = (await database.rows("SELECT sha256 FROM integration_evidence WHERE id=?", (key,)))[0]
    assert row["sha256"] == hashlib.sha256(b"").hexdigest()
