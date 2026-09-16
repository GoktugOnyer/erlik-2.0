"""E-019: evidence retention, and the two things its acceptance names.

    "Retention never silently deletes evidence needed by an active assessment."
    "Define which metadata survives evidence expiry."

The second is the one that matters to every later reader. `evidence_bytes` raised one
`EvidenceIntegrityError` for a missing artifact, so a store that LOST something and a store
that expired something on purpose were the same event — and they need opposite responses. One
is a fault to investigate; the other is a decision somebody made.

So the row survives the bytes: id, session, stage, kind, sha256, size and the date it went.
`EvidenceExpired` is a SUBCLASS of the integrity error, so every existing handler keeps
working and nothing starts treating an expiry as readable.
"""
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from orchestrator.integrations.persistence import (
    ACTIVE_ASSESSMENT_STATUSES, EvidenceExpired, EvidenceIntegrityError, expire_evidence)
from orchestrator.integrations.security import runtime_root


@pytest.fixture
async def lane(tmp_path, monkeypatch):
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    return db


async def session(db, name, status="completed"):
    await db.execute(
        "INSERT INTO integration_assessments(session_id,target,status,config) VALUES(?,?,?,?)",
        (name, "http://app.test/", status, "{}"))


async def aged(db, name, days, content="the response that proves it"):
    """One artifact, backdated so a retention sweep can see it."""
    evidence_id = await db.evidence(name, "stage-1", "testcase:WSTG-INPV-05", content)
    when = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    await db.execute("UPDATE integration_evidence SET created_at=? WHERE id=?",
                     (when, evidence_id))
    return evidence_id


# ------------------------------------------------- it never touches an active assessment


@pytest.mark.parametrize("status", ACTIVE_ASSESSMENT_STATUSES)
async def test_an_active_assessment_keeps_its_evidence_whatever_its_age(lane, status):
    """The acceptance, in its own words. A run that is queued, running or paused for
    authentication is still being worked on, and deleting what it rests on mid-flight is the
    silent deletion this exists to prevent."""
    await session(lane, "live", status=status)
    evidence_id = await aged(lane, "live", days=400)
    result = await expire_evidence(30, confirm=True)
    assert result["expired"] == []
    assert result["held_for_active_assessments"][0]["id"] == evidence_id
    assert "still active" in result["held_for_active_assessments"][0]["held_because"]
    assert (await lane.evidence_bytes(evidence_id)).decode() == "the response that proves it"


@pytest.mark.parametrize("status", ["completed", "partial", "failed", "cancelled"])
async def test_a_finished_assessment_is_expirable_however_unhappily_it_finished(lane, status):
    """`partial` and `failed` are finished. Reading the active set as the complement of
    `FINISHED_STAGE_STATUSES` would hold their evidence for ever."""
    await session(lane, "done", status=status)
    await aged(lane, "done", days=400)
    assert len((await expire_evidence(30, confirm=True))["expired"]) == 1


async def test_evidence_inside_the_window_is_not_touched(lane):
    await session(lane, "recent")
    evidence_id = await aged(lane, "recent", days=5)
    result = await expire_evidence(30, confirm=True)
    assert result["expired"] == []
    assert await lane.evidence_bytes(evidence_id)


# --------------------------------------------- an expiry does not read as a corrupt store


async def test_an_expired_artifact_says_it_was_expired(lane):
    """The distinction the whole increment is about. Before this, a retention policy and a
    corrupted store raised the same error and sent an operator looking for a fault."""
    await session(lane, "old")
    evidence_id = await aged(lane, "old", days=400)
    await expire_evidence(30, confirm=True)
    with pytest.raises(EvidenceExpired) as raised:
        await lane.evidence_bytes(evidence_id)
    assert "retention policy" in str(raised.value)
    assert "digest, size and kind are retained" in str(raised.value)


async def test_a_genuinely_missing_artifact_still_says_missing(lane):
    """The other half. Weakening the integrity error into an expiry would be worse than the
    conflation it replaces."""
    await session(lane, "old")
    evidence_id = await aged(lane, "old", days=1)
    (runtime_root() / "evidence" / evidence_id).unlink()
    with pytest.raises(EvidenceIntegrityError) as raised:
        await lane.evidence_bytes(evidence_id)
    assert not isinstance(raised.value, EvidenceExpired)
    assert "missing" in str(raised.value)


def test_the_expiry_error_is_a_subclass_so_existing_handlers_keep_working():
    """Several callers already catch `EvidenceIntegrityError`. A sibling type would make an
    expiry escape them and surface as an unhandled error to whoever reads a report."""
    assert issubclass(EvidenceExpired, EvidenceIntegrityError)


async def test_the_metadata_survives_the_bytes(lane):
    """"Define which metadata survives evidence expiry." It is defined here: enough to tell
    a reader what was there and that its digest was recorded."""
    await session(lane, "old")
    evidence_id = await aged(lane, "old", days=400)
    before = dict((await lane.rows(
        "SELECT * FROM integration_evidence WHERE id=?", (evidence_id,)))[0])
    await expire_evidence(30, confirm=True)
    after = dict((await lane.rows(
        "SELECT * FROM integration_evidence WHERE id=?", (evidence_id,)))[0])
    for field in ("id", "session_id", "stage_id", "kind", "sha256", "size"):
        assert after[field] == before[field], field
    assert after["expired_at"], "nothing records that this was a decision"


# ------------------------------------------------------------------ preview by default


async def test_it_removes_nothing_without_confirm(lane):
    """This destroys bytes a finding may cite and a client may be owed."""
    await session(lane, "old")
    evidence_id = await aged(lane, "old", days=400)
    result = await expire_evidence(30)
    assert result["applied"] is False
    assert [row["id"] for row in result["expired"]] == [evidence_id], (
        "a preview that shows nothing is not a preview")
    assert await lane.evidence_bytes(evidence_id), "it deleted without confirm"
    assert "run again with confirm" in result["establishes"]


async def test_the_preview_and_the_sweep_agree(lane):
    await session(lane, "old")
    await aged(lane, "old", days=400)
    preview = await expire_evidence(30)
    applied = await expire_evidence(30, confirm=True)
    assert [r["id"] for r in preview["expired"]] == [r["id"] for r in applied["expired"]]


async def test_sweeping_twice_expires_nothing_the_second_time(lane):
    await session(lane, "old")
    await aged(lane, "old", days=400)
    await expire_evidence(30, confirm=True)
    assert (await expire_evidence(30, confirm=True))["expired"] == []


async def test_an_artifact_already_gone_does_not_stop_the_sweep(lane):
    """One missing file must not leave the rest of the sweep undone — the lesson
    `service.release` learned about collectors, applied to a filesystem."""
    await session(lane, "old")
    first = await aged(lane, "old", days=400, content="first")
    second = await aged(lane, "old", days=400, content="second")
    (runtime_root() / "evidence" / first).unlink()
    result = await expire_evidence(30, confirm=True)
    assert {row["id"] for row in result["expired"]} == {first, second}
    with pytest.raises(EvidenceExpired):
        await lane.evidence_bytes(second)


# --------------------------------------------------------- and what it does not claim


async def test_it_does_not_call_itself_secure_deletion(lane):
    """The bytes are unlinked, which returns them to the filesystem and not to nobody. E-019
    asks for a secure deletion POLICY; this is a retention mechanism, and claiming otherwise
    would be exactly the kind of confident wrong statement this project keeps removing."""
    await session(lane, "old")
    await aged(lane, "old", days=400)
    establishes = (await expire_evidence(30, confirm=True))["establishes"]
    assert "not secure deletion" in establishes
    assert "not the same as unrecoverable" in establishes


# ------------------------------------------- and the bundle tells the two apart


async def test_a_bundle_calls_an_expiry_an_expiry(lane):
    """The reader that most needs the distinction. A bundle filing a retention expiry beside
    a corrupted artifact sends whoever receives it looking for a failure that did not
    happen."""
    from orchestrator.integrations.bundle import finding_bundle

    await session(lane, "old")
    evidence_id = await aged(lane, "old", days=400)
    await lane.execute("INSERT INTO integration_findings VALUES(?,?,?)", ("old", "fp-1",
        json.dumps({"fingerprint": "fp-1", "title": "t", "url": "http://app.test/x",
                    "rule": "r", "source": "testcase", "severity": "high",
                    "confidence": "confirmed", "basis": "b", "evidence_ids": [evidence_id],
                    "triage_state": "open"})))
    await expire_evidence(30, confirm=True)
    bundle = await finding_bundle("old", "fp-1")
    entry = bundle["evidence_not_readable"][0]
    assert entry["expired"] is True
    assert entry["sha256"], "the digest did not survive, so nothing identifies what was there"
    assert "retention removed the bytes" in bundle["establishes"]
    assert "decision rather than a fault" in bundle["establishes"]


async def test_a_bundle_still_calls_a_corrupted_artifact_a_fault(lane):
    from orchestrator.integrations.bundle import finding_bundle

    await session(lane, "old")
    evidence_id = await aged(lane, "old", days=1)
    await lane.execute("INSERT INTO integration_findings VALUES(?,?,?)", ("old", "fp-2",
        json.dumps({"fingerprint": "fp-2", "title": "t", "url": "http://app.test/x",
                    "rule": "r", "source": "testcase", "severity": "high",
                    "confidence": "confirmed", "basis": "b", "evidence_ids": [evidence_id],
                    "triage_state": "open"})))
    (runtime_root() / "evidence" / evidence_id).write_text("tampered")
    bundle = await finding_bundle("old", "fp-2")
    assert bundle["evidence_not_readable"][0]["expired"] is False
    assert "retention removed" not in bundle["establishes"]
