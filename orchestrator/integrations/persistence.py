"""Additive integration storage. Artifacts are addressed by opaque IDs."""
from __future__ import annotations
import hashlib
from datetime import datetime, timedelta, timezone
import json
import re
import uuid
from pathlib import Path
from orchestrator.database import get_db
from .security import private_write, runtime_root, redact


async def migrate():
    db = await get_db()
    try:
        await db.executescript("""
        CREATE TABLE IF NOT EXISTS integration_assessments (
          session_id TEXT PRIMARY KEY, target TEXT NOT NULL, config TEXT NOT NULL,
          config_secret_id TEXT,
          status TEXT NOT NULL DEFAULT 'queued', elapsed_seconds REAL NOT NULL DEFAULT 0,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS integration_stages (
          id TEXT PRIMARY KEY, session_id TEXT NOT NULL, adapter TEXT NOT NULL,
          identity_id TEXT NOT NULL, status TEXT NOT NULL, reason TEXT DEFAULT '',
          result TEXT DEFAULT '{}', started_at TEXT, finished_at TEXT);
        CREATE TABLE IF NOT EXISTS integration_endpoints (
          session_id TEXT NOT NULL, url TEXT NOT NULL, method TEXT NOT NULL,
          identity_id TEXT NOT NULL, sources TEXT NOT NULL,
          parameters TEXT NOT NULL DEFAULT '[]',
          PRIMARY KEY(session_id,url,method,identity_id));
        CREATE TABLE IF NOT EXISTS integration_findings (
          session_id TEXT NOT NULL, fingerprint TEXT NOT NULL, payload TEXT NOT NULL,
          PRIMARY KEY(session_id,fingerprint));
        CREATE TABLE IF NOT EXISTS integration_evidence (
          id TEXT PRIMARY KEY, session_id TEXT NOT NULL, stage_id TEXT NOT NULL,
          kind TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS integration_identities (
          id TEXT PRIMARY KEY, name TEXT NOT NULL, target_origin TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS integration_exports (
          id TEXT PRIMARY KEY, session_id TEXT NOT NULL, destination TEXT NOT NULL,
          payload_hash TEXT NOT NULL, status TEXT NOT NULL, remote_test_id INTEGER,
          detail TEXT DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS integration_export_destinations (
          destination TEXT PRIMARY KEY, server TEXT NOT NULL, remote_test_id INTEGER NOT NULL,
          remote_engagement_id INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS integration_check_runs (
          id TEXT PRIMARY KEY, session_id TEXT NOT NULL, check_name TEXT NOT NULL,
          first_identity TEXT NOT NULL, second_identity TEXT NOT NULL,
          arguments TEXT NOT NULL DEFAULT '{}',
          refused_because TEXT NOT NULL DEFAULT '[]',
          checked INTEGER NOT NULL DEFAULT 0, findings INTEGER NOT NULL DEFAULT 0,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS integration_remote_findings (
          server TEXT NOT NULL, remote_test_id INTEGER NOT NULL, fingerprint TEXT NOT NULL,
          remote_finding_id INTEGER NOT NULL, payload_hash TEXT NOT NULL,
          updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
          PRIMARY KEY(server,remote_test_id,fingerprint));
        CREATE INDEX IF NOT EXISTS integration_stage_session ON integration_stages(session_id);
        CREATE INDEX IF NOT EXISTS integration_check_run_session ON integration_check_runs(session_id);
        """)
        columns = {r[1] for r in await (await db.execute("PRAGMA table_info(integration_assessments)")).fetchall()}
        if "elapsed_seconds" not in columns:
            await db.execute("ALTER TABLE integration_assessments ADD COLUMN elapsed_seconds REAL NOT NULL DEFAULT 0")
        if "config_secret_id" not in columns:
            await db.execute("ALTER TABLE integration_assessments ADD COLUMN config_secret_id TEXT")
        endpoint_columns = {r[1] for r in await (await db.execute("PRAGMA table_info(integration_endpoints)")).fetchall()}
        if "parameters" not in endpoint_columns:
            # CREATE TABLE IF NOT EXISTS is a no-op on a database that already
            # has this table, so an existing assessment store needs the column
            # added explicitly. Existing rows default to "no parameters known",
            # which is exactly what was true of them.
            await db.execute("ALTER TABLE integration_endpoints ADD COLUMN parameters TEXT NOT NULL DEFAULT '[]'")
        export_columns = {r[1] for r in await (await db.execute("PRAGMA table_info(integration_exports)")).fetchall()}
        for name, declaration in (("action", "TEXT NOT NULL DEFAULT 'reimport'"),
                                  ("remote_engagement_id", "INTEGER"), ("evidence_id", "TEXT")):
            if name not in export_columns:
                await db.execute(f"ALTER TABLE integration_exports ADD COLUMN {name} {declaration}")
        evidence_columns = {r[1] for r in await (await db.execute(
            "PRAGMA table_info(integration_evidence)")).fetchall()}
        if "expired_at" not in evidence_columns:
            # THE ROW SURVIVES THE BYTES. E-019 asks which metadata survives evidence
            # expiry, and the answer has to be "enough to tell a deliberate expiry from a
            # loss": the digest, the size, the kind and when it went. Without this column a
            # retention policy and a corrupted store are the same event to every reader —
            # `evidence_bytes` raises the same integrity error for both — and one of those
            # is a decision somebody made while the other is a failure.
            await db.execute("ALTER TABLE integration_evidence ADD COLUMN expired_at TEXT")
        await _withdraw_invertible_marker_digests(db)
        await db.commit()
    finally:
        await db.close()


async def execute(sql, args=()):
    db = await get_db()
    try:
        await db.execute(sql, args)
        await db.commit()
    finally:
        await db.close()


async def migrated() -> bool:
    """Whether the integration schema exists in this database yet.

    `migrate()` runs from the app lifespan, but the report builder is also
    called by the agent loop, the CLI and the tests, none of which start the
    app. Querying an absent table there raised OperationalError out of a report
    that had nothing to do with integrations — so the question has to be asked
    before it is answered, and "no tables" means "no assessment".
    """
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='integration_assessments'")
        return await cursor.fetchone() is not None
    finally:
        await db.close()


async def rows(sql, args=()):
    db = await get_db()
    try:
        cursor = await db.execute(sql, args)
        return [dict(row) for row in await cursor.fetchall()]
    finally:
        await db.close()


class EvidenceIntegrityError(Exception):
    """A stored artifact is missing, or no longer the bytes that were stored."""


class EvidenceExpired(EvidenceIntegrityError):
    """The artifact was deliberately removed under a retention policy.

    A SUBCLASS, so every existing `except EvidenceIntegrityError` keeps working and nothing
    starts treating an expiry as readable. It is a distinct type because the two events need
    opposite responses: a store that lost an artifact is a failure to investigate, and a
    retention expiry is a decision somebody made — and a report that renders them identically
    sends an operator looking for a fault that is not there.
    """


async def evidence_bytes(evidence_id: str) -> bytes:
    """An artifact, checked against the digest recorded when it was written.

    The digest was write-only state: computed here, stored, and never consulted
    again. The download route fetched the row only to prove the id was known and
    then streamed whatever was on disk; defectdojo.reconcile reads an artifact
    and DECIDES from its contents whether a remote export matches, which is the
    sharper risk of the two; and the benchmark's own resolvable-evidence check
    read `size` from the database row rather than the file, so it compared the
    row against itself.

    A missing artifact and an unknown id are different answers on purpose: one
    is an integrity failure, the other is a caller asking for something that was
    never stored.
    """
    entries = await rows("SELECT * FROM integration_evidence WHERE id=?", (evidence_id,))
    if not entries:
        raise KeyError(evidence_id)
    path = runtime_root() / "evidence" / evidence_id
    if not path.is_file():
        if entries[0]["expired_at"]:
            raise EvidenceExpired(
                f"evidence artifact was expired under the retention policy on "
                f"{entries[0]['expired_at']}; its digest, size and kind are retained")
        raise EvidenceIntegrityError("evidence artifact is missing")
    content = path.read_bytes()
    if hashlib.sha256(content).hexdigest() != entries[0]["sha256"]:
        raise EvidenceIntegrityError("evidence artifact failed its digest check")
    return content


async def evidence(session_id: str, stage_id: str, kind: str, content: str, known=()) -> str:
    cleaned = redact(content, known).encode()
    key = uuid.uuid4().hex
    private_write(runtime_root() / "evidence" / key, cleaned)
    await execute("INSERT INTO integration_evidence(id,session_id,stage_id,kind,sha256,size) VALUES(?,?,?,?,?,?)",
                  (key, session_id, stage_id, kind, hashlib.sha256(cleaned).hexdigest(), len(cleaned)))
    return key


# An assessment in one of these is still being worked on, and its evidence is what the work
# rests on. E-019: "retention never silently deletes evidence needed by an active assessment."
# Read as the complement of `FINISHED_STAGE_STATUSES` would be wrong — `partial` and `failed`
# assessments are finished, however unhappily, and their evidence is as expirable as any.
ACTIVE_ASSESSMENT_STATUSES = ("queued", "running", "needs_auth")


async def expire_evidence(older_than_days: int, *, confirm: bool = False) -> dict:
    """Remove evidence BYTES past their retention age, keeping the row that describes them.

    E-019 asks for configurable retention and for "which metadata survives evidence expiry"
    to be defined. It is: the id, the session, the stage, the kind, the sha256, the size and
    the date it went. Enough to tell a reader what was there, that its digest was recorded,
    and that it left on purpose.

    THREE RULES, and the first two are the acceptance:

    - Evidence belonging to an ACTIVE assessment is never touched, whatever its age. A run
      that is queued, running or paused for authentication is still being worked on, and
      deleting what it rests on mid-flight is the silent deletion the entry names.
    - Nothing is removed without `confirm`. This destroys bytes that a finding may cite and a
      client may be owed; the default is to report what WOULD go.
    - The row survives the file. `EvidenceExpired` is what a later read gets — a distinct type
      from the integrity error, because a retention decision and a corrupted store need
      opposite responses from whoever reads them.

    WHAT THIS DOES NOT CLAIM: it is not secure deletion. The bytes are unlinked, which returns
    them to the filesystem and not to nobody; on a journalled or copy-on-write volume, or with
    a snapshot behind it, they may persist. E-019 asks for a secure deletion POLICY and this
    is a retention mechanism — saying otherwise would be the kind of confident wrong claim
    this project keeps removing.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=max(0, older_than_days))).isoformat()
    active = {row["session_id"] for row in await rows(
        "SELECT session_id FROM integration_assessments WHERE status IN "
        f"({','.join('?' * len(ACTIVE_ASSESSMENT_STATUSES))})", ACTIVE_ASSESSMENT_STATUSES)}
    candidates = [dict(row) for row in await rows(
        "SELECT id,session_id,stage_id,kind,sha256,size,created_at FROM integration_evidence "
        "WHERE expired_at IS NULL AND created_at < ?", (cutoff,))]

    expiring = [row for row in candidates if row["session_id"] not in active]
    held = [{**row, "held_because": "its assessment is still active"}
            for row in candidates if row["session_id"] in active]
    if confirm:
        stamp = datetime.now(timezone.utc).isoformat()
        for row in expiring:
            path = runtime_root() / "evidence" / row["id"]
            # `missing_ok`: an artifact already gone is still expired from here on, and
            # raising would leave the rest of the sweep undone over a file nobody has.
            path.unlink(missing_ok=True)
            await execute("UPDATE integration_evidence SET expired_at=? WHERE id=?",
                          (stamp, row["id"]))
    return {
        "applied": bool(confirm),
        "cutoff": cutoff,
        "expired": [{k: row[k] for k in ("id", "session_id", "kind", "sha256", "size",
                                         "created_at")} for row in expiring],
        "held_for_active_assessments": held,
        "bytes_released": sum(row["size"] for row in expiring),
        "establishes": (
            ("expired " if confirm else "would expire ")
            + f"{len(expiring)} artifact(s) older than {older_than_days} day(s), releasing "
              f"{sum(row['size'] for row in expiring)} byte(s). {len(held)} were HELD because "
              f"their assessment is still active. Each expired row keeps its digest, size and "
              f"kind, so a later read reports an expiry rather than an integrity failure"
            + ("; run again with confirm to remove them" if not confirm else "")
            + ". This is retention, not secure deletion: the bytes are unlinked, which is not "
              "the same as unrecoverable."),
    }

async def persist_result(session_id, stage_id, result):
    await execute("UPDATE integration_stages SET status=?, reason=?, result=?, finished_at=CURRENT_TIMESTAMP WHERE id=?",
                  (result.status, result.reason, result.model_dump_json(), stage_id))
    for endpoint in result.endpoints:
        old = await rows("SELECT sources,parameters FROM integration_endpoints WHERE session_id=? AND url=? AND method=? AND identity_id=?",
                         (session_id, endpoint.url, endpoint.method, endpoint.identity))
        sources = set(json.loads(old[0]["sources"])) if old else set()
        sources.add(endpoint.source)
        # Parameters MERGE across sources the way sources do: katana sees the
        # query string, ZAP names the field it exercised, and neither is a
        # superset of the other. Merged per (url, method, identity), so a
        # parameter learned as one identity is never offered to another.
        parameters = set(json.loads(old[0]["parameters"] or "[]")) if old else set()
        parameters.update(endpoint.parameters)
        await execute("INSERT OR REPLACE INTO integration_endpoints VALUES(?,?,?,?,?,?)",
                      (session_id, endpoint.url, endpoint.method, endpoint.identity,
                       json.dumps(sorted(sources)), json.dumps(sorted(parameters))))
    await persist_findings(session_id, result.findings)


# The line the cross-arm authorization findings used to carry: an UNSALTED
# `sha256(marker)[:12]`, which a 4050-candidate search inverts in 0.0007s.
_INVERTIBLE_DIGEST_LINE = re.compile(r"(?m)^\s*marker digest:.*\n?")


async def _withdraw_invertible_marker_digests(db) -> int:
    """Strip the pre-keying marker label out of evidence already on disk.

    A SCHEMA MIGRATION WOULD NOT HAVE BEEN ENOUGH. The label moved from the `evidence`
    prose to a keyed field, so new findings are safe — but rows persisted before that still
    carry the invertible form in their prose, and the export still publishes it. Measured on
    the real Juice Shop store: 2 of 11 findings still held `marker digest: c5c79a1df019`,
    from which the marker recovers in under a millisecond.

    It STRIPS rather than re-labels, because it cannot do anything else: recomputing a keyed
    label needs the marker, and the marker was never stored — which is the design working.
    Losing an unrecoverable-by-design label from an old row is a small cost; keeping an
    invertible one is not a cost the operator chose.

    Bounded to the two authorization rules, and idempotent: a row with no such line is not
    rewritten.
    """
    changed = 0
    cursor = await db.execute("SELECT session_id,fingerprint,payload FROM integration_findings")
    for session_id, fingerprint, payload in await cursor.fetchall():
        if "marker digest:" not in (payload or ""):
            continue
        try:
            finding = json.loads(payload)
        except (ValueError, TypeError):
            continue
        if not str(finding.get("rule", "")).startswith("erlik:authorization:"):
            continue
        stripped = _INVERTIBLE_DIGEST_LINE.sub("", finding.get("evidence") or "")
        if stripped == finding.get("evidence"):
            continue
        finding["evidence"] = stripped
        await db.execute("UPDATE integration_findings SET payload=? WHERE session_id=? "
                         "AND fingerprint=?", (json.dumps(finding), session_id, fingerprint))
        changed += 1
    return changed


async def persist_findings(session_id, findings):
    """Write findings, preserving triage and never replacing evidence with nothing.

    Split out of `persist_result` so the cross-arm authorization checks can record what they
    find without pretending to be a stage. They are asked for on demand and at the end of a
    run, and before this they persisted NOTHING — so the lane's strongest evidence reached no
    report, no export and no triage. One implementation, because the triage-merge rule below is
    the sort of thing that drifts when copied.
    """
    for finding in findings:
        old = await rows("SELECT payload FROM integration_findings WHERE session_id=? AND fingerprint=?", (session_id, finding.fingerprint))
        if old:
            prior = json.loads(old[0]["payload"])
            finding.evidence_ids = sorted(set(prior.get("evidence_ids", []) + finding.evidence_ids))
            # THE SAME RULE, for the same reason. Two operator declarations that both prove
            # one operation is broken are two proofs of one finding — `fingerprint` has no
            # marker term, so they arrive as two writes to one row. Replacing rather than
            # merging made the row attest to the last declaration alone, and the earlier one
            # vanished from the product.
            finding.marker_digests = sorted(set(prior.get("marker_digests", [])
                                                + finding.marker_digests))
            finding.triage_state = prior.get("triage_state", "open")
            finding.triage_note = prior.get("triage_note", "")
            # A fingerprint covers (case, step, url, parameter, identity), so two
            # writes are two runs of the SAME probe and the later proof is as
            # good as the earlier — except when it is empty. An empty artifact is
            # not evidence and must not replace one that exists: a re-run whose
            # window came back blank would otherwise silently strip a finding of
            # the only thing that made it checkable.
            finding.evidence = finding.evidence or prior.get("evidence", "")
        await execute("INSERT OR REPLACE INTO integration_findings VALUES(?,?,?)", (session_id, finding.fingerprint, finding.model_dump_json()))
