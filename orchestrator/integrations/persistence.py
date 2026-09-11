"""Additive integration storage. Artifacts are addressed by opaque IDs."""
from __future__ import annotations
import hashlib
import json
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
        CREATE TABLE IF NOT EXISTS integration_remote_findings (
          server TEXT NOT NULL, remote_test_id INTEGER NOT NULL, fingerprint TEXT NOT NULL,
          remote_finding_id INTEGER NOT NULL, payload_hash TEXT NOT NULL,
          updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
          PRIMARY KEY(server,remote_test_id,fingerprint));
        CREATE INDEX IF NOT EXISTS integration_stage_session ON integration_stages(session_id);
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
