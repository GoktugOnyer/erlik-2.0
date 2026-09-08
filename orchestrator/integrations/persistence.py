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
        old = await rows("SELECT sources FROM integration_endpoints WHERE session_id=? AND url=? AND method=? AND identity_id=?",
                         (session_id, endpoint.url, endpoint.method, endpoint.identity))
        sources = set(json.loads(old[0]["sources"])) if old else set()
        sources.add(endpoint.source)
        await execute("INSERT OR REPLACE INTO integration_endpoints VALUES(?,?,?,?,?)",
                      (session_id, endpoint.url, endpoint.method, endpoint.identity, json.dumps(sorted(sources))))
    for finding in result.findings:
        old = await rows("SELECT payload FROM integration_findings WHERE session_id=? AND fingerprint=?", (session_id, finding.fingerprint))
        if old:
            prior = json.loads(old[0]["payload"])
            finding.evidence_ids = sorted(set(prior.get("evidence_ids", []) + finding.evidence_ids))
            finding.triage_state = prior.get("triage_state", "open")
            finding.triage_note = prior.get("triage_note", "")
        await execute("INSERT OR REPLACE INTO integration_findings VALUES(?,?,?)", (session_id, finding.fingerprint, finding.model_dump_json()))
