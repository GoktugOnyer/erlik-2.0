"""Save v2 RunResult / ChainRun to the SQLite database."""

import json
import uuid
from typing import Any

from orchestrator.database import get_db
from orchestrator.testcase.runner import RunResult
from orchestrator.testcase.chain import ChainRun


async def save_run(result: RunResult, *, provider: str | None, model: str | None,
                   chain_root_run_id: str | None = None) -> str:
    """Persist a single RunResult. Returns the new run_id."""
    run_id = str(uuid.uuid4())
    db = await get_db()
    try:
        await db.execute(
            """INSERT INTO v2_runs
               (id, test_case_id, target_json, provider, model, duration_ms,
                stopped_early, chain_root_run_id, steps_json, chain_next_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                result.test_case_id,
                json.dumps(result.target),
                provider,
                model,
                result.duration_ms,
                1 if result.stopped_early else 0,
                chain_root_run_id,
                json.dumps([s.model_dump() for s in result.steps]),
                json.dumps(result.chain_next),
            ),
        )
        for f in result.findings:
            # Provenance mirrors the `findings` table (see _record_finding in
            # main.py). This is a different table with a different schema, so it
            # keeps its own INSERT — but a v2 row must be attributable too, or a
            # "which rule produced this?" query silently returns fewer rows than
            # the corpus actually holds.
            await db.execute(
                """INSERT INTO v2_findings
                   (run_id, test_case_id, step, vuln_type, severity, url, parameter,
                    evidence, source, detector)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (run_id, f.test_case_id, f.step, f.vuln_type, f.severity,
                 f.url, f.parameter, f.evidence,
                 "v2_testcase", f"v2:{f.test_case_id}:{f.step}"),
            )
        await db.commit()
    finally:
        await db.close()
    return run_id


async def save_chain(chain: ChainRun, *, provider: str | None, model: str | None) -> dict[str, Any]:
    """Persist a ChainRun. Returns {root_run_id, run_ids}."""
    if not chain.runs:
        return {"root_run_id": None, "run_ids": []}
    root_id = await save_run(chain.runs[0], provider=provider, model=model)
    ids = [root_id]
    for r in chain.runs[1:]:
        rid = await save_run(r, provider=provider, model=model, chain_root_run_id=root_id)
        ids.append(rid)
    return {"root_run_id": root_id, "run_ids": ids}


async def list_runs(limit: int = 50) -> list[dict[str, Any]]:
    db = await get_db()
    try:
        cur = await db.execute(
            """SELECT id, test_case_id, target_json, provider, model, duration_ms,
                      stopped_early, chain_root_run_id, created_at
               FROM v2_runs ORDER BY created_at DESC LIMIT ?""",
            (limit,),
        )
        rows = await cur.fetchall()
        out = []
        for row in rows:
            d = dict(row)
            d["target"] = json.loads(d.pop("target_json") or "{}")
            out.append(d)
        return out
    finally:
        await db.close()


async def get_run(run_id: str) -> dict[str, Any] | None:
    db = await get_db()
    try:
        cur = await db.execute("SELECT * FROM v2_runs WHERE id = ?", (run_id,))
        row = await cur.fetchone()
        if not row:
            return None
        d = dict(row)
        d["target"] = json.loads(d.pop("target_json") or "{}")
        d["steps"] = json.loads(d.pop("steps_json") or "[]")
        d["chain_next"] = json.loads(d.pop("chain_next_json") or "[]")

        cur = await db.execute(
            "SELECT * FROM v2_findings WHERE run_id = ? ORDER BY id", (run_id,)
        )
        d["findings"] = [dict(r) for r in await cur.fetchall()]
        return d
    finally:
        await db.close()
