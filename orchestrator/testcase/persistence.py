"""Save v2 RunResult / ChainRun to the SQLite database."""

import json
import uuid
from typing import Any

from orchestrator.database import get_db
from orchestrator.testcase.runner import RunResult
from orchestrator.testcase.chain import ChainRun


async def _asset_for(db, engagement_id: str | None, url: str | None) -> str | None:
    """Inventory a deterministic finding's URL, or None when there is no
    engagement or the URL is outside its scope."""
    if not engagement_id or not url:
        return None
    try:
        from orchestrator.assets import path_for_url
        aid, _ = await path_for_url(db, engagement_id, url, source="testcase")
        return aid
    except Exception:  # noqa: BLE001 — inventory must never fail a run
        return None


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
        # Same inventory as the agent lane. Without this the deterministic
        # half — the part erlik actually asks a client to trust — contributes
        # nothing to the asset tree, and the column added for it stays empty.
        _eid = None
        try:
            if chain_root_run_id is None:
                pass
            cur = await db.execute(
                "SELECT engagement_id FROM v2_runs WHERE id = ?", (run_id,))
            row = await cur.fetchone()
            _eid = row[0] if row else None
        except Exception:
            _eid = None

        for f in result.findings:
            # Provenance mirrors the `findings` table (see _record_finding in
            # main.py). This is a different table with a different schema, so it
            # keeps its own INSERT — but a v2 row must be attributable too, or a
            # "which rule produced this?" query silently returns fewer rows than
            # the corpus actually holds.
            await db.execute(
                """INSERT INTO v2_findings
                   (run_id, test_case_id, step, vuln_type, severity, url, parameter,
                    evidence, source, detector, asset_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (run_id, f.test_case_id, f.step, f.vuln_type, f.severity,
                 f.url, f.parameter, f.evidence,
                 "v2_testcase", f"v2:{f.test_case_id}:{f.step}",
                 await _asset_for(db, _eid, f.url)),
            )
        # Persist what this run DISCOVERED, so the next sweep starts where this
        # one ended instead of from the same bare URL. Best-effort: an
        # inventory failure must never fail a run that already produced results.
        try:
            from orchestrator.testcase import endpoints as _EP
            _t = result.target if isinstance(result.target, dict) else {}
            _n = await _EP.record(db, _t.get("url") or _t.get("host") or "",
                                  result.test_case_id, result.produced or {},
                                  source="testcase")
            if _n:
                print(f"[endpoints {run_id[:8]}] recorded {_n} discovered "
                      f"endpoint(s) for reuse", flush=True)
        except Exception as e:  # noqa: BLE001
            print(f"[endpoints {run_id[:8]}] skipped: {e}", flush=True)

        # Hand the results to the AI lane. Until now a deterministic run's
        # findings went only to v2_findings, which main.py never reads — so
        # every agent run started from a bare URL and rediscovered what a scan
        # had already established.
        try:
            from orchestrator.handoff import bridge_run
            _t = result.target if isinstance(result.target, dict) else {}
            _url = _t.get("url") or _t.get("host") or ""
            n = await bridge_run(db, run_id, _url, result.findings)
            if n:
                print(f"[handoff {run_id[:8]}] {n} deterministic result(s) "
                      f"available to the agent", flush=True)
        except Exception as e:  # noqa: BLE001 — a broken handoff must not fail a run
            print(f"[handoff {run_id[:8]}] skipped: {e}", flush=True)

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
