#!/usr/bin/env python3
"""Run the preset comparison sweep and record per-run results.

Compares the three arms that matter — unaided baseline, guided, guided plus
environment techniques — across both lab targets, several times each, because a
single run on a 7B is noise: identical configurations have produced 16 and 30
turns on consecutive attempts.

Deliberate choices:

  ai_review is OFF for every run. The critique costs ~90s on the 35B reviewer and
  contributes nothing to the measurement; coverage is computed here directly from
  the findings and the ground-truth table, with no model involved.

  playbooks is forced OFF on DVWA. guided_ai and guided_techniques both pin
  playbooks="juiceshop", which is the wrong target's endpoint list — leaving it on
  would measure how badly a mismatched playbook hurts, not how the arm performs.

  Both precision and recall are recorded. Coverage alone rewards spraying generic
  findings: a run producing 15 vague findings scored 6/35 while one producing 3
  precise findings scored 3/35, so ranking arms on recall alone would crown the
  noisiest arm.

Usage:
    python scripts/preset_sweep.py [--reps 3] [--out data/sweep.jsonl]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

API = "http://127.0.0.1:8002"

TARGETS = [
    {
        "name": "juice-shop",
        "url": "http://juice-shop:3000",
        "mission": ("Assess the OWASP Juice Shop instance for injection, authentication "
                    "and access-control flaws. Report only what you can evidence from "
                    "tool output."),
        "allow_playbook": True,
    },
    {
        "name": "dvwa",
        "url": "http://dvwa",
        "mission": ("Assess the DVWA instance for injection, authentication and "
                    "access-control flaws. Valid credentials are admin/password at "
                    "/login.php. Report only what you can evidence from tool output."),
        "allow_playbook": False,
    },
]

PRESETS = ["ai_only", "guided_ai", "guided_techniques"]


async def _wait(client: httpx.AsyncClient, sid: str, timeout_s: int = 1500) -> str:
    start = time.time()
    while time.time() - start < timeout_s:
        r = await client.get(f"{API}/api/sessions/{sid}")
        status = r.json().get("status")
        if status != "running":
            return status
        await asyncio.sleep(10)
    return "timeout"


async def run_one(client: httpx.AsyncClient, target: dict, preset: str, rep: int) -> dict:
    cfg = {"preset": preset, "ai_review": False}
    if not target["allow_playbook"]:
        cfg["playbooks"] = ""

    body = {
        "target_url": target["url"],
        "scope_mode": "full",
        "system_prompt": target["mission"],
        "model": "qwen2.5-coder:7b",
        "max_turns": 30,
        "run_config": cfg,
    }
    sid = (await client.post(f"{API}/api/sessions", json=body)).json()["id"]
    t0 = time.time()
    await client.post(f"{API}/api/sessions/{sid}/start")
    status = await _wait(client, sid)
    elapsed = round(time.time() - t0)

    sess = (await client.get(f"{API}/api/sessions/{sid}")).json()
    findings = (await client.get(f"{API}/api/sessions/{sid}/findings")).json()

    return {
        "target": target["name"], "preset": preset, "rep": rep, "session_id": sid,
        "status": status, "turns": sess.get("total_steps"),
        "findings": len(findings), "duration_s": elapsed,
    }


async def score(session_id: str, target_url: str) -> dict:
    """Coverage and precision, computed with no model involved."""
    import orchestrator.database as db_mod
    from orchestrator import review as R
    from orchestrator.main import _assign_findings_to_ground_truth

    async def load():
        db = await db_mod.get_db()
        gt = [dict(r) for r in await (await db.execute(
            "SELECT target_name,target_url,vuln_type,severity,url_pattern,parameter,"
            "owasp_category FROM ground_truth")).fetchall()]
        fs = [dict(r) for r in await (await db.execute(
            "SELECT vuln_type,severity,url,parameter FROM findings WHERE session_id = ?",
            (session_id,))).fetchall()]
        await db.close()
        return gt, fs

    # await, never asyncio.run(): this is called from inside the sweep's own
    # event loop, where asyncio.run() raises and every run is recorded as an
    # error even though the session itself completed fine.
    gt, fs = await load()
    name = R.match_target_name(target_url, gt)
    gts = [g for g in gt if g.get("target_name") == name]
    if not gts:
        return {"target_name": None}
    a = _assign_findings_to_ground_truth(fs, gts)
    tp, total_f, total_g = len(a["matched"]), len(fs), len(gts)
    return {
        "target_name": name, "tp": tp, "total_findings": total_f, "total_gt": total_g,
        "recall": round(tp / total_g, 4) if total_g else 0.0,
        "precision": round(tp / total_f, 4) if total_f else 0.0,
    }


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--out", default="data/sweep.jsonl")
    ns = ap.parse_args()

    out = Path(ns.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    # Resume: a run that already produced a scored row is not repeated. Sessions
    # are expensive (minutes each), so a crash mid-sweep must not discard them.
    done: set[tuple] = set()
    if out.exists():
        for line in out.read_text().splitlines():
            try:
                d = json.loads(line)
            except ValueError:
                continue
            if d.get("status") not in (None, "error"):
                done.add((d.get("target"), d.get("preset"), d.get("rep")))
    if done:
        print(f"[resume] skipping {len(done)} already-scored run(s)", flush=True)
    total = len(TARGETS) * len(PRESETS) * ns.reps
    n = 0

    async with httpx.AsyncClient(timeout=60.0) as client:
        for target in TARGETS:
            for preset in PRESETS:
                for rep in range(1, ns.reps + 1):
                    n += 1
                    if (target["name"], preset, rep) in done:
                        print(f"[{n}/{total}] {target['name']} / {preset} rep{rep} "
                              f"— already scored, skipping", flush=True)
                        continue
                    print(f"[{n}/{total}] {target['name']} / {preset} rep{rep} …",
                          flush=True)
                    try:
                        row = await run_one(client, target, preset, rep)
                        row.update(await score(row["session_id"], target["url"]))
                    except Exception as e:  # noqa: BLE001
                        row = {"target": target["name"], "preset": preset, "rep": rep,
                               "status": "error", "error": str(e)[:200]}
                    with out.open("a") as fh:
                        fh.write(json.dumps(row) + "\n")
                    print(f"      {row.get('status')} turns={row.get('turns')} "
                          f"findings={row.get('findings')} "
                          f"tp={row.get('tp')} recall={row.get('recall')} "
                          f"precision={row.get('precision')} {row.get('duration_s')}s",
                          flush=True)
    print(f"[done] {n} runs -> {out}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
