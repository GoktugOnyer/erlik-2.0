#!/usr/bin/env python3
"""Test whether injected context volume, not guidance quality, drives recall.

The preset sweep found the UNAIDED arm scored highest recall (0.181 vs 0.162 vs
0.143 on Juice Shop), with the most-guided arm lowest on both targets. One
explanation is that guidance is worthless. A better one is that it crowds a 7B's
context: guided_techniques injects ~9 KB playbook + ~18 KB skills + ~12 KB
techniques before turn one, and the guided arms used MORE turns for FEWER
findings.

The sweep could not separate those, because its arms differ in several flags at
once — ai_only also forces cve_enrich, primitives and target_memory off, while
guided_ai turns them on. So this varies ONLY skills and playbook, holding every
other lever fixed, and records the actual injected context size per run as the
independent variable.

  none          no skills, no playbook      (~0 KB injected)
  skills_only   skills, no playbook         (~18 KB)
  playbook_only playbook, no skills         (~9 KB)
  both          skills + playbook           (~27 KB)

If recall falls as injected bytes rise, the finding is about context budget. If
recall is flat, guidance simply is not helping.

Usage:
    python scripts/context_test.py [--reps 3] [--out data/context_test.jsonl]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

API = "http://127.0.0.1:8002"
TARGET = "http://juice-shop:3000"
MISSION = ("Assess the OWASP Juice Shop instance for injection, authentication and "
           "access-control flaws. Report only what you can evidence from tool output.")

# Everything except skills/playbooks is pinned, so the only thing that varies
# between arms is how many bytes of guidance get injected.
BASE = {
    "preset": "custom",
    "cve_enrich": False, "nettacker": False, "techniques": False,
    "primitives": False, "target_memory": False, "poc_verify": False,
    "ai_review": False,
}

ARMS = {
    "none":          {"skills": False, "playbooks": ""},
    "playbook_only": {"skills": False, "playbooks": "juiceshop"},
    "skills_only":   {"skills": True,  "playbooks": ""},
    "both":          {"skills": True,  "playbooks": "juiceshop"},
}


def injected_chars(server_log: Path, sid: str) -> int:
    """Bytes of guidance actually injected, read from the server's own log."""
    if not server_log.exists():
        return -1
    total = 0
    short = sid[:8]
    for line in server_log.read_text(errors="replace").splitlines():
        if short not in line:
            continue
        m = re.search(r"injected (\d+) chars", line)
        if m:
            total += int(m.group(1))
    return total


async def _wait(client: httpx.AsyncClient, sid: str, timeout_s: int = 3600) -> str:
    start = time.time()
    while time.time() - start < timeout_s:
        st = (await client.get(f"{API}/api/sessions/{sid}")).json().get("status")
        if st != "running":
            return st
        await asyncio.sleep(10)
    return "timeout"


async def score(session_id: str) -> dict:
    import orchestrator.database as db_mod
    from orchestrator import review as R
    from orchestrator.main import _assign_findings_to_ground_truth

    db = await db_mod.get_db()
    gt = [dict(r) for r in await (await db.execute(
        "SELECT target_name,target_url,vuln_type,severity,url_pattern,parameter,"
        "owasp_category FROM ground_truth")).fetchall()]
    fs = [dict(r) for r in await (await db.execute(
        "SELECT vuln_type,severity,url,parameter FROM findings WHERE session_id = ?",
        (session_id,))).fetchall()]
    await db.close()

    name = R.match_target_name(TARGET, gt)
    gts = [g for g in gt if g.get("target_name") == name]
    a = _assign_findings_to_ground_truth(fs, gts)
    tp = len(a["matched"])
    return {"tp": tp, "total_gt": len(gts), "total_findings": len(fs),
            "recall": round(tp / len(gts), 4) if gts else 0.0,
            "precision": round(tp / len(fs), 4) if fs else 0.0}


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--out", default="data/context_test.jsonl")
    ap.add_argument("--server-log", default="")
    ap.add_argument("--model", default="qwen2.5-coder:7b",
                    help="attack model under test")
    ns = ap.parse_args()

    out = Path(ns.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    log = Path(ns.server_log) if ns.server_log else None

    done: set[tuple] = set()
    if out.exists():
        for line in out.read_text().splitlines():
            try:
                d = json.loads(line)
            except ValueError:
                continue
            if d.get("status") not in (None, "error"):
                done.add((d.get("model"), d.get("arm"), d.get("rep")))
    if done:
        print(f"[resume] skipping {len(done)} scored run(s)", flush=True)

    total = len(ARMS) * ns.reps
    n = 0
    async with httpx.AsyncClient(timeout=60.0) as client:
        for arm, flags in ARMS.items():
            for rep in range(1, ns.reps + 1):
                n += 1
                if (ns.model, arm, rep) in done:
                    print(f"[{n}/{total}] {arm} rep{rep} — skipping", flush=True)
                    continue
                cfg = dict(BASE); cfg.update(flags)
                body = {"target_url": TARGET, "scope_mode": "full",
                        "system_prompt": MISSION, "model": ns.model,
                        "max_turns": 30, "run_config": cfg}
                print(f"[{n}/{total}] {arm} rep{rep} …", flush=True)
                try:
                    sid = (await client.post(f"{API}/api/sessions", json=body)).json()["id"]
                    t0 = time.time()
                    await client.post(f"{API}/api/sessions/{sid}/start")
                    status = await _wait(client, sid)
                    sess = (await client.get(f"{API}/api/sessions/{sid}")).json()
                    row = {"arm": arm, "rep": rep, "model": ns.model,
                           "session_id": sid, "status": status,
                           "turns": sess.get("total_steps"),
                           "duration_s": round(time.time() - t0),
                           "injected_chars": injected_chars(log, sid) if log else -1}
                    row.update(await score(sid))
                except Exception as e:  # noqa: BLE001
                    row = {"arm": arm, "rep": rep, "status": "error", "error": str(e)[:200]}
                with out.open("a") as fh:
                    fh.write(json.dumps(row) + "\n")
                print(f"      {row.get('status')} injected={row.get('injected_chars')} "
                      f"turns={row.get('turns')} findings={row.get('total_findings')} "
                      f"recall={row.get('recall')} precision={row.get('precision')} "
                      f"{row.get('duration_s')}s", flush=True)
    print(f"[done] {n} runs -> {out}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
