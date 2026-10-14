#!/usr/bin/env python3
"""Warm-start experiment — does the learning loop make erlik better at a target
it has already seen?

PROTOCOL (two phases, one target, one model, pinned to the recorded inference
path so the comparison is treatment-only):

  SEED    One run with `learned_playbooks` + `poc_verify` ON and enough guidance
          to actually find and CONFIRM something. Its verified findings are
          harvested into PENDING candidate playbooks at end of run. An admin
          then APPROVES them — this script approves every pending candidate for
          the target via the review API (needs ERLIK_API_TOKEN, admin by
          construction).

  MEASURE N interleaved reps of two arms on the SAME target, differing in ONE
          lever:
            learned_off  (control) — learned_playbooks False
            learned_on             — learned_playbooks True: the approved
                                      candidates are injected, fenced as
                                      untrusted data, at session start.
          Recall/precision are scored against ground truth exactly as
          scripts/context_test.py does (the one-to-one assignment confusion
          matrix), so numbers are comparable with the recorded arms.

HYPOTHESIS: learned_on > learned_off in recall on the repeat run, WITHOUT the
generic-playbook recall penalty the record already measured (playbook_only
0.1143 vs none 0.1429) — because the injected plays are the target's OWN
verified exploits, class-routed and bounded, not speculative guidance. A null or
negative result is itself a finding: it would say learned context is no better
than authored context, and that Track B (fine-tuning on the same verified
corpus) is where the gain has to come from.

NOT runnable in CI or this repo's container: it needs a live orchestrator,
Ollama, and the Juice Shop target. Run it on the lab box:

    ERLIK_API_TOKEN=<admin-token> python scripts/warm_start_experiment.py --reps 5
"""

import argparse
import asyncio
import hashlib
import json
import os
import time
from pathlib import Path

import httpx

API = os.environ.get("ERLIK_API", "http://127.0.0.1:8002")
TARGET = os.environ.get("ERLIK_TARGET", "http://juice-shop:3000")
MODEL = os.environ.get("ERLIK_MATRIX_MODEL", "qwen2.5-coder:7b")
TOKEN = os.environ.get("ERLIK_API_TOKEN", "")
MISSION = ("Assess the OWASP Juice Shop instance for injection, cross-site scripting, "
           "access-control and authentication flaws. Report each with evidence.")

# Pinned to the recorded inference path (see context_test.py for why): every
# archived row ran on qwen2.5-coder:7b through Ollama, and a hosted model is a
# DIFFERENT model, so an arm compared against those rows must take the same path.
BASE = {
    "preset": "custom",
    "provider": "ollama",
    "safe_mode": True,
    "max_playbooks": 3,
    # Guidance held FIXED and identical across both measured arms, so the only
    # thing that varies is learned_playbooks. These match guided_ai's knowledge
    # levers; without them a 7B rarely produces a confirmable finding to learn
    # from in the seed, and the measure arms would differ by noise.
    "skills": True, "cve_enrich": True, "primitives": True,
    "nettacker": False, "techniques": False,
    # poc_verify ON in BOTH measure arms too: recall is scored from findings, and
    # verification does not drop findings, only labels them — so leaving it on
    # keeps the two arms identical except for the lever under test.
    "poc_verify": True,
    "ai_review": False,
}

# The seed run must HARVEST, so learned_playbooks on; everything else as BASE.
SEED_CFG = {**BASE, "learned_playbooks": True}

MEASURE_ARMS = {
    "learned_off": {**BASE, "learned_playbooks": False},
    "learned_on":  {**BASE, "learned_playbooks": True},
}


def _hdr() -> dict:
    return {"X-API-Token": TOKEN} if TOKEN else {}


async def _wait(client: httpx.AsyncClient, sid: str, timeout_s: int = 3600) -> str:
    t0 = time.time()
    while time.time() - t0 < timeout_s:
        s = (await client.get(f"{API}/api/sessions/{sid}", headers=_hdr())).json()
        if s.get("status") in ("completed", "error", "stopped"):
            return s.get("status")
        await asyncio.sleep(5)
    return "timeout"


async def _run_session(client: httpx.AsyncClient, cfg: dict) -> str:
    body = {"target_url": TARGET, "scope_mode": "full", "system_prompt": MISSION,
            "model": MODEL, "max_turns": 30, "run_config": cfg}
    sid = (await client.post(f"{API}/api/sessions", json=body, headers=_hdr())).json()["id"]
    await client.post(f"{API}/api/sessions/{sid}/start", headers=_hdr())
    await _wait(client, sid)
    return sid


def _target_key(url: str) -> str:
    from urllib.parse import urlparse
    p = urlparse(url if "://" in url else f"http://{url}")
    host = (p.hostname or "").lower()
    port = p.port or (443 if p.scheme == "https" else 80)
    return f"{host}:{port}"


async def seed_and_approve(client: httpx.AsyncClient) -> dict:
    """Run the seed, then approve every pending candidate it harvested."""
    tk = _target_key(TARGET)
    sid = await _run_session(client, SEED_CFG)
    pending = (await client.get(
        f"{API}/api/candidate-playbooks?target_key={tk}&status=pending",
        headers=_hdr())).json()
    approved = 0
    for c in pending:
        r = await client.post(f"{API}/api/candidate-playbooks/{c['id']}/review",
                              json={"status": "approved",
                                    "note": "warm-start experiment seed"},
                              headers=_hdr())
        if r.status_code == 200:
            approved += 1
    return {"seed_session": sid, "harvested": len(pending), "approved": approved}


async def score(session_id: str) -> dict:
    """Recall/precision vs ground truth — the SAME scoring as context_test.py,
    reusing the real assignment function, not a re-implementation."""
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
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--out", default="data/warm_start_experiment.jsonl")
    ap.add_argument("--skip-seed", action="store_true",
                    help="reuse candidates already approved for the target")
    ns = ap.parse_args()
    out = Path(ns.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    async with httpx.AsyncClient(timeout=120.0) as client:
        if not ns.skip_seed:
            seed = await seed_and_approve(client)
            print(f"[seed] {seed}", flush=True)
            with out.open("a") as fh:
                fh.write(json.dumps({"phase": "seed", **seed}) + "\n")

        total = len(MEASURE_ARMS) * ns.reps
        n = 0
        # Interleaved, not arm-by-arm: Juice Shop is stateful, so running all of
        # one arm then the other turns target drift into an apparent arm effect.
        for rep in range(1, ns.reps + 1):
            for arm, cfg in MEASURE_ARMS.items():
                n += 1
                print(f"[{n}/{total}] {arm} rep{rep} …", flush=True)
                try:
                    sid = await _run_session(client, cfg)
                    row = {"phase": "measure", "arm": arm, "rep": rep,
                           "session_id": sid, "model": MODEL,
                           "mission_sha": hashlib.sha1(MISSION.encode()).hexdigest()[:8]}
                    row.update(await score(sid))
                except Exception as e:  # noqa: BLE001
                    row = {"phase": "measure", "arm": arm, "rep": rep,
                           "status": "error", "error": str(e)[:200]}
                with out.open("a") as fh:
                    fh.write(json.dumps(row) + "\n")
                print(f"      {row.get('recall')=} {row.get('precision')=}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
