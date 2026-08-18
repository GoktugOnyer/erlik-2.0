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
import hashlib
import json
import re
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

API = "http://127.0.0.1:8002"
TARGET = "http://juice-shop:3000"
MISSION = ("Assess the OWASP Juice Shop instance for injection, cross-site scripting, "
           "SSRF, open redirect, broken access control and authentication flaws. "
           "Report only what you can evidence from tool output.")
# The mission is part of the independent variable now: `auto` routes playbooks
# from the classes the mission NAMES, so the older MISSION (which named none of
# the six playbook classes) would have made the arm vacuous. Recorded per row —
# recall from a different mission is not comparable.

# Everything except skills/playbooks is pinned, so the only thing that varies
# between arms is how many bytes of guidance get injected.
BASE = {
    "preset": "custom",
    "cve_enrich": False, "nettacker": False, "techniques": False,
    "primitives": False, "target_memory": False, "poc_verify": False,
    "ai_review": False,
    # Pinned explicitly. Safe mode did not exist when the first 12 runs were
    # recorded, and it now defaults ON — so leaving it implicit would vary a
    # lever between arms and across generations of the corpus without saying so.
    "safe_mode": True,
    # Pinned. It was env-only and read once at import, so two runs of one arm
    # could differ in treatment with nothing in the record showing it.
    "max_playbooks": 3,
}

ARMS = {
    "none":          {"skills": False, "playbooks": ""},
    # NEW. Generic playbooks routed to the classes the mission names — what
    # ships by default now. `playbook_only` is the block it REPLACED, kept as
    # the reference arm so "smaller" can be told apart from "better".
    "auto":          {"skills": False, "playbooks": "auto"},

    # HANDOFF — the deterministic WSTG lane's results as starting context.
    # Gated on `handoff`, NOT `target_memory`: the latter also replays every
    # prior agent finding for the target (436 rows / 102 sessions here), which
    # would make this arm measure "hand the agent every answer ever recorded".
    "handoff":       {"skills": False, "playbooks": "", "handoff": True},
    "playbook_only": {"skills": False, "playbooks": "juiceshop"},
    "skills_only":   {"skills": True,  "playbooks": ""},
    "both":          {"skills": True,  "playbooks": "juiceshop"},

    # DOSE LADDER — skills on, budget varied. No previous arm did this, so
    # nothing so far can tell "too much guidance" from "this guidance is wrong".
    #
    # Measured with the real selector, the sheets ACCUMULATE across these three
    # (authentication-quickstart, +access-control-resources, +injection-principles),
    # so it is genuinely more-of-the-same rather than a different corpus:
    #     dose_1   6,452 chars   1 sheet
    #     dose_2  11,496 chars   2 sheets
    #     dose_3  18,166 chars   3 sheets
    # Deliberately stops at 14000: at 24000 the router SUBSTITUTES different
    # sheets rather than adding, which would confound dose with content.
    # Keyed on skills_max_files, which is what varies the dose since the
    # default became one sheet. The earlier 7B ladder used skills_max_chars,
    # which reached the same volumes by STARVING the per-class share — and so
    # also selected worse sheets. These arms hold sheet QUALITY fixed.
    "dose_1": {"skills": True, "playbooks": "", "skills_max_files": 1},
    "dose_2": {"skills": True, "playbooks": "", "skills_max_files": 2},
    "dose_3": {"skills": True, "playbooks": "", "skills_max_files": 3},
}


# One definition of the log format. Two copies is how one of them silently
# stops matching the line it is supposed to read, and a control that stops
# matching reports 0 or -1 — which reads as "treatment absent", not "parser
# broken".
_INJECTED_RX = re.compile(r"injected (\d+) chars")


def injected_chars(server_log: Path, sid: str) -> int:
    """Bytes of guidance actually injected, read from the server's own log."""
    if not server_log.exists():
        return -1
    total = 0
    short = sid[:8]
    for line in server_log.read_text(errors="replace").splitlines():
        if short not in line:
            continue
        m = _INJECTED_RX.search(line)
        if m:
            total += int(m.group(1))
    return total


def tagged_chars(server_log: Path, sid: str, tag: str) -> int:
    """Bytes injected by ONE named path, read from the server's own log.

    THIS IS THE CONTROL THAT KEEPS GOING MISSING. Every run in
    context_test_v2/v3.jsonl records injected_chars = -1 because --server-log
    was never passed, so nothing in that corpus proves the arms ever differed in
    what reached the model — a broken injection path would have produced two
    runs of the SAME condition and a confident "no effect".

    It then went missing a second time, differently: the first handoff runs
    recorded playbook_chars = 0 for both arms, which is CORRECT (that experiment
    varies the handoff, not playbooks) and therefore useless as a control. The
    column measured the wrong lever, so the record could not distinguish the
    arms at all. Hence one function, parameterised by tag, and every lever
    recorded on every row.

    Returns the byte count, 0 when the server logged an explicit skip (verified
    silent), or -1 when unknown.
    """
    if not server_log.exists():
        return -1
    short = sid[:8]
    for line in server_log.read_text(errors="replace").splitlines():
        if f"[{tag} {short}]" not in line:
            continue
        m = _INJECTED_RX.search(line)
        if m:
            return int(m.group(1))
        if "skipped" in line:
            return 0
    return -1


def playbook_chars(server_log: Path, sid: str) -> int:
    return tagged_chars(server_log, sid, "playbooks")


def handoff_chars(server_log: Path, sid: str) -> int:
    return tagged_chars(server_log, sid, "handoff-ctx")


def _code_version() -> str:
    """The commit under test. Recorded per row because detection changed a lot:
    two dead detectors were revived, four false-positive sources fixed, and
    refusals stopped manufacturing findings — so a recall number is only
    comparable against runs from the same code."""
    import subprocess
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                              capture_output=True, text=True,
                              cwd=Path(__file__).resolve().parents[1]
                              ).stdout.strip() or "unknown"
    except Exception:
        return "unknown"


CODE_VERSION = _code_version()


async def run_facts(session_id: str) -> dict:
    """Per-run facts the old harness could not record: how much guidance the
    router ACTUALLY delivered, and how many commands were refused."""
    import json as _json
    import orchestrator.database as db_mod

    db = await db_mod.get_db()
    try:
        cur = await db.execute(
            "SELECT skills_trace FROM sessions WHERE id = ?", (session_id,))
        row = await cur.fetchone()
        trace = {}
        if row and row[0]:
            try:
                trace = _json.loads(row[0])
            except (ValueError, TypeError):
                trace = {}
        cur = await db.execute(
            "SELECT COUNT(*) FROM steps WHERE session_id = ? AND denied = 1",
            (session_id,))
        denied = (await cur.fetchone())[0]
    finally:
        await db.close()
    return {
        "skills_sheets": len(trace.get("selected") or []),
        "skills_rendered_chars": trace.get("rendered_chars", 0),
        "denied_steps": denied,
    }


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
    # New file, not an append. The first 12 runs measured a DIFFERENT detector
    # set: wfuzz and dirb could not fire, four false-positive sources were live,
    # and refusals manufactured findings. Mixing them in one file would invite
    # exactly the comparison that is not valid.
    ap.add_argument("--out", default="data/context_test_v2.jsonl")
    ap.add_argument("--arms", default="", help="comma-separated subset of arms")
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

    arms = ({a: ARMS[a] for a in ns.arms.split(",") if a.strip() in ARMS}
            if ns.arms.strip() else ARMS)
    total = len(arms) * ns.reps
    n = 0
    async with httpx.AsyncClient(timeout=60.0) as client:
        # INTERLEAVED, not arm-by-arm. Juice Shop is a stateful application:
        # runs create users, upload files and store XSS payloads that persist
        # for every later run. Executing all of arm A then all of arm B makes
        # "later" a property of the arm, so target drift would be read as an
        # arm effect. Interleaving spreads drift across arms instead.
        for rep in range(1, ns.reps + 1):
            for arm, flags in arms.items():
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
                           "commit": CODE_VERSION,
                           "injected_chars": injected_chars(log, sid) if log else -1,
                           "playbook_chars": playbook_chars(log, sid) if log else -1,
                           "handoff_chars": handoff_chars(log, sid) if log else -1,
                           "playbooks_mode": cfg.get("playbooks", ""),
                           "handoff_on": bool(cfg.get("handoff")),
                           "mission_sha": hashlib.sha1(
                               MISSION.encode()).hexdigest()[:8]}
                    row.update(await score(sid))
                    row.update(await run_facts(sid))
                except Exception as e:  # noqa: BLE001
                    row = {"arm": arm, "rep": rep, "status": "error", "error": str(e)[:200]}
                with out.open("a") as fh:
                    fh.write(json.dumps(row) + "\n")
                # A dead control is only useful if it is noticed while the
                # experiment is still running. Analysis-time discovery means the
                # GPU hours are already spent.
                if row.get("handoff_on") and row.get("handoff_chars", -1) <= 0:
                    print(f"      !! arm claims handoff but injected "
                          f"{row.get('handoff_chars')} chars — TREATMENT DEAD",
                          flush=True)
                if cfg.get("playbooks") and row.get("playbook_chars", -1) <= 0:
                    print(f"      !! arm claims playbooks={cfg.get('playbooks')!r} but "
                          f"injected {row.get('playbook_chars')} chars — TREATMENT DEAD",
                          flush=True)
                print(f"      {row.get('status')} pb={row.get('playbook_chars')} "
                      f"ho={row.get('handoff_chars')} "
                      f"turns={row.get('turns')} findings={row.get('total_findings')} "
                      f"recall={row.get('recall')} precision={row.get('precision')} "
                      f"{row.get('duration_s')}s", flush=True)
    print(f"[done] {n} runs -> {out}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
