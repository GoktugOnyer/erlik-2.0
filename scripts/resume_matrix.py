#!/usr/bin/env python3
"""Resume a sprint_matrix from where it stopped.

Reads an existing summary.csv, identifies completed (turn,phase,toolset) tuples,
and runs only the missing ones. Appends new rows to the same summary.csv.
"""
import csv
import json
import os
import subprocess
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path

BASE = "http://localhost:8002"
TARGET = os.environ.get("ERLIK_TARGET", "http://localhost:3000")
MODEL = os.environ.get("ERLIK_MATRIX_MODEL", "qwen2.5-coder:7b-cipher")
PLAYBOOK = "owasp_methodology"
POLL_INTERVAL = 5

TURN_OPTIONS = [15, 30, 45]
TOOLSETS = ["core_10", "standard_20", "full_30"]
PHASES = ["cold", "warm", "chain"]

RUN_DIR = Path(sys.argv[1]) if len(sys.argv) > 1 else None
if RUN_DIR is None or not RUN_DIR.exists():
    print(f"Usage: resume_matrix.py <run_dir>"); sys.exit(1)
SUMMARY = RUN_DIR / "summary.csv"
LOG = RUN_DIR / "run.log"


def log(msg):
    print(msg)
    with open(LOG, "a") as f: f.write(msg + "\n")


def http(method, path, body=None, timeout=30):
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(BASE + path, data=data,
        headers={"Content-Type": "application/json"} if data else {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read() or b"{}")
    except Exception as e:
        log(f"  HTTP {method} {path}: {e}")
        return None


def juice_shop_reset():
    """Reset Juice Shop state between sessions."""
    try:
        subprocess.run(["docker", "exec", "juice-shop", "pkill", "-USR1", "node"],
                       capture_output=True, timeout=10)
        time.sleep(2)
        log(f"[reset] juice-shop ready")
    except Exception as e:
        log(f"[reset] error {e}")


def parse_done(summary_path):
    """Return set of (turn_count, phase, toolset) tuples completed."""
    done = set()
    if not summary_path.exists(): return done
    with open(summary_path) as f:
        for row in csv.DictReader(f):
            if row.get("status") in ("completed", "stopped"):
                done.add((int(row["turn_count"]), row["kind"], row["toolset_preset"]))
    return done


def write_row(path, row, first_row):
    header = ["id","turn_count","phase","kind","toolset_preset","max_turns","status",
              "total_steps","total_findings","duration_s","parent_id","label",
              "true_positives","false_positives","precision","gt_coverage"]
    with open(path, "a") as f:
        w = csv.DictWriter(f, fieldnames=header)
        if first_row and not path.exists(): w.writeheader()
        w.writerow({k: row.get(k, "") for k in header})


def eval_session(sid):
    """Fetch findings + compute TP/FP vs ground truth."""
    gt_path = RUN_DIR / "ground_truth.json"
    gt_urls = set()
    if gt_path.exists():
        try:
            gt = json.load(open(gt_path))
            for item in gt.get("ground_truth", []):
                url = item.get("url", "")
                if url: gt_urls.add(url.rstrip("/").lower())
        except Exception: pass
    findings = http("GET", f"/api/sessions/{sid}/findings") or []
    if not isinstance(findings, list): findings = []
    tp = sum(1 for f in findings if any(gt in (f.get("url","") or "").lower() for gt in gt_urls)) if gt_urls else len(findings)
    fp = len(findings) - tp
    return len(findings), tp, fp


def run_cold(turn, toolset):
    juice_shop_reset()
    label = f"cold-{toolset}-{turn}t"
    log(f"│   ▶ {label}")
    t0 = time.time()
    s = http("POST", "/api/sessions", {
        "target_url": TARGET, "model": MODEL, "playbook": PLAYBOOK,
        "toolset_preset": toolset, "max_turns": turn, "phase": "cold"})
    if not s: return None
    sid = s["id"]
    http("POST", f"/api/sessions/{sid}/start")
    while True:
        time.sleep(POLL_INTERVAL)
        s2 = http("GET", f"/api/sessions/{sid}")
        if not s2: continue
        if s2.get("status") in ("completed","stopped","error"): break
    dur = int(time.time() - t0)
    findings, tp, fp = eval_session(sid)
    log(f"│   ◀ {label} → {s2.get('status','?')}  steps={s2.get('total_steps',0)}  findings={findings}  TP={tp}  dur={dur}s")
    return {"id":sid,"turn_count":turn,"phase":1,"kind":"cold","toolset_preset":toolset,
            "max_turns":turn,"status":s2.get("status",""),"total_steps":s2.get("total_steps",0),
            "total_findings":findings,"duration_s":dur,"parent_id":"","label":label,
            "true_positives":tp,"false_positives":fp,
            "precision":f"{tp/max(tp+fp,1):.2f}","gt_coverage":"0.0"}


def run_warm(turn, toolset, parent_id):
    juice_shop_reset()
    label = f"warm-{toolset}-{turn}t"
    log(f"│   ▶ {label}  (parent={parent_id})")
    t0 = time.time()
    s = http("POST", "/api/sessions", {
        "target_url": TARGET, "model": MODEL, "playbook": PLAYBOOK,
        "toolset_preset": toolset, "max_turns": turn, "phase": "warm",
        "parent_session_id": parent_id})
    if not s: return None
    sid = s["id"]
    http("POST", f"/api/sessions/{sid}/start")
    while True:
        time.sleep(POLL_INTERVAL)
        s2 = http("GET", f"/api/sessions/{sid}")
        if not s2: continue
        if s2.get("status") in ("completed","stopped","error"): break
    dur = int(time.time() - t0)
    findings, tp, fp = eval_session(sid)
    log(f"│   ◀ {label} → {s2.get('status','?')}  steps={s2.get('total_steps',0)}  findings={findings}  TP={tp}  dur={dur}s")
    return {"id":sid,"turn_count":turn,"phase":2,"kind":"warm","toolset_preset":toolset,
            "max_turns":turn,"status":s2.get("status",""),"total_steps":s2.get("total_steps",0),
            "total_findings":findings,"duration_s":dur,"parent_id":parent_id,"label":label,
            "true_positives":tp,"false_positives":fp,
            "precision":f"{tp/max(tp+fp,1):.2f}","gt_coverage":"0.0"}


def run_chain(turn, toolset):
    juice_shop_reset()
    label = f"chain-{toolset}-{turn}tpp"
    log(f"│   ▶ {label}")
    t0 = time.time()
    c = http("POST", "/api/chains", {
        "target_url": TARGET, "model": MODEL, "playbook": PLAYBOOK,
        "toolset_preset": toolset, "max_turns_per_session": turn, "auto_progress": True})
    if not c: return None
    cid = c["id"]
    HARD_TIMEOUT = 20*60  # 20 min hard cap per chain
    start = time.time()
    while True:
        time.sleep(POLL_INTERVAL)
        c2 = http("GET", f"/api/chains/{cid}")
        if not c2: continue
        st = c2.get("status","")
        if st in ("completed","stopped","error"): break
        if time.time() - start > HARD_TIMEOUT:
            log(f"│   ⚠ HARD TIMEOUT on chain {cid}, stopping")
            http("POST", f"/api/chains/{cid}/stop")
            break
    dur = int(time.time() - t0)
    # Gather findings from child sessions
    findings_total = tp_total = fp_total = steps_total = 0
    children = (c2 or {}).get("sessions", []) or []
    for ch in children:
        sid = ch.get("id","")
        if not sid: continue
        f, t, fp = eval_session(sid)
        findings_total += f; tp_total += t; fp_total += fp
        steps_total += int(ch.get("total_steps",0) or 0)
    status = (c2 or {}).get("status","")
    log(f"│   ◀ {label} → {status}  steps={steps_total}  findings={findings_total}  TP={tp_total}  dur={dur}s")
    return {"id":cid,"turn_count":turn,"phase":3,"kind":"chain","toolset_preset":toolset,
            "max_turns":turn,"status":status,"total_steps":steps_total,
            "total_findings":findings_total,"duration_s":dur,"parent_id":"","label":label,
            "true_positives":tp_total,"false_positives":fp_total,
            "precision":f"{tp_total/max(tp_total+fp_total,1):.2f}","gt_coverage":"0.0"}


def main():
    done = parse_done(SUMMARY)
    log(f"[resume] Run dir: {RUN_DIR}")
    log(f"[resume] Done: {len(done)} sessions")
    log(f"[resume] Target: {TARGET} | Model: {MODEL}")
    # Collect cold parent IDs by (turn, toolset) for warm lookup
    cold_ids = {}
    with open(SUMMARY) as f:
        for row in csv.DictReader(f):
            if row.get("kind")=="cold" and row.get("status") in ("completed","stopped"):
                cold_ids[(int(row["turn_count"]), row["toolset_preset"])] = row["id"]

    remaining = []
    for turn in TURN_OPTIONS:
        for ts in TOOLSETS:
            for phase in PHASES:
                if (turn, phase, ts) not in done:
                    remaining.append((turn, phase, ts))
    log(f"[resume] Remaining: {len(remaining)}")
    for i, (turn, phase, ts) in enumerate(remaining, 1):
        log(f"\n[{i}/{len(remaining)}] turn={turn} phase={phase} toolset={ts}")
        row = None
        if phase == "cold":
            row = run_cold(turn, ts)
            if row: cold_ids[(turn, ts)] = row["id"]
        elif phase == "warm":
            parent = cold_ids.get((turn, ts), "")
            if not parent:
                log(f"  ⚠ No cold parent for ({turn},{ts}); skipping warm")
                continue
            row = run_warm(turn, ts, parent)
        else:  # chain
            row = run_chain(turn, ts)
        if row:
            with open(SUMMARY, "a") as f:
                w = csv.DictWriter(f, fieldnames=list(row.keys()))
                w.writerow(row)
    log(f"\n[resume] DONE. All sessions recorded to {SUMMARY}")


if __name__ == "__main__":
    main()
