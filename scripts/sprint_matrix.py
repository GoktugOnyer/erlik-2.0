#!/usr/bin/env python3
"""sprint_matrix.py — drive an eval matrix against Juice Shop.

Matrix: 2 turn counts × 3 toolsets × 3 phases (cold/warm/chain) = 18 runs.

For each turn count in TURN_OPTIONS:
  Phase 1 (cold):  3 sessions, one per toolset preset, all at the same turn count.
  Phase 2 (warm):  3 sessions, one per toolset preset, each parented to the
                   matching Phase 1 cold session of the same toolset.
  Phase 3 (chain): 3 chains, one per toolset preset, auto-progressing 4 internal
                   phases at `turns` turns each. Polled to completion.

Partial results are flushed to runs/<timestamp>/summary.csv after every run
so the output is useful even if the script is interrupted.

Usage:
  python3 scripts/sprint_matrix.py
"""
import csv
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

BASE = "http://localhost:8002"
TARGET = os.environ.get("ERLIK_TARGET", "http://localhost:3000")
MODEL = os.environ.get("ERLIK_MATRIX_MODEL", "qwen2.5-coder:7b")
PLAYBOOK = "owasp_methodology"
POLL_INTERVAL = 5

TURN_OPTIONS = [15, 30, 45]
TOOLSETS = ["core_10", "standard_20", "full_30"]

# Wall-clock ceilings (minutes). 0 = unlimited — turn count bounds the session.
# Previously 60/60/120, but time ceilings unfairly penalize larger (slower) models.
# The fair comparison unit is turns, not wall-clock time.
MAX_WAIT_COLD_MIN = 20   # hard cap per cold session (prevent hangs)
MAX_WAIT_WARM_MIN = 20   # hard cap per warm session
MAX_WAIT_CHAIN_MIN = 30  # hard cap per chain session (4 phases × ~7 min each)


def http(method: str, path: str, body: dict | None = None, timeout: int = 30) -> dict | None:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8", errors="replace")
        print(f"    HTTPError {e.code} on {method} {path}: {err[:200]}", flush=True)
        return None
    except Exception as e:
        print(f"    ERROR on {method} {path}: {e}", flush=True)
        return None


def log(msg: str, log_path: Path):
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    with log_path.open("a") as f:
        f.write(line + "\n")


def create_session(prompt: str, toolset: str, turns: int, stype: str, parent: str | None) -> str | None:
    body = {
        "target_url": TARGET,
        "scope_mode": "full",
        "model": MODEL,
        "system_prompt": prompt,
        "toolset_preset": toolset,
        "session_type": stype,
        "parent_session_id": parent,
        "no_timeout": True,  # tools get the 600s global cap instead of per-tool caps
        "max_turns": turns,
        "disable_stagnation": True,  # benchmark runs use the full turn budget
    }
    resp = http("POST", "/api/sessions", body)
    return resp.get("id") if resp else None


def create_chain(prompt: str, toolset: str, turns_per: int) -> str | None:
    body = {
        "target_url": TARGET,
        "scope_mode": "full",
        "model": MODEL,
        "system_prompt": prompt,
        "toolset_preset": toolset,
        "max_turns_per_session": turns_per,
        "no_timeout": True,  # tools get the 600s global cap instead of per-tool caps
        "auto_progress": True,
        "disable_stagnation": True,  # benchmark runs use the full turn budget
    }
    resp = http("POST", "/api/chains", body)
    return resp.get("id") if resp else None


def poll_session(sid: str, max_wait_min: int, log_path: Path) -> dict:
    t0 = time.time()
    deadline = t0 + max_wait_min * 60
    status = "running"
    row: dict = {}
    while True:
        if max_wait_min > 0 and time.time() > deadline:
            log(f"    TIMEOUT {sid} after {max_wait_min} min — stopping", log_path)
            http("POST", f"/api/sessions/{sid}/stop")
            status = "timeout"
            break
        time.sleep(POLL_INTERVAL)
        row = http("GET", f"/api/sessions/{sid}") or {}
        status = row.get("status", "") or ""
        if status in ("completed", "failed", "error", "stopped"):
            break
    dur = int(time.time() - t0)
    return {
        "status": status,
        "steps": row.get("total_steps", 0) or 0,
        "findings": row.get("total_findings", 0) or 0,
        "duration_s": dur,
        "row": row,
    }


def poll_chain(chain_id: str, max_wait_min: int, log_path: Path) -> dict:
    """Poll /api/chains/{id} until terminal. Aggregates findings across sessions."""
    t0 = time.time()
    deadline = t0 + max_wait_min * 60
    status = "running"
    row: dict = {}
    last_logged_pos = -1
    while True:
        if max_wait_min > 0 and time.time() > deadline:
            log(f"    TIMEOUT chain {chain_id} after {max_wait_min} min — stopping", log_path)
            http("POST", f"/api/chains/{chain_id}/stop")
            status = "timeout"
            break
        time.sleep(POLL_INTERVAL)
        row = http("GET", f"/api/chains/{chain_id}") or {}
        status = row.get("status", "") or ""
        pos = row.get("current_position", -1)
        phase = row.get("current_phase", "?")
        if pos != last_logged_pos:
            log(f"    chain {chain_id}  phase={phase}  pos={pos}  status={status}", log_path)
            last_logged_pos = pos
        if status in ("completed", "failed", "error", "stopped"):
            break
    dur = int(time.time() - t0)
    # Aggregate findings from all child sessions
    total_steps = 0
    total_findings = 0
    for s in row.get("sessions", []):
        total_steps += s.get("total_steps", 0) or 0
        total_findings += s.get("total_findings", 0) or 0
    return {
        "status": status,
        "steps": total_steps,
        "findings": total_findings,
        "duration_s": dur,
        "row": row,
    }


def reset_ollama_runner():
    """Force ollama to drop any loaded model. The next call will reload from
    disk cleanly. Mitigates the long-running-runner deadlock pattern observed
    in the 17:30 matrix run where warm-core_10-30t hung 23 min on the first
    LLM call after ollama had been serving requests for ~1.5 hours.

    See: https://github.com/ollama/ollama/issues — long-running runners can
    enter a state where new requests block indefinitely.
    """
    body = json.dumps({"model": MODEL, "keep_alive": 0}).encode("utf-8")
    req = urllib.request.Request(
        "http://localhost:11434/api/generate",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
        print("[startup] ollama runner reset (model will reload on first call)", flush=True)
    except Exception as e:
        print(f"[startup] ollama reset failed (continuing anyway): {e}", flush=True)


def reset_target():
    """Reset the target application for clean state between sessions.

    For Juice Shop: kill node process and restart (in-memory SQLite resets).
    For DVWA: reset the MySQL database to default state via setup.php.
    This eliminates cross-session state pollution as a confounding variable.
    """
    native = os.environ.get("ERLIK_NATIVE", "")
    is_dvwa = "8080" in TARGET or "dvwa" in TARGET.lower()

    if is_dvwa:
        # DVWA: reset database via setup endpoint
        try:
            urllib.request.urlopen(TARGET + "/setup.php", timeout=10)
            # POST to reset DB
            data = b"create_db=Create+%2F+Reset+Database"
            req = urllib.request.Request(TARGET + "/setup.php", data=data, method="POST")
            urllib.request.urlopen(req, timeout=10)
            print("[reset] dvwa database reset", flush=True)
        except Exception as e:
            print(f"[reset] dvwa reset warning: {e}", flush=True)
    elif native:
        # Juice Shop native: kill and restart node process
        subprocess.run(["pkill", "-f", "node.*juice-shop"],
                        timeout=5, capture_output=True)
        time.sleep(3)
        js_dir = "/opt/juice-shop" if Path("/opt/juice-shop/build/app.js").exists() else "/root/juice-shop"
        env = os.environ.copy()
        env["NODE_OPTIONS"] = "--max-old-space-size=8192"
        subprocess.Popen(
            ["node", "build/app.js"],
            cwd=js_dir, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    else:
        # Juice Shop Docker
        subprocess.run(["docker", "restart", "juice-shop"],
                        timeout=30, capture_output=True)

    # Wait for health check
    target_name = "dvwa" if is_dvwa else "juice-shop"
    for attempt in range(30):
        time.sleep(2)
        try:
            urllib.request.urlopen(TARGET, timeout=3)
            print(f"[reset] {target_name} ready after {(attempt + 1) * 2}s", flush=True)
            return
        except Exception:
            pass
    print(f"[reset] {target_name} WARNING: not ready after 60s", flush=True)


def fetch_metrics(session_id: str) -> dict:
    """Get ground-truth validation metrics for a session."""
    resp = http("GET", f"/api/benchmark/{session_id}/metrics")
    if not resp:
        return {"true_positives": 0, "false_positives": 0, "precision": 0.0, "gt_coverage": 0.0}
    return {
        "true_positives": resp.get("true_positives", 0),
        "false_positives": resp.get("false_positives", 0),
        "precision": round(resp.get("precision", 0.0), 3),
        "gt_coverage": round(resp.get("coverage", 0.0), 3),
    }


def fetch_chain_metrics(chain_row: dict) -> dict:
    """Aggregate ground-truth metrics across all child sessions of a chain."""
    tp_total, fp_total = 0, 0
    gt_ids_hit: set[int] = set()
    for s in chain_row.get("sessions", []):
        sid = s.get("id", "")
        if not sid:
            continue
        m = fetch_metrics(sid)
        tp_total += m["true_positives"]
        fp_total += m["false_positives"]
    total = tp_total + fp_total
    return {
        "true_positives": tp_total,
        "false_positives": fp_total,
        "precision": round(tp_total / total, 3) if total > 0 else 0.0,
        "gt_coverage": 0.0,  # chain-level coverage needs dedicated endpoint
    }


def _load_existing_csv(csv_path: Path) -> tuple[set, dict]:
    """Read an existing summary.csv and return (completed_labels, cold_parents_by_toolset_and_turns).

    completed_labels: set of label strings that already finished — we skip these on resume.
    cold_parents: { (toolset, turns): session_id } — used so warm sessions in resume mode
                  can find their already-completed cold parent.
    """
    completed = set()
    parents = {}
    if not csv_path.exists():
        return completed, parents
    with csv_path.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            label = row.get("label", "")
            if row.get("status") == "completed":
                completed.add(label)
                if row.get("kind") == "cold":
                    try:
                        parents[(row["toolset_preset"], int(row["max_turns"]))] = row["id"]
                    except Exception:
                        pass
    return completed, parents


def main():
    # Parse args (very minimal, no argparse needed)
    resume_dir = None
    repeats = 1
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--resume" and i + 1 < len(args):
            resume_dir = Path(args[i + 1])
            if not resume_dir.exists():
                print(f"ABORT: --resume directory does not exist: {resume_dir}"); sys.exit(1)
            i += 2
        elif args[i] == "--repeats" and i + 1 < len(args):
            repeats = int(args[i + 1])
            i += 2
        else:
            i += 1

    # Pre-flight
    health = http("GET", "/api/health")
    if not health or health.get("ollama") != "connected":
        print("ABORT: orchestrator or ollama not reachable"); sys.exit(1)
    presets = http("GET", "/api/presets")
    if not presets or PLAYBOOK not in presets:
        print(f"ABORT: playbook '{PLAYBOOK}' not available"); sys.exit(1)
    prompt = presets[PLAYBOOK]["prompt"]

    # Reset ollama before the run so we don't inherit a stuck runner from
    # whatever was using ollama before. The first session will pay a ~30s
    # model-load cost; everything after that benefits from a clean state.
    reset_ollama_runner()

    # Save ground truth reference for this run
    gt = http("GET", "/api/ground-truth") or []
    # (saved to file after out_dir is determined)

    if resume_dir:
        out_dir = resume_dir
        csv_path = out_dir / "summary.csv"
        log_path = out_dir / "run.log"
        detail_path = out_dir / "sessions.jsonl"
        completed_labels, prior_cold_parents = _load_existing_csv(csv_path)
        # Open files in append mode — keep header from prior run
        csv_file = csv_path.open("a", newline="", buffering=1)
        csv_writer = csv.writer(csv_file)
        detail_file = detail_path.open("a", buffering=1)
    else:
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        out_dir = Path("runs") / ts
        out_dir.mkdir(parents=True, exist_ok=True)
        csv_path = out_dir / "summary.csv"
        log_path = out_dir / "run.log"
        detail_path = out_dir / "sessions.jsonl"
        completed_labels = set()
        prior_cold_parents = {}
        csv_file = csv_path.open("w", newline="", buffering=1)
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow([
            "id", "turn_count", "phase", "kind", "toolset_preset", "max_turns",
            "status", "total_steps", "total_findings", "duration_s", "parent_id", "label",
            "true_positives", "false_positives", "precision", "gt_coverage",
        ])
        detail_file = detail_path.open("w", buffering=1)

    # Persist ground truth snapshot for reproducibility
    gt_path = out_dir / "ground_truth.json"
    if not gt_path.exists() and gt:
        gt_path.write_text(json.dumps(gt, indent=2))

    log("=========================================", log_path)
    if resume_dir:
        log(f"Sprint matrix · RESUME mode · model={MODEL} · playbook={PLAYBOOK}", log_path)
        log(f"Resuming from: {out_dir}", log_path)
        log(f"Already completed (will skip): {len(completed_labels)} labels", log_path)
        log(f"Inherited cold parents: {len(prior_cold_parents)}", log_path)
    else:
        log(f"Sprint matrix · model={MODEL} · playbook={PLAYBOOK}", log_path)
    log(f"Turn options: {TURN_OPTIONS}  Toolsets: {TOOLSETS}", log_path)
    total_planned = len(TURN_OPTIONS) * len(TOOLSETS) * 3
    log(f"Total runs planned: {len(TURN_OPTIONS)} * {len(TOOLSETS)} * 3 = {total_planned} (skipping {len(completed_labels)})", log_path)
    log(f"Output dir: {out_dir}", log_path)
    log("=========================================", log_path)

    for turns in TURN_OPTIONS:
        log(f"┌── TURN BLOCK: {turns} turns ─────────────────────", log_path)

        # -------- Phase 1: cold sessions --------
        log(f"│ PHASE 1 (cold) · {turns}t · all 3 toolsets", log_path)
        cold_parents: dict[str, str] = {}
        # Inherit any cold parents from a prior partial run so warm sessions
        # in this same turn block can find them.
        for toolset in TOOLSETS:
            inherited = prior_cold_parents.get((toolset, turns))
            if inherited:
                cold_parents[toolset] = inherited
        for toolset in TOOLSETS:
            label = f"cold-{toolset}-{turns}t"
            if label in completed_labels:
                log(f"│   ⊘ SKIP {label} (already completed)", log_path)
                continue
            reset_target()
            log(f"│   ▶ {label}", log_path)
            sid = create_session(prompt, toolset, turns, "cold", None)
            if not sid:
                log(f"│   ✗ create FAILED: {label}", log_path)
                csv_writer.writerow(["", turns, 1, "cold", toolset, turns,
                                     "create-failed", 0, 0, 0, "", label, 0, 0, 0, 0])
                continue
            http("POST", f"/api/sessions/{sid}/start")
            result = poll_session(sid, MAX_WAIT_COLD_MIN, log_path)
            metrics = fetch_metrics(sid)
            csv_writer.writerow([sid, turns, 1, "cold", toolset, turns,
                                 result["status"], result["steps"], result["findings"],
                                 result["duration_s"], "", label,
                                 metrics["true_positives"], metrics["false_positives"],
                                 metrics["precision"], metrics["gt_coverage"]])
            detail_file.write(json.dumps({"label": label, **result.get("row", {})}) + "\n")
            log(f"│   ◀ {label} → {result['status']}  steps={result['steps']}  findings={result['findings']}  TP={metrics['true_positives']}  dur={result['duration_s']}s", log_path)
            if result["status"] == "completed":
                cold_parents[toolset] = sid

        # -------- Phase 2: warm sessions --------
        log(f"│ PHASE 2 (warm) · {turns}t · parented to Phase 1 colds", log_path)
        for toolset in TOOLSETS:
            label = f"warm-{toolset}-{turns}t"
            if label in completed_labels:
                log(f"│   ⊘ SKIP {label} (already completed)", log_path)
                continue
            parent = cold_parents.get(toolset)
            if not parent:
                log(f"│   ✗ SKIP {label}: no parent", log_path)
                csv_writer.writerow(["", turns, 2, "warm", toolset, turns,
                                     "no-parent", 0, 0, 0, "", label, 0, 0, 0, 0])
                continue
            reset_target()
            log(f"│   ▶ {label}  (parent={parent})", log_path)
            sid = create_session(prompt, toolset, turns, "warm", parent)
            if not sid:
                log(f"│   ✗ create FAILED: {label}", log_path)
                csv_writer.writerow(["", turns, 2, "warm", toolset, turns,
                                     "create-failed", 0, 0, 0, parent, label, 0, 0, 0, 0])
                continue
            http("POST", f"/api/sessions/{sid}/start")
            result = poll_session(sid, MAX_WAIT_WARM_MIN, log_path)
            metrics = fetch_metrics(sid)
            csv_writer.writerow([sid, turns, 2, "warm", toolset, turns,
                                 result["status"], result["steps"], result["findings"],
                                 result["duration_s"], parent, label,
                                 metrics["true_positives"], metrics["false_positives"],
                                 metrics["precision"], metrics["gt_coverage"]])
            detail_file.write(json.dumps({"label": label, **result.get("row", {})}) + "\n")
            log(f"│   ◀ {label} → {result['status']}  steps={result['steps']}  findings={result['findings']}  TP={metrics['true_positives']}  dur={result['duration_s']}s", log_path)

        # -------- Phase 3: chain sessions --------
        log(f"│ PHASE 3 (chain) · {turns}t/phase · all 3 toolsets", log_path)
        for toolset in TOOLSETS:
            label = f"chain-{toolset}-{turns}tpp"
            if label in completed_labels:
                log(f"│   ⊘ SKIP {label} (already completed)", log_path)
                continue
            reset_target()
            log(f"│   ▶ {label}", log_path)
            chain_id = create_chain(prompt, toolset, turns)
            if not chain_id:
                log(f"│   ✗ chain create FAILED: {label}", log_path)
                csv_writer.writerow(["", turns, 3, "chain", toolset, turns,
                                     "create-failed", 0, 0, 0, "", label, 0, 0, 0, 0])
                continue
            result = poll_chain(chain_id, MAX_WAIT_CHAIN_MIN, log_path)
            metrics = fetch_chain_metrics(result.get("row", {}))
            csv_writer.writerow([chain_id, turns, 3, "chain", toolset, turns,
                                 result["status"], result["steps"], result["findings"],
                                 result["duration_s"], "", label,
                                 metrics["true_positives"], metrics["false_positives"],
                                 metrics["precision"], metrics["gt_coverage"]])
            detail_file.write(json.dumps({"label": label, **result.get("row", {})}) + "\n")
            log(f"│   ◀ {label} → {result['status']}  steps={result['steps']}  findings={result['findings']}  TP={metrics['true_positives']}  dur={result['duration_s']}s", log_path)

        log(f"└── TURN BLOCK {turns} turns done ────────────────", log_path)

    # -------- Repeats: variance data for representative config --------
    if repeats > 1:
        log(f"┌── REPEATS: {repeats - 1} extra runs of cold-standard_20-30t ──", log_path)
        for r in range(2, repeats + 1):
            label = f"cold-standard_20-30t-r{r}"
            if label in completed_labels:
                log(f"│   ⊘ SKIP {label}", log_path)
                continue
            reset_target()
            log(f"│   ▶ {label}", log_path)
            sid = create_session(prompt, "standard_20", 30, "cold", None)
            if not sid:
                log(f"│   ✗ create FAILED: {label}", log_path)
                csv_writer.writerow(["", 30, "R", "cold", "standard_20", 30,
                                     "create-failed", 0, 0, 0, "", label, 0, 0, 0, 0])
                continue
            http("POST", f"/api/sessions/{sid}/start")
            result = poll_session(sid, 0, log_path)
            metrics = fetch_metrics(sid)
            csv_writer.writerow([sid, 30, "R", "cold", "standard_20", 30,
                                 result["status"], result["steps"], result["findings"],
                                 result["duration_s"], "", label,
                                 metrics["true_positives"], metrics["false_positives"],
                                 metrics["precision"], metrics["gt_coverage"]])
            detail_file.write(json.dumps({"label": label, **result.get("row", {})}) + "\n")
            log(f"│   ◀ {label} → {result['status']}  findings={result['findings']}  TP={metrics['true_positives']}  dur={result['duration_s']}s", log_path)
        log(f"└── REPEATS done ────────────────", log_path)

    log("=========================================", log_path)
    log("MATRIX COMPLETE", log_path)
    log(f"CSV:    {csv_path}", log_path)
    log(f"Detail: {detail_path}", log_path)
    log(f"Log:    {log_path}", log_path)
    log("=========================================", log_path)

    csv_file.close()
    detail_file.close()


if __name__ == "__main__":
    main()
