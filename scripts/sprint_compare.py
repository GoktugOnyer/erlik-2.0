#!/usr/bin/env python3
"""sprint_compare.py — A/B comparison driver for the owasp_guided playbook.

Runs N sessions of cold-standard_20-30t under the new `owasp_guided` playbook
and compares them against the baseline `owasp_methodology` results from the
main matrix. Output is appended to a NEW runs/ directory so the main matrix
CSV stays clean.

The point: validate that Fix 1 (nuclei tag injection) + Fix 2 (guided playbook
with mandatory A02/A07/A08/A10 actions) actually closes the OWASP coverage gap.

Usage:
  python3 scripts/sprint_compare.py
"""
import csv
import json
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

BASE = "http://localhost:8002"
TARGET = "http://localhost:3000"
MODEL = "qwen2.5-coder:7b"
PLAYBOOK = "owasp_guided"        # ← the new playbook
TOOLSET = "standard_20"
TURNS = 30
N_SESSIONS = 3                    # 3 sessions for averaging
POLL_INTERVAL = 5
MAX_WAIT_MIN = 60                 # same as the bumped matrix ceiling


def http(method, path, body=None, timeout=30):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8", errors="replace")
        print(f"  HTTPError {e.code} on {method} {path}: {err[:200]}", flush=True)
        return None
    except Exception as e:
        print(f"  ERROR on {method} {path}: {e}", flush=True)
        return None


def log(msg, log_path):
    line = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    with log_path.open("a") as f:
        f.write(line + "\n")


def main():
    health = http("GET", "/api/health")
    if not health or health.get("ollama") != "connected":
        print("ABORT: orchestrator/ollama not reachable"); sys.exit(1)
    presets = http("GET", "/api/presets")
    if not presets or PLAYBOOK not in presets:
        print(f"ABORT: playbook '{PLAYBOOK}' not in /api/presets"); sys.exit(1)
    prompt = presets[PLAYBOOK]["prompt"]

    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    out_dir = Path("runs") / f"{ts}-compare-guided"
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "summary.csv"
    log_path = out_dir / "run.log"
    detail_path = out_dir / "sessions.jsonl"

    csv_file = csv_path.open("w", newline="", buffering=1)
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow([
        "id", "iteration", "playbook", "toolset_preset", "max_turns",
        "status", "total_steps", "total_findings", "duration_s", "label",
    ])
    detail_file = detail_path.open("w", buffering=1)

    log("=========================================", log_path)
    log(f"Sprint COMPARE · model={MODEL} · playbook={PLAYBOOK}", log_path)
    log(f"Config: cold {TOOLSET} {TURNS}t × {N_SESSIONS} sessions", log_path)
    log(f"Output: {out_dir}", log_path)
    log("=========================================", log_path)

    for i in range(1, N_SESSIONS + 1):
        label = f"cold-{TOOLSET}-{TURNS}t-guided-iter{i}"
        log(f"▶ {label}", log_path)
        body = {
            "target_url": TARGET,
            "scope_mode": "full",
            "model": MODEL,
            "system_prompt": prompt,
            "toolset_preset": TOOLSET,
            "session_type": "cold",
            "parent_session_id": None,
            "no_timeout": True,
            "max_turns": TURNS,
            "disable_stagnation": True,
        }
        resp = http("POST", "/api/sessions", body)
        if not resp or "id" not in resp:
            log(f"  ✗ create failed", log_path)
            csv_writer.writerow(["", i, PLAYBOOK, TOOLSET, TURNS,
                                 "create-failed", 0, 0, 0, label])
            continue
        sid = resp["id"]
        http("POST", f"/api/sessions/{sid}/start")

        # Poll until terminal
        t0 = time.time()
        deadline = t0 + MAX_WAIT_MIN * 60
        status = "running"; steps = 0; findings = 0
        while True:
            if time.time() > deadline:
                log(f"  ⏱ timeout {sid}", log_path)
                http("POST", f"/api/sessions/{sid}/stop")
                status = "timeout"
                break
            time.sleep(POLL_INTERVAL)
            row = http("GET", f"/api/sessions/{sid}")
            if not row:
                continue
            status = row.get("status", "") or ""
            steps = row.get("total_steps", 0) or 0
            findings = row.get("total_findings", 0) or 0
            if status in ("completed", "failed", "error", "stopped"):
                break

        dur = int(time.time() - t0)
        csv_writer.writerow([sid, i, PLAYBOOK, TOOLSET, TURNS,
                             status, steps, findings, dur, label])
        detail_row = http("GET", f"/api/sessions/{sid}") or {}
        detail_file.write(json.dumps({"label": label, **detail_row}) + "\n")
        log(f"◀ {label} → {status}  steps={steps}  findings={findings}  dur={dur}s",
            log_path)

    log("=========================================", log_path)
    log("COMPARE COMPLETE", log_path)
    log(f"CSV: {csv_path}", log_path)
    log("=========================================", log_path)

    csv_file.close()
    detail_file.close()


if __name__ == "__main__":
    main()
