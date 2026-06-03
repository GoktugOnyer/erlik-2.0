#!/usr/bin/env python3
"""
Memory-Augmented Pentesting Experiment

Compares 4 approaches on the same target (Juice Shop):
1. COLD   — fresh start, no prior context
2. WARM   — inherits parent session context (standard Erlik warm)
3. CHAIN  — 4-phase sequential (recon → discovery → vuln_scan → exploit)
4. MEMORY — injected memory context from accumulated knowledge

Tests whether runtime context injection (memory) outperforms
fine-tuning and multi-phase session architectures.
"""

import json
import time
import urllib.request
import sys
import os
from datetime import datetime

BASE = "http://localhost:8002"
TARGET = os.environ.get("ERLIK_TARGET", "http://localhost:3000")
MODEL = os.environ.get("ERLIK_MATRIX_MODEL", "qwen2.5-coder:7b")
TURNS = int(os.environ.get("MEMORY_TURNS", "30"))
TOOLSET = os.environ.get("MEMORY_TOOLSET", "standard_20")

# The accumulated "memory" — this is what a persistent agent memory system
# would have built up after several pentest sessions against Juice Shop.
# It represents knowledge the agent DISCOVERED in prior runs.
PENTEST_MEMORY = """
=== ACCUMULATED TARGET KNOWLEDGE (from previous pentest sessions) ===

TARGET: {target_url}
TECH STACK: Node.js 18 / Express.js / Angular SPA / SQLite in-memory DB

DISCOVERED ENDPOINTS (from prior recon + discovery):
  APIs requiring NO authentication:
    GET  /api/Users         → returns ALL users with email, role, MD5 password hashes
    GET  /api/Products      → product catalog, supports PUT for modification
    GET  /api/Feedbacks     → user feedback, POST accepts arbitrary UserId
    GET  /api/SecurityQuestions → lists all security questions
    GET  /api/SecurityAnswers   → CRITICAL: exposes password reset answers!
    GET  /api/Quantitys     → inventory data, PUT allows quantity changes
    GET  /api/Challenges    → challenge metadata

  APIs requiring authentication:
    GET  /api/Complaints    → 401 without token
    GET  /api/Recycles      → 401 without token

  REST endpoints:
    POST /rest/user/login   → returns JWT token, no rate limiting
    POST /rest/user/reset-password → accepts email + security answer
    GET  /rest/basket/:id   → IDOR: any basket accessible by changing ID
    GET  /rest/products/search?q= → SQL injection point (parameter: q)
    POST /profile/image/url → SSRF: server fetches provided URL
    GET  /redirect?to=      → open redirect with allowlist (bypassable)

  Static/file endpoints:
    GET  /ftp/              → directory listing with backup files (.bak)
    GET  /ftp/package.json.bak → exposes dependency versions
    GET  /main.js           → SPA source with routes: /#/administration, /#/basket
    GET  /robots.txt        → reveals /ftp path
    GET  /.well-known/security.txt → org info disclosure
    POST /file-upload       → PDF-only filter, bypassable with null byte (%2500)

  Authentication:
    Admin email: admin@juice-sh.op
    Admin password: admin123 (weak)
    JWT signing secret: "secret" (crackable with rockyou.txt)
    JWT accepts alg:none tokens (signature bypass)
    Security answer for jim@juice-sh.op: "Samuel"

PREVIOUSLY FOUND VULNERABILITIES:
  - SQL Injection on /rest/products/search?q= (UNION + blind)
  - XSS on /rest/products/search?q= (reflected), /#/search (DOM), /#/track-result (DOM)
  - CORS: Access-Control-Allow-Origin: * on all endpoints
  - Missing security headers (CSP, X-Frame-Options, HSTS)
  - Swagger docs at /api-docs exposing full API surface
  - Prometheus metrics at /metrics leaking server internals
  - Verbose error pages with Express stack traces

KNOWN BUT NOT YET EXPLOITED:
  - IDOR on /rest/basket/:id — try accessing baskets 1-5
  - Forged feedback via POST /api/Feedbacks with arbitrary UserId
  - Product price manipulation via PUT /api/Products/:id
  - SSRF via POST /profile/image/url with internal URLs
  - XXE via XML file upload to /file-upload
  - Prototype pollution via __proto__ in JSON POST to /api/Users
  - Open redirect bypass on /redirect?to= (append to allowed domain)
  - File upload null byte bypass: filename.php%2500.pdf
  - Admin panel at /#/administration (client-side only restriction)
  - Quantity manipulation via PUT /api/Quantitys/:id

RECOMMENDED NEXT ACTIONS:
  1. Test access control: curl /api/Users, /rest/basket/1, PUT /api/Products/1
  2. Test auth: login as admin, crack JWT, try alg:none
  3. Test SSRF: POST /profile/image/url with http://localhost:3000/api/Users
  4. Test file upload: upload XML with XXE payload
  5. Test prototype pollution: POST /api/Users with __proto__ in JSON
=== END OF ACCUMULATED KNOWLEDGE ===
"""


def http(method, path, body=None):
    """Make HTTP request to orchestrator API."""
    url = f"{BASE}{path}"
    data = json.dumps(body).encode() if body else None
    headers = {"Content-Type": "application/json"} if body else {}
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        resp = urllib.request.urlopen(req, timeout=30)
        return json.loads(resp.read())
    except Exception as e:
        print(f"  API error: {e}")
        return None


def create_session(toolset, turns, stype, parent=None, extra_prompt=""):
    """Create a session via the orchestrator API."""
    body = {
        "model": MODEL,
        "target_url": TARGET,
        "scope_mode": "full",
        "session_type": stype,
        "toolset_preset": toolset,
        "max_turns": turns,
        "playbook": "owasp_methodology",
    }
    if parent:
        body["parent_session_id"] = parent
    if extra_prompt:
        # Pass memory as system_prompt — gets appended to TOOL_USE_SYSTEM_PROMPT
        body["system_prompt"] = extra_prompt

    resp = http("POST", "/api/sessions", body)
    if resp and resp.get("id"):
        return resp["id"]
    return None


def poll_session(sid, label=""):
    """Poll until session completes."""
    print(f"    Polling {label} ({sid[:12]})...", end="", flush=True)
    start = time.time()
    while True:
        resp = http("GET", f"/api/sessions/{sid}")
        if not resp:
            time.sleep(5)
            continue
        status = resp.get("status", "")
        if status in ("completed", "stopped", "error", "failed"):
            dur = int(time.time() - start)
            findings = resp.get("total_findings", 0)
            steps = resp.get("total_steps", 0)
            print(f" {status} ({steps} steps, {findings} findings, {dur}s)")
            return {
                "status": status,
                "steps": steps,
                "findings": findings,
                "duration_s": dur,
                "id": sid,
            }
        print(".", end="", flush=True)
        time.sleep(5)


def get_metrics(sid):
    """Get GT metrics for a session."""
    resp = http("GET", f"/api/benchmark/{sid}/metrics")
    if resp:
        return {
            "true_positives": resp.get("true_positives", 0),
            "recall": resp.get("recall", 0),
            "unique_gt": round(resp.get("recall", 0) * 35),
        }
    return {"true_positives": 0, "recall": 0, "unique_gt": 0}


def reset_target():
    """Reset Juice Shop for clean state."""
    import subprocess
    subprocess.run(["docker", "restart", "juice-shop"], timeout=30, capture_output=True)
    for i in range(30):
        time.sleep(2)
        try:
            urllib.request.urlopen(TARGET, timeout=3)
            print(f"  [reset] Juice Shop ready ({(i+1)*2}s)")
            return
        except:
            pass
    print("  [reset] WARNING: Juice Shop not ready after 60s")


def run_experiment():
    """Run the 4-way comparison experiment."""
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    results = []

    print(f"\n{'='*60}")
    print(f"MEMORY EXPERIMENT — {ts}")
    print(f"Model: {MODEL} | Target: {TARGET}")
    print(f"Turns: {TURNS} | Toolset: {TOOLSET}")
    print(f"{'='*60}\n")

    # ===== 1. COLD START =====
    print("=== TEST 1: COLD START (no context) ===")
    reset_target()
    sid = create_session(TOOLSET, TURNS, "cold")
    if sid:
        http("POST", f"/api/sessions/{sid}/start")
        result = poll_session(sid, "cold")
        metrics = get_metrics(sid)
        results.append({"type": "cold", **result, **metrics})
    else:
        print("  Failed to create cold session!")

    # ===== 2. WARM START (parent = cold) =====
    print("\n=== TEST 2: WARM START (inherits cold context) ===")
    reset_target()
    parent_id = results[0]["id"] if results else None
    sid = create_session(TOOLSET, TURNS, "warm", parent=parent_id)
    if sid:
        http("POST", f"/api/sessions/{sid}/start")
        result = poll_session(sid, "warm")
        metrics = get_metrics(sid)
        results.append({"type": "warm", **result, **metrics})

    # ===== 3. CHAIN (4-phase) =====
    print("\n=== TEST 3: CHAIN (4-phase sequential) ===")
    reset_target()
    chain_body = {
        "model": MODEL,
        "target_url": TARGET,
        "scope_mode": "full",
        "toolset_preset": TOOLSET,
        "max_turns_per_phase": TURNS,
        "playbook": "owasp_methodology",
    }
    chain_resp = http("POST", "/api/chains", chain_body)
    if chain_resp and chain_resp.get("id"):
        chain_id = chain_resp["id"]
        print(f"  Chain {chain_id[:12]} started")
        # Poll chain
        start = time.time()
        while True:
            resp = http("GET", f"/api/chains/{chain_id}")
            if not resp:
                time.sleep(10)
                continue
            status = resp.get("status", "")
            phase = resp.get("current_phase", "?")
            if status in ("completed", "stopped", "error", "failed"):
                dur = int(time.time() - start)
                # Get aggregate metrics from child sessions
                children = resp.get("sessions", [])
                total_findings = sum(c.get("total_findings", 0) for c in children)
                total_steps = sum(c.get("total_steps", 0) for c in children)
                # Get unique GT from all children
                all_gt = set()
                for c in children:
                    c_id = c.get("id", "")
                    if c_id:
                        m = get_metrics(c_id)
                        # We can't get exact GT IDs, use recall approximation
                print(f"  Chain {status} ({total_steps} steps, {total_findings} findings, {dur}s)")
                # Get metrics from last child (best approximation)
                last_metrics = {"true_positives": 0, "recall": 0, "unique_gt": 0}
                if children:
                    last_id = children[-1].get("id", "")
                    if last_id:
                        last_metrics = get_metrics(last_id)
                results.append({
                    "type": "chain",
                    "status": status,
                    "steps": total_steps,
                    "findings": total_findings,
                    "duration_s": dur,
                    "id": chain_id,
                    **last_metrics,
                })
                break
            print(f"  Chain phase={phase} status={status}", end="\r", flush=True)
            time.sleep(10)
    else:
        print("  Failed to create chain!")

    # ===== 4. MEMORY-AUGMENTED =====
    print("\n=== TEST 4: MEMORY-AUGMENTED (injected knowledge) ===")
    reset_target()
    memory_prompt = PENTEST_MEMORY.replace("{target_url}", TARGET)
    sid = create_session(TOOLSET, TURNS, "cold", extra_prompt=memory_prompt)
    if sid:
        http("POST", f"/api/sessions/{sid}/start")
        result = poll_session(sid, "memory")
        metrics = get_metrics(sid)
        results.append({"type": "memory", **result, **metrics})

    # ===== RESULTS =====
    print(f"\n{'='*60}")
    print("RESULTS COMPARISON")
    print(f"{'='*60}")
    print(f"{'Type':<10} {'Steps':>6} {'Findings':>9} {'TP':>4} {'GT':>4} {'Time':>6}")
    print("-" * 45)
    for r in results:
        print(f"{r['type']:<10} {r.get('steps',0):>6} {r.get('findings',0):>9} "
              f"{r.get('true_positives',0):>4} {r.get('unique_gt',0):>4} "
              f"{r.get('duration_s',0):>5}s")

    # Save results
    out_path = f"runs/memory_experiment_{ts}.json"
    os.makedirs("runs", exist_ok=True)
    with open(out_path, "w") as f:
        json.dump({"model": MODEL, "target": TARGET, "turns": TURNS,
                   "toolset": TOOLSET, "timestamp": ts, "results": results}, f, indent=2)
    print(f"\nResults saved to {out_path}")

    return results


if __name__ == "__main__":
    run_experiment()
