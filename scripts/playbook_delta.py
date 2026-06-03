#!/usr/bin/env python3
"""Compute delta: playbook-enabled run vs the overnight baseline.

Fetches findings + steps from the live orchestrator API (not sessions.jsonl,
which stores session metadata but not finding rows).

Reports:
  1. Headline — total TP, FP, precision, per-kind breakdown.
  2. The 6 missed classes — did we detect any new ones?
  3. Playbook-endpoint engagement — did the model even try the right URLs?

Usage:
  python3 scripts/playbook_delta.py <playbook_run_dir> [baseline_run_dir]
  # defaults to runs/2026-04-17_00-07-23 for baseline (30-turn slice only)
"""

import csv
import json
import sys
import urllib.request
from pathlib import Path
from collections import defaultdict

BASE = "http://localhost:8002"

MISSED_CLASSES = {
    "SSRF": ["ssrf", "server-side request forgery", "server side request forgery"],
    "Open Redirect": ["open redirect", "openredirect"],
    "File Upload": ["file upload", "malicious file upload", "unrestricted file upload"],
    "XXE": ["xxe", "xml external entity"],
    "Prototype Pollution": ["prototype pollution"],
    "Stored XSS": ["stored xss", "persistent xss"],
}

PLAYBOOK_ENDPOINT_MARKERS = {
    "SSRF (/profile/image/url)": ["/profile/image/url", "imageurl"],
    "Open Redirect (/redirect?to=)": ["/redirect?to=", "/redirect to=", "\\/redirect"],
    "File Upload (/file-upload)": ["/file-upload"],
    "XXE (xml + DOCTYPE)": ["<!doctype", "<!entity"],
    "Prototype Pollution (__proto__)": ["__proto__", "constructor.prototype"],
    "Stored XSS (<iframe / onerror)": ["<iframe", "onerror=", "<svg/onload"],
}


def api_get(path: str):
    try:
        with urllib.request.urlopen(f"{BASE}{path}", timeout=10) as r:
            return json.loads(r.read())
    except Exception as e:
        print(f"api_get fail {path}: {e}", file=sys.stderr)
        return None


def classify_finding(f: dict) -> str | None:
    vtype = (f.get("vuln_type") or "").lower()
    ev = (f.get("evidence") or "").lower()
    for cls, keywords in MISSED_CLASSES.items():
        if any(k in vtype for k in keywords) or any(k in ev for k in keywords):
            return cls
    return None


def is_tp(f: dict) -> bool:
    # Overnight analysis counts a finding as TP if it isn't flagged FP. `verified`
    # only gets set when a reviewer re-checks, so requiring verified=1 would zero
    # out raw agent findings that haven't been reviewed yet.
    return f.get("false_positive", 0) == 0


def load_summary(run_dir: Path) -> list[dict]:
    path = run_dir / "summary.csv"
    if not path.exists():
        return []
    with path.open() as f:
        return list(csv.DictReader(f))


def ids_to_scan(sid: str, kind: str) -> list[str]:
    """For chain sessions, findings live under sub-session IDs (the chain ID itself
    has zero). Expand to the full list of session IDs that actually hold findings.

    Fallback: if the chain lookup fails (e.g. the session was labelled "chain" but
    created via /api/sessions instead of /api/chains), scan the session ID directly
    so we don't silently drop its data.
    """
    if kind == "chain":
        chain = api_get(f"/api/chains/{sid}")
        if isinstance(chain, dict):
            subs = chain.get("sessions") or []
            out = []
            for s in subs:
                if isinstance(s, str):
                    out.append(s)
                elif isinstance(s, dict) and s.get("id"):
                    out.append(s["id"])
            if out:
                return out
        # Fallback — session was tagged "chain" but has no chain parent
        return [sid]
    return [sid]


def summarize(rows: list[dict], label: str, turn_filter: int | None = None) -> dict:
    """For each session row in summary.csv, fetch findings + steps via API and aggregate."""
    total_tp = 0
    total_fp = 0
    per_kind = defaultdict(lambda: {"tp": 0, "fp": 0, "sessions": 0})
    class_hits = defaultdict(list)
    engaged_sessions = defaultdict(int)
    used_session_ids = []

    for row in rows:
        if turn_filter is not None:
            try:
                mt = int(row.get("max_turns") or 0)
            except (ValueError, TypeError):
                mt = 0
            if mt != turn_filter:
                continue
        sid = row.get("session_id") or row.get("id")
        if not sid:
            continue
        kind = row.get("session_kind") or row.get("kind") or row.get("session_type") or "?"
        per_kind[kind]["sessions"] += 1
        used_session_ids.append(sid)

        scan_ids = ids_to_scan(sid, kind)
        findings = []
        for ssid in scan_ids:
            findings.extend(api_get(f"/api/sessions/{ssid}/findings") or [])
        for f in findings:
            if is_tp(f):
                total_tp += 1
                per_kind[kind]["tp"] += 1
            else:
                total_fp += 1
                per_kind[kind]["fp"] += 1
            cls = classify_finding(f)
            if cls:
                class_hits[cls].append({
                    "session": sid[:12],
                    "tp": is_tp(f),
                    "evidence": (f.get("evidence") or "")[:140],
                    "url": f.get("url", ""),
                    "parameter": f.get("parameter", ""),
                })

        # Playbook engagement: scan tool_input across all steps for the markers
        # (for chain sessions, aggregate across all sub-sessions)
        steps = []
        for ssid in scan_ids:
            steps.extend(api_get(f"/api/sessions/{ssid}/steps") or [])
        engaged_this_session = set()
        for st in steps:
            tool_in = (st.get("tool_input") or "").lower()
            resp = (st.get("model_response") or "").lower()
            probe = tool_in + " " + resp
            for marker_label, keywords in PLAYBOOK_ENDPOINT_MARKERS.items():
                if any(k in probe for k in keywords):
                    engaged_this_session.add(marker_label)
        for marker_label in engaged_this_session:
            engaged_sessions[marker_label] += 1

    return {
        "label": label,
        "total_sessions": len(used_session_ids),
        "total_tp": total_tp,
        "total_fp": total_fp,
        "precision": total_tp / max(total_tp + total_fp, 1),
        "per_kind": dict(per_kind),
        "class_hits": dict(class_hits),
        "engaged_sessions": dict(engaged_sessions),
    }


def pretty_report(pb: dict, base: dict) -> str:
    out = []
    out.append("=" * 72)
    out.append("PLAYBOOK RAG — EFFECT ON 6 MISSED VULNERABILITY CLASSES")
    out.append("=" * 72)
    out.append(f"{'':<20} {'baseline':>16} {'playbooks':>16}  {'Δ':>8}")
    out.append(f"{'sessions':<20} {base['total_sessions']:>16} {pb['total_sessions']:>16}")
    out.append(f"{'total TP':<20} {base['total_tp']:>16} {pb['total_tp']:>16}  "
               f"{pb['total_tp'] - base['total_tp']:+d}")
    out.append(f"{'total FP':<20} {base['total_fp']:>16} {pb['total_fp']:>16}  "
               f"{pb['total_fp'] - base['total_fp']:+d}")
    out.append(f"{'precision':<20} {base['precision']:>16.1%} {pb['precision']:>16.1%}")
    out.append("")
    out.append("By session kind:")
    kinds = sorted(set(list(base["per_kind"].keys()) + list(pb["per_kind"].keys())))
    for k in kinds:
        b = base["per_kind"].get(k, {"tp": 0, "sessions": 0})
        p = pb["per_kind"].get(k, {"tp": 0, "sessions": 0})
        out.append(f"  {k:<10}  baseline {b['tp']:>3} TP / {b['sessions']:>2} sess "
                   f"  playbooks {p['tp']:>3} TP / {p['sessions']:>2} sess")
    out.append("")
    out.append("-" * 72)
    out.append("6 MISSED CLASSES — the thesis target")
    out.append("-" * 72)
    for cls in MISSED_CLASSES:
        b_hits = base["class_hits"].get(cls, [])
        p_hits = pb["class_hits"].get(cls, [])
        b_tp = sum(1 for h in b_hits if h["tp"])
        p_tp = sum(1 for h in p_hits if h["tp"])
        status = "★ NEW!" if p_tp > 0 and b_tp == 0 else ("✓" if p_tp > 0 else "✗")
        out.append(f"  {cls:<22} baseline TP={b_tp}  playbooks TP={p_tp}  {status}")
        for h in p_hits[:3]:
            flag = "TP" if h["tp"] else "FP"
            out.append(f"      └─ {h['session']} {flag}: {h['evidence']}")
    out.append("")
    out.append("-" * 72)
    out.append("Playbook-endpoint engagement (sessions that tried the right URL)")
    out.append("-" * 72)
    for marker in PLAYBOOK_ENDPOINT_MARKERS:
        b = base["engaged_sessions"].get(marker, 0)
        p = pb["engaged_sessions"].get(marker, 0)
        delta = p - b
        out.append(f"  {marker:<32}  baseline={b:>2}  playbooks={p:>2}  Δ={delta:+d}")
    out.append("=" * 72)
    return "\n".join(out)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    pb_dir = Path(sys.argv[1])
    base_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("runs/2026-04-17_00-07-23")
    if not pb_dir.exists():
        print(f"playbook run dir not found: {pb_dir}", file=sys.stderr)
        sys.exit(1)
    if not base_dir.exists():
        print(f"baseline run dir not found: {base_dir}", file=sys.stderr)
        sys.exit(1)

    pb_rows = load_summary(pb_dir)
    base_rows = load_summary(base_dir)
    if not pb_rows:
        print(f"no rows in {pb_dir}/summary.csv yet — matrix still running?", file=sys.stderr)
        sys.exit(2)

    # Baseline ran 15/30/45 turns; my matrix is 30 only — filter baseline to 30 for fairness
    pb = summarize(pb_rows, f"playbooks ({pb_dir.name})", turn_filter=None)
    base = summarize(base_rows, f"baseline 30t slice ({base_dir.name})", turn_filter=30)
    print(pretty_report(pb, base))


if __name__ == "__main__":
    main()
