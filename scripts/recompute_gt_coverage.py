#!/usr/bin/env python3
"""Recompute GT coverage for ALL experiments using the canonical programmatic
matcher from orchestrator/main.py. Produces one consistent table for thesis.

Algorithm (verbatim from orchestrator's _match_finding_to_ground_truth_scored):
  - type match (+1)  — required, with type aliases
  - url match (+1)   — GT url_pattern in finding.url or finding.evidence
                       (+0.5 if GT has no URL pattern = generic vuln)
  - param match (+1) — GT param in finding.param or finding.evidence
                       (+0.5 if GT has no param = generic)
  - evidence (+1)    — confirmation keywords in finding text
  Threshold: score >= 2.0 for TP match.
"""
import json
import sqlite3
import sys
from collections import Counter, defaultdict
from pathlib import Path

# ═══ Canonical matcher ═══

_EVIDENCE_CONFIRMATION_KEYWORDS = {
    "sql injection": ["vulnerable", "injection point", "payload", "union", "boolean-based",
                      "time-based", "error-based", "1=1", "or 1=1", "dbms", "token",
                      "sqli confirmed", "back-end dbms"],
    "xss": ["vulnerable", "confirmed", "reflected", "alert(", "<script", "xss",
            "payload", "dom-based", "stored xss"],
    "broken access control": ["accessible", "unauthorized", "idor", "products",
                              "basket", "user record", "enumeration", "without auth"],
    "broken authentication": ["bypass", "token", "jwt", "brute", "weak password",
                              "login success", "credential"],
    "sensitive data exposure": ["email", "password", "user record", "ftp", "backup",
                                "md5", "hash", "exposed", "api key"],
    "security misconfiguration": ["missing", "header", "x-frame", "x-content-type",
                                  "hsts", "csp", "swagger", "api-docs", "debug"],
    "cors misconfiguration": ["access-control-allow-origin", "wildcard", "cors",
                              "origin: null", "arbitrary origin"],
    "ssrf": ["ssrf", "server-side", "internal", "127.0.0.1", "localhost"],
    "open redirect": ["redirect", "location:", "302", "moved"],
    "file upload": ["upload", "unrestricted", "file type", "extension"],
    "xxe": ["xxe", "xml", "entity", "dtd", "external"],
    "prototype pollution": ["__proto__", "prototype", "pollution", "constructor"],
}

_TYPE_ALIASES = {
    "sql injection": ["sqli", "sql", "injection"],
    "xss": ["cross-site", "xss", "script", "dom"],
    "cors misconfiguration": ["cors", "cross-domain", "cross domain", "origin"],
    "information disclosure": ["info", "disclosure", "error", "version", "header"],
    "broken access control": ["access", "authorization", "idor", "privilege", "enumerat"],
    "broken authentication": ["auth", "login", "brute", "jwt", "credential", "password", "token"],
    "sensitive data exposure": ["sensitive", "data", "exposure", "ftp", "backup", "crypto", "hash", "md5"],
    "security misconfiguration": ["misconfig", "header", "nikto", "swagger", "api-doc", "metric", "config"],
    "ssrf": ["ssrf", "server-side", "request forgery"],
    "open redirect": ["redirect", "open redirect", "url redirect"],
    "file upload": ["upload", "file", "unrestricted"],
    "xxe": ["xxe", "xml", "external entity"],
    "prototype pollution": ["prototype", "pollution", "__proto__"],
}


def match_finding(finding: dict, gt_list: list) -> dict:
    """Returns {match, score, gt_id} using canonical algorithm."""
    f_type = (finding.get("vuln_type") or "").lower()
    f_url = (finding.get("url") or "").lower()
    f_param = (finding.get("parameter") or "").lower()
    f_evidence = (finding.get("evidence") or "").lower()
    f_all = f"{f_type} {f_url} {f_param} {f_evidence}"

    best_score = 0.0
    best_gt = None

    for g in gt_list:
        gt_type = g["vuln_type"].lower()
        gt_url = (g.get("url_pattern") or "").lower()
        gt_param = (g.get("parameter") or "").lower()

        type_ok = gt_type in f_type or f_type in gt_type
        if not type_ok:
            for alias in _TYPE_ALIASES.get(gt_type, []):
                if alias in f_type:
                    type_ok = True; break
        if not type_ok:
            continue

        score = 1.0  # type match
        if gt_url:
            if gt_url in f_url or gt_url in f_evidence:
                score += 1.0
        else:
            score += 0.5

        if gt_param:
            if gt_param in f_param or gt_param in f_evidence:
                score += 1.0
        else:
            score += 0.5

        kws = _EVIDENCE_CONFIRMATION_KEYWORDS.get(gt_type, [])
        if kws and any(k in f_all for k in kws):
            score += 1.0

        if score > best_score:
            best_score = score
            best_gt = g

    return {
        "match": best_score >= 2.0,
        "score": best_score,
        "gt_id": best_gt["id"] if (best_gt and best_score >= 2.0) else None,
    }


# ═══ Data collection helpers ═══

def collect_session_ids(run_dir: Path, db: sqlite3.Connection, model_name: str) -> set:
    """From a sprint-matrix run dir, collect all session IDs including chain children."""
    import csv
    sids = set()
    summary = run_dir / "summary.csv"
    if not summary.exists():
        return sids
    rows = list(csv.DictReader(open(summary)))
    for r in rows:
        sids.add(r["id"])
        if r.get("kind") == "chain":
            # chain children by time window on chains table
            c = db.execute("SELECT created_at, updated_at FROM chains WHERE id=?", (r["id"],)).fetchone()
            if c:
                cur = db.execute(
                    "SELECT id FROM sessions WHERE session_type='chain' AND model=? AND created_at>=? AND created_at<=?",
                    (model_name, c["created_at"], c["updated_at"]))
                for row in cur:
                    sids.add(row["id"])
    return sids


def pull_findings(db: sqlite3.Connection, sids: set) -> list:
    if not sids: return []
    placeholders = ",".join("?" * len(sids))
    return list(db.execute(
        f"SELECT session_id, vuln_type, url, parameter, evidence FROM findings WHERE session_id IN ({placeholders})",
        list(sids)))


def compute_gt_coverage(findings: list, gt_list: list) -> dict:
    """Canonical programmatic matcher. Returns per-GT hit set + stats."""
    hits = set()
    scores_by_gt = defaultdict(float)
    tp_count = 0
    for f in findings:
        m = match_finding(dict(f), gt_list)
        if m["match"]:
            tp_count += 1
            hits.add(m["gt_id"])
            if m["score"] > scores_by_gt[m["gt_id"]]:
                scores_by_gt[m["gt_id"]] = m["score"]
    return {
        "findings": len(findings),
        "tp_findings": tp_count,
        "fp_findings": len(findings) - tp_count,
        "unique_gt_hit": len(hits),
        "gt_hit_ids": sorted(hits, key=lambda x: (isinstance(x, str), x)),
        "precision": tp_count / max(len(findings), 1),
    }


# ═══ Main ═══

def main():
    db = sqlite3.connect("data/pentest.db")
    db.row_factory = sqlite3.Row

    # Define the experiments we want to recompute
    # (label, run_dir, ollama_model_name, gt_source)
    experiments = [
        ("baseline_7b_apr17",   "runs/2026-04-17_00-07-23",       "qwen2.5-coder:7b",         "js"),
        ("baseline_7b_juicy1",  "runs/cloud_2026-04-15_balanced", "qwen2.5-coder:7b",         "js"),  # best earlier baseline
        ("ft_v3_7b_apr17",      "runs/2026-04-17_19-24-01",       "qwen2.5-coder:7b-juicy3",  "js"),
        ("ft_v3_14b_apr17",     "runs/2026-04-17_12-29-10",       "qwen2.5-coder:14b-juicy3", "js"),
    ]

    # Load GT from the newest juicy3 run (all runs have 35 Juice Shop GT entries)
    gt_path = Path("runs/2026-04-17_19-24-01/ground_truth.json")
    gt = json.load(open(gt_path))
    print(f"Ground truth: {len(gt)} Juice Shop entries")
    print(f"Using canonical programmatic matcher from orchestrator.\n")

    print(f"{'Experiment':<28} {'Sessions':>10} {'Findings':>10} {'TP_find':>10} {'GT_hit':>8} {'GT%':>8} {'Prec%':>8}")
    print("─" * 88)

    results = {}
    for label, run, model, gt_src in experiments:
        run_dir = Path(run)
        if not run_dir.exists():
            print(f"{label:<28} (no dir)")
            continue
        sids = collect_session_ids(run_dir, db, model)
        findings = pull_findings(db, sids)
        cov = compute_gt_coverage([dict(f) for f in findings], gt)
        results[label] = {"sessions": len(sids), "model": model, **cov}
        pct = cov["unique_gt_hit"] / len(gt) * 100
        prec = cov["precision"] * 100
        print(f"{label:<28} {len(sids):>10} {cov['findings']:>10} {cov['tp_findings']:>10} "
              f"{cov['unique_gt_hit']:>8} {pct:>7.1f}% {prec:>7.1f}%")

    # Union-of-coverage (baseline ∪ juicy3) at 7B scale
    b_hits = set(results.get("baseline_7b_apr17", {}).get("gt_hit_ids", []))
    j_hits = set(results.get("ft_v3_7b_apr17", {}).get("gt_hit_ids", []))
    combined = b_hits | j_hits
    print("─" * 88)
    print(f"{'COMBINED baseline∪ft_v3 (7B)':<28} {'-':>10} {'-':>10} {'-':>10} "
          f"{len(combined):>8} {len(combined)/len(gt)*100:>7.1f}% {'-':>7}")

    # Per-GT dump
    print(f"\n=== Per-GT-entry hit table (canonical programmatic matcher) ===")
    print(f"{'GT_ID':<6} {'Type':<30} {'b-7B':<6} {'ft-v3-7B':<10} {'ft-v3-14B':<10}")
    all_hits = {
        "b-7B": b_hits,
        "ft-v3-7B": j_hits,
        "ft-v3-14B": set(results.get("ft_v3_14b_apr17", {}).get("gt_hit_ids", [])),
    }
    for g in gt:
        gid = g["id"]
        row = [str(gid), g.get("vuln_type","")[:28]]
        for exp in ("b-7B", "ft-v3-7B", "ft-v3-14B"):
            row.append("✓" if gid in all_hits[exp] else "-")
        print(f"{row[0]:<6} {row[1]:<30} {row[2]:<6} {row[3]:<10} {row[4]:<10}")

    # Unique-to-each + overlap (canonical)
    only_b = b_hits - j_hits
    only_j = j_hits - b_hits
    both = b_hits & j_hits
    print(f"\n=== 7B complementarity (canonical matcher) ===")
    print(f"  Baseline only:   {sorted(only_b)}   ({len(only_b)})")
    print(f"  FT-v3 only:      {sorted(only_j)}   ({len(only_j)})")
    print(f"  Both:            {sorted(both)}   ({len(both)})")
    print(f"  Union:           {len(combined)}/{len(gt)} = {len(combined)/len(gt)*100:.1f}%")

    # Save
    out = {
        "algorithm": "canonical programmatic matcher (orchestrator/main.py _match_finding_to_ground_truth_scored, threshold>=2.0)",
        "gt_total": len(gt),
        "results": results,
        "combined_7b": {
            "unique_gt_hit": len(combined),
            "gt_hit_ids": sorted(combined, key=lambda x: (isinstance(x,str),x)),
            "coverage_pct": len(combined)/len(gt)*100,
            "unique_to_baseline": sorted(only_b),
            "unique_to_ft_v3": sorted(only_j),
            "overlap": sorted(both),
        },
    }
    Path("docs/recomputed_gt_coverage.json").write_text(json.dumps(out, indent=2, default=str))
    print(f"\nSaved → docs/recomputed_gt_coverage.json")


if __name__ == "__main__":
    main()
