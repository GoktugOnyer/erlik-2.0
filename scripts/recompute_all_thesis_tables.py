#!/usr/bin/env python3
"""Recompute unique-GT coverage for every run referenced in the thesis,
using the canonical programmatic matcher. Produces a CSV + JSON that
enumerates (run_dir, model, target, sessions, findings, TP, unique_GT,
coverage_pct, precision) per experiment.

Data source for each run: its own `pentest.db`, discovered by directory.
"""
import csv
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from recompute_gt_coverage import match_finding, compute_gt_coverage

# ─── Every run dir that has a sprint-matrix CSV + pentest.db ───
# (run_dir, db_path, target_key ['js' | 'dvwa'])
EXPERIMENTS = [
    # Apr 9 — clean Docker RTX 4090 baseline (Juice Shop)
    ("runs/clean_2026-04-09/7B",                           "runs/clean_2026-04-09/pentest.db",  "js"),
    ("runs/clean_2026-04-09/14B",                          "runs/clean_2026-04-09/pentest.db",  "js"),
    ("runs/clean_2026-04-09/32B",                          "runs/clean_2026-04-09/pentest.db",  "js"),
    # 32B-Instruct dir's IDs don't exist in the DB — skip (data loss)
    # Apr 11 — DVWA
    ("runs/dvwa_2026-04-11/7B",                            "runs/dvwa_2026-04-11/pentest.db",   "dvwa"),
    ("runs/dvwa_2026-04-11/14B",                           "runs/dvwa_2026-04-11/pentest.db",   "dvwa"),
    ("runs/dvwa_2026-04-11/32B",                           "runs/dvwa_2026-04-11/pentest.db",   "dvwa"),
    ("runs/dvwa_2026-04-11/32B-Instruct",                  "runs/dvwa_2026-04-11/pentest.db",   "dvwa"),
    # Apr 13 — A100 baseline + FT variants
    ("runs/cloud_2026-04-13/2026-04-12_19-37-45",          "runs/cloud_2026-04-13/pentest.db",  "js"),
    ("runs/cloud_2026-04-13/2026-04-12_22-11-23",          "runs/cloud_2026-04-13/pentest.db",  "js"),
    ("runs/cloud_2026-04-13/2026-04-13_11-47-21",          "runs/cloud_2026-04-13/pentest.db",  "js"),
    ("runs/cloud_2026-04-13/2026-04-13_11-50-01",          "runs/cloud_2026-04-13/pentest.db",  "js"),
    ("runs/cloud_2026-04-13/2026-04-13_14-12-57",          "runs/cloud_2026-04-13/pentest.db",  "js"),
    # Apr 14 — additional FT experiments
    ("runs/cloud_2026-04-14_ft/2026-04-14_11-07-42",       "runs/cloud_2026-04-14_ft/pentest.db",  "js"),
    ("runs/cloud_2026-04-14_ft/2026-04-14_11-37-17",       "runs/cloud_2026-04-14_ft/pentest.db",  "js"),
    ("runs/cloud_2026-04-14_ft/2026-04-14_12-26-08",       "runs/cloud_2026-04-14_ft/pentest.db",  "js"),
    ("runs/cloud_2026-04-14_proper/2026-04-14_15-40-57",   "runs/cloud_2026-04-14_proper/pentest.db",  "js"),
    ("runs/cloud_2026-04-14_proper/2026-04-14_16-39-28",   "runs/cloud_2026-04-14_proper/pentest.db",  "js"),
    ("runs/cloud_2026-04-14_proper/2026-04-14_17-32-25",   "runs/cloud_2026-04-14_proper/pentest.db",  "js"),
    ("runs/cloud_2026-04-14_32b/2026-04-14_21-17-14",      "runs/cloud_2026-04-14_32b/pentest.db",  "js"),
    ("runs/cloud_2026-04-14_32b/2026-04-14_23-59-45",      "runs/cloud_2026-04-14_32b/pentest.db",  "js"),
    # Apr 15 — final PRO 6000 run
    ("runs/cloud_2026-04-15_balanced/2026-04-14_21-17-14", "runs/cloud_2026-04-15_balanced/pentest.db",  "js"),
    ("runs/cloud_2026-04-15_balanced/2026-04-14_23-59-45", "runs/cloud_2026-04-15_balanced/pentest.db",  "js"),
    ("runs/cloud_2026-04-15_balanced/2026-04-15_02-48-01", "runs/cloud_2026-04-15_balanced/pentest.db",  "js"),
    ("runs/cloud_2026-04-15_balanced/2026-04-15_04-44-17", "runs/cloud_2026-04-15_balanced/pentest.db",  "js"),
    # Apr 17 — juicy3 era
    ("runs/2026-04-17_00-07-23",                           "data/pentest.db",  "js"),
    ("runs/2026-04-17_12-29-10",                           "data/pentest.db",  "js"),
    ("runs/2026-04-17_19-24-01",                           "data/pentest.db",  "js"),
]

# Load both GT sets once
GT_JS   = json.load(open("runs/2026-04-17_19-24-01/ground_truth.json"))
GT_DVWA = json.load(open("runs/dvwa_2026-04-11/ground_truth.json"))

for idx, g in enumerate(GT_JS):
    g.setdefault("id", g.get("id", f"J{idx+1}"))
for idx, g in enumerate(GT_DVWA):
    g.setdefault("id", g.get("id", f"D{idx+1}"))


def collect_sessions(run_dir: Path, db: sqlite3.Connection, model: str) -> set:
    """Sprint-matrix top-level + chain child sessions."""
    sids = set()
    summary = run_dir / "summary.csv"
    if not summary.exists(): return sids
    rows = list(csv.DictReader(open(summary)))
    for r in rows:
        sids.add(r["id"])
        if r.get("kind") == "chain":
            c = db.execute(
                "SELECT created_at, updated_at FROM chains WHERE id=?",
                (r["id"],),
            ).fetchone()
            if c:
                for child in db.execute(
                    "SELECT id FROM sessions WHERE session_type='chain' AND model=? "
                    "AND created_at>=? AND created_at<=?",
                    (model, c["created_at"], c["updated_at"]),
                ):
                    sids.add(child["id"])
    return sids


def recompute_one(run_dir: str, db_path: str, target_key: str) -> dict | None:
    rp = Path(run_dir)
    dp = Path(db_path)
    if not (rp.exists() and dp.exists()):
        return None
    summary = rp / "summary.csv"
    if not summary.exists(): return None

    rows = list(csv.DictReader(open(summary)))
    if not rows: return None

    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row

    # Figure out model from first session
    row0 = db.execute("SELECT model, target_url FROM sessions WHERE id=?", (rows[0]["id"],)).fetchone()
    if not row0:
        db.close()
        return {"run_dir": run_dir, "error": "session IDs not in DB"}
    model = row0["model"]
    target = row0["target_url"]

    sids = collect_sessions(rp, db, model)
    if not sids:
        db.close()
        return None

    ph = ",".join("?" * len(sids))
    findings = list(db.execute(
        f"SELECT session_id, vuln_type, url, parameter, evidence FROM findings WHERE session_id IN ({ph})",
        list(sids),
    ))
    findings = [dict(f) for f in findings]

    gt = GT_JS if target_key == "js" else GT_DVWA
    cov = compute_gt_coverage(findings, gt)

    db.close()
    return {
        "run_dir": run_dir,
        "db": db_path,
        "model": model,
        "target": target,
        "target_key": target_key,
        "gt_size": len(gt),
        "sessions": len(sids),
        "top_level_rows": len(rows),
        **cov,
    }


def main():
    results = []
    print(f"{'Run dir':<60} {'Model':<30} {'Tgt':<5} {'Sess':>5} {'Find':>6} {'TP':>5} {'GT':>4} {'GT%':>7} {'Prec%':>7}")
    print("─" * 135)

    for run_dir, db_path, target_key in EXPERIMENTS:
        r = recompute_one(run_dir, db_path, target_key)
        if r is None:
            print(f"{run_dir:<60} (MISSING)")
            continue
        if "error" in r:
            print(f"{run_dir:<60} ERROR: {r['error']}")
            continue
        results.append(r)
        pct = r["unique_gt_hit"] / r["gt_size"] * 100
        prec = r["precision"] * 100
        print(f"{r['run_dir']:<60} {r['model']:<30} {r['target_key']:<5} {r['sessions']:>5} "
              f"{r['findings']:>6} {r['tp_findings']:>5} "
              f"{r['unique_gt_hit']:>4} {pct:>6.1f}% {prec:>6.1f}%")

    # Save
    Path("docs/recomputed_all_experiments.json").write_text(json.dumps({
        "algorithm": "orchestrator canonical (type + url + param + evidence, score>=2.0)",
        "gt_js_size": len(GT_JS),
        "gt_dvwa_size": len(GT_DVWA),
        "experiments": results,
    }, indent=2, default=str))

    Path("docs/recomputed_all_experiments.csv").write_text("")
    with open("docs/recomputed_all_experiments.csv", "w") as f:
        w = csv.DictWriter(f, fieldnames=[
            "run_dir", "model", "target", "target_key", "gt_size",
            "sessions", "findings", "tp_findings", "fp_findings",
            "unique_gt_hit", "precision",
        ])
        w.writeheader()
        for r in results:
            w.writerow({k: r.get(k) for k in w.fieldnames})

    print(f"\nSaved → docs/recomputed_all_experiments.{{json,csv}}  ({len(results)} experiments)")


if __name__ == "__main__":
    main()
