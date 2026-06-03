#!/usr/bin/env python3
"""Compare multiple sprint_matrix runs side-by-side, output thesis-ready markdown."""
import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from datetime import datetime


def load_run(run_dir: Path) -> list[dict]:
    summary = run_dir / "summary.csv"
    if not summary.exists():
        return []
    return list(csv.DictReader(open(summary)))


def safe_int(v, d=0):
    try: return int(v or 0)
    except: return d


def safe_float(v, d=0.0):
    try: return float(v or 0.0)
    except: return d


def aggregate(rows: list[dict]) -> dict:
    if not rows: return {"sessions": 0}
    total_findings = sum(safe_int(r.get("total_findings")) for r in rows)
    tp = sum(safe_int(r.get("true_positives")) for r in rows)
    fp = sum(safe_int(r.get("false_positives")) for r in rows)
    dur = sum(safe_int(r.get("duration_s")) for r in rows)
    steps = sum(safe_int(r.get("total_steps")) for r in rows)
    # Per-kind breakdown
    by_kind = defaultdict(lambda: {"sessions": 0, "findings": 0, "tp": 0, "fp": 0})
    for r in rows:
        k = r.get("kind", "unknown")
        by_kind[k]["sessions"] += 1
        by_kind[k]["findings"] += safe_int(r.get("total_findings"))
        by_kind[k]["tp"] += safe_int(r.get("true_positives"))
        by_kind[k]["fp"] += safe_int(r.get("false_positives"))
    # Per-toolset breakdown
    by_toolset = defaultdict(lambda: {"sessions": 0, "findings": 0, "tp": 0})
    for r in rows:
        t = r.get("toolset_preset", "unknown")
        by_toolset[t]["sessions"] += 1
        by_toolset[t]["findings"] += safe_int(r.get("total_findings"))
        by_toolset[t]["tp"] += safe_int(r.get("true_positives"))
    return {
        "sessions": len(rows),
        "findings": total_findings,
        "tp": tp,
        "fp": fp,
        "precision": tp / max(tp + fp, 1),
        "duration_s": dur,
        "steps": steps,
        "by_kind": dict(by_kind),
        "by_toolset": dict(by_toolset),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", action="append", required=True,
                    help="label=<run_dir>, repeatable")
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    runs = {}
    for pair in args.label:
        if "=" not in pair: continue
        name, path = pair.split("=", 1)
        name = name.strip()
        path = Path(path.strip()) if path.strip() else None
        if path and path.exists():
            rows = load_run(path)
            runs[name] = {"dir": str(path), "rows": rows, "agg": aggregate(rows)}

    # Build markdown
    lines = []
    lines.append(f"# Overnight Run Results — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    lines.append("")
    lines.append(f"**Dataset:** 300-example CIPHER reasoning-chain SFT dataset")
    lines.append(f"**Target:** OWASP Juice Shop v17.1.1")
    lines.append(f"**Matrix:** 3 turn counts × 3 toolsets × 3 phases = 27 sessions/model")
    lines.append("")

    # Headline table
    lines.append("## Headline comparison")
    lines.append("")
    lines.append("| Model | Sessions | Findings | TP | FP | Precision | Avg TP/session |")
    lines.append("|---|---|---|---|---|---|---|")
    for name, data in runs.items():
        a = data["agg"]
        if a["sessions"] == 0:
            lines.append(f"| **{name}** | 0 | — | — | — | — | — |")
            continue
        lines.append(
            f"| **{name}** | {a['sessions']} | {a['findings']} | {a['tp']} | {a['fp']} | "
            f"{a['precision']*100:.1f}% | {a['tp']/a['sessions']:.1f} |"
        )
    lines.append("")

    # By-kind breakdown
    lines.append("## By session kind (cold / warm / chain)")
    lines.append("")
    for name, data in runs.items():
        a = data["agg"]
        if a["sessions"] == 0: continue
        lines.append(f"### {name}")
        lines.append("")
        lines.append("| Kind | Sessions | Findings | TP | FP |")
        lines.append("|---|---|---|---|---|")
        for kind in ["cold", "warm", "chain"]:
            k = a["by_kind"].get(kind, {"sessions": 0, "findings": 0, "tp": 0, "fp": 0})
            lines.append(f"| {kind} | {k['sessions']} | {k['findings']} | {k['tp']} | {k['fp']} |")
        lines.append("")

    # By-toolset breakdown
    lines.append("## By toolset (core_10 / standard_20 / full_30)")
    lines.append("")
    for name, data in runs.items():
        a = data["agg"]
        if a["sessions"] == 0: continue
        lines.append(f"### {name}")
        lines.append("")
        lines.append("| Toolset | Sessions | Findings | TP |")
        lines.append("|---|---|---|---|")
        for ts in ["core_10", "standard_20", "full_30"]:
            t = a["by_toolset"].get(ts, {"sessions": 0, "findings": 0, "tp": 0})
            lines.append(f"| {ts} | {t['sessions']} | {t['findings']} | {t['tp']} |")
        lines.append("")

    # Per-session detail table
    lines.append("## Per-session detail")
    lines.append("")
    lines.append("| Model | Kind | Toolset | Turns | TP | FP | Duration(s) |")
    lines.append("|---|---|---|---|---|---|---|")
    for name, data in runs.items():
        for r in data.get("rows", []):
            lines.append(
                f"| {name} | {r.get('kind','')} | {r.get('toolset_preset','')} | "
                f"{r.get('turn_count','')} | {r.get('true_positives','')} | "
                f"{r.get('false_positives','')} | {r.get('duration_s','')} |"
            )
    lines.append("")

    # Write
    Path(args.output).write_text("\n".join(lines))
    print(f"Report written: {args.output}")
    for name, data in runs.items():
        a = data["agg"]
        print(f"  {name}: {a.get('sessions',0)} sessions, {a.get('tp',0)} TP")


if __name__ == "__main__":
    main()
