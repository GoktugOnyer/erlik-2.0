#!/usr/bin/env python3
"""Split unique-GT coverage by SESSION TYPE (cold / warm / chain) for one run.

Answers the question the aggregate tables cannot: *does a chain find vulns a
cold start does NOT, or does it just re-find the same ones more often?*

Coverage per type is a SET of ground-truth ids (canonical matcher, threshold
>=2.0), so duplicates within a type collapse to one — the comparison is on
genuinely distinct vulns, not raw finding counts.

Usage:
    python scripts/chain_vs_cold_gt.py <pentest.db> [--model qwen2.5-coder:7b] \
        [--gt runs/<dir>/ground_truth.json]

If --gt is omitted, the 35-entry Juice Shop catalogue hardcoded in
orchestrator/main.py is used.
"""
import argparse
import json
import re
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from recompute_gt_coverage import match_finding  # canonical scored matcher


def load_gt_from_main() -> list:
    src = (Path(__file__).parent.parent / "orchestrator" / "main.py").read_text()
    m = re.search(r"JUICE_SHOP_GROUND_TRUTH\s*=\s*\[(.*?)\n\]", src, re.S)
    entries = re.findall(r"\{[^{}]*?\}", m.group(1), re.S)
    gt = []
    for i, e in enumerate(entries, 1):
        vt = re.search(r'"vuln_type"\s*:\s*"([^"]+)"', e)
        url = re.search(r'"url_pattern"\s*:\s*"([^"]*)"', e)
        par = re.search(r'"parameter"\s*:\s*"([^"]*)"', e)
        gt.append({"id": i, "vuln_type": vt.group(1) if vt else "?",
                   "url_pattern": url.group(1) if url else "",
                   "parameter": par.group(1) if par else ""})
    return gt


def coverage_ids(findings: list, gt: list) -> set:
    hits = set()
    for f in findings:
        r = match_finding(dict(f), gt)
        if r["match"] and r["gt_id"] is not None:
            hits.add(r["gt_id"])
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("db")
    ap.add_argument("--model", default=None, help="filter to one model")
    ap.add_argument("--gt", default=None, help="ground_truth.json (default: JS catalogue)")
    args = ap.parse_args()

    gt = json.load(open(args.gt)) if args.gt else load_gt_from_main()
    for i, g in enumerate(gt, 1):
        g.setdefault("id", i)
    gt_by_id = {g["id"]: g for g in gt}

    db = sqlite3.connect(args.db)
    db.row_factory = sqlite3.Row

    where = "WHERE s.session_type IS NOT NULL"
    params = []
    if args.model:
        where += " AND s.model = ?"
        params.append(args.model)

    rows = db.execute(
        f"""SELECT s.session_type st, f.vuln_type, f.url, f.parameter, f.evidence
            FROM sessions s JOIN findings f ON f.session_id = s.id {where}""",
        params).fetchall()

    by_type = defaultdict(list)
    for r in rows:
        by_type[r["st"]].append(dict(r))

    ids = {t: coverage_ids(fs, gt) for t, fs in by_type.items()}
    cold = ids.get("cold", set())
    warm = ids.get("warm", set())
    chain = ids.get("chain", set())

    print(f"DB: {args.db}   model: {args.model or 'ALL'}   GT: {len(gt)} entries\n")
    print(f"{'type':<8} {'raw findings':>13} {'unique GT':>10}")
    for t in ("cold", "warm", "chain"):
        print(f"{t:<8} {len(by_type.get(t, [])):>13} {len(ids.get(t, set())):>10}")

    print("\n=== Per-vuln: which session type caught it ===")
    print(f"{'#':>2} {'vuln':<26} cold warm chain")
    allhit = cold | warm | chain
    for gid in sorted(allhit):
        g = gt_by_id[gid]
        c = lambda s: " ✓ " if gid in s else " · "
        print(f"{gid:>2} {g['vuln_type'][:26]:<26}{c(cold)} {c(warm)} {c(chain)}")

    print("\n=== The decisive comparison ===")
    print(f"cold unique GT ......... {sorted(cold)}  ({len(cold)})")
    print(f"chain unique GT ........ {sorted(chain)}  ({len(chain)})")
    print(f"CHAIN found, COLD missed {sorted(chain - cold)}  ({len(chain - cold)})  <-- chain's real added value")
    print(f"COLD found, CHAIN missed {sorted(cold - chain)}  ({len(cold - chain)})")
    print(f"both ................... {sorted(cold & chain)}  ({len(cold & chain)})")
    if chain and cold:
        overlap = len(cold & chain) / len(chain) * 100
        print(f"\n{overlap:.0f}% of chain's vulns were ALSO found by cold.")
        if not (chain - cold):
            print("=> chain found ZERO vulns cold missed: its advantage is repetition, not reach.")
        else:
            print(f"=> chain reached {len(chain - cold)} vuln(s) cold never did: genuine added coverage.")


if __name__ == "__main__":
    main()
