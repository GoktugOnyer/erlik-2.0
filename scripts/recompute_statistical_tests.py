#!/usr/bin/env python3
"""Regenerate docs/statistical_tests.json — the significance tests for the
primary Apr 17 baseline-7B vs FT-v3-7B comparison.

Until this script existed, statistical_tests.json was the one pinned artefact in
docs/REPRODUCIBILITY.md with no tracked producer: its hash proved the file was
unmodified but nothing could regenerate it. This closes that gap.

Provenance of each test
----------------------
Two of the three tests are recomputed entirely from repository-tracked data and
are therefore verifiable from a clean clone:

  mcnemar_per_gt      Paired per-ground-truth-entry comparison. Reads the
                      gt_hit_ids sets from docs/recomputed_gt_coverage.json
                      (itself produced by scripts/recompute_gt_coverage.py).
                      Exact binomial test on the discordant pairs.

  fisher_per_category Per-vulnerability-class 2x2 tables, built by mapping GT
                      ids onto JUICE_SHOP_GROUND_TRUTH in orchestrator/main.py.
                      Fisher exact, then Benjamini-Hochberg across the classes.

The third cannot be:

  wilcoxon_per_session  Needs the per-session findings vector, which lives only
                      in runs/*/pentest.db. runs/ and data/ are excluded by
                      .gitignore, so a clean clone has no way to recompute it.
                      Supply the pairs with --wilcoxon-pairs, or the script
                      carries the committed values forward and says so.

GT ids are 1-based indices into JUICE_SHOP_GROUND_TRUTH; this is what
recompute_gt_coverage.py emits and is verified by --check.

Usage
-----
  python3 scripts/recompute_statistical_tests.py            # rewrite the file
  python3 scripts/recompute_statistical_tests.py --check    # verify, write nothing
  python3 scripts/recompute_statistical_tests.py --wilcoxon-pairs pairs.json

pairs.json is {"baseline": [...], "ftv3": [...]} — two equal-length arrays of
per-session finding counts, paired by matrix cell.

Requires scipy.
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path

try:
    from scipy.stats import binomtest, fisher_exact, wilcoxon
except ImportError:  # pragma: no cover
    sys.exit("scipy is required: pip install scipy")

REPO = Path(__file__).resolve().parent.parent
MAIN_PY = REPO / "orchestrator" / "main.py"
COVERAGE = REPO / "docs" / "recomputed_gt_coverage.json"
OUT = REPO / "docs" / "statistical_tests.json"

PRIMARY = "Apr17 baseline 7B vs FT-v3 7B"
ALPHA = 0.05
BASELINE_KEY = "baseline_7b_apr17"
FTV3_KEY = "ft_v3_7b_apr17"


def load_ground_truth() -> list[dict]:
    """Parse JUICE_SHOP_GROUND_TRUTH out of main.py without importing it.

    Importing orchestrator.main would pull in FastAPI and open a database; the
    catalogue is a plain literal, so read it directly.
    """
    lines = MAIN_PY.read_text().splitlines()
    start = next(i for i, l in enumerate(lines)
                 if l.startswith("JUICE_SHOP_GROUND_TRUTH = ["))
    depth, buf = 0, []
    for line in lines[start:]:
        buf.append(line)
        depth += line.count("[") - line.count("]")
        if depth == 0 and len(buf) > 1:
            break
    return ast.literal_eval("\n".join(buf).split("=", 1)[1].strip())


def benjamini_hochberg(pvals: list[float]) -> list[float]:
    """BH step-up adjusted p-values, enforcing monotonicity and capping at 1."""
    n = len(pvals)
    order = sorted(range(n), key=lambda i: pvals[i])
    adjusted = [0.0] * n
    prev = 1.0
    for rank, idx in enumerate(reversed(order), start=1):
        i = n - rank + 1  # original ascending rank of this element
        val = min(prev, pvals[idx] * n / i)
        adjusted[idx] = min(val, 1.0)
        prev = adjusted[idx]
    return adjusted


def mcnemar(baseline: set[int], ftv3: set[int], gt_total: int) -> dict:
    both = len(baseline & ftv3)
    b_only = len(baseline - ftv3)
    f_only = len(ftv3 - baseline)
    neither = gt_total - len(baseline | ftv3)

    discordant = b_only + f_only
    # Exact binomial on the discordant pairs; with none, there is nothing to test.
    p = binomtest(min(b_only, f_only), discordant, 0.5).pvalue if discordant else 1.0
    return {
        "both": both,
        "baseline_only": b_only,
        "ftv3_only": f_only,
        "neither": neither,
        "p_exact": p,
        "verdict": "significant" if p < ALPHA else "not significant",
    }


def fisher_per_category(gt: list[dict], baseline: set[int], ftv3: set[int]) -> list[dict]:
    cats: dict[str, dict] = {}
    for idx, entry in enumerate(gt, start=1):
        c = cats.setdefault(entry["vuln_type"],
                            {"n_gt": 0, "baseline_hits": 0, "ftv3_hits": 0})
        c["n_gt"] += 1
        if idx in baseline:
            c["baseline_hits"] += 1
        if idx in ftv3:
            c["ftv3_hits"] += 1

    rows = []
    for name in sorted(cats):
        c = cats[name]
        n, bh, fh = c["n_gt"], c["baseline_hits"], c["ftv3_hits"]
        # hit / miss for each arm, over the entries in this class
        _, p = fisher_exact([[bh, n - bh], [fh, n - fh]])
        rows.append({"category": name, **c, "p_raw": p})

    for row, p_bh in zip(rows, benjamini_hochberg([r["p_raw"] for r in rows])):
        row["p_bh"] = p_bh
        row["significant_bh"] = bool(p_bh < ALPHA)
    return rows


def wilcoxon_section(pairs_path: str | None) -> tuple[dict, bool]:
    """Return (section, recomputed). Falls back to the committed values."""
    if pairs_path:
        data = json.loads(Path(pairs_path).read_text())
        base, ft = data["baseline"], data["ftv3"]
        if len(base) != len(ft):
            sys.exit("--wilcoxon-pairs: 'baseline' and 'ftv3' must be equal length")
        stat, p = wilcoxon(base, ft)
        return {
            "n_pairs": len(base),
            "baseline_mean": sum(base) / len(base),
            "ftv3_mean": sum(ft) / len(ft),
            "W": float(stat),
            "p": float(p),
            "verdict": "significant" if p < ALPHA else "not significant",
        }, True

    if not OUT.exists():
        sys.exit("no --wilcoxon-pairs and no existing statistical_tests.json to "
                 "carry forward; the per-session vector lives only in runs/*/pentest.db")
    return json.loads(OUT.read_text())["wilcoxon_per_session"], False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true",
                    help="recompute and compare against the committed file; write nothing")
    ap.add_argument("--wilcoxon-pairs", metavar="FILE",
                    help='JSON {"baseline": [...], "ftv3": [...]} of per-session counts')
    args = ap.parse_args()

    gt = load_ground_truth()
    coverage = json.loads(COVERAGE.read_text())["results"]
    baseline = set(coverage[BASELINE_KEY]["gt_hit_ids"])
    ftv3 = set(coverage[FTV3_KEY]["gt_hit_ids"])

    print(f"ground truth      : {len(gt)} Juice Shop entries")
    print(f"baseline hits     : {len(baseline)}/{len(gt)}")
    print(f"FT-v3 hits        : {len(ftv3)}/{len(gt)}")

    wilcox, recomputed = wilcoxon_section(args.wilcoxon_pairs)
    if not recomputed:
        print("wilcoxon          : CARRIED FORWARD (per-session data absent; "
              "runs/ is gitignored) -- pass --wilcoxon-pairs to recompute")

    result = {
        "primary_comparison": PRIMARY,
        "alpha": ALPHA,
        "mcnemar_per_gt": mcnemar(baseline, ftv3, len(gt)),
        "wilcoxon_per_session": wilcox,
        "fisher_per_category_bh": fisher_per_category(gt, baseline, ftv3),
    }
    # Match the committed file exactly: indent=2, no trailing newline.
    serialised = json.dumps(result, indent=2)

    if args.check:
        if not OUT.exists():
            print(f"\nFAIL: {OUT} does not exist")
            return 1
        if OUT.read_text() == serialised:
            print("\nOK: regenerated output is byte-identical to the committed file")
            return 0
        print("\nFAIL: regenerated output differs from the committed file")
        return 1

    OUT.write_text(serialised)
    print(f"\nwrote {OUT.relative_to(REPO)} ({len(serialised)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
