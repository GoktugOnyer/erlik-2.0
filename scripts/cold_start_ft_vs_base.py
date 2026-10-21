#!/usr/bin/env python3
"""Cold-start (or any session kind) unique-GT comparison: fine-tuned vs untuned.

Puts a baseline (untuned) model and a fine-tuned model side by side on ONE
session kind (default: ``cold``) and reports which covered more ground-truth
entries, which each found that the other missed, and the per-vuln hit matrix.

It answers the question the committed thesis tables cannot: *in cold starts —
the condition where a small model is most "lost" — did fine-tuning cover more,
fewer, or simply different GT entries than its baseline?* The aggregate tables
(docs/recomputed_all_experiments.csv) collapse all session kinds together, and
docs/THESIS_UNIFIED_RESULTS.md §6 records the fine-tuned per-kind split only as
raw/TP counts, leaving the cold unique-GT number unrecorded.

Nothing here re-implements the matcher. Ground-truth matching is the canonical
``_match_finding_to_ground_truth_scored`` from ``orchestrator/main.py``, reached
through ``recompute_gt_coverage.compute_gt_coverage``; the 35-entry Juice Shop
catalogue is read through ``chain_vs_cold_gt.load_gt_from_main``. The canonical
matcher returns a 0-based GT index; ids are DISPLAYED as ``index + 1`` so they
line up with docs/recomputed_gt_coverage_all.json and THESIS_UNIFIED_RESULTS.md,
which are 1-based.

Usage
-----
Two models that live in one database (distinct model tags)::

    python scripts/cold_start_ft_vs_base.py data/pentest.db \
        --base qwen2.5-coder:7b --ft qwen2.5-coder:7b-juicy3

Models in two separate databases::

    python scripts/cold_start_ft_vs_base.py \
        --base-db runs/2026-04-17_00-07-23/pentest.db --base qwen2.5-coder:7b \
        --ft-db   runs/2026-04-17_19-24-01/pentest.db --ft   qwen2.5-coder:7b-juicy3

Other kinds, or a run-specific ground truth::

    python scripts/cold_start_ft_vs_base.py data/pentest.db \
        --base qwen2.5-coder:7b --ft qwen2.5-coder:7b-juicy3 --kind chain
    ... --gt runs/2026-04-17_19-24-01/ground_truth.json

If a side's model tag is omitted and exactly one model has sessions of the
chosen kind in that database, it is used automatically; otherwise the choices
are listed and the script stops. A per-side line prints the session count and
the created_at date range so a database that bundles several campaigns under
the same base tag is visible rather than silently mixed.
"""
import argparse
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
# Canonical stats (imports the real matcher from orchestrator/main.py) and the
# shared GT loader — neither is re-implemented here.
from recompute_gt_coverage import compute_gt_coverage  # noqa: E402
from chain_vs_cold_gt import load_gt_from_main  # noqa: E402


def _connect(db_path: str) -> sqlite3.Connection:
    p = Path(db_path)
    if not p.exists():
        sys.exit(
            f"error: database not found: {db_path}\n"
            f"       drop the pentest.db there, or pass --base-db/--ft-db. "
            f"The runs/ and data/ corpora are gitignored and absent from a "
            f"clean clone."
        )
    db = sqlite3.connect(str(p))
    db.row_factory = sqlite3.Row
    return db


def _models_with_kind(db: sqlite3.Connection, kind: str) -> list[str]:
    try:
        rows = db.execute(
            "SELECT DISTINCT model FROM sessions WHERE session_type = ? "
            "AND model IS NOT NULL ORDER BY model",
            (kind,),
        ).fetchall()
    except sqlite3.OperationalError as e:
        sys.exit(f"error: cannot read sessions table ({e}). Is this an Erlik pentest.db?")
    return [r["model"] for r in rows]


def _resolve_model(db: sqlite3.Connection, kind: str, given: str | None, side: str) -> str:
    present = _models_with_kind(db, kind)
    if given:
        if given not in present:
            avail = ", ".join(present) or "(none)"
            sys.exit(
                f"error: --{side} model {given!r} has no {kind!r} sessions in its "
                f"database.\n       models with {kind!r} sessions there: {avail}"
            )
        return given
    if len(present) == 1:
        return present[0]
    if not present:
        sys.exit(f"error: no {kind!r} sessions in the --{side} database.")
    listed = "\n       ".join(present)
    sys.exit(
        f"error: --{side} database has several models with {kind!r} sessions; "
        f"pass --{side} <model>:\n       {listed}"
    )


def _slice(db: sqlite3.Connection, model: str, kind: str) -> tuple[list[dict], dict]:
    """Findings for one model on one session kind, plus a provenance summary."""
    rows = db.execute(
        """SELECT f.vuln_type, f.url, f.parameter, f.evidence
           FROM sessions s JOIN findings f ON f.session_id = s.id
           WHERE s.session_type = ? AND s.model = ?""",
        (kind, model),
    ).fetchall()
    meta = db.execute(
        """SELECT COUNT(*) n, MIN(created_at) lo, MAX(created_at) hi
           FROM sessions WHERE session_type = ? AND model = ?""",
        (kind, model),
    ).fetchone()
    return [dict(r) for r in rows], dict(meta)


def _fmt_span(meta: dict) -> str:
    lo, hi = meta.get("lo"), meta.get("hi")
    if not lo and not hi:
        return "no sessions"
    lo, hi = str(lo)[:19], str(hi)[:19]
    return f"{meta['n']} sessions, {lo} … {hi}"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("db", nargs="?", help="shared pentest.db (when both models live in one database)")
    ap.add_argument("--base-db", help="database for the baseline model (overrides the shared db)")
    ap.add_argument("--ft-db", help="database for the fine-tuned model (overrides the shared db)")
    ap.add_argument("--base", help="baseline (untuned) model tag, e.g. qwen2.5-coder:7b")
    ap.add_argument("--ft", help="fine-tuned model tag, e.g. qwen2.5-coder:7b-juicy3")
    ap.add_argument("--kind", default="cold", help="session kind to compare (default: cold)")
    ap.add_argument("--gt", default=None, help="ground_truth.json (default: 35-entry JS catalogue from main.py)")
    ap.add_argument("--json", dest="json_out", default=None, help="also write the comparison as JSON to this path")
    args = ap.parse_args()

    base_db_path = args.base_db or args.db
    ft_db_path = args.ft_db or args.db
    if not base_db_path or not ft_db_path:
        ap.error("need a database: give a positional db, or both --base-db and --ft-db")

    gt = json.load(open(args.gt)) if args.gt else load_gt_from_main()
    kind = args.kind

    base_db = _connect(base_db_path)
    ft_db = _connect(ft_db_path)
    base_model = _resolve_model(base_db, kind, args.base, "base")
    ft_model = _resolve_model(ft_db, kind, args.ft, "ft")

    base_f, base_meta = _slice(base_db, base_model, kind)
    ft_f, ft_meta = _slice(ft_db, ft_model, kind)

    base = compute_gt_coverage(base_f, gt)   # canonical matcher
    ft = compute_gt_coverage(ft_f, gt)
    base_hits = {i for i in base["gt_hit_ids"] if isinstance(i, int)}
    ft_hits = {i for i in ft["gt_hit_ids"] if isinstance(i, int)}

    both = base_hits & ft_hits
    base_only = base_hits - ft_hits
    ft_only = ft_hits - base_hits
    disp = lambda s: sorted(i + 1 for i in s)  # 0-based index -> 1-based display id

    print(f"Session kind: {kind}    Ground truth: {len(gt)} entries    "
          f"(canonical matcher; ids shown 1-based)\n")
    print(f"{'':<14} {'model':<26} {'raw':>5} {'TP':>5} {'FP':>4} {'uniqueGT':>9} {'prec%':>7}")
    print("-" * 74)
    for label, model, cov in (("BASELINE", base_model, base), ("FINE-TUNED", ft_model, ft)):
        print(f"{label:<14} {model:<26} {cov['findings']:>5} {cov['tp_findings']:>5} "
              f"{cov['fp_findings']:>4} {cov['unique_gt_hit']:>9} {cov['precision']*100:>6.1f}%")
    print(f"\n  baseline   provenance: {_fmt_span(base_meta)}")
    print(f"  fine-tuned provenance: {_fmt_span(ft_meta)}")

    # Decisive comparison on unique ground-truth coverage.
    b, f = base["unique_gt_hit"], ft["unique_gt_hit"]
    verdict = ("TIE on count" if b == f else
               f"BASELINE +{b - f}" if b > f else f"FINE-TUNED +{f - b}")
    print(f"\n=== {kind} unique-GT coverage ===")
    print(f"  baseline ...... {b}/{len(gt)}   {disp(base_hits)}")
    print(f"  fine-tuned .... {f}/{len(gt)}   {disp(ft_hits)}")
    print(f"  winner ........ {verdict}")
    print(f"  union ......... {len(base_hits | ft_hits)}/{len(gt)}   {disp(base_hits | ft_hits)}")
    print(f"  FT found, baseline missed: {disp(ft_only)}  ({len(ft_only)})")
    print(f"  baseline found, FT missed: {disp(base_only)}  ({len(base_only)})")
    print(f"  both found ..............: {disp(both)}  ({len(both)})")

    # Per-vuln matrix over the union of what either caught in this kind.
    union = base_hits | ft_hits
    if union:
        print(f"\n=== per-vuln hit matrix ({kind}) ===")
        print(f"{'id':>3}  {'vuln_type':<28} {'base':^6} {'ft':^6}")
        mark = lambda idx, s: "  ✓  " if idx in s else "  ·  "
        for idx in sorted(union):
            vt = (gt[idx].get("vuln_type", "?") if idx < len(gt) else "?")[:28]
            print(f"{idx + 1:>3}  {vt:<28} {mark(idx, base_hits)} {mark(idx, ft_hits)}")

    if args.json_out:
        out = {
            "kind": kind, "gt_total": len(gt),
            "baseline": {"model": base_model, "provenance": _fmt_span(base_meta), **base,
                         "gt_hit_ids_1based": disp(base_hits)},
            "fine_tuned": {"model": ft_model, "provenance": _fmt_span(ft_meta), **ft,
                           "gt_hit_ids_1based": disp(ft_hits)},
            "ft_found_baseline_missed_1based": disp(ft_only),
            "baseline_found_ft_missed_1based": disp(base_only),
            "both_1based": disp(both),
            "union_1based": disp(union),
            "verdict": verdict,
        }
        Path(args.json_out).write_text(json.dumps(out, indent=2, default=str))
        print(f"\nSaved -> {args.json_out}")


if __name__ == "__main__":
    main()
