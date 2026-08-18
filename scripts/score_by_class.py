#!/usr/bin/env python3
"""Rescore recorded runs on ONLY the classes the playbooks actually addressed.

WHY THIS EXISTS

Aggregate recall over Juice Shop's 35 ground-truth items cannot detect a
playbook effect. Measured across 12 runs, only 7 of 35 items were ever matched,
and Information Disclosure accounts for most of them — a class no playbook
targets. So the denominator is dominated by outcomes the treatment cannot
influence, and one true positive (0.0286) is larger than the entire observed
between-arm difference.

Restricting the denominator to the routed classes asks the sharper question:
of the vulnerabilities this guidance was ABOUT, how many were found?

    routed classes -> GT items      (OWASP Juice Shop)
      stored_xss   -> XSS                    4
      ssrf         -> SSRF                   1
      open_redirect-> Open Redirect          1
                                        --------
                                             6

This is a rescore of runs already recorded. It launches nothing.

CAVEAT THIS CANNOT FIX: a 6-item denominator quantises recall to 0.1667 per
finding. It sharpens WHAT is measured, not the resolution of the measurement.
"""

from __future__ import annotations

import argparse
import asyncio
import collections
import itertools
import json
import statistics as st
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Playbook class -> ground_truth.vuln_type. Declared, never inferred: a fuzzy
# match here would silently redefine the denominator and every number below it.
CLASS_TO_GT = {
    "ssrf": ("SSRF",),
    "open_redirect": ("Open Redirect",),
    "stored_xss": ("XSS",),
    "file_upload": ("File Upload",),
    "xxe": ("XXE",),
    "prototype_pollution": ("Prototype Pollution",),
}

TARGET = "http://juice-shop:3000"


async def rescore(rows: list[dict], classes: list[str]) -> dict:
    import orchestrator.database as db_mod
    from orchestrator import review as R
    from orchestrator.main import _assign_findings_to_ground_truth

    wanted = {t for c in classes for t in CLASS_TO_GT.get(c, ())}
    db = await db_mod.get_db()
    gt = [dict(r) for r in await (await db.execute(
        "SELECT target_name,target_url,vuln_type,severity,url_pattern,parameter,"
        "owasp_category FROM ground_truth")).fetchall()]
    gts = [g for g in gt if g.get("target_name") == R.match_target_name(TARGET, gt)]
    sub = [g for g in gts if g["vuln_type"] in wanted]
    if not sub:
        raise SystemExit(f"no ground truth for {sorted(wanted)} — refusing to "
                         f"report 0.0 recall over an empty denominator")

    out = collections.defaultdict(list)
    per_item = collections.defaultdict(collections.Counter)
    for r in rows:
        fs = [dict(x) for x in await (await db.execute(
            "SELECT vuln_type,severity,url,parameter FROM findings WHERE session_id=?",
            (r["session_id"],))).fetchall()]
        m = _assign_findings_to_ground_truth(fs, sub)["matched"]
        out[r["arm"]].append(len(m) / len(sub))
        for x in m:
            g = x["ground_truth"]
            per_item[r["arm"]][f"{g['vuln_type']} {g['url_pattern']}"] += 1
    await db.close()
    return {"recall": dict(out), "n_gt": len(sub), "items": sub,
            "per_item": {k: dict(v) for k, v in per_item.items()}}


def perm_p(a: list[float], b: list[float]) -> float:
    obs = abs(st.mean(a) - st.mean(b)); pool = a + b; n = len(a)
    hits = tot = 0
    for idx in itertools.combinations(range(len(pool)), n):
        g1 = [pool[i] for i in idx]
        g2 = [pool[i] for i in range(len(pool)) if i not in idx]
        tot += 1
        if abs(st.mean(g1) - st.mean(g2)) >= obs - 1e-12:
            hits += 1
    return hits / tot


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--classes", default="ssrf,open_redirect,stored_xss")
    ns = ap.parse_args()
    classes = [c.strip() for c in ns.classes.split(",") if c.strip()]

    rows = []
    for f in ns.files:
        rows += [json.loads(l) for l in Path(f).read_text().splitlines() if l.strip()]
    rows = [r for r in rows if r.get("session_id") and r.get("status") == "completed"]

    res = await rescore(rows, classes)
    print(f"CLASS-RESTRICTED SCORING — classes {classes}")
    print(f"denominator: {res['n_gt']} ground-truth items (was 35)")
    for g in res["items"]:
        print(f"    {g['vuln_type']:22s} {g['url_pattern']:24s} param={g['parameter']!r}")
    print(f"one finding = {1/res['n_gt']:.4f} recall\n")

    arms = sorted(res["recall"])
    print(f"  {'arm':14s} {'n':>2s} {'mean':>8s} {'sd':>8s} {'hits':>6s}  per-rep")
    for a in arms:
        v = res["recall"][a]
        hits = sum(1 for x in v if x > 0)
        sd = st.stdev(v) if len(v) > 1 else 0.0
        print(f"  {a:14s} {len(v):2d} {st.mean(v):8.4f} {sd:8.4f} {hits:3d}/{len(v):<2d}  "
              + " ".join(f"{x:.3f}" for x in v))
    print()
    for a, b in itertools.combinations(arms, 2):
        va, vb = res["recall"][a], res["recall"][b]
        if len(va) == len(vb):
            print(f"  {a} vs {b}: |Δ|={abs(st.mean(va)-st.mean(vb)):.4f}  p={perm_p(va,vb):.4f}")
    print("\nWHICH ITEMS WERE EVER REACHED")
    for a in arms:
        print(f"  {a:14s} {res['per_item'].get(a) or '— nothing —'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
