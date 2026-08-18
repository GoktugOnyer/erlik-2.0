#!/usr/bin/env python3
"""Run the whole WSTG catalogue against one target, deterministically.

This is the lane that produces facts without a model deciding what to try, and
whose results the handoff (orchestrator/handoff.py) hands to the agent as a
starting point.

TARGETING MATTERS MORE THAN COVERAGE. A case pointed at the wrong endpoint does
not merely miss — it produces a confident wrong answer. The SSRF case had been
run against `/rest/products/search`, which takes a search term and not a URL,
and it recorded "SSRF (suspected — LLM judged)" there. Juice Shop's actual SSRF
is `/profile/image/url?imageUrl=`. So endpoints come from a per-target profile,
and any case whose required inputs cannot be supplied is SKIPPED OUT LOUD
rather than run against a default that cannot exercise it.

Usage:
    python scripts/deterministic_sweep.py --target http://juice-shop:3000 \
        --profile juiceshop [--only WSTG-INPV-19,WSTG-CLNT-04]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

API = "http://127.0.0.1:8002"

# Targeting lives in orchestrator/testcase/sweep.py so this CLI and the
# dashboard's /api/v2/sweep/plan endpoint cannot drift apart. A second copy of
# the endpoint map is exactly how one of them ends up aiming a case at a
# parameter that cannot exercise it.
from orchestrator.testcase.sweep import PROFILES, UNSUPPLIABLE, build_target  # noqa: E402


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--profile", default="")
    ap.add_argument("--only", default="")
    ap.add_argument("--model", default="qwen2.5-coder:7b")
    ns = ap.parse_args()
    base = ns.target.rstrip("/")
    profile = PROFILES.get(ns.profile, {})
    only = {x.strip() for x in ns.only.split(",") if x.strip()}

    async with httpx.AsyncClient(timeout=600.0) as c:
        cases = (await c.get(f"{API}/api/v2/testcases")).json()["test_cases"]
        if only:
            cases = [x for x in cases if x["id"] in only]
        print(f"{len(cases)} case(s) vs {base}  profile={ns.profile or 'none'}\n")
        ran = skipped = total_f = 0
        for case in cases:
            tgt, why = build_target(case, base, profile)
            if tgt is None:
                skipped += 1
                print(f"  SKIP  {case['id']:16s} — {why}", flush=True)
                continue
            try:
                r = await c.post(f"{API}/api/v2/testcases/{case['id']}/run",
                                 json={"target": tgt, "model": ns.model})
                if r.status_code != 200:
                    print(f"  ERR   {case['id']:16s} — {r.status_code} {r.text[:90]}", flush=True)
                    continue
                d = r.json()
                fs = d.get("findings") or []
                ran += 1; total_f += len(fs)
                where = tgt.get("url") or tgt.get("login_url") or tgt.get("host")
                print(f"  {'HIT ' if fs else 'ok  '} {case['id']:16s} "
                      f"findings={len(fs):2d}  {str(where)[:56]}", flush=True)
                for f in fs:
                    print(f"          → {f.get('vuln_type')} [{f.get('severity')}]", flush=True)
            except Exception as e:  # noqa: BLE001
                print(f"  ERR   {case['id']:16s} — {type(e).__name__}: {e}"[:140], flush=True)
        print(f"\nran={ran} skipped={skipped} findings={total_f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
