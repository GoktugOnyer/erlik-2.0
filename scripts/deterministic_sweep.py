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

# Per-target endpoint knowledge. Same idea as playbook_catalog: target-specific
# facts live in a named profile, never guessed from the URL.
PROFILES: dict[str, dict[str, dict]] = {
    "juiceshop": {
        "WSTG-CLNT-04":   {"url": "{base}/redirect", "parameter": "to"},
        "WSTG-INPV-19":   {"url": "{base}/profile/image/url", "parameter": "imageUrl"},
        "WSTG-INPV-01":   {"url": "{base}/rest/products/search", "parameter": "q"},
        "WSTG-INPV-05":   {"url": "{base}/rest/products/search", "parameter": "q"},
        "WSTG-INPV-05.6": {"url": "{base}/rest/user/login", "parameter": "email"},
        "WSTG-INPV-06":   {"url": "{base}/rest/user/login", "parameter": "email"},
        "WSTG-ERRH-01":   {"url": "{base}/rest/products/search", "parameter": "q"},
        "WSTG-ATHN-01":   {"login_url": "{base}/rest/user/login"},
        "WSTG-CONF-04":   {"url": "{base}"},
        "WSTG-CONF-02":   {"url": "{base}"},
    },
}

# Requirements this sweep cannot synthesise. Named with the reason, because a
# silently missing case reads as "the lane found nothing here".
UNSUPPLIABLE = {
    "low_priv_token": "needs two authenticated accounts",
    "high_priv_token": "needs two authenticated accounts",
    "request_template": "needs a hand-written request template",
    "success_marker": "needs a hand-written success marker",
    "jwt": "needs a captured JWT",
}


def build_target(case: dict, base: str, profile: dict) -> tuple[dict | None, str]:
    req = (case.get("target_schema") or {}).get("required") or []
    for r in req:
        if r in UNSUPPLIABLE:
            return None, UNSUPPLIABLE[r]
    over = {k: v.replace("{base}", base) if isinstance(v, str) else v
            for k, v in (profile.get(case["id"]) or {}).items()}
    host = urlparse(base).hostname or ""
    port = urlparse(base).port or 80
    defaults = {"url": base, "host": host, "port": port,
                "login_url": f"{base}/login", "parameter": "q",
                "url_template": base}
    tgt = {}
    for r in req:
        tgt[r] = over.get(r, defaults.get(r))
        if tgt[r] is None:
            return None, f"no value for required field {r!r}"
    for o in (case.get("target_schema") or {}).get("optional") or []:
        if o in over:
            tgt[o] = over[o]
        elif o == "parameter" and "parameter" in over:
            tgt[o] = over["parameter"]
    tgt.setdefault("host", host)
    tgt["scope"] = {"allow_hosts": [host], "allow_ports": [port]}
    return tgt, ""


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
