"""Plan a whole-catalogue deterministic run against one target.

WHY A PLAN IS A SEPARATE STEP

A test case pointed at the wrong endpoint does not merely miss — it produces a
confident wrong answer. WSTG-INPV-19 (SSRF) was run against
`/rest/products/search`, which takes a search term rather than a URL, and duly
recorded "SSRF (suspected)" there. Nothing in the output said the target was
implausible.

So planning is separated from running and is a pure function: it answers "what
would run, where, and what would be skipped and why" without touching the
network. The UI shows the plan before anything executes, and a case whose
required inputs cannot be supplied is reported as a NAMED SKIP rather than
silently dropped — a missing case reads as "the lane found nothing here", which
is the same failure this module exists to prevent.

This is the single source of truth for sweep targeting: both
`scripts/deterministic_sweep.py` and the `/api/v2/sweep/plan` endpoint import
from here, so the CLI and the dashboard cannot drift apart.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

# Per-target endpoint knowledge. Same principle as playbook_catalog: facts about
# a specific application live in a named profile and are never inferred from a
# URL. Milestone B moves these into engagement_targets so an operator can enter
# them for their own customer instead of editing Python.
PROFILES: dict[str, dict[str, dict[str, str]]] = {
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

# Required inputs this sweep cannot synthesise, each with the reason shown to
# the operator. Two of these disappear once milestone D (authentication) lands.
UNSUPPLIABLE: dict[str, str] = {
    "low_priv_token": "needs two authenticated accounts",
    "high_priv_token": "needs two authenticated accounts",
    "request_template": "needs a hand-written request template",
    "success_marker": "needs a hand-written success marker",
    "jwt": "needs a captured JWT",
}


def available_profiles() -> list[str]:
    return sorted(PROFILES)


def build_target(case: dict[str, Any], base: str,
                 profile: dict[str, dict[str, str]] | None = None,
                 extra: dict[str, Any] | None = None) -> tuple[dict | None, str]:
    """(target, skip_reason). target is None exactly when skip_reason is set."""
    profile = profile or {}
    schema = case.get("target_schema") or {}
    req = schema.get("required") or []
    for r in req:
        if r in UNSUPPLIABLE and not (extra or {}).get(r):
            return None, UNSUPPLIABLE[r]

    base = (base or "").rstrip("/")
    over = {k: (v.replace("{base}", base) if isinstance(v, str) else v)
            for k, v in (profile.get(case.get("id", "")) or {}).items()}
    over.update({k: v for k, v in (extra or {}).items() if v not in (None, "")})

    p = urlparse(base)
    host = p.hostname or ""
    port = p.port or (443 if p.scheme == "https" else 80)
    defaults = {"url": base, "host": host, "port": port,
                "login_url": f"{base}/login", "parameter": "q",
                "url_template": base}

    tgt: dict[str, Any] = {}
    for r in req:
        tgt[r] = over.get(r, defaults.get(r))
        if tgt[r] in (None, ""):
            return None, f"no value for required field {r!r}"
    for o in schema.get("optional") or []:
        if o in over:
            tgt[o] = over[o]
    tgt.setdefault("host", host)
    # Scope travels WITH the target. The runner enforces it, so a plan that
    # omitted it would hand the executor a case with no boundary.
    tgt["scope"] = {"allow_hosts": [host], "allow_ports": [port]}
    return tgt, ""


def plan_sweep(cases: list[dict[str, Any]], base: str, profile_name: str = "",
               only: list[str] | None = None,
               extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """What a sweep WOULD do. Pure — no network, no database, no execution."""
    profile = PROFILES.get(profile_name or "", {})
    wanted = set(only or [])
    runnable, skipped = [], []
    for case in cases:
        if wanted and case.get("id") not in wanted:
            continue
        tgt, why = build_target(case, base, profile, extra)
        entry = {"id": case.get("id"), "name": case.get("name"),
                 "category": case.get("category"), "severity": case.get("severity"),
                 "required": (case.get("target_schema") or {}).get("required") or [],
                 "optional": (case.get("target_schema") or {}).get("optional") or []}
        if tgt is None:
            skipped.append({**entry, "reason": why})
        else:
            runnable.append({**entry, "target": tgt,
                             "where": tgt.get("url") or tgt.get("login_url")
                                      or tgt.get("host")})
    return {"base": (base or "").rstrip("/"), "profile": profile_name or None,
            "runnable": runnable, "skipped": skipped,
            "counts": {"runnable": len(runnable), "skipped": len(skipped),
                       "total": len(runnable) + len(skipped)}}
