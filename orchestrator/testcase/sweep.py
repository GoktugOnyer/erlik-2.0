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
    # These become suppliable once credentials are stored and a session has
    # been VERIFIED — see orchestrator/credentials.auth_inputs, whose values
    # arrive through `extra` and clear the skip. Unverified is not enough: a
    # case that runs unauthenticated while claiming otherwise is a false
    # negative with extra steps.
    "low_priv_token": "needs two authenticated accounts "
                      "(store low- and high-privilege credentials for this target)",
    "high_priv_token": "needs two authenticated accounts "
                       "(store low- and high-privilege credentials for this target)",
    "request_template": "needs a hand-written request template",
    "success_marker": "needs a hand-written success marker",
    "jwt": "needs a captured JWT (log in with a stored credential first)",
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

    # DERIVED from the target the operator gave us. These are facts, not
    # guesses: the base URL is the base URL.
    derived = {"url": base, "host": host, "port": port, "url_template": base}

    # GUESSES. A parameter named "q" and a login form at /login are inventions
    # that happen to be true on some applications and false on most.
    #
    # They used to sit in the same dict as the derived values, which quietly
    # defeated the skip logic this module exists for: because the default
    # SUPPLIED a value, a case requiring `parameter` never hit the
    # "no value for required field" branch. On any target without a profile the
    # SSRF, XSS, SQLi and open-redirect cases all ran against the bare base URL
    # with ?q= and reported "no finding" — 22 confident negative verdicts, most
    # of which assessed nothing. That is a precision failure, and precision is
    # what a client deliverable is made of.
    #
    # A guess may still FILL a field the operator or a profile did not name, but
    # it can never SATISFY a required one. Required means "this case cannot be
    # run without knowing this", and inventing the answer does not make it known.
    guessed = {"parameter": "q", "login_url": f"{base}/login"}
    GUESS_REASON = {
        "parameter": "needs a parameter name; none known for this target "
                     "(supply one, add a target profile, or run discovery first)",
        "login_url": "needs the login URL; none known for this target "
                     "(supply one or add a target profile)",
    }

    tgt: dict[str, Any] = {}
    for r in req:
        if r in over:
            tgt[r] = over[r]
        elif r in derived:
            tgt[r] = derived[r]
        elif r in guessed:
            return None, GUESS_REASON.get(r, f"no known value for {r!r}; refusing to guess")
        else:
            return None, f"no value for required field {r!r}"
        if tgt[r] in (None, ""):
            return None, f"no value for required field {r!r}"
    for o in schema.get("optional") or []:
        if o in over:
            tgt[o] = over[o]
    tgt.setdefault("host", host)
    # Every rendered value is checked, not just the host. The scope object below
    # constrains WHICH HOST may be contacted; it says nothing about the other
    # fields, and those are substituted into `bash -c '...'` command templates.
    from orchestrator.engagement import looks_injectable
    for k, v in tgt.items():
        if isinstance(v, str):
            bad = looks_injectable(v)
            if bad:
                return None, f"target field {k!r} {bad}"
    # Scope travels WITH the target. The runner enforces it, so a plan that
    # omitted it would hand the executor a case with no boundary.
    tgt["scope"] = {"allow_hosts": [host], "allow_ports": [port]}
    return tgt, ""


# One case fanned over a hundred discovered endpoints is a hundred runs. The
# cap bounds a plan; the entries it drops are visible because the plan reports
# how many values it fanned over.
MAX_FAN_OUT = 25


def _entry(case: dict[str, Any]) -> dict[str, Any]:
    """The shape a plan row shares whether or not it was fanned out."""
    return {"id": case.get("id"), "name": case.get("name"),
            "category": case.get("category"), "severity": case.get("severity"),
            "required": (case.get("target_schema") or {}).get("required") or [],
            "optional": (case.get("target_schema") or {}).get("optional") or []}


def plan_sweep(cases: list[dict[str, Any]], base: str, profile_name: str = "",
               only: list[str] | None = None,
               extra: dict[str, Any] | None = None,
               discovered: dict[str, list[str]] | None = None) -> dict[str, Any]:
    """What a sweep WOULD do. Pure — no network, no database, no execution.

    `discovered` is what earlier runs found for this target, shaped
    {field: [values]} — see testcase.endpoints.as_sweep_inputs. It fans a case
    out over real endpoints instead of running it once against the base URL,
    and it can SATISFY a required field that would otherwise be a named skip.
    Discovery is knowledge about this specific target; a default was a guess,
    which is why one may fill a required field and the other may not.

    With nothing discovered the plan is byte-identical to before.
    """
    profile = PROFILES.get(profile_name or "", {})
    wanted = set(only or [])
    discovered = {k: v for k, v in (discovered or {}).items() if v}
    runnable, skipped = [], []
    for case in cases:
        if wanted and case.get("id") not in wanted:
            continue
        req = (case.get("target_schema") or {}).get("required") or []
        fan_field = next(
            (f for f in ("url", "parameter") if f in req and f in discovered), None)
        if fan_field:
            # The discovered values are ADDITIONAL targets, not replacements.
            # Fanning over them alone traded "test the site root" for "test
            # /ftp" — one discovered path silently removed the base URL from
            # the plan, which is a coverage regression wearing the costume of a
            # feature. `url` has a legitimate default (the base), so it leads;
            # `parameter` has none, which is the whole point of refusing to
            # invent one.
            values = list(discovered[fan_field])
            if fan_field == "url" and base not in values:
                values.insert(0, base)
            entries, reason = [], ""
            for value in values[:MAX_FAN_OUT]:
                t, w = build_target(case, base, profile,
                                    {**(extra or {}), fan_field: value})
                if t is None:
                    reason = w
                    break
                entries.append((t, value))
            if entries:
                for t, value in entries:
                    runnable.append({**_entry(case), "target": t,
                                     "where": t.get("url") or t.get("login_url")
                                              or t.get("host"),
                                     "discovered": {fan_field: value}})
                continue
            if reason:
                skipped.append({**_entry(case), "reason": reason})
                continue
        tgt, why = build_target(case, base, profile, extra)
        entry = _entry(case)
        if tgt is None:
            skipped.append({**entry, "reason": why})
        else:
            runnable.append({**entry, "target": tgt,
                             "where": tgt.get("url") or tgt.get("login_url")
                                      or tgt.get("host")})
    return {"base": (base or "").rstrip("/"), "profile": profile_name or None,
            "runnable": runnable, "skipped": skipped,
            "counts": {"runnable": len(runnable), "skipped": len(skipped),
                       # `total` counts PLAN ENTRIES, and fanning one case over
                       # three endpoints makes three. `cases` counts distinct
                       # test cases, which is what "did every case get a
                       # verdict?" needs — the two diverge the moment discovery
                       # is used, and conflating them would hide a dropped case
                       # behind a larger number.
                       "total": len(runnable) + len(skipped),
                       "cases": len({e["id"] for e in runnable}
                                    | {e["id"] for e in skipped})}}
