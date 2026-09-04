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
    # DVWA. Added after a full sweep against it returned four findings at
    # security=low and the SAME four at security=impossible — every one of them
    # infrastructure (phpinfo, server banner, robots.txt), none affected by the
    # security level. The lane was testing http://dvwa, and DVWA's
    # vulnerabilities all live under /vulnerabilities/<module>/. It was not
    # finding nothing; it was never reaching anything.
    #
    # This is the endpoint-reaching bottleneck measured in the agent lane,
    # arrived at from the deterministic side: the cases were correct and the
    # targeting was not.
    "dvwa": {
        # `Submit` for the same reason `Upload` is on BUSL-09 below: DVWA runs
        # the query only when isset($_GET['Submit']), so without it the page
        # renders and the database is never touched — which reads as CLEAN.
        "WSTG-INPV-05":   {"url": "{base}/vulnerabilities/sqli/", "parameter": "id",
                           "submit": "Submit=Submit"},
        "WSTG-INPV-01":   {"url": "{base}/vulnerabilities/xss_r/", "parameter": "name"},
        "WSTG-INPV-11.2": {"url": "{base}/vulnerabilities/exec/", "parameter": "ip"},
        # INPV-15 is Hop-by-Hop Header Handling and its schema requires only
        # `url` — it declares no optional fields, so the `parameter: "page"`
        # that used to sit here was silently discarded. Dead knowledge in a
        # profile reads as coverage and is not.
        "WSTG-INPV-15":   {"url": "{base}/vulnerabilities/fi/"},
        # The `page` parameter belongs to the case that can actually use it.
        # DVWA's file-inclusion module runs with allow_url_include=On, so it
        # fetches whatever URL it is given — `file:///etc/passwd` comes back in
        # full. Verified to track the security level: disclosed at low, medium
        # and high, blocked at impossible.
        "WSTG-INPV-19":   {"url": "{base}/vulnerabilities/fi/", "parameter": "page"},
        # Same sink, different class. The parameter takes a local PATH as well
        # as a remote URL, and the two need different fixes, so both cases run.
        "WSTG-AUTHZ-01":  {"url": "{base}/vulnerabilities/fi/", "parameter": "page"},
        "WSTG-CLNT-04":   {"url": "{base}/vulnerabilities/open_redirect/",
                           "parameter": "redirect"},
        # No `submit` here, unlike INPV-05. ERRH-01 provokes errors with
        # MALFORMED PATHS (`{url}/%ff%fe`), not with a query the SQLi handler
        # gates on — so a submit token would be a field its schema discards.
        # It was added here speculatively and the profile guard caught it.
        "WSTG-ERRH-01":   {"url": "{base}/vulnerabilities/sqli/", "parameter": "id"},
        "WSTG-ATHN-01":   {"login_url": "{base}/login.php"},
        # `uploaded` and the `Upload` button are not decoration: DVWA gates the
        # whole handler on isset($_POST['Upload']), and a POST with the wrong
        # field name renders the page normally — which reads as CLEAN.
        "WSTG-BUSL-09":   {"url": "{base}/vulnerabilities/upload/",
                           "parameter": "uploaded", "submit": "Upload=Upload"},
        "WSTG-CONF-02":   {"url": "{base}"},
        "WSTG-CONF-04":   {"url": "{base}"},
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
    # Same requirement, different material. A case may accept either via
    # `required_any`, and the operator-facing message must not change with
    # which one happens to be missing.
    "low_priv_cookie": "needs two authenticated accounts "
                       "(store low- and high-privilege credentials for this target)",
    "high_priv_cookie": "needs two authenticated accounts "
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
    # Each group is satisfied by ANY member — see TargetSchema.required_any.
    req_any = [list(g) for g in (schema.get("required_any") or []) if g]
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
    # Alternation first, so a group that cannot be satisfied names ALL the
    # fields that would have satisfied it rather than the first one tried.
    for group in req_any:
        chosen = next((f for f in group
                       if (over.get(f) or derived.get(f)) not in (None, "")), None)
        if chosen is None:
            reasons = [UNSUPPLIABLE[f] for f in group if f in UNSUPPLIABLE]
            return None, (reasons[0] if reasons else
                          f"needs one of: {', '.join(group)}")
        tgt[chosen] = over.get(chosen, derived.get(chosen))
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
        if o in over and o not in tgt:
            tgt[o] = over[o]
    # Every OTHER member of a satisfied group is offered too when it exists, so
    # a command written for both shapes can pick whichever it was given.
    for group in req_any:
        for f in group:
            if f not in tgt and over.get(f) not in (None, ""):
                tgt[f] = over[f]
    tgt.setdefault("host", host)
    # Every rendered value is checked, not just the host. The scope object below
    # constrains WHICH HOST may be contacted; it says nothing about the other
    # fields, and those are substituted into `bash -c '...'` command templates.
    from orchestrator.engagement import looks_injectable
    for k, v in tgt.items():
        # `if isinstance(v, str)` let EVERY non-string value past the gate
        # untouched, and the runner stringifies whatever it is into the command
        # template — so a list value carried its contents through verbatim.
        # Harmless while profiles were Python source written by us; not
        # harmless the moment this knowledge becomes data an operator types.
        if isinstance(v, bool) or v is None:
            return None, f"target field {k!r} must be text or a number"
        if isinstance(v, (int, float)):
            continue                       # port, parallel_n — no shell surface
        if not isinstance(v, str):
            return None, (f"target field {k!r} must be text, not "
                          f"{type(v).__name__}")
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
               discovered: dict[str, list[str]] | None = None,
               declared: dict[str, dict[str, str]] | None = None) -> dict[str, Any]:
    """What a sweep WOULD do. Pure — no network, no database, no execution.

    `discovered` is what earlier runs found for this target, shaped
    {field: [values]} — see testcase.endpoints.as_sweep_inputs. It fans a case
    out over real endpoints instead of running it once against the base URL,
    and it can SATISFY a required field that would otherwise be a named skip.
    Discovery is knowledge about this specific target; a default was a guess,
    which is why one may fill a required field and the other may not.

    With nothing discovered the plan is byte-identical to before.
    """
    # PROFILES is the BUILT-IN layer, not the only layer. It stays a plain
    # module-level dict: scripts/deterministic_sweep.py imports it, five tests
    # subscript it synchronously with no event loop, and the benchmark depends
    # on the two lab profiles resolving with no database at all. What an
    # operator declares for their own customer is merged OVER it, per
    # (case, field) — see orchestrator/testcase/declared.py.
    from orchestrator.testcase.declared import merge
    profile = merge(PROFILES.get(profile_name or "", {}), declared or {})
    wanted = set(only or [])
    discovered = {k: v for k, v in (discovered or {}).items() if v}
    runnable, skipped = [], []
    for case in cases:
        if wanted and case.get("id") not in wanted:
            continue
        req = (case.get("target_schema") or {}).get("required") or []
        # A field something already BOUND for this case is not a candidate for
        # fan-out. The fanned value was passed through `extra`, and `extra`
        # beats the profile in build_target — so one discovered path DELETED
        # the profile's declared endpoint from the plan:
        #
        #   dvwa / WSTG-INPV-05, declared {base}/vulnerabilities/sqli/
        #   + any discovered path
        #   -> ran at /, /robots.txt and /ftp, each with parameter=id, and the
        #      declared SQLi endpoint appeared NOWHERE.
        #
        # Three confident "no SQLi" verdicts about pages with no `id`
        # parameter, and zero runs against the one endpoint erlik knew was
        # right. `endpoints.record` runs after every v2 run, so a target
        # acquires discovered paths and then permanently stops being tested
        # where it matters. The comment below says discovered values are
        # "ADDITIONAL targets, not replacements" — that was only ever true of
        # the no-profile path.
        #
        # A declaration binds case <-> field <-> value; a discovered row asserts
        # only "this path exists on this host". The tighter binding wins.
        bound = set((profile.get(case.get("id", "")) or {}))
        bound |= {k for k, v in (extra or {}).items() if v not in (None, "")}
        fan_field = next(
            (f for f in ("url", "parameter")
             if f in req and f in discovered and f not in bound), None)
        suppressed = sorted(f for f in ("url", "parameter")
                            if f in req and f in discovered and f in bound)
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
        if suppressed:
            # NAMED, not silent. An operator seeing three fewer rows cannot
            # otherwise tell a declaration taking over from a regression.
            entry["suppressed_discovered"] = suppressed
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
