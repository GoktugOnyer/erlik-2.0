"""Identity-specific inventory shared by discovery and downstream testing."""
import hashlib
import json
import re
import uuid
from functools import lru_cache
from urllib.parse import unquote_plus, urldefrag, urlsplit, urlunsplit
from orchestrator import http_capture
from orchestrator.engagement import looks_injectable
from .contracts import (FINISHED_STAGE_STATUSES, MAX_EVIDENCE_CHARS, PARAMETER_NAME,
                        AssessmentConfig, IntegrationFinding, fingerprint, parameter_names)
from .security import (SecretStore, marker_digest, redact, safe_evidence,
                       secret_values)
from . import persistence as db
from .egress_policy import EgressPolicy


async def seeds(context, policy, include_form_actions: bool = False):
    """URLs a stage may FETCH, for this identity.

    `include_form_actions` defaults to False, and the default is the point. A URL
    that exists only because a GET form was found is not a page: requesting it
    performs the form's action. On DVWA a bare GET of
    `/vulnerabilities/csrf/?Change=Change` sets the admin password to the md5 of
    an empty string.

    That was fixed twice before, at the two call sites known about at the time —
    the crawler seed and the catalogue adapter's read-only cases. It was not
    fixed here, so `ZapAdapter.run` kept handing the whole list to a ZAP
    **requestor** job, which is ZAP being told to GET each URL. Three paths, two
    guarded, and the guard was in the consumers rather than in the producer.

    So it lives here now. A caller that genuinely needs these URLs asks for them,
    and the only one that does is the catalogue adapter — which wants them in
    order to REPORT the surface it declined to touch, as a `form_url_withheld`
    observation. Withholding must not become silence.

    Parameter probes are unaffected: they come from `parameters_by_url`, which
    reads the endpoint rows directly and deliberately keeps a form's companion
    query, because that query is what the form's handler requires.
    """
    rows = await db.rows("SELECT url,method,sources FROM integration_endpoints WHERE session_id=? AND identity_id=? ORDER BY url,method",
                         (context.session_id, context.identity_id))
    if not include_form_actions:
        actions = await form_urls(context)
        rows = [row for row in rows if row["url"] not in actions]
    # A route read out of a JavaScript body has never been requested by anything. It is
    # a proposal for an operator, not a page to fetch: measured on Juice Shop, the same
    # bundle names `/rest/products/search?q=` and `/rest/user/change-password?current=`,
    # and nothing syntactic separates them. See adapters.infer_from_scripts.
    rows = [row for row in rows
            if "javascript" not in json.loads(row.get("sources") or "[]")]
    candidates = [{"url": context.target, "method": "GET"}, *rows]
    selected, seen = [], set()
    for item in candidates:
        url = urldefrag(item["url"])[0]
        method = item["method"].upper()
        if method not in ("GET", "HEAD", "OPTIONS") or url in seen:
            continue
        if not EgressPolicy(policy).check(url, method)[0]:
            continue
        # A discovered URL is TARGET-CONTROLLED text, and it is substituted into
        # a double-quoted slot (`curl ... -i "{{url}}"`) which curl_request then
        # shlex.splits. A quote in the value therefore closes that slot and the
        # rest becomes new argv tokens — verified: a stored URL ending
        # `a" -o /dev/null -A "` parsed clean, and the trailing empty -A was
        # swallowed by the unfilled-option rule so the injection closed neatly.
        # Every injected token still has to pass the option allowlist, but the
        # right answer is not to let a target open the argv at all. Endpoint.url
        # is a bare `str` and katana/ZAP/playwright store what they found.
        if looks_injectable(url):
            continue
        seen.add(url)
        selected.append(url)
    return selected[:context.config.max_urls]


# The only target field this lane can supply to a catalogue case. Discovery
# produces endpoints; it does not produce parameter names, login URLs or
# credentials, so a case requiring any of those cannot run here however
# cleanly its command parses. `required_any` groups are credential
# alternatives — the lane has nothing to choose between.
LANE_TARGET_FIELDS = frozenset({"url", "parameter"})

# Executed through the Interactsh collector rather than the curl dialect, so it
# is selectable without being parseable here (see CatalogueAdapter.run).
COLLECTOR_CASES = ("WSTG-INPV-19",)

# Placeholders that are SUPPOSED to render empty here: identity is attached
# per stage by the proxy, never by the case (curl_request refuses a case that
# carries its own credentials). Every other empty placeholder means the command
# is not the command its author wrote.
IDENTITY_FIELDS = frozenset({"cookie", "auth_header"})

# Derived by run_test_case from the endpoint itself, so a case referencing one
# is never waiting on something a caller forgot to supply.
DERIVED_FIELDS = frozenset({"origin", "origin_host"})

_PROBE_URL = "https://erlik-capability-probe.invalid/"
_PROBE_PARAMETER = "erlikprobe"


def unfilled_fields(command: str, target: dict) -> list[str]:
    """Target fields a step's command references but nothing supplies.

    WSTG-CLNT-04 is why this exists. It requires only `url` and lists
    `parameter` as OPTIONAL, so it passes a target-schema check — but three of
    its four steps interpolate `{{parameter}}` into the query, and with nothing
    to substitute they probe `?=//erlik-redir.oast.test/`: an open-redirect
    test against a parameter with no name. That runs, finds nothing, and
    reports clean, which is worse than not running.
    """
    from orchestrator.testcase.runner import _TEMPLATE_RX
    missing = []
    for field in _TEMPLATE_RX.findall(command):
        if field.startswith("step.") or field in IDENTITY_FIELDS or field in DERIVED_FIELDS:
            continue
        if not str(target.get(field, "") or "").strip():
            missing.append(field)
    return sorted(set(missing))


@lru_cache(maxsize=32)
def executable_test_cases(url: str = _PROBE_URL) -> tuple[str, ...]:
    """Which catalogue cases this lane can actually execute — DERIVED, not listed.

    This used to be the literal list ["WSTG-SESS-02", "WSTG-CONF-06",
    "WSTG-CLNT-07"], maintained by hand alongside a second copy in
    AssessmentConfig.test_cases. Two hand-written lists and one parser is two
    claims and one fact, and the claims were already stale: widening
    curl_request changed what the lane can run and neither list would have
    noticed. So the question is asked of the parser instead.

    A case qualifies when ALL of these hold:
      - every field its target_schema requires is one the lane supplies,
      - every one of its steps parses under curl_request, and
      - no step interpolates a field nothing supplies (see unfilled_fields).

    EVERY step, not most. A case whose steps only partly run is not a weaker
    version of that case; it is a different check with the same name, and it
    reports clean on the strength of the steps that were skipped. WSTG-INFO-02
    is the example — its first step is a plain `curl -sI`, but the two after it
    run whatweb and wafw00f, so "INFO-02 passed" here would mean almost none of
    what INFO-02 means.

    The parse requirement is why this is worth deriving: most of the catalogue
    is out of reach not because of an option we could allow, but because the
    step is a shell pipeline, names several URLs, or runs a tool that is not
    curl. Widening the curl dialect cannot reach those.
    """
    from orchestrator.testcase.loader import load_catalog
    from orchestrator.testcase.runner import _render
    from orchestrator.testcase.scope import ScopeViolation
    from .deterministic import curl_request

    target = {"url": url, "parameter": _PROBE_PARAMETER}
    supported = []
    for case_id, tc in sorted(load_catalog().items()):
        schema = tc.target_schema
        if schema.required_any or not set(schema.required).issubset(LANE_TARGET_FIELDS):
            continue
        try:
            for step in tc.steps:
                if unfilled_fields(step.command, target):
                    raise ValueError("step interpolates a field the lane cannot supply")
                curl_request(_render(step.command, {**target, "step": {}}))
        except (ScopeViolation, ValueError):
            continue
        supported.append(case_id)
    return tuple(supported)


# One URL that offers a hundred query parameters must not become a hundred runs
# of every case. The per-URL cap keeps one pathological endpoint from consuming
# the whole budget; the total is charged against max_urls, which is the budget
# the operator already set for how much of the target this assessment touches.
MAX_PARAMETERS_PER_URL = 10


def base_url(url: str) -> str:
    """The URL with its query and fragment removed.

    WSTG-CLNT-04 interpolates `"{{url}}?{{parameter}}=…"`, so a url that already
    carried a query would produce two `?` and test nothing. Stripping it also
    matches the convention this codebase already uses for parameter-bearing
    targets in orchestrator/testcase/sweep.py PROFILES.

    The stripped URL is a DIFFERENT URL from the one discovery saw, so callers
    must re-check it against scope rather than inheriting the original's
    approval.
    """
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def parameter_can_forge(tc, name: str) -> bool:
    """Whether this parameter NAME could satisfy the case's own evidence.

    A parameter name is chosen by the target; so is the response. Most
    applications echo an unrecognised parameter name back — a hidden input, a
    "no such field" message, a search summary — so a name that matches the
    case's own marker makes the echo the evidence.

    WSTG-INPV-18 looks for the literal `219359`, being 31337*7 evaluated. That
    reasoning held while the payload was the only case-supplied text in the
    request. Supplying a target-CHOSEN name puts a second target-controlled
    string in there, and that one comes back by design: a planted
    `<a href="/search?219359=1">` yields a CRITICAL "Server-Side Template
    Injection" from an application with no template engine at all. Measured —
    `219359` and `7777777` forge two criticals, `XPathException` and `smtplib`
    two highs, against a stub that only echoes the name.

    So the pairing is refused rather than the finding downgraded: a probe whose
    positive result cannot be told from its own input is not a weaker probe, it
    is an uninterpretable one. A genuinely injectable parameter that happens to
    be NAMED `219359` is missed, which is the right side to err on.
    """
    for step in tc.steps:
        for ev in step.evaluators:
            if ev.type != "regex" or not ev.pattern:
                continue
            try:
                if re.search(ev.pattern, name, re.IGNORECASE if ev.case_insensitive else 0):
                    return True
            except re.error:
                continue
    return False


def case_needs_parameter(tc) -> bool:
    """Whether any step of this case interpolates {{parameter}}."""
    return any("parameter" in unfilled_fields(step.command, {"url": "x"}) for step in tc.steps)


async def parameters_by_url(context, policy) -> dict[str, list[str]]:
    """Query-free URL -> parameter names observed on it, for THIS identity.

    Rows are keyed by identity_id, and this reads only the caller's own, so a
    parameter learned while authenticated as an admin is never replayed on an
    anonymous stage — the same separation seeds() keeps for URLs.
    """
    rows = await db.rows(
        "SELECT url,parameters,sources FROM integration_endpoints "
        "WHERE session_id=? AND identity_id=? ORDER BY url",
        (context.session_id, context.identity_id))
    # The operator's own target is a candidate here for the same reason seeds()
    # treats it as one: if they pointed the assessment at
    # https://app.test/search?q=… they named a parameter, and waiting for a
    # crawler to rediscover it would be perverse.
    candidates = [{"url": context.target, "sources": "[]",
                   "parameters": json.dumps(parameter_names(context.target))}, *rows]
    checker, found, dropped = EgressPolicy(policy), {}, 0
    for row in candidates:
        # An inferred route is not a probe target until an operator selects it. Its
        # PARAMETER is the valuable half and also the dangerous half: injecting into
        # `change-password?current=` as an authenticated identity is the password
        # change. See adapters.infer_from_scripts.
        if "javascript" in json.loads(row.get("sources") or "[]"):
            continue
        names = [n for n in json.loads(row["parameters"] or "[]") if PARAMETER_NAME.match(n)]
        if not names:
            continue
        # A FORM endpoint keeps its query: that query is the form's companion
        # fields, which its handler usually requires, and it deliberately holds
        # none of the names about to be tested — so appending one cannot
        # duplicate it. A crawler-derived URL is stripped, because there the
        # query holds the very names being tested and their sample values.
        from_form = "form" in json.loads(row.get("sources") or "[]")
        url = row["url"] if from_form else base_url(row["url"])
        # Re-checked, because stripping the query produced a URL that was never
        # itself discovered or approved.
        if looks_injectable(url) or not checker.check(url, "GET")[0]:
            continue
        bucket = found.setdefault(url, [])
        for name in names:
            if name in bucket:
                continue
            if len(bucket) < MAX_PARAMETERS_PER_URL:
                bucket.append(name)
            else:
                dropped += 1
    if dropped:
        # A cap that is not reported reads as "we tested everything".
        print(f"[integrations] {dropped} discovered parameter(s) beyond "
              f"{MAX_PARAMETERS_PER_URL} per URL were not tested", flush=True)
    return found


async def form_urls(context) -> set[str]:
    """URLs that exist only because a GET FORM was found, for THIS identity.

    A URL like `/vulnerabilities/csrf/?Change=Change` was synthesised by
    form_endpoint: the query is the form's companion fields, including its
    SUBMIT control. Requesting it does not read a page — it performs the form's
    action.

    Measured against DVWA on 2026-09-10, and the reason this function exists:

        GET     /vulnerabilities/csrf/?Change=Change                  -> password changed
        HEAD    /vulnerabilities/csrf/?Change=Change                  -> password changed
        OPTIONS /vulnerabilities/csrf/?Change=Change                  -> password changed
        GET     /vulnerabilities/csrf/?Change=Change&password_new=x   -> no change
        GET     /vulnerabilities/csrf/                               -> no change

    The module's handler runs on `isset($_GET['Change'])` and compares
    `$_GET['password_new']` with `$_GET['password_conf']`; with neither present
    both are NULL, NULL == NULL, and the admin password is set to md5("").
    So the mutation comes from the PARAMETER-FREE fetch, by the three methods a
    scope gate trusts most — and a parameter probe, the thing the lane is
    actually for, does not mutate at all.
    """
    rows = await db.rows(
        "SELECT url,sources FROM integration_endpoints WHERE session_id=? AND identity_id=?",
        (context.session_id, context.identity_id))
    # A QUERY is what makes a form URL an action, and the table above is the
    # evidence: `GET /vulnerabilities/csrf/` changed nothing, while the same URL
    # with `?Change=Change` changed the password. With no named companion there is
    # no submission signal for a handler to fire on.
    #
    # Without that condition this withheld pages. DVWA's xss_r form declares its
    # submit control with no `name`, so at `security=low` the form has no named
    # companions at all, form_endpoint yields the page's own URL with an empty
    # query, and the row key (session_id, url, method, identity_id) merges it with
    # the crawled page row — `sources` becomes ["form","playwright"]. Every
    # read-only case then skipped a real page. At `impossible` the hidden
    # `user_token` IS a named companion, so the action is a separate row and the
    # page survives: the token's ABSENCE forked the reading arms in the opposite
    # direction from its presence, and the vulnerable arm read one URL FEWER.
    return {row["url"] for row in rows
            if "form" in json.loads(row.get("sources") or "[]")
            and urlsplit(row["url"]).query}


async def operations(session_id, identity_id=None) -> dict[str, dict]:
    """The session's OPERATIONS, with the concrete observations beneath each.

    E-007 asks for an operation inventory where "concrete URLs [are kept] as
    observations beneath the operation". The rows in integration_endpoints ARE
    those observations — keyed (session_id, url, method, identity_id) — and this
    groups them by what `contracts.operation_key` says they are.

    Nothing is discarded. Each operation lists the identities that observed it,
    the discovery sources, the union of parameter names, and every distinct URL,
    so a reader can still see the token DVWA baked into one arm's copy. What
    changes is that those two URLs now sit under ONE operation instead of being
    two rows with no stated relationship.

    `identity_id` narrows to one arm, which is how the comparison below gets its
    two sides.
    """
    from .contracts import operation_key

    query = "SELECT * FROM integration_endpoints WHERE session_id=?"
    args = [session_id]
    if identity_id is not None:
        query += " AND identity_id=?"
        args.append(identity_id)
    found: dict[str, dict] = {}
    for row in await db.rows(query + " ORDER BY url,method", tuple(args)):
        names = json.loads(row["parameters"] or "[]")
        key = operation_key(row["url"], row["method"], names)
        from .contracts import canonical_origin
        entry = found.setdefault(key, {
            "operation": key, "method": row["method"],
            # origin + path, so a caller can ask "what else is at this endpoint?"
            # without parsing the key back apart.
            "endpoint": canonical_origin(row["url"]) + (urlsplit(row["url"]).path or "/"),
            "parameters": [], "identities": [], "sources": [], "observations": [],
        })
        for name in names:
            if name not in entry["parameters"]:
                entry["parameters"].append(name)
        if row["identity_id"] not in entry["identities"]:
            entry["identities"].append(row["identity_id"])
        for source in json.loads(row["sources"] or "[]"):
            if source not in entry["sources"]:
                entry["sources"].append(source)
        entry["observations"].append({"url": row["url"], "identity": row["identity_id"],
                                      "sources": json.loads(row["sources"] or "[]")})
    for entry in found.values():
        entry["parameters"].sort()
        entry["identities"].sort()
        entry["sources"].sort()
    return found


# The states a known operation can be in, worst-known-first. Order matters: a pair can
# attract more than one observation — truncated by the URL budget AND refused for a
# forgeable name — and the reader needs the one that explains why nothing was learned.
# Observations about an ARM's whole surface rather than one case's pairs. They skip
# `coverage`'s eligibility filter, because the work they say did not happen was not scoped to
# a case in the first place.
ARM_WIDE_OBSERVATIONS = ("surface_read_truncated", "crawl_truncated")

COVERAGE_STATES = ("verified", "answered", "unreachable", "refused", "not_run",
                   "indistinct", "inferred", "not_attempted")

# Deliberately absent: `tested`. `answered` means bytes came back, which is not proof
# the check exercised anything — measured on DVWA, a probe missing its CSRF token
# answers HTTP 200 with 389 bytes of PHP warnings, so the emptiness-only detector does
# not fire and nothing was tested all the same. `verified` is reserved for "a finding
# came out of it", which is the only state the lane can actually stand behind.
_ANSWERED_CAVEAT = ("the probe ran and the target returned bytes; that is not proof the "
                    "check exercised the application, only that something answered")


def probe_key(url: str, sources) -> str:
    """The URL a case is actually given for this endpoint row.

    THE UNIT OF WORK IS THE PROBEABLE PAIR, NOT THE ENDPOINT ROW, and conflating them
    broke the coverage report in both directions. `parameters_by_url` keeps a FORM
    action's query — that query is the form's companion fields, which its handler
    requires — and strips a crawled URL's, because there the query holds a sample value
    rather than the name under test. So twenty crawled variants of `/api/Challenges/`
    are ONE probeable pair per parameter.

    Matching endpoint rows literally credited 2 of 13 probes; normalising both sides
    without grouping credited 57. Defining the unit once, here, is what makes the
    before-the-run preview and the after-the-run coverage agree by construction.
    """
    return url if "form" in (sources or []) else base_url(url)


async def preview(session_id, config, identity_id=None) -> dict:
    """What the run will and will NOT reach, before it starts.

    E-010 asks for "an explicit preview of work to be resumed" and that the preview
    "state what the run **will not** do, not only what it will". §E-010 gives the
    measured reason: at the default `max_urls` with every runnable case selected, the
    2026-09-10 run tested one or two parameters per case out of eight and lost six of
    nine findings — and said so twelve times, in per-case observations nobody reads
    before launch.

    Measured again while building `coverage`, which is this function's mirror: on Juice
    Shop at `max_urls=140`, seven times the default share per case, **158 of 163
    (endpoint, parameter) pairs were still not run**. That is the number to see
    beforehand.

    The arithmetic is `deterministic.target_budget`, the same function the runner uses,
    so the preview cannot promise what the run will not do.
    """
    from .deterministic import target_budget
    from orchestrator.testcase.loader import find_by_id

    where, args = "WHERE session_id=?", [session_id]
    if identity_id is not None:
        where += " AND identity_id=?"
        args.append(identity_id)
    rows = await db.rows(
        f"SELECT url,parameters,sources FROM integration_endpoints {where}", tuple(args))

    selected = list(config.test_cases or [])
    # Grouped into probeable pairs by the same rule `coverage` uses, so the two agree.
    grouped, inferred = {}, 0
    for row in rows:
        sources = json.loads(row["sources"] or "[]")
        names = [n for n in json.loads(row["parameters"] or "[]") if PARAMETER_NAME.match(n)]
        # Withheld from probing, so it is not a target however many parameters it names.
        if "javascript" in sources:
            inferred += len(names) or 1
            continue
        grouped.setdefault(probe_key(row["url"], sources), set()).update(names)
    readable = sorted(grouped)
    probeable = sorted((url, name) for url, names in grouped.items() for name in names)

    cases = []
    for case_id in selected:
        tc = find_by_id(case_id)
        if not tc:
            cases.append({"test_case_id": case_id, "eligible_pairs": 0, "target_budget": 0,
                          "not_reached": 0, "note": "this case is not in the catalogue"})
            continue
        budget = target_budget(config.max_urls, len(selected), len(tc.steps))
        if case_id in COLLECTOR_CASES:
            # ITS TARGETS ARE THE OPERATOR'S, NOT DISCOVERY'S. A collector case runs against
            # `config.callback.probes`, which `eligible_test_cases` knows nothing about — so
            # the parameter branch below counted zero and this surface, whose whole job is to
            # say what the run will NOT do, told the operator before launch that the case
            # "will run against nothing and report nothing". Measured: a session with one
            # declared probe and WSTG-INPV-19 selected reported `eligible_pairs=0` and that
            # sentence, for a case that was about to run against the probe.
            #
            # A confident wrong prediction in the preview is worse than no prediction: the
            # operator's remedy for it is to deselect the case.
            # NO "none declared" BRANCH, because that state cannot be built: selecting this
            # case requires the Interactsh stage, and `AssessmentConfig` refuses that without
            # "active testing, a self-hosted server, and explicit probes". A note for it would
            # be a sentence no run can produce.
            eligible, note = len(config.callback.probes), ""
        elif case_needs_parameter(tc):
            eligible = len([1 for url, name in probeable
                            if case_id in eligible_test_cases(url, "GET", [name])])
            note = ("" if eligible else
                    "no discovered parameter to test — this case needs one, so it will "
                    "run against nothing and report nothing")
        else:
            eligible = len([1 for url in readable if case_id in eligible_test_cases(url)])
            note = ("" if eligible else
                    "no discovered URL this case can run against")
        reached = min(eligible, budget)
        cases.append({"test_case_id": case_id, "steps": len(tc.steps),
                      "eligible_pairs": eligible, "target_budget": budget,
                      "not_reached": eligible - reached, "note": note})

    # SUMMED ACROSS CASES, and said so. Several cases usually share one pair, so this is
    # the number of case-targets the run will not get to — not the number of distinct
    # pairs left untested. Labelling it as pairs read as the smaller, wronger number.
    not_reached = sum(c["not_reached"] for c in cases)
    distinct_pairs = len({(url, name) for url, name in probeable})
    return {
        "cases": cases,
        "max_urls": config.max_urls,
        "selected": len(selected),
        "not_reached": not_reached,
        "distinct_pairs": distinct_pairs,
        "inferred_not_probed": inferred,
        "remedy": (f"{not_reached} case-target(s) will not be reached at "
                   f"max_urls={config.max_urls} across {len(selected)} selected case(s) "
                   f"and {distinct_pairs} distinct (endpoint, parameter) pair(s); raise "
                   f"max_urls or select fewer cases"
                   if not_reached else
                   f"every eligible case-target fits within max_urls={config.max_urls}"),
        # WHICH CROSS-ARM CHECKS THIS CONFIGURATION CANNOT SUPPORT, before the
        # containers run. E-010: the preview must "state what the run will not do".
        # The budget half above was already here; this is the half that costs a whole
        # assessment, because the cross-arm checks are the highest-value capability in
        # the product and the commonest way to lose them is a declaration nobody
        # filled in.
        "authorization_readiness": authorization_readiness(config),
    }

def authorization_readiness(config) -> dict:
    """Can the cross-arm checks run at all against these declarations?

    Answered from `declaration_refusals` — the predicate the checks themselves use — so the
    preview cannot promise a check the check will not perform.

    THE PAIRS ARE ORDERED and both directions are reported, because which identity is the
    caller and which is the owner is the operator's choice at the route, and a configuration
    that supports one direction may not support the other.

    IT DOES NOT PREDICT THE ARGUMENTS. The anonymous arm, the owner field and the marker
    reach the checks from the route rather than the configuration, so this reports whether an
    anonymous arm will be REGISTERED — both checks refuse without one — and says nothing
    about a marker it cannot see. A preview that guessed at arguments would be predicting the
    operator's next keystroke and would be wrong for free.
    """
    from .security import SecretStore

    store = SecretStore()
    declarations = {}
    for identity_id in config.identity_ids:
        try:
            declarations[identity_id] = store.get(identity_id) or {}
        except Exception:
            declarations[identity_id] = {}

    def name(identity_id):
        return declarations[identity_id].get("name") or identity_id[:8]

    pairs = []
    for first in config.identity_ids:
        for second in config.identity_ids:
            if first == second:
                continue
            for check in ("object", "function"):
                pairs.append({
                    "check": check, "first": name(first), "second": name(second),
                    "will_refuse": declaration_refusals(
                        check, declarations[first], declarations[second])})
    runnable = [pair for pair in pairs if not pair["will_refuse"]]
    anonymous = bool(config.anonymous_arm) or "anonymous" in config.identity_ids
    blocked_by = sorted({reason for pair in pairs for reason in pair["will_refuse"]})
    remedies = {
        "caller_has_no_subject_id": "declare `subject_id` on every identity — it is who the "
                                    "operator says the caller IS, and no response supplies it",
        "owner_has_no_subject_id": "declare `subject_id` on every identity — it is who the "
                                   "operator says the caller IS, and no response supplies it",
        "role_not_declared": "declare `role` on every identity; the lane will not guess which "
                             "of two is the privileged one",
        "arms_share_a_role": "give the two arms different `role` values, or the comparison "
                             "has no privilege boundary to cross",
    }
    advice = [remedies[reason] for reason in blocked_by if reason in remedies]
    if not anonymous:
        advice.append("register an anonymous arm (`anonymous_arm: true`); both cross-arm "
                      "checks refuse without one")
    return {
        "pairs": pairs,
        "runnable_pairs": len(runnable),
        "anonymous_arm_registered": anonymous,
        "remedy": "; ".join(advice) or (
            "every identity pair can be compared in both directions" if runnable else
            "no cross-arm comparison is possible: fewer than two identities are declared"),
    }


# Which stage a finding's `source` came out of, so "did the check that found this run again"
# has an answer. `cross-arm` is absent on purpose: those come from an on-demand route over
# stored evidence and NOTHING records that the route ran, so absence in a retest cannot be
# told from never having asked. See `compare_assessments`.
PRODUCING_STAGE = {"zap": "zap", "schemathesis": "schemathesis", "katana": "katana",
                   "interactsh": "interactsh", "testcase": "testcases"}

# Coverage states that mean a probe reached this pair and got an answer. `not_run`,
# `not_attempted`, `refused`, `unreachable`, `inferred` and `indistinct` all mean the opposite,
# and each carries its own reason, which is what a `not_retested` row quotes.
REACHED_STATES = ("answered", "verified")

RETEST_STATES = ("new", "unchanged", "changed", "regressed", "fixed", "not_retested")


async def record_check_run(session_id, check, first, second, arguments, result) -> None:
    """That an on-demand cross-arm check RAN, which nothing recorded.

    E-017 needs it and could not have it: a cross-arm finding absent from a retest was
    indistinguishable from a check the retest never invoked, so those findings could never be
    reported `fixed`. Inferring the invocation from findings — which
    `_already_compared_the_other_way` does for its own purpose — only works when there ARE
    findings, and the whole question here is what an absence means.

    RECORDED INSIDE THE CHECK, not at the route. Both checks are importable and are called
    directly by harnesses and tests; a record only the routes wrote would be a guard some
    callers opt into, which is the defect E-033 filed about the mutation refusal.

    THE MARKER IS NOT AN ARGUMENT THAT TRAVELS. `arguments` carries what is safe to keep:
    the object check's `owner_field` is a JSON path the operator chose and names no data,
    while the function check's marker IS the data — so that one is stored as the keyed digest
    the findings already carry, and the value never reaches the row. See E-032's per-path
    table for where the marker does and does not travel.

    A REFUSED RUN IS NOT A RUN, and it is recorded anyway with its reasons: `refused_because`
    is what tells a later retest that this invocation established nothing, and dropping the
    row would leave the same silence this exists to remove.
    """
    await db.execute(
        "INSERT INTO integration_check_runs(id,session_id,check_name,first_identity,"
        "second_identity,arguments,refused_because,checked,findings) "
        "VALUES(?,?,?,?,?,?,?,?,?)",
        (uuid.uuid4().hex, session_id, check, _arm_name(first) or "anonymous",
         _arm_name(second) or "anonymous", json.dumps(arguments, sort_keys=True),
         json.dumps(sorted(result.get("refused_because") or [])),
         int(result.get("checked") or 0), len(result.get("findings") or [])))


async def conclusive_check_runs(session_id) -> set:
    """(check, first, second) triples this session actually compared.

    Refused runs are excluded: a comparison that refused did not look, and treating it as
    evidence is the unrun-clause defect one level up from the one it refuses over.
    """
    return {(row["check_name"], row["first_identity"], row["second_identity"])
            for row in await db.rows(
                "SELECT check_name,first_identity,second_identity,refused_because "
                "FROM integration_check_runs WHERE session_id=?", (session_id,))
            if json.loads(row["refused_because"] or "[]") == []}

async def compare_assessments(baseline_session, retest_session) -> dict:
    """What a retest establishes about each finding of an earlier assessment. E-017.

    THE ONE RULE THIS IS BUILT AROUND: a finding is `fixed` only on POSITIVE evidence that
    the check which found it ran again and did not find it. Absence is not evidence. The
    entry says it in the project's own idiom — "a probe that received no bytes is
    not-retested, never fixed" — and `COVERAGE_STATES` says the sharper version beside it:
    even `answered` only means bytes came back, not that a check exercised anything.

    So three things must hold before `fixed`:

      1. the stage that produced the finding FINISHED in the retest, for that arm;
      2. the retest reached the same (url, parameter, identity) pair — `coverage` says so,
         and where it does not, its reason is quoted verbatim rather than summarised;
      3. for a catalogue finding, the same CASE ran against that pair, not merely some case.
         `rule` is `<case>:<step>` and `coverage` records the case, so this is checkable.

    Anything short of all three is `not_retested`, which is a different claim from `fixed`
    and must not be collapsed into it — an automatic closure is how a live vulnerability
    leaves a client's tracker.

    A CROSS-ARM FINDING CAN NOW BE `fixed`, AND THIS PARAGRAPH USED TO SAY IT COULD NOT.
    It described a real limitation — nothing recorded that an on-demand check RAN, so a
    retest that never invoked it was indistinguishable from one that invoked it and found
    nothing — and that limitation was then removed by `record_check_run` and
    `conclusive_check_runs`, which this function reads a few lines below. The paragraph was
    left behind, telling a reader the product cannot do something it does.

    What it costs to close one is higher than for a catalogue finding, not lower: the same
    check, the same ORDERED pair, and a run that did not refuse. Privilege is an order, so a
    comparison made the other way round asserts the opposite of the finding, and a finding
    with no `compared_with` is `not_retested` rather than closed on a guess at which arm it
    meant.
    """
    async def findings_of(session_id):
        return {row["fingerprint"]: json.loads(row["payload"]) for row in await db.rows(
            "SELECT fingerprint,payload FROM integration_findings WHERE session_id=?",
            (session_id,))}

    baseline, retest = await findings_of(baseline_session), await findings_of(retest_session)
    finished = {(row["adapter"], row["identity_id"]) for row in await db.rows(
        "SELECT adapter,identity_id,status FROM integration_stages WHERE session_id=?",
        (retest_session,)) if row["status"] in FINISHED_STAGE_STATUSES}
    conclusive = await conclusive_check_runs(retest_session)
    covered = {}
    for row in await coverage(retest_session):
        covered[(base_url(row["url"]), row["parameter"] or "", row["identity"])] = row

    def retested(finding):
        """(did the check demonstrably run again, why not). The `why not` is the reason a
        `not_retested` row carries, so it has to be specific enough to act on."""
        source = finding.get("source", "")
        stage = PRODUCING_STAGE.get(source)
        if source == "cross-arm":
            # NOW ANSWERABLE, because the checks record their own invocations. Before
            # `record_check_run` existed this returned "nothing records that the check ran",
            # and the product's highest-value findings could never be retested at all.
            #
            # The pair and the DIRECTION both matter: `identity` is the arm the finding is
            # about and `compared_with` is the one it was compared against, and a comparison
            # run the other way round asserts the opposite privilege order — see
            # `_already_compared_the_other_way`.
            check = CHECK_OF_RULE.get(str(finding.get("rule", "")))
            pair = (check, finding.get("identity", "anonymous"),
                    finding.get("compared_with", ""))
            if check is None:
                return False, (f"this finding's rule {finding.get('rule', '')!r} names no "
                               f"known cross-arm check, so nothing can establish that it ran")
            if not finding.get("compared_with"):
                return False, ("this finding does not record which arm it was compared "
                               "against, so a retest cannot re-run the same comparison")
            if pair not in conclusive:
                return False, (f"the retest ran no conclusive {check} comparison of "
                               f"{pair[1]!r} against {pair[2]!r} — a comparison that was "
                               f"never invoked, or that refused, establishes nothing")
            return True, ""
        if stage is None:
            return False, (f"a {source!r} finding comes from an on-demand check over stored "
                           f"evidence, and nothing records that the check ran in the retest — "
                           f"so its absence cannot be told from its never having been asked")
        arm = finding.get("identity", "anonymous")
        if (stage, arm) not in finished:
            return False, (f"the {stage} stage did not finish for the {arm!r} arm in the "
                           f"retest, so nothing re-probed this")
        key = (base_url(finding.get("url", "")), finding.get("parameter") or "", arm)
        row = covered.get(key)
        if row is None:
            return False, ("the retest has no coverage record for this operation, so it was "
                           "not part of the surface that was read")
        if row["state"] not in REACHED_STATES:
            return False, f"the retest reported this operation {row['state']}: {row['reason']}"
        case = str(finding.get("rule", "")).split(":")[0]
        if source == "testcase" and row["test_case_id"] and row["test_case_id"] != case:
            return False, (f"the retest probed this operation with {row['test_case_id']} "
                           f"rather than {case}, which is the check that found it")
        return True, ""

    out = []
    for fingerprint, finding in sorted(baseline.items()):
        present = retest.get(fingerprint)
        if present:
            was_fixed = finding.get("triage_state") == "fixed"
            changed = (present.get("severity") != finding.get("severity")
                       or present.get("confidence") != finding.get("confidence"))
            state = "regressed" if was_fixed else ("changed" if changed else "unchanged")
            reason = ""
            if state == "regressed":
                reason = ("this was triaged `fixed` and the retest found it again")
            elif state == "changed":
                reason = (f"severity {finding.get('severity')} -> {present.get('severity')}, "
                          f"confidence {finding.get('confidence')} -> {present.get('confidence')}")
        else:
            ran, why = retested(finding)
            state = "fixed" if ran else "not_retested"
            reason = ("the check that found it ran against this operation again and did not "
                      "report it" if ran else why)
        out.append({"fingerprint": fingerprint, "url": finding.get("url", ""),
                    "parameter": finding.get("parameter") or "",
                    "identity": finding.get("identity", "anonymous"),
                    "rule": finding.get("rule", ""), "severity": finding.get("severity", ""),
                    "state": state, "reason": reason})
    for fingerprint, finding in sorted(retest.items()):
        if fingerprint not in baseline:
            out.append({"fingerprint": fingerprint, "url": finding.get("url", ""),
                        "parameter": finding.get("parameter") or "",
                        "identity": finding.get("identity", "anonymous"),
                        "rule": finding.get("rule", ""),
                        "severity": finding.get("severity", ""),
                        "state": "new", "reason": "not present in the baseline assessment"})

    differences = await _configuration_differences(baseline_session, retest_session)
    states = {state: sum(1 for row in out if row["state"] == state) for state in RETEST_STATES}
    return {
        "findings": out,
        "states": states,
        "configuration_differences": differences,
        "establishes": (
            f"{states['fixed']} finding(s) were re-probed by the check that found them and "
            f"not reported again. {states['not_retested']} were NOT re-probed and are "
            f"unknown rather than fixed — read their reasons before closing any of them"
            + ("; and the two assessments differ in configuration, so this is not a "
               "like-for-like retest" if differences else "")),
    }


# What a retest outcome is allowed to do to a finding's LOCAL triage, and nothing else does
# anything. `not_retested` is absent by design and asserted absent: it is the state that means
# nobody looked, and an automatic closure is how a live vulnerability leaves a client's
# tracker. `unchanged`, `changed` and `new` are absent because they assert nothing about
# whether the finding was dealt with.
RETEST_TRIAGE = {
    # The retest re-ran the check that found it and did not report it — see
    # `compare_assessments` for the three conditions that has to satisfy.
    "fixed": "fixed",
    # It was triaged `fixed` and the retest found it again. The earlier claim was wrong, so
    # the finding goes back to open rather than staying closed with a contradiction beside it.
    "regressed": "open",
}


async def apply_retest(baseline_session, retest_session, *, confirm=False) -> dict:
    """Move the BASELINE findings' local triage to match what a retest established.

    E-018 asks for a remediation workflow and says "keep external sending explicit". This is
    the step before the sending: it changes what a later export will tell a client's tracker,
    so `confirm` defaults to False and the call is a preview until somebody says otherwise.

    THREE THINGS IT WILL NOT DO, each for a reason that has cost somebody something:

    - It never acts on `not_retested`. That state means nobody looked, and closing on it is
      the automatic closure E-017 exists to prevent.
    - It never overwrites `false_positive`. A human judged the finding not to be a bug; a
      retest reporting `fixed` would replace that judgement with a weaker one, and reporting
      `regressed` would resurface noise somebody already dismissed. The operator's call
      stands until the operator changes it.
    - It writes nothing without a trace. Every change records an evidence artifact naming the
      retest session, the state it established and the reason — because a finding that closed
      with no record of why is indistinguishable from one that was closed by hand, and only
      one of those can be checked.
    """
    comparison = await compare_assessments(baseline_session, retest_session)
    planned, refused = [], []
    for row in comparison["findings"]:
        target = RETEST_TRIAGE.get(row["state"])
        if target is None:
            continue
        entries = await db.rows(
            "SELECT payload FROM integration_findings WHERE session_id=? AND fingerprint=?",
            (baseline_session, row["fingerprint"]))
        if not entries:
            continue
        finding = json.loads(entries[0]["payload"])
        current = finding.get("triage_state", "open")
        if current == "false_positive":
            refused.append({**row, "would_have_become": target,
                            "left_alone_because": "an operator triaged this false_positive, "
                                                  "and a retest does not overrule that"})
            continue
        if current == target:
            continue
        planned.append({"fingerprint": row["fingerprint"], "url": row["url"],
                        "from": current, "to": target, "retest_state": row["state"],
                        "reason": row["reason"]})
        if not confirm:
            continue
        note = (f"set to {target} by the retest in session {retest_session}: "
                f"{row['state']} — {row['reason']}")
        finding.update(triage_state=target, triage_note=note)
        await db.execute(
            "UPDATE integration_findings SET payload=? WHERE session_id=? AND fingerprint=?",
            (json.dumps(finding), baseline_session, row["fingerprint"]))
        await db.evidence(baseline_session, "triage", "retest-applied", json.dumps({
            "fingerprint": row["fingerprint"], "state": target, "from": current,
            "retest_session": retest_session, "retest_state": row["state"],
            "reason": row["reason"]}))
    return {
        "applied": bool(confirm),
        "changes": planned,
        "left_alone": refused,
        "not_retested": comparison["states"]["not_retested"],
        "configuration_differences": comparison["configuration_differences"],
        "establishes": (
            ("applied " if confirm else "would apply ")
            + f"{len(planned)} triage change(s) from the retest. "
              f"{comparison['states']['not_retested']} finding(s) are not_retested and were "
              f"NOT touched — nobody looked at those, and closing them is the automatic "
              f"closure this refuses to do"
            + ("; run again with confirm to make these changes" if not confirm else "")),
    }

async def _configuration_differences(baseline_session, retest_session) -> list[dict]:
    """Ways the two assessments are not the same scan, so a comparison is not read as one.

    E-017: compare "while considering schema, identity, rule, and scope changes". A retest
    against a different schema, a different scope or a different set of arms can move a
    finding for reasons that have nothing to do with a fix, and an operator reading only the
    state column would never know.
    """
    async def shape(session_id):
        rows = await db.rows(
            "SELECT config FROM integration_assessments WHERE session_id=?", (session_id,))
        config = json.loads(rows[0]["config"]) if rows and rows[0]["config"] else {}
        digests = sorted({
            json.loads(row["result"] or "{}").get("metadata", {}).get("schema_sha256")
            for row in await db.rows(
                "SELECT result FROM integration_stages WHERE session_id=?", (session_id,))
        } - {None})
        # The DECLARED inventory alongside the digest, so the comparison can say what
        # changed rather than only that something did. Merged across stages and de-duplicated
        # by id: ZAP and Schemathesis both record it from the same document, so the same
        # operation arrives twice and is one operation.
        operations = {}
        for row in await db.rows(
                "SELECT result FROM integration_stages WHERE session_id=?", (session_id,)):
            try:
                metadata = json.loads(row["result"] or "{}").get("metadata") or {}
            except (ValueError, TypeError):
                continue
            for item in metadata.get("declared_operations") or []:
                operations.setdefault(item["id"], item)
        return {
            "scope": config.get("scope"),
            "test_cases": sorted(config.get("test_cases") or []),
            "stages": sorted(config.get("stages") or []),
            "arms": sorted({row["identity_id"] for row in await db.rows(
                "SELECT DISTINCT identity_id FROM integration_stages WHERE session_id=?",
                (session_id,))}),
            "schema_sha256": digests,
            "_operations": [operations[k] for k in sorted(operations)],
        }

    first, second = await shape(baseline_session), await shape(retest_session)
    labels = {"scope": "the authorised scope", "test_cases": "the selected catalogue checks",
              "stages": "the selected stages", "arms": "the identities that ran",
              "schema_sha256": "the API schema"}
    changes = [{"field": field, "baseline": first[field], "retest": second[field],
                "why_it_matters": f"{labels[field]} changed between the two assessments, so a "
                                  f"finding can move for a reason that is not a fix"}
               for field in labels if first[field] != second[field]]
    # WHAT changed, not only that it did. A digest answers "same schema?" and leaves the
    # operator to diff two documents by hand — which they cannot do at all when the schema
    # was supplied by URL, because the fetched bytes were never stored.
    #
    # The two halves are not the same finding. Operations ADDED are surface the baseline
    # never assessed. An operation REMOVED is the more interesting one: withdrawn from the
    # schema, it should now be gone, and if it still answers it is a live endpoint the
    # documentation no longer admits to.
    for entry in changes:
        if entry["field"] != "schema_sha256":
            continue
        from orchestrator.integrations.adapters import schema_diff

        difference = schema_diff(first["_operations"], second["_operations"])
        entry["operations"] = difference
        if difference["removed"]:
            entry["why_it_matters"] += (
                f"; {len(difference['removed'])} operation(s) present at baseline are no "
                f"longer declared — if any still answers, it is live and undocumented")
        if difference["added"]:
            entry["why_it_matters"] += (
                f"; {len(difference['added'])} operation(s) are new since baseline and were "
                f"never assessed by it")
        if not first["_operations"] and not second["_operations"]:
            entry["why_it_matters"] += (
                "; no declared inventory was recorded on either side, so what changed "
                "cannot be shown — only that the digest differs")
    return changes

def _incompleteness_caveat(unfinished: dict, not_probed: list) -> str:
    """What `establishes` must add when the comparison had blind spots.

    `establishes` was a constant, so the one sentence a caller is told to read said the same
    thing whether every arm had finished or one had stopped halfway. These two conditions are
    the difference between "no findings" and "no findings that this run could have seen", and
    a caller cannot be expected to cross-reference two other keys to learn which they have.
    """
    if not unfinished and not not_probed:
        return ""
    parts = []
    if unfinished:
        parts.append(f"{len(unfinished)} arm(s) have stages that did not finish")
    if not_probed:
        parts.append(f"{len(set(not_probed))} operation(s) the other arm never probed")
    return (". AND NOT A CLEAN RESULT EITHER: " + ", and ".join(parts)
            + " — an incomplete arm loses findings without inventing any, so read "
              "`arms_with_unfinished_stages` and "
              "`operations_the_other_arm_did_not_probe` before treating a zero as clean")


# The adapters whose output a cross-arm comparison actually reads.
#
# `arm_responses` takes only evidence whose kind starts with `testcase:`, and the catalogue
# adapter is the one that writes it. Every other stage feeds something else: katana fills the
# endpoint inventory, zap and schemathesis contribute findings, interactsh owns the callback.
#
# THIS SCOPING IS THE DIFFERENCE BETWEEN A SIGNAL AND NOISE, and it was measured the wrong way
# first. A real three-arm Juice Shop run has all three arms' katana stages `partial` with
# "request or URL budget exhausted" — the crawler doing exactly what `max_urls` told it — while
# every testcases stage is `completed`. Unscoped, `unfinished_stages` named all three arms on
# that run and `establishes` called a correct result unclean. Across the eleven lane databases
# on this machine, 7 of 57 stage rows are `partial` and ALL SEVEN are that same budget message.
#
# A truncated crawl is not invisible; it is reported where it belongs, as the arm-wide
# truncation `coverage()` now indexes.
COMPARED_STAGE_ADAPTERS = ("testcases",)


async def unfinished_stages(session_id, *identity_ids) -> dict:
    """Which of these arms have a stage that did not read everything it was going to.

    NOTHING IN THIS MODULE EVER SELECTED `integration_stages.status`. It selected `id` and
    `result`, so every consumer here — `coverage`, `arm_responses`, both cross-arm checks —
    was blind to whether an arm finished. Measured on a copy of the real Juice Shop run, with
    the customer arm's stages marked `partial` and its two decisive captures deleted:

        complete run   findings=2 checked=225 refused=[] not_shared=5 not_comparable=15
        half run       findings=0 checked=225 refused=[] not_shared=5 not_comparable=15

    Every count byte-identical, two true positives gone, and nothing said so.

    IT IS REPORTED, NOT REFUSED, and that is a deliberate reversal of this module's usual
    answer. A refusal means `authorization_findings` persists nothing — and an incomplete arm
    can only LOSE findings, never invent one, because a finding still needs positive evidence
    from both arms plus an anonymous arm that asked and was refused. So refusing would
    discard the true positives a half run did find in order to report the ones it missed,
    which is strictly worse than the defect. The zero is what must not read as clean, and
    saying so is what makes that true.
    """
    out = {}
    for identity_id in identity_ids:
        if identity_id in (None, ""):
            continue
        placeholders = ",".join("?" * len(COMPARED_STAGE_ADAPTERS))
        outstanding = [(row["adapter"], row["status"], row["reason"] or "")
                       for row in await db.rows(
                           f"SELECT adapter,status,reason FROM integration_stages "
                           f"WHERE session_id=? AND identity_id=? "
                           f"AND adapter IN ({placeholders}) ORDER BY rowid",
                           (session_id, identity_id, *COMPARED_STAGE_ADAPTERS))
                       if row["status"] not in FINISHED_STAGE_STATUSES]
        if outstanding:
            out[identity_id] = outstanding
    return out


async def arm_responses(session_id, identity_id) -> tuple[dict, set, dict]:
    """What one arm recorded, keyed by the REQUEST it recorded it for.

    Returns `({key: output}, ambiguous, {key: evidence_id})` for
    `key = (url, test_case, step, parameter)`.

    THE ARTIFACT ID TRAVELS WITH THE OUTPUT. It was read here and thrown away, and the
    consequence was measured: of eleven findings in a real assessment nine cited a
    resolvable evidence artifact, and the two that cited none were the only two graded
    `confirmed` — the product could not show a reader the bytes behind the claims it was
    most sure of. It has to come from HERE rather than be looked up per URL afterwards,
    because a URL does not have one artifact: 27 of one arm's 96 urls carry more than one
    `(url, case, step, parameter)` key, sixteen of them for `/socket.io/`, so a lookup by
    URL would cite a capture the clauses never read.

    THE KEY IS THE WHOLE REQUEST, not the url. This used to key by the run's declared
    `target.url` and take the FIRST step that had output, and that was the common cause
    of four ways to manufacture a finding:

      * a run whose steps were [`login` 200 carrying the owner, `read_as_caller` 403]
        reported the LOGIN's body as the caller's access, so a refused read became a
        finding;
      * one arm's body could come from a different test case entirely — an injection
        probe against the same URL — so two arms that issued different requests were
        compared as a differential;
      * two steps in one run disagreeing about the owner silently discarded the second;
      * two artifacts for one request let ROW ORDER decide, which both invents findings
        and loses real ones.

    `ambiguous` holds keys that appeared more than once with different captures. They are
    dropped rather than ranked: neither capture is more the arm's answer than the other,
    and a caller that picks one is picking by insertion order.

    A missing url, an unreadable artifact and a run with no steps are all skipped. None
    of them is a verdict, and inventing an empty response for one would let a check
    conclude "this arm was refused" from a read failure.
    """
    out: dict[tuple, str] = {}
    ambiguous: set = set()
    artifacts: dict[tuple, str] = {}
    stages = {row["id"] for row in await db.rows(
        "SELECT id FROM integration_stages WHERE session_id=? AND identity_id=?",
        (session_id, identity_id))}
    for row in await db.rows(
            "SELECT id,stage_id,kind FROM integration_evidence WHERE session_id=?",
            (session_id,)):
        if row["stage_id"] not in stages or not row["kind"].startswith("testcase:"):
            continue
        try:
            run = json.loads((await db.evidence_bytes(row["id"])).decode("utf-8", "replace"))
        except Exception:
            continue            # an unreadable artifact is not a verdict
        if not isinstance(run, dict):
            continue
        target = run.get("target") or {}
        url = target.get("url")
        case = run.get("test_case_id") or ""
        # THE PARAMETER IS PART OF THE REQUEST. Leaving it out of the key collapsed two
        # genuinely different probes into one and then called them contradictory: measured on
        # the first real DVWA run, `WSTG-INPV-05.2:single_quote` ran once for `username` and
        # once for `password` on `/vulnerabilities/brute/?Login=Login`, the two captures
        # differed as they should, and `ambiguous_evidence` refused the WHOLE comparison.
        # Every fixture had used `parameter: ""`, so only a real run could show it.
        parameter = target.get("parameter") or ""
        if not url:
            continue
        for step in run.get("steps") or []:
            if not isinstance(step, dict) or not step.get("output"):
                continue
            key = (url, case, step.get("step") or "", parameter)
            if key in out and out[key] != step["output"]:
                ambiguous.add(key)
            out[key] = step["output"]
            artifacts[key] = row["id"]
    for key in ambiguous:
        out.pop(key, None)
        # AND ITS ARTIFACT GOES TOO. A finding must never cite bytes whose contents this
        # function refused to use — that would hand a reader an artifact as the proof of a
        # comparison that was dropped precisely because the artifact was not trustworthy.
        artifacts.pop(key, None)
    return out, ambiguous, artifacts


async def derived_urls(session_id) -> set:
    """URLs the lane DERIVED rather than discovered — an instance built from an id it read
    out of a collection body.

    THE OBJECT-LEVEL CHECK MUST NOT SEE THESE. `cross_arm_authorization` asks whether the
    target attributed an object to somebody who is not the caller — and on a derived
    instance the asserted owner IS the path segment the lane chose. Measured: `GET
    /api/Users/1` answers `{"data":{"id":1,…}}`, so `owner_field: data.id` reads back the
    `1` the lane put in the URL. An adversarial pass scored it across four owner_field
    declarations on real captures: derivation took the check from 0 findings to 1 true
    positive and SEVEN false positives, precision over all declarations falling from 1.00 to
    0.42 — and porting the reflection clause to it removed all seven along with the only true
    positive. There is nothing for it to keep on a URL the lane invented.

    `cross_arm_privileged_function` is unaffected and gains from them, because its marker is
    the OPERATOR'S and no choice of URL satisfies it: on the same captures it went from 1 of
    4 known violations to 2, with zero false positives. That is the safety asymmetry one
    level down — who the caller is comes from the operator, and so does what privileged data
    looks like, but an OWNER is read from the response and the lane just wrote it.
    """
    return {row["url"] for row in await db.rows(
        "SELECT url,sources FROM integration_endpoints WHERE session_id=?", (session_id,))
        if "derived" in json.loads(row["sources"] or "[]")}


async def arm_urls(session_id, identity_id) -> set:
    """The URLs this arm has an ENDPOINT row for.

    `compare_arms` gates on those rows, so a finding about a URL absent from them is a
    finding nothing gated — measured: evidence targeting `/admin/export?all=1` while the
    rows knew only `/rest/basket/1`, and the isolation summary read "1 of 1 operations
    seen by both".
    """
    return {row["url"] for row in await db.rows(
        "SELECT url FROM integration_endpoints WHERE session_id=? AND identity_id=?",
        (session_id, identity_id))}


def _arm_name(identity_id):
    """The arm actually named, or None. `""` names no arm.

    The route's model accepted an empty string, which then passed an `is None` presence
    check and left the load-bearing clause unevaluated.
    """
    if identity_id is None:
        return None
    name = str(identity_id).strip()
    return name or None


def _declared_access(identity_declaration) -> tuple:
    """Paths this identity is declared to be entitled to reach.

    `Identity.may_access` has existed, been validated, and been read by NOTHING. This is
    the first reader, and it reads it in the only direction that is safe: as an
    OPEN-WORLD suppression. A declared path removes a finding; an empty declaration
    removes none. Read the other way — as a closed-world allowlist, "anything not
    declared is a violation" — it manufactures findings, worst of all for the anonymous
    arm, whose allowlist is empty and for whom every public endpoint would then read as
    forbidden.

    Measured on Juice Shop: `GET /rest/basket/2` is jim's OWN basket, and the
    administrator can read it too, so a marker naming jim's own data is present in the
    privileged arm AND the unprivileged arm while anonymous is refused — every clause
    satisfied, and nothing wrong. No rule reading only responses can tell that from a
    real crossing, because the difference is entitlement, which only the operator knows.
    """
    declared = identity_declaration or {}
    return tuple(path for path in (declared.get("may_access") or [])
                 if isinstance(path, str) and path.startswith("/"))


def _entitled(url, declared_paths) -> bool:
    """True when a declared path covers this URL.

    Exact path match, or a declaration ending in `/` covering everything beneath it. The
    query is ignored: entitlement is to an operation, and a declaration cannot be made
    to depend on a value the probe chose.
    """
    path = urlsplit(url).path or "/"
    for declared in declared_paths:
        if declared.endswith("/"):
            if path == declared.rstrip("/") or path.startswith(declared):
                return True
        elif path == declared or path == declared + "/":
            return True
    return False


def _unmatched_declarations(declared_paths, considered) -> list:
    """Declared paths that covered nothing this check looked at.

    A DECLARATION THAT MATCHED NOTHING MUST NOT READ AS ONE THAT WAS HONOURED, which is
    this repository's oldest rule applied to the operator's side of the contract. Measured
    on `_entitled`'s three shapes against four object URLs:

        /api/Users/2   suppresses 1 of 4   exact, and what an operator means
        /api/Users/    suppresses 3 of 4   the whole collection, listed in
                                           `suppressed_declared_access` so it is visible
        /api/Users     suppresses 0 of 4   SILENTLY

    The third is the one that costs an operator an afternoon: it is the spelling a person
    reaches for — "this identity may read users" — and `_entitled` matches it against
    `/api/Users` and `/api/Users/` only, never `/api/Users/2`. The false finding stays, the
    declaration looks applied, and nothing anywhere says the two are related.

    `considered` is every URL this check reached a verdict about, so a path that matched
    none of them is reported whether the reason is a missing slash, a typo, or an operation
    this assessment never saw. Naming which of those it is would be a guess; naming that it
    matched nothing is a fact.
    """
    return [path for path in declared_paths
            if not any(_entitled(url, (path,)) for url in considered)]


def _suppressing_declaration(url) -> str:
    """The exact `may_access` entry that would suppress a finding about this URL.

    The operator can only learn which paths to declare by reading the findings — E-032
    records that, and it is inherent: the object id is not derivable from `subject_id`
    (jim's is 2 while his address ids are 4 and 5). What is NOT inherent is having to
    then work out the spelling, and get it wrong in the direction that silently does
    nothing. This is the path, exactly as `_entitled` matches it.
    """
    return urlsplit(url).path or "/"

def declaration_refusals(check: str, first: dict, second: dict) -> list[str]:
    """Refusals decidable from the operator's DECLARATIONS alone, before anything runs.

    E-010 asks that the launch preview "state what the run **will not** do, not only what it
    will". The budget arithmetic was already there; this is the other half, and it is the one
    that costs a whole assessment. The cross-arm checks are the product's highest-value
    capability, and the commonest way to lose them is a declaration nobody filled in — an
    identity with no `subject_id`, two arms the operator labelled with the same role. Measured
    repeatedly while building them: the refusal is honest, and it arrives after the containers
    have run.

    ONE PREDICATE, called by the checks AND by the preview, because the alternative is a
    preview that predicts one thing while the check does another — two copies of one fact,
    which is the defect this codebase names about its own catalogue lists.
    `test_the_preview_predicts_what_the_check_actually_does` walks a matrix of declarations
    and asserts the two agree.

    DECLARATIONS ONLY. `no_anonymous_arm` is not here: the checks learn the anonymous arm from
    a route ARGUMENT, so a config that registers one does not guarantee one is passed. The
    preview says what it can — whether an anonymous arm will be registered at all — rather
    than predicting an argument it cannot see.
    """
    refused = []
    if check == "object":
        if not str((first or {}).get("subject_id") or "").strip():
            refused.append("caller_has_no_subject_id")
        if not str((second or {}).get("subject_id") or "").strip():
            refused.append("owner_has_no_subject_id")
        return refused
    high = str((first or {}).get("role") or "").strip()
    low = str((second or {}).get("role") or "").strip()
    if not high or not low:
        refused.append("role_not_declared")
    elif high == low:
        refused.append("arms_share_a_role")
    return refused

async def cross_arm_authorization(session_id, caller, owner, owner_field,
                                  anonymous=None) -> dict:
    """Object-level authorization, compared ACROSS stages. E-011's remaining half.

    A lane stage carries exactly ONE identity, so the `ownership` evaluator — which needs
    the caller, the declared owner and an anonymous arm in a single case execution — can
    never run inside one. This asks the same four-clause question of what each STAGE
    recorded instead, which is the lane-native shape.

    IT COMPOSES ON THE ISOLATION GATE RATHER THAN REPEATING IT. `compare_arms` already
    establishes whether two arms describe the same surface, including the case the
    operation key introduces — both arms reaching an operation at DIFFERENT concrete URLs
    because one carried a single-use token. Comparing responses from arms that issued
    different requests measures the request, so this refuses out loud instead of reporting
    no finding, because those are not the same answer.

    THE SAFETY ASYMMETRY IS THE REASON IT IS SAFE TO BUILD. Who each caller IS comes from
    the OPERATOR, via `Identity.subject_id`; the asserted owner comes from the TARGET. A
    target can cost itself a finding and cannot manufacture one. The anonymous arm is what
    stops it calling published content a leak — measured on Juice Shop,
    `/rest/products/1/reviews` hands every reviewer's email address to anybody who asks.

    Returns `{findings, refused_because, checked}`. A refusal is not a clean result, and
    callers must not read an empty `findings` list as one.
    """
    from orchestrator.testcase.runner import _asserted_owner, _http_status_ok
    from .security import SecretStore

    def declared(identity_id):
        if identity_id in (None, "", "anonymous"):
            return {}
        try:
            return SecretStore().get(identity_id) or {}
        except Exception:
            return {}

    refused = []
    entitled = _declared_access(declared(caller))
    caller_subject = str(declared(caller).get("subject_id") or "").strip()
    owner_subject = str(declared(owner).get("subject_id") or "").strip()
    # The same predicate the launch preview reads, so a preview cannot promise a check the
    # check will not perform — see `declaration_refusals`.
    refused += declaration_refusals("object", declared(caller), declared(owner))
    anonymous = _arm_name(anonymous)
    if anonymous is None:
        # The clause cannot be evaluated without the arm, and a clause nobody ran is not
        # a clause that passed.
        refused.append("no_anonymous_arm")

    surfaces = await compare_arms(session_id, caller, owner)
    refused += [reason for reason in surfaces["refused_because"]
                if reason not in PER_OPERATION_REFUSALS]

    unfinished = await unfinished_stages(session_id, caller, owner,
                                        anonymous)
    caller_saw, caller_split, caller_art = await arm_responses(session_id, caller)
    owner_saw, owner_split, owner_art = await arm_responses(session_id, owner)
    anonymous_saw, anonymous_split, anonymous_art = ((await arm_responses(session_id, anonymous))
                                      if anonymous is not None else ({}, set(), {}))
    # Evidence that contradicts itself about ONE request is not a record to compare — and
    # `arm_responses` has already dropped those keys, so nothing downstream can read them.
    # It is NOT a session refusal: the same over-broad shape as the per-operation conditions
    # above, and measured the same way. Counted so it cannot be silent.
    ambiguous = len(caller_split | owner_split | anonymous_split)
    if anonymous is not None and not anonymous_saw:
        # `service.register` creates an anonymous stage only via
        # `config.identity_ids or ["anonymous"]`, so a two-identity run has none — and an
        # operator passing the lane's own name for it would otherwise get findings whose
        # load-bearing clause was never evaluated.
        refused.append("anonymous_arm_did_not_run")
    # AND THE SAME GUARD FOR THE ARMS BEING COMPARED. `anonymous_arm_did_not_run` has
    # protected the third arm all along and the other two had no equivalent, so an arm with NO
    # evidence at all produced a clean-looking zero over nothing. Measured with one arm's stage
    # set `skipped` and its artifacts removed: the object-level check reported
    # `checked=0 findings=0 refused=[]`, `arms_with_unfinished_stages={}` and no caveat —
    # nothing anywhere said that arm had done nothing.
    #
    # THIS ONE REFUSES, where the half-run case reports, and the difference is real: an arm
    # that read PART of the surface still produces findings as interpretable as a complete
    # run's, so refusing there would discard evidenced HIGHs — an adversarial pass measured one
    # surviving a 60-of-117 truncation and confirmed all three of its cited artifacts. An arm
    # with NOTHING has no findings to discard and no comparison to interpret.
    #
    # It reads EVIDENCE rather than stage status, which is why it catches `skipped` — a status
    # `FINISHED_STAGE_STATUSES` calls finished, and rightly, because an adapter nobody selected
    # lost nothing; an arm whose evidence is absent is a different fact.
    if not caller_saw:
        refused.append("caller_arm_did_not_run")
    if not owner_saw:
        refused.append("owner_arm_did_not_run")

    # Only URLs the isolation gate actually looked at. `compare_arms` reads the endpoint
    # rows; without this, evidence could report a finding for a URL those rows never held.
    #
    # IT DOES NOT ALSO SUBTRACT THE INCOMPARABLE OPERATIONS, and the reason is worth stating
    # because the first fix did. `compare_arms` warns that an operation both arms reached at
    # DIFFERENT concrete URLs cannot be compared — but `arm_responses` keys evidence by the
    # request, URL included, so two arms are only ever compared on the IDENTICAL url, case,
    # step and parameter. The danger the warning describes cannot arise through this path.
    # Verified by removing the subtraction and re-running both real lab sessions: identical
    # results (34/34 and 37/38 checked). So it is counted and reported, not subtracted —
    # code that cannot fire implies a protection that is not there.
    not_comparable = (len(surfaces["per_arm_value_in_operation"])
                      + len(surfaces["only_in_first"]) + len(surfaces["only_in_second"]))
    # MINUS THE URLS THE LANE ITSELF INVENTED. See `derived_urls`: on an instance built from
    # an id the lane read out of a collection, the owner this check reads back is that id.
    invented = await derived_urls(session_id)
    gated = (await arm_urls(session_id, caller)
             & await arm_urls(session_id, owner)) - invented

    # See the sibling check: operations counted one way, URLs another, and only the URL
    # number answers "I read N, why did you compare M?".
    read_urls = {key[0] for key in caller_saw}
    not_shared = len(read_urls - gated)
    findings, checked, allowed, reported = [], 0, [], set()
    # Every URL this check reached a verdict about, so a declaration matching none of them
    # can be named. `read_urls` is the same set before the gating clauses narrow it.
    considered = read_urls
    not_probed = []
    if not refused:
        for key, body in sorted(caller_saw.items()):
            url = key[0]
            if url not in gated:
                continue
            checked += 1
            if not _http_status_ok(body):
                continue
            asserted = _asserted_owner(body, owner_field)
            if asserted in (None, "") or str(asserted) == caller_subject:
                continue
            if str(asserted) != owner_subject:
                # The target named somebody who is not either declared identity, so
                # nothing here can corroborate the claim.
                continue
            # The SAME request, as recorded by the other arm — not merely the same URL.
            #
            # AND A REQUEST THAT ARM NEVER MADE IS NOT A FAILURE TO CORROBORATE. The same
            # `.get(key, "")` defect as the sibling check's clause 2: an absent capture read
            # as "the owner's arm did not see this object", which is indistinguishable from
            # "the owner's arm never asked". Counted and listed instead, because a
            # comparison that silently drops operations reports its own blind spot as a
            # clean result.
            if key not in owner_saw:
                not_probed.append(url)
                continue
            corroborating = owner_saw[key]
            if not (_http_status_ok(corroborating)
                    and _asserted_owner(corroborating, owner_field) == asserted):
                continue
            if key not in anonymous_saw or not http_capture.answered(anonymous_saw[key]):
                continue            # the anonymous arm never issued this request, or the
                                    # proxy refused it — neither is the target saying no
            # RECEIPT, not the owner's value. Comparing the anonymous arm's owner field
            # let the target escape this clause by retyping it ("1" for 1) or omitting
            # it — a no-privilege-needed way to manufacture a high finding on fully
            # public data. A 2xx to an unauthenticated caller is publication whatever
            # the body calls the owner.
            if _http_status_ok(anonymous_saw[key]):
                continue
            # Declared entitlement, the same open-world suppression the function-level
            # check applies: an object the operator says this caller may read is not a
            # crossing, and no response can say so.
            if _entitled(url, entitled):
                allowed.append(url)
                continue
            if url in reported:
                continue            # one finding per object, not per probe — see the twin
            reported.add(url)
            findings.append({
                "url": url, "owner_field": owner_field,
                # THE EXACT DECLARATION THAT WOULD SUPPRESS THIS, so the operator does not
                # have to work out the spelling and get it wrong silently. Re-running the
                # check after `PUT /identities/{id}` costs one request: both checks read the
                # declaration live, and neither needs a new assessment.
                "declaration_that_would_suppress": _suppressing_declaration(url),
                "arm_evidence": {name: art[key] for name, art in
                                 ((caller, caller_art), (owner, owner_art),
                                  (anonymous or "anonymous", anonymous_art))
                                 if key in art},
                "caller": caller, "caller_subject_id": caller_subject,
                "owner": owner, "asserted_owner": asserted,
                "detail": (f"the caller is declared to be {caller_subject!r} and the "
                           f"application attributed this object to {asserted!r}, which the "
                           f"declared owner corroborated; an anonymous arm did not receive "
                           f"it, so it is not published content"),
            })

    outcome = {
        "findings": findings,
        "refused_because": refused,
        "checked": checked,
        "suppressed_declared_access": allowed,
        # AND THE DECLARATIONS THAT SUPPRESSED NOTHING. See `_unmatched_declarations`:
        # `/api/Users` is the spelling an operator reaches for and the one `_entitled`
        # matches against nothing below it.
        "declared_access_that_matched_nothing": _unmatched_declarations(entitled, considered),
        "not_comparable": not_comparable,
        "urls_not_shared_by_both_arms": not_shared,
        # Instances the lane derived, excluded because this check would read its own input
        # back as the asserted owner. The function-level check uses them.
        "derived_urls_excluded": len(invented),
        # OPERATIONS THE OTHER ARM NEVER PROBED, so the comparison had nothing to compare.
        # Not a denial and not a clean result: this is the number that stayed at 0 while two
        # true findings disappeared, because an absent capture was read as "did not receive
        # it". Listed rather than counted, because an operator has to be able to see WHICH.
        "operations_the_other_arm_did_not_probe": sorted(set(not_probed)),
        # ARMS THAT DID NOT FINISH READING. Reported rather than refused — see
        # `unfinished_stages` for why discarding a half run's true positives would be worse
        # than the defect. `{identity_id: [(adapter, status, reason)]}`.
        "arms_with_unfinished_stages": unfinished,
        "ambiguous_evidence": ambiguous,
        "surfaces": surfaces["summary"],
        "establishes": ("nothing, when `refused_because` is non-empty — an empty findings "
                        "list is not a clean result unless the comparison actually ran" + _incompleteness_caveat(unfinished, not_probed)),
    }
    # Recorded HERE rather than at the route, so a harness or a direct caller cannot skip
    # it — see `record_check_run`. `owner_field` names a JSON path the operator chose and no
    # data, so it is kept as written.
    await record_check_run(session_id, "object", caller, owner,
                           {"owner_field": owner_field}, outcome)
    return outcome




def _names_the_caller(url, subject_id) -> bool:
    """A path segment of this URL IS the unprivileged arm's own declared principal id.

    THE CHECK'S FOURTH FALSE-POSITIVE CLASS, and the only one a structural rule reaches.
    Measured on Juice Shop with a marker naming the customer's own email: `/api/Users/2`
    satisfies every clause — the privileged arm received the marked data, the unprivileged
    arm received the SAME bytes, the anonymous arm asked and got 401 — and the claim is
    false, because record 2 IS the customer. jim's declared `subject_id` is "2".

WHY THIS IS SAFE TO SUPPRESS ON, stated carefully, because the first version of this
    docstring got it wrong. The id VALUE is the target's — `instance_urls` derives an
    instance from an id read out of a collection body — so it is not true that "the lane
    chose it". What is true is narrower and sufficient: the thing it is compared against is
    the OPERATOR's declaration of who the caller is, and the only finding a target can
    suppress this way is one at the single URL that addresses the declared caller. By the
    operator's own account that URL is the caller's own record, and a target wanting to hide
    a leak there could simply not leak.

    ONLY THE LAST SEGMENT, because that is the one `instance_urls` appends. Matching any
    segment made the rule depend on path vocabulary: measured on the real run, a declared
    `subject_id` of "api" skipped 25 of 31 derived urls and "Users" skipped 2, neither
    having anything to do with an identity.

    NO MARKER RULE CAN DO THIS JOB. A gate comparing the marker to the identity's
    declarations assigns one grade per MARKER, and the two findings from the jim marker
    differ only in URL: `/api/Users` is real and `/api/Users/2` is not. Measured over 16
    markers and 26 findings, the gate proposed for this left the motivating false positive
    at `confirmed` and downgraded two true findings.
    """
    # No guard for an empty `subject_id`: empty segments are filtered out, so the
    # comparison below can never be true for one. An explicit check read as the protection
    # and was unreachable — ablating it changed nothing, which is how it was found.
    segments = [segment for segment in (urlsplit(url).path or "/").split("/") if segment]
    return bool(segments) and segments[-1] == subject_id


async def _already_compared_the_other_way(session_id, rule, privileged,
                                          unprivileged) -> list:
    """Fingerprints of findings in this session that assert the OPPOSITE privilege order.

    Privilege is an ORDER, so `X is above Y` and `Y is above X` cannot both hold. The
    product cannot tell which one the operator meant — `role` is a label it deliberately
    does not interpret, and guessing from a name is the assumption-driven finding that
    `role_not_declared` already refuses to make. But it can tell that it is being asked
    to hold both, and holding both means at least one recorded finding is wrong.

    Measured before this existed: running the real Juice Shop check with `privileged` and
    `unprivileged` swapped was not refused, found the same two violations, and wrote two
    more rows titled "admin reached a privileged function" — four confirmed, high,
    exported rows for two violations, two of them naming the administrator as the
    intruder into a function the administrator owns.

    THE PAIR, not one half of it. A three-tier engagement legitimately records `manager`
    as the unprivileged arm against `admin` and then asks about `manager` against
    `customer`; matching on the privileged arm alone would refuse that, which is why
    `IntegrationFinding.compared_with` had to exist.

    FALSE POSITIVES DO NOT BLOCK THE OPERATOR. A row triaged `false_positive` is the
    operator saying they already know it was wrong, so it stops contradicting anything
    and the correct direction can be run. That is the recovery path: triage the bad row,
    re-run.

    THE SIBLING OBJECT CHECK GETS NO SUCH RULE, deliberately. "jim read a record the
    application attributes to the administrator" and "the administrator read a record it
    attributes to jim" are two different findings that can both be true; there is no
    order to contradict.
    """
    found = []
    for row in await db.rows("SELECT payload FROM integration_findings WHERE session_id=?",
                             (session_id,)):
        try:
            payload = json.loads(row["payload"])
        except (ValueError, TypeError):
            continue
        if (payload.get("rule") == rule
                and payload.get("identity") == privileged
                and payload.get("compared_with") == unprivileged
                and payload.get("triage_state") != "false_positive"):
            found.append(payload.get("fingerprint", ""))
    return sorted(found)


async def cross_arm_privileged_function(session_id, privileged, unprivileged, marker,
                                        anonymous=None) -> dict:
    """Privileged-function access, compared ACROSS stages. E-011's last clause.

    Object-level authorization reads an owner out of the response, so the TARGET says who
    a record belongs to and the check only has to notice that it is not the caller. A
    FUNCTION has no owner to read. `GET /api/Users` returns every user and nothing in the
    payload says "only an administrator may ask this" — so the one thing that cannot be
    inferred, that this is privileged at all, comes from the OPERATOR as a marker
    identifying privileged data. Everything else comes from what the arms recorded.

    WHY NOT COMPARE STATUSES. "Both authenticated arms got 200, the anonymous arm did
    not" describes every ordinary authenticated endpoint in an application. Measured on
    Juice Shop v17.1.1, identical three-arm shapes for a violation and for a customer
    reading their own orders:

        /api/Users                          admin 200   customer 200   anon 401
        /rest/user/authentication-details         200            200         401
        /rest/order-history                       200            200         500   <- not a finding

    The marker separates them, because the administrator's data is not in the customer's
    order history. A status-shaped rule cannot, and would report the third.

    WHY THE ANONYMOUS ARM CARRIES THE WEIGHT. Three of the first four candidates measured
    are PUBLIC, and two of those have `admin` in the path:

        /rest/admin/application-configuration   200  200  200
        /rest/admin/application-version         200  200  200
        /api/Feedbacks                          200  200  200
        /api/Recycles                           200  200  200

    A path-name heuristic reports all four. A two-arm rule reports all four. They are
    published content, and clause 3 is what says so.

    AND THE MARKER REMOVES THE NEED FOR A DENIAL LIST. A refusal is not always a 4xx:
    Juice Shop denies `/api/Cards/3` to the wrong customer with HTTP **400**
    `{"status":"error","data":"Malicious activity detected"}`, and DVWA denies with HTTP
    **200** `{"result":"fail","error":"Access denied"}`. Neither body contains the
    privileged data, so clause 2 rejects both without knowing anything about how this
    application spells "no".

    THE SAFETY ASYMMETRY IS WHY THIS IS SAFE TO BUILD. Which role is privileged comes
    from the operator, via `Identity.role`; whether the data came back comes from the
    target. A target can cost itself a finding by denying the unprivileged arm, and
    cannot manufacture one — the only way to fabricate a finding is to hand privileged
    data to an unprivileged caller while withholding it from nobody, which IS the finding.

    Returns `{findings, refused_because, checked}`. A refusal means the comparison never
    ran, and an empty `findings` list is then not a clean result.
    """
    from orchestrator.testcase import declared
    from orchestrator.testcase.runner import _http_status_ok, _response_body
    from .security import SecretStore

    def role_of(identity_id):
        if identity_id in (None, "", "anonymous"):
            return "anonymous"
        try:
            return str((SecretStore().get(identity_id) or {}).get("role") or "").strip()
        except Exception:
            return ""

    refused = []
    # The marker is held to the rule that already governs it as a declaration, rather
    # than to a second rule invented here that could drift from it.
    bad = declared.validate("private_object_marker", marker)
    if bad:
        refused.append("marker_unusable")
    try:
        declaration = (SecretStore().get(unprivileged)
                       if unprivileged not in (None, "", "anonymous") else {}) or {}
    except Exception:
        declaration = {}
    entitled = _declared_access(declaration)
    subject = str(declaration.get("subject_id") or "").strip()
    derived = await derived_urls(session_id)
    high, low = role_of(privileged), role_of(unprivileged)
    # Guessing which of two identities is privileged — from a name, from which was passed
    # first — would let the lane report a finding off its own assumption. And a privilege
    # crossing needs two privilege LEVELS: two identities the operator labelled the same way
    # is a configuration mistake, and a finding drawn from it would report that mistake as a
    # vulnerability (this also subsumes one identity passed twice). Both conditions live in
    # `declaration_refusals`, which the launch preview reads too.
    refused += declaration_refusals(
        "function", {"role": high}, {"role": low})
    # AND THE SESSION MUST NOT ALREADY SAY THE OPPOSITE. Two identities cannot each be
    # the more privileged one, and a swapped declaration is otherwise indistinguishable
    # from a correct one — see `_already_compared_the_other_way`.
    contradicted = await _already_compared_the_other_way(
        session_id, AUTHORIZATION_RULES["function"], privileged, unprivileged)
    if contradicted:
        refused.append("arms_already_compared_in_the_opposite_direction")
    anonymous = _arm_name(anonymous)
    if anonymous is None:
        refused.append("no_anonymous_arm")

    surfaces = await compare_arms(session_id, privileged, unprivileged)
    refused += [reason for reason in surfaces["refused_because"]
                if reason not in PER_OPERATION_REFUSALS]

    unfinished = await unfinished_stages(session_id, privileged, unprivileged,
                                        anonymous)
    privileged_saw, high_split, high_art = await arm_responses(session_id, privileged)
    unprivileged_saw, low_split, low_art = await arm_responses(session_id, unprivileged)
    anonymous_saw, anonymous_split, anonymous_art = ((await arm_responses(session_id, anonymous))
                                      if anonymous is not None else ({}, set(), {}))
    ambiguous = len(high_split | low_split | anonymous_split)
    if anonymous is not None and not anonymous_saw:
        refused.append("anonymous_arm_did_not_run")
    # AND THE SAME GUARD FOR THE ARMS BEING COMPARED. `anonymous_arm_did_not_run` has
    # protected the third arm all along and the other two had no equivalent, so an arm with NO
    # evidence at all produced a clean-looking zero over nothing. Measured with one arm's stage
    # set `skipped` and its artifacts removed: the object-level check reported
    # `checked=0 findings=0 refused=[]`, `arms_with_unfinished_stages={}` and no caveat —
    # nothing anywhere said that arm had done nothing.
    #
    # THIS ONE REFUSES, where the half-run case reports, and the difference is real: an arm
    # that read PART of the surface still produces findings as interpretable as a complete
    # run's, so refusing there would discard evidenced HIGHs — an adversarial pass measured one
    # surviving a 60-of-117 truncation and confirmed all three of its cited artifacts. An arm
    # with NOTHING has no findings to discard and no comparison to interpret.
    #
    # It reads EVIDENCE rather than stage status, which is why it catches `skipped` — a status
    # `FINISHED_STAGE_STATUSES` calls finished, and rightly, because an adapter nobody selected
    # lost nothing; an arm whose evidence is absent is a different fact.
    if not privileged_saw:
        refused.append("privileged_arm_did_not_run")
    if not unprivileged_saw:
        refused.append("unprivileged_arm_did_not_run")

    # Only URLs the isolation gate looked at, and a COUNT of the operations it says are not
    # comparable rather than a subtraction of them — see the sibling check for why the
    # subtraction cannot fire.
    not_comparable = (len(surfaces["per_arm_value_in_operation"])
                      + len(surfaces["only_in_first"]) + len(surfaces["only_in_second"]))
    gated = (await arm_urls(session_id, privileged)
             & await arm_urls(session_id, unprivileged))

    needle = marker.strip() if isinstance(marker, str) else ""

    def carries(response):
        """The marked data came back in the BODY of a successful response.

        Body, because a marker reflected into a `Location:` header is not the
        application handing over a record. Successful, because a 400 that echoes the
        request would otherwise let reflected input satisfy a clause.
        """
        return bool(response) and _http_status_ok(response) and needle in _response_body(response)

    # HOW MANY OF THIS ARM'S READS COULD NOT BE COMPARED AT ALL. `not_comparable` counts
    # OPERATIONS, and measured on a real run that understated the loss 28:1: each arm held
    # evidence for 130 URLs, `gated` was 46, and the only visible trace was `checked=46`
    # against a 130-URL read. The 84 missing were all `/socket.io/?…&sid=…`, whose per-arm
    # session id puts them in one arm's endpoint rows and not the other's — correct to drop,
    # and not something an operator should have to infer from a subtraction.
    read_urls = {key[0] for key in privileged_saw}
    not_shared = len(read_urls - gated)
    findings, checked, reflected, allowed, reported = [], 0, [], [], set()
    indistinct_responses = []
    # Computed from the PRIVILEGED arm's captures, which are the ones clause 1 reads.
    indistinct = indistinct_urls([(key[0], capture)
                                  for key, capture in privileged_saw.items()])
    caller_named, redirected, not_probed = [], [], []
    if not refused:
        for key, response in sorted(privileged_saw.items()):
            url = key[0]
            if url not in gated:
                continue
            checked += 1
            # 0. THE MARKER MUST NOT BE THE CALLER'S OWN INPUT. Measured on Juice Shop:
            #    `GET /rest/track-order/99999` answers 200 `{"data":[{"orderId":"99999"}]}`
            #    — the whole record is the value from the path. An endpoint that echoes
            #    input AND requires a session would satisfy all three clauses below
            #    without disclosing anything, because the target would be supplying the
            #    evidence for its own verdict. Checked unquoted too, since a marker in a
            #    query arrives percent-encoded.
            # `unquote_plus`, not `unquote`: a form-encoded marker carries `+` for
            # space, so `?name=Vulnerability%3A+Reflected` did not match the marker
            # `Vulnerability: Reflected` that DVWA reflects three times into that page.
            if needle in url or needle in unquote_plus(url):
                reflected.append(url)
                continue
            # 0b. AND THE RESPONSE MUST BE ABOUT THIS OPERATION, not a document the
            #     application serves everywhere. E-011's acceptance names generic error
            #     pages as a negative control, and the status clause only catches the ones
            #     that come with an error STATUS. Measured: one error body carrying the
            #     operator's marker, served 200 at five URLs and refused to the anonymous
            #     arm, produced FIVE high findings — five copies of one document reported as
            #     five privilege crossings.
            #
            #     `indistinct_urls` already answers this and the cross-arm checks were not
            #     asking it: two URLs that answered with the same status, headers and bytes
            #     produced one observation. The most canonical spelling SURVIVES and is still
            #     reported, so a real leak at one URL is not lost — only its repeats are.
            #     Skipped and listed rather than dropped, which is E-034's answer for an
            #     operation that alone is uninterpretable.
            #
            #     The object-level check needs no such clause and does not get one: measured
            #     on the same evidence it reported 1 of 6, because its own clauses require an
            #     asserted owner read from the body and an error page has none. A clause that
            #     cannot fire is a protection that is not there.
            if url in indistinct:
                indistinct_responses.append({"url": url, "same_response_as": indistinct[url]})
                continue
            # 1. The privileged arm received the marked data, so there is a privileged
            #    function here to cross into. Without this the operator's declaration
            #    alone decides, and a marker naming something the endpoint never returns
            #    would be reported against every endpoint that denies the anonymous arm.
            if not carries(response):
                continue
            # 2. The unprivileged arm received the SAME marked data. This is the crossing,
            #    and it is also what makes a denial — in any dialect, at any status — not
            #    a finding, and a dead session not a finding either.
            #
            #    "DID NOT RECEIVE IT" AND "NEVER ASKED" ARE DIFFERENT, and `.get(key, "")`
            #    made them the same. Clause 3 below already draws this distinction for the
            #    ANONYMOUS arm, in as many words — "`get` with a default would read 'the
            #    anonymous arm never probed this' as 'the anonymous arm was refused', which
            #    is the unrun-clause defect this project keeps removing" — and the arm the
            #    finding is ABOUT did not get the same care.
            #
            #    Measured: on a copy of the real Juice Shop run, marking the customer arm's
            #    stages `partial` and deleting its two captures for the operations that
            #    matter took the check from 2 findings to 0 with `checked=225`,
            #    `refused_because=[]`, `urls_not_shared_by_both_arms=5` and
            #    `not_comparable=15` all BYTE-IDENTICAL to the complete run. An operator
            #    reading that sees 225 operations checked and nothing refused.
            if key not in unprivileged_saw:
                not_probed.append(url)
                continue
            if not carries(unprivileged_saw[key]):
                continue
            # 3. An anonymous arm ASKED and did not receive it. `get` with a default would
            #    read "the anonymous arm never probed this" as "the anonymous arm was
            #    refused", which is the unrun-clause defect this project keeps removing.
            if key not in anonymous_saw:
                continue
            # AND IT MUST HAVE BEEN ANSWERED BY THE APPLICATION. A probe the egress proxy
            # refused, or one that timed out, contains nothing — so it satisfied this clause
            # for free. Measured: a finding on Juice Shop's `/rest/products/1/reviews`,
            # content every arm can read, because the anonymous arm's capture was erlik's own
            # refusal text.
            if not http_capture.answered(anonymous_saw[key]):
                continue
            # AND A REDIRECT IS NOT A DENIAL. `carries` requires a 2xx, so a 3xx with an
            # empty body satisfied "asked for it and did not receive it" for free — while the
            # content it points at may be public. Measured on DVWA, the negative-control
            # target: the anonymous arm's capture for `/` is `302 Found / Location:
            # login.php / Content-Length: 0`, the same arm holds `login.php` 200 carrying
            # that page's own text, and three markers naming that text each produced a
            # finding against an application where nothing was wrong. `assertion_verdict`
            # already refuses a redirected response for exactly this reason.
            #
            # A LISTED SKIP rather than a denial, because what that arm would have received
            # is unknown and that is the whole point. Measured cost: it withdraws the DVWA
            # finding for every marker that produced one, and nothing on the Juice Shop run,
            # where 0 of 250 anonymous captures are 3xx-with-empty-body.
            status = http_capture.status(anonymous_saw[key])
            if status is not None and 300 <= status < 400 \
                    and not http_capture.body(anonymous_saw[key]).strip():
                redirected.append(url)
                continue
            if carries(anonymous_saw[key]):
                continue            # published content, not a privilege crossing
            # 4. The operator has not declared the unprivileged identity entitled to this
            #    operation. Measured: `/rest/basket/2` is jim's OWN basket and the
            #    administrator can read it too, so a marker naming jim's own data
            #    satisfies every clause above with nothing wrong. Entitlement is the one
            #    thing no response can express.
            if _entitled(url, entitled):
                allowed.append(url)
                continue
            # 5. AND THE OPERATION MUST NOT BE THE CALLER'S OWN RECORD, where the lane
            #    derived the instance and its id is the caller's own declared principal.
            #
            #    LAST, not first, although it is clause 0's twin in spirit. Placed before
            #    the evidence clauses it reported every derived url carrying that segment —
            #    8 of 31 on the measured run, identically for a marker where nothing was
            #    wrong — so `skipped_url_names_the_caller` was 8:1 noise and the one case it
            #    mattered was invisible. Here it names exactly the findings the rule took
            #    away, which is the only version an operator can act on. Every clause is a
            #    pure read of captures already in memory, so the order costs nothing.
            #
            #    The cost is irreducible and belongs in the open: an object id can equal a
            #    principal id by coincidence, and then this removes a true finding. Measured
            #    on this assessment, a declared `subject_id` of "1" removes `/api/Users/1`,
            #    which is one of its two true positives. That is why it is LISTED.
            if url in derived and _names_the_caller(url, subject):
                caller_named.append(url)
                continue
            # ONE FINDING PER OPERATION, not per probe that happened to fetch it. The
            # evidence is keyed by request, so two catalogue cases reading the same URL
            # produce two keys — and measured on the first real DVWA run, `WSTG-CONF-06:
            # options` and `WSTG-SESS-02:fetch_headers` both fetched `http://dvwa/`, so this
            # emitted two byte-identical findings. Which case did the fetching is not part of
            # the claim, so it cannot be what distinguishes two of them.
            if url in reported:
                continue
            reported.add(url)
            findings.append({
                "url": url,
                # The exact `may_access` entry that would suppress this one — see the twin.
                "declaration_that_would_suppress": _suppressing_declaration(url),
                # THE THREE ARTIFACTS THIS RESTS ON, for the KEY that satisfied the clauses
                # — not looked up by URL afterwards, because a URL does not have one
                # artifact and a lookup would cite a capture no clause read. Keyed by arm
                # rather than listed, so a reader can tell which arm each one is.
                "arm_evidence": {name: art[key] for name, art in
                                 ((privileged, high_art), (unprivileged, low_art),
                                  (anonymous or "anonymous", anonymous_art))
                                 if key in art},
                "privileged": privileged, "privileged_role": high,
                "unprivileged": unprivileged, "unprivileged_role": low,
                # The marker is NOT echoed. It is operator text describing the
                # application's private data — a real customer's address, an internal
                # identifier — and a finding travels into an export. The digest is here
                # so two markers used in one session can be told apart.
                # KEYED, not a bare digest of the marker. `sha256(marker)[:12]` was not a
                # label but an oracle: a 4050-candidate space recovered a real marker from
                # a real export in 0.0007s, because a marker is short and structured by
                # construction. See `security.marker_digest`.
                "marker_digest": marker_digest(session_id, needle),
                "marker_not_quoted": ("the declared marker identifies privileged data and is "
                                      "recorded as a label keyed to this assessment, from "
                                      "which the marker cannot be recovered"),
                "detail": (f"the operator declared {low!r} to be less privileged than "
                           f"{high!r}; both arms received the marked data from this "
                           f"operation, and an anonymous arm asked for it and did not "
                           f"receive it, so it is not published content"),
            })

    outcome = {
        "findings": findings,
        "refused_because": refused,
        "checked": checked,
        # NAMED, so the refusal is actionable. The operator has to be able to find the rows
        # that contradict this call in order to triage one of them away, and a bare reason
        # token would have left them searching.
        "contradicting_findings": contradicted,
        # Named and listed, not counted silently: these operations were NOT evaluated,
        # and a report that omitted them would read as a clean result for them.
        "skipped_reflected_marker": reflected,
        # Operations where the anonymous arm was REDIRECTED rather than refused. Not
        # evaluated, because an unfollowed 3xx says nothing about what that arm could read.
        "skipped_anonymous_was_redirected": redirected,
        # OPERATIONS THE OTHER ARM NEVER PROBED, so the comparison had nothing to compare.
        # Not a denial and not a clean result: this is the number that stayed at 0 while two
        # true findings disappeared, because an absent capture was read as "did not receive
        # it". Listed rather than counted, because an operator has to be able to see WHICH.
        "operations_the_other_arm_did_not_probe": sorted(set(not_probed)),
        # ARMS THAT DID NOT FINISH READING. Reported rather than refused — see
        # `unfinished_stages` for why discarding a half run's true positives would be worse
        # than the defect. `{identity_id: [(adapter, status, reason)]}`.
        "arms_with_unfinished_stages": unfinished,
        # Operations the LANE addressed to the unprivileged identity's own declared
        # principal id. Not evaluated, and named for the same reason as the reflected ones:
        # the rule cannot tell an identity id from an unrelated object id that happens to
        # match, so an operator has to be able to see what it took out.
        "skipped_url_names_the_caller": caller_named,
        # AND WHETHER THAT CLAUSE COULD RUN AT ALL. `subject_id` is optional on an identity,
        # and with none declared the clause above is inert — it would otherwise be a silent
        # protection, which is the shape this project keeps removing. The sibling
        # object-level check refuses outright without a subject_id; this one cannot, because
        # it does not otherwise need one and refusing would withdraw findings that are fine.
        "caller_own_records_not_excluded": not subject,
        # Operations whose response the privileged arm had already seen at another URL, so
        # the marker in them is one document rather than one record per operation. The
        # surviving spelling is still checked; these are its repeats.
        "skipped_indistinct_response": indistinct_responses,
        # Operations the operator declared this identity entitled to, via
        # `Identity.may_access`. Listed, because a suppression nobody can see is
        # indistinguishable from a check that never looked.
        "suppressed_declared_access": allowed,
        # AND THE DECLARATIONS THAT SUPPRESSED NOTHING, for the same reason one step
        # earlier: a declaration matching nothing is not a declaration that was honoured.
        # `gated` is every operation this check reached a verdict about.
        "declared_access_that_matched_nothing": _unmatched_declarations(entitled, gated),
        # Operations both arms reached at DIFFERENT URLs, or that only one arm saw. Counted,
        # because a comparison that quietly skipped them would read as having covered them.
        "not_comparable": not_comparable,
        # URLs this arm has evidence for that the other arm has no endpoint row for, so there
        # was nothing to compare them against. The number an operator needs to reconcile
        # "I read N" with "you checked M".
        "urls_not_shared_by_both_arms": not_shared,
        # Requests one arm recorded twice with different captures. Dropped, not ranked.
        "ambiguous_evidence": ambiguous,
        "surfaces": surfaces["summary"],
        "establishes": ("nothing, when `refused_because` is non-empty. What the marker "
                        "means is the operator's claim; that both arms received it and an "
                        "anonymous arm did not is the application's answer"
                        + _incompleteness_caveat(unfinished, not_probed)),
    }
    # The MARKER never reaches this row — it is the operator's description of privileged
    # data, and `marker_digest` is the keyed stand-in the findings already carry. See E-032's
    # per-path table for where the marker does and does not travel.
    await record_check_run(session_id, "function", privileged, unprivileged,
                           {"marker_digest": marker_digest(session_id, marker)}, outcome)
    return outcome




# The rules the two cross-arm checks report under. Stable strings, because `fingerprint` hashes
# them and DefectDojo dedups on that hash — a rename would orphan every finding already exported.
AUTHORIZATION_RULES = {
    "object": "erlik:authorization:object",
    "function": "erlik:authorization:privileged-function",
}

# The same map read backwards, so a recorded finding can say which check made it. Derived
# rather than written out twice — the two copies would drift the moment a third check exists.
CHECK_OF_RULE = {rule: check for check, rule in AUTHORIZATION_RULES.items()}


# How many of a collapsed group's URLs a finding names before it stops listing and
# says how many more there were. Enough to show the shape of the group — the largest
# real one measured was ten `/redirect?to=…` URLs — and bounded because the list is
# built from target-supplied strings.
MAX_URLS_NAMED = 12


def _arm_secrets(result: dict) -> tuple:
    """Every secret value carried by the arms this result compares.

    The cross-arm path had no `known` set at all, because it is the one finding
    producer that is not a stage and so never had a `JobContext`. Every other
    producer redacts against the identities in play (`adapters`, `interactsh`,
    `deterministic`), and this one quoted URLs straight from discovery into a
    description whose banner reads "Evidence (credentials redacted)".

    The realistic leak is not a planted one. An application that puts a session
    token in a link is committing an ordinary, reportable bug; katana follows the
    link, the URL lands in an endpoint row, and the token travels into the export as
    the finding's own `endpoints` value. Measured: a URL carrying a JWT reached
    `IntegrationFinding.url` verbatim while `redact()` on the same string yields
    `?token=[REDACTED]`.
    """
    known = []
    for finding in result.get("findings") or []:
        for field in ("privileged", "unprivileged", "caller", "owner"):
            arm = finding.get(field)
            if not arm or arm == "anonymous":
                continue
            try:
                known += list(secret_values(SecretStore().get(arm) or {}))
            except Exception:
                # A missing or unreadable declaration means one fewer value to
                # redact against, never a finding withheld. The header-level rules
                # inside `redact` do not depend on this set.
                continue
    return tuple(known)


def authorization_findings(target, check: str, result: dict) -> list:
    """Turn a cross-arm check's result into findings the product can actually carry.

    THE CHECKS USED TO PERSIST NOTHING. Nine increments built them, a real three-arm run produced
    two true positives with no false positives — and they existed only as the body of an API
    response. Measured on that run: `integration_findings` held NINE rows, all from catalogue
    cases, while the checks reported `/api/Users` and `/api/Users/1`. So
    `GET /sessions/{id}/findings` omitted them, the DefectDojo export omitted them, triage could
    not mark them, and `coverage()` never credited those operations as `verified`. The lane's
    strongest evidence was the only evidence it threw away.

    THE MARKER NEVER TRAVELS. It names the application's private data, and a finding goes into an
    export — so the finding carries the digest the check already computed and a sentence saying
    why, exactly as the check's own payload does. The `evidence` text states what each arm
    RECEIVED rather than quoting any of it, for the same reason: the obvious evidence string
    would quote the response around the marker, which is the private data itself.

    `refused_because` is honoured. A refusal means the comparison did not run, and turning an
    empty findings list into zero rows would be indistinguishable from a clean result — so a
    refused check yields nothing and the caller is expected to read the reason.
    """
    if result.get("refused_because"):
        return []
    rule = AUTHORIZATION_RULES[check]
    known = _arm_secrets(result)

    def arms_of(finding):
        """(the arm the claim is about, the arm it was compared against)."""
        if check == "function":
            return finding.get("unprivileged", ""), finding.get("privileged", "")
        return finding.get("caller", ""), finding.get("owner", "")

    # ONE FINDING PER KEY, BECAUSE THE KEY IS WHAT THE DATABASE STORES.
    #
    # `fingerprint` deliberately drops query VALUES and keeps names: a value is the
    # payload, and two SQL injection probes at `?id=1` and `?id=2` are one finding at
    # one operation. That is right, and it is right here too — an IDOR is a property of
    # `/rest/order`, not of order 1 — but the check emits one record per URL, and
    # `persist_findings` writes them with `INSERT OR REPLACE`. So the second silently
    # took the first's row. Measured: violations at `/rest/order?id=1` and `?id=2` built
    # ONE fingerprint and left ONE row, whose `url` was `?id=2`; across the 189
    # operations both arms of a real Juice Shop run shared, five groups collapsed and 13
    # URLs would have been dropped, the largest group being ten `/redirect?to=…`.
    #
    # Collapsing is the answer rather than distinguishing, because the ten redirect URLs
    # ARE one finding and ten rows of them would be ten times the noise. What was wrong
    # was losing the other nine without saying so — so the group is named in the
    # evidence and the row that survives is the most canonical member, chosen by the
    # same `canonicality` rule the duplicate-response pruner already uses rather than by
    # whichever URL happened to sort last.
    groups = {}
    for finding in result.get("findings") or []:
        arm, _ = arms_of(finding)
        key = fingerprint(target, rule, "GET", finding.get("url", ""), "", arm)
        groups.setdefault(key, {}).setdefault(finding.get("url", ""), finding)

    out = []
    for key, members in groups.items():
        urls = sorted(members, key=canonicality)
        finding = members[urls[0]]
        url = urls[0]
        arm, other = arms_of(finding)
        if check == "function":
            title = (f"{finding.get('unprivileged_role') or 'a less privileged role'} reached a "
                     f"privileged function")
            evidence = (
                "erlik compared what three arms received for the SAME request. The marker is the\n"
                "operator's description of privileged data and is NOT quoted here, because a\n"
                "finding travels into an export; which declaration this rests on is carried as a\n"
                "keyed label on the finding, outside this prose so that it survives a merge.\n"
                f"  privileged arm   ({finding.get('privileged_role')}): received the marked data\n"
                f"  unprivileged arm ({finding.get('unprivileged_role')}): received the SAME data\n"
                "  anonymous arm:     asked for it and did not receive it")
            basis = ("Three-arm differential. The operator declared which role is privileged and "
                     "what privileged data looks like; that both arms received it and an "
                     "anonymous arm asked and did not is the application's own answer.")
        else:
            title = "One identity read an object the application attributes to another"
            evidence = (
                "erlik compared an ownership claim the application made against the identity it\n"
                "was made to. The quoted values are the application's own.\n"
                f"  the caller is declared to be:  {finding.get('caller_subject_id')!r}"
                "  (operator-supplied)\n"
                f"  the response attributes it to: {finding.get('asserted_owner')!r}"
                f"  (read from {finding.get('owner_field')!r})\n"
                "  the declared owner's arm:       received the same object\n"
                "  anonymous arm:                  was refused, so it is not published")
            basis = ("Three-arm differential. Who the caller IS comes from the operator via "
                     "Identity.subject_id and the asserted owner comes from the target, so a "
                     "target can cost itself a finding and cannot manufacture one.")
        # THE ARTIFACTS, NAMED BEFORE THE COLLAPSED GROUP. `evidence` is capped at
        # MAX_EVIDENCE_CHARS, and a collapsed group of twelve urls of the length the real
        # run produces (up to 106 characters each) needs more room than the cap leaves — so
        # putting the group first would truncate away the proof and keep the context.
        cited = {name: eid for name, eid in (finding.get("arm_evidence") or {}).items()}
        if cited:
            evidence += ("\n  the response each arm received is stored; read it at\n"
                         + "".join(f"    GET /api/integrations/evidence/{eid}   ({name})\n"
                                   for name, eid in sorted(cited.items(), key=lambda kv: kv[1])))
        if len(urls) > 1:
            shown = urls[:MAX_URLS_NAMED]
            evidence += (
                f"\n  this operation was reached at {len(urls)} urls that a fingerprint\n"
                "  does not distinguish, so they are one finding and named here:\n"
                + "".join(f"    {one}\n" for one in shown)
                + (f"    and {len(urls) - len(shown)} more\n" if len(urls) > len(shown) else ""))
        out.append(IntegrationFinding(
            fingerprint=key,
            # REDACTED AND SANITISED LIKE EVERY OTHER PRODUCER'S. This path quoted
            # discovery's URLs and the target's own owner value into a description whose
            # banner says "Evidence (credentials redacted)", and nothing redacted them.
            # `basis` is exempt because it is lane-authored, which is the distinction
            # `IntegrationFinding.evidence` already documents.
            title=safe_evidence(title), url=redact(url, known),
            rule=rule, source="cross-arm", identity=arm, compared_with=other,
            marker_digests=[d for d in [finding.get("marker_digest")] if d],
            # THE PRODUCT'S STRONGEST FINDINGS WERE ITS ONLY UNCITABLE ONES. Measured on a
            # real assessment: nine of eleven findings cited a resolvable artifact, and the
            # two that cited none were the two the lane was most sure of. Served by
            # `GET /api/integrations/evidence/{id}` with the stored digest re-checked, and
            # reached by `service.report`; nothing in the DefectDojo payload carries them,
            # so this publishes nothing new.
            evidence_ids=sorted(set((finding.get("arm_evidence") or {}).values())),
            severity="high",
            # `likely` FOR THE FUNCTION-LEVEL CHECK, and the grade is the finding.
            #
            # `finding_payload` maps `confirmed` to DefectDojo's `verified=True`, which tells
            # a client that a human need not check this. The one thing that most needs
            # checking here is whether the marker names privileged data — and that is both
            # unverifiable from any evidence the lane holds AND deliberately absent from the
            # report, because the marker is not quoted. Measured over 16 markers on a real
            # assessment: 12 of 26 findings true (0.46), 12 of 16 over the ten realistic
            # markers (0.75), and one plausible marker on the negative-control target gives
            # 0 of 1. Those two rows were also the ONLY `confirmed` findings in that whole
            # assessment, so the single producer of `verified=True` was the one whose
            # decisive input is an operator string nothing can corroborate.
            #
            # The OBJECT-level check keeps `confirmed`: its load-bearing value — who the
            # application says owns the record — comes from the TARGET, and the own-data case
            # is excluded in code by `derived_urls` rather than left to a declaration.
            # `severity` stays high in both: the grade is about certainty, not impact.
            confidence="confirmed" if check == "object" else "likely", basis=basis,
            evidence=safe_evidence(redact(evidence, known))[:MAX_EVIDENCE_CHARS],
            methodology=["WSTG-AUTHZ-04"],
            # A BARE NUMBER, matching what the ZAP adapter already stores and what DefectDojo's
            # Finding.cwe expects (an integer). 639 is authorization bypass through a
            # user-controlled key — the object-level case; 285 is improper authorization.
            cwe="639" if check == "object" else "285"))
    return out


async def declared_probe_pairs(session_id, identity_id=None) -> list[dict]:
    """One coverage row per declared callback probe per arm, shaped like an endpoint row.

    The probe is a surface the OPERATOR nominated rather than one a crawler found, and it is
    the only surface the out-of-band case can test — `config.callback.probes`, which
    `integration_endpoints` never holds. See `coverage` for why it is not given an endpoint
    row instead.

    `eligible` carries `COLLECTOR_CASES`, because `eligible_test_cases` lists what the curl
    dialect can execute and never names one; without it a probe row would drop the budget
    truncation of the very case that owns it.

    A row is emitted for every arm the assessment registered, not only for arms with a
    catalogue stage: an assessment that declared probes and did NOT select the case has no
    catalogue stage at all, and that is precisely the case the report has to distinguish.
    """
    rows = await db.rows("SELECT config FROM integration_assessments WHERE session_id=?",
                         (session_id,))
    if not rows:
        return []
    try:
        config = AssessmentConfig.model_validate_json(rows[0]["config"])
    except (ValueError, TypeError):
        return []
    # No early return for "no probes": the loop below yields nothing, so a guard here would
    # be a clause no ablation can catch — measured, and removed rather than kept.
    probes = list(getattr(config.callback, "probes", None) or []) if config.callback else []
    drivers = sorted(set(config.test_cases or ()) & set(COLLECTOR_CASES))
    arms = sorted({row["identity_id"] for row in await db.rows(
        "SELECT DISTINCT identity_id FROM integration_stages WHERE session_id=?",
        (session_id,))} or {"anonymous"})
    if identity_id is not None:
        arms = [arm for arm in arms if arm == identity_id]
    # The reason a probe NOBODY recorded carries. Two different facts, and the difference is
    # the whole point of the row: a selected case that reported nothing about its own probe
    # means the stage did not get there, while an unselected case means the catalogue was
    # never going to.
    declared_reason = (
        (f"declared as a callback probe and driven by {', '.join(drivers)}, which reported "
         f"nothing about it — read this arm's interactsh and testcases stages; a zero here is "
         f"untested, not clean")
        if drivers else
        ("declared as a callback probe, and no out-of-band case is selected for this "
         "assessment — the callback engine still issues it, but no catalogue check drove it, "
         "so nothing here has been evaluated against a response"))
    out = []
    for probe in probes:
        url = probe.get("url") if isinstance(probe, dict) else getattr(probe, "url", "")
        name = (probe.get("parameter") if isinstance(probe, dict)
                else getattr(probe, "parameter", "")) or ""
        if not url:
            continue
        for arm in arms:
            out.append({"url": url, "method": "GET", "identity_id": arm,
                        "sources": {"callback"}, "parameters": [name],
                        "eligible": COLLECTOR_CASES,
                        "declared_reason": declared_reason})
    return out


async def coverage(session_id, identity_id=None) -> list[dict]:
    """Per (operation, parameter, identity): what happened, and why not.

    The plan asks that an operator "sees its coverage", and §E-010 gives the measured
    reason: at the default `max_urls` the 2026-09-10 run tested one or two parameters
    per case out of eight and LOST SIX OF NINE FINDINGS. It said so twelve times, in
    per-case observations nobody reads.

    Everything needed was already recorded — `test_case`, `test_case_not_run`,
    `test_case_truncated`, `test_case_unreachable`, `parameter_refused`,
    `form_url_withheld` — and scattered across stage results, so the one question an
    operator has ("was this endpoint tested?") had no answer. This aggregates it.

    Every row carries a reason, including the ones nothing touched: a report that
    listed only what ran would read as a clean bill of health for everything it left
    out, which is the shape of wrongness this project keeps removing.
    """
    from .contracts import operation_key

    where, args = "WHERE session_id=?", [session_id]
    if identity_id is not None:
        where += " AND identity_id=?"
        args.append(identity_id)

    # BOTH SIDES OF THE JOIN ARE NORMALISED, because the probe's URL is not the
    # endpoint row's. `parameters_by_url` hands a case the QUERY-STRIPPED url — a
    # crawled `/search?q=hello` becomes `/search`, since the query holds a sample value
    # rather than the name being tested — so an observation says `/search` while the row
    # says `/search?q=hello`. Matching them literally attached almost nothing: measured
    # on Juice Shop, 13 probes ran and this credited 2. The launch preview predicted 13
    # correctly, which is how the disagreement surfaced.
    #
    # A form action keeps its companion query and is probed at that exact URL, so both
    # sides are stripped rather than one side being reconstructed.
    def pair(url, parameter, identity):
        return (base_url(url), parameter or "", identity)

    findings = {}
    for row in await db.rows("SELECT payload FROM integration_findings WHERE session_id=?",
                             (session_id,)):
        payload = json.loads(row["payload"])
        findings.setdefault(pair(payload.get("url", ""), payload.get("parameter"),
                                 payload.get("identity", "anonymous")), []).append(
            payload.get("rule", ""))

    # Observations, indexed by what they are about. A `url`-less observation (a budget
    # truncation, a refusal) applies to every pair of that case for that identity.
    seen, case_wide = {}, {}
    for row in await db.rows(f"SELECT identity_id,result FROM integration_stages {where}",
                            tuple(args)):
        try:
            observations = json.loads(row["result"] or "{}").get("observations") or []
        except (ValueError, TypeError):
            continue
        for item in observations:
            kind, case = item.get("type"), item.get("test_case_id") or ""
            # `surface_read_truncated` AND `crawl_truncated` WERE DROPPED HERE, and they are
            # the two that say the most. Measured on the real Juice Shop run, whose coverage
            # report this module exists to produce:
            #
            #     124 of 182 in-scope URLs were not read as the admin arm
            #     123 of 181 as the customer arm, 126 of 184 as the anonymous arm
            #     2 to 4 object instances per arm never fetched
            #
            # six observations in total, one of them saying in its own reason "so the
            # cross-arm authorization checks have no evidence for them" — and `coverage()`
            # indexed none of them. Two thirds of the in-scope surface went unread and the
            # report could not attribute a single row of it, so those pairs came out
            # `not_attempted`: "no catalogue check ran against this pair", which is the
            # sentence for an endpoint nothing was eligible for, not for one the budget cut.
            if kind not in ("test_case", "test_case_unreachable", "test_case_not_run",
                            "test_case_truncated", "parameter_refused", "form_url_withheld",
                            "indistinct_url", "surface_read_truncated", "crawl_truncated"):
                continue
            record = (kind, case, item.get("reason") or "", item.get("parameters") or [])
            if item.get("url"):
                seen.setdefault(pair(item["url"], item.get("parameter"),
                                     row["identity_id"]), []).append(record)
            else:
                case_wide.setdefault(row["identity_id"], []).append(record)

    def state_of(kind):
        return {"test_case": "answered", "test_case_unreachable": "unreachable",
                "test_case_not_run": "not_run", "test_case_truncated": "not_run",
                # Both are "this work did not happen", which is what `not_run` means. They
                # rank below `answered`, so a pair some case DID probe keeps its own state —
                # an arm-wide truncation cannot downgrade an operation that was read.
                "surface_read_truncated": "not_run", "crawl_truncated": "not_run",
                "parameter_refused": "refused", "form_url_withheld": "refused",
                # Not untested work. This URL answered with a response another URL had
                # already given, so there is nothing here left to test — see
                # `indistinct_urls`. Reporting it as `not_run` read as outstanding work:
                # measured on a real run, 461 of 566 coverage rows were `not_run` and a
                # third of the arm's reads were spellings of one document.
                "indistinct_url": "indistinct"}[kind]

    # AND WHICH ARMS DID NOT FINISH READING. A stage that TRUNCATED says so in an
    # observation, which the arm-wide indexing above now carries onto its rows. A stage that
    # FAILED records no observations at all — so every pair it never reached came out
    # `not_attempted`, whose reason reads "no catalogue check ran against this pair — it may
    # not have been selected, or no selected case tests a parameter". That is a by-design
    # cause offered with confidence for an accident. Measured with one arm's catalogue stage
    # set `failed` and its evidence removed: 176 of that arm's 185 rows carried that sentence
    # and NOT ONE mentioned the failure.
    #
    # Read from the stage rows, which this function already queries and never looked at.
    #
    # AND FROM THE ARMS THAT HAVE NO ENDPOINT ROWS AT ALL. The identity set was read from
    # `integration_endpoints`, so an arm whose crawl found nothing was absent from it — and
    # katana finding nothing is not hypothetical, it is what it does on DVWA. That arm can
    # still have a declared probe, and its probe row would then be the one row in the report
    # that could not say the arm's catalogue stage had failed.
    probes = await declared_probe_pairs(session_id, identity_id)
    incomplete = await unfinished_stages(session_id, *sorted(
        {row["identity_id"] for row in await db.rows(
            f"SELECT DISTINCT identity_id FROM integration_endpoints {where}", tuple(args))}
        | {probe["identity_id"] for probe in probes}))

    # Grouped into probeable pairs first, so one probe is credited once.
    grouped: dict[tuple, dict] = {}
    for row in await db.rows(
            f"SELECT url,method,identity_id,sources,parameters FROM integration_endpoints "
            f"{where} ORDER BY url", tuple(args)):
        sources = json.loads(row["sources"] or "[]")
        key = (probe_key(row["url"], sources), row["method"], row["identity_id"])
        entry = grouped.setdefault(key, {"url": probe_key(row["url"], sources),
                                         "method": row["method"],
                                         "identity_id": row["identity_id"],
                                         "sources": set(), "parameters": []})
        entry["sources"].update(sources)
        for name in json.loads(row["parameters"] or "[]"):
            if name not in entry["parameters"]:
                entry["parameters"].append(name)

    # THE DECLARED CALLBACK PROBES ARE A SURFACE, AND COVERAGE COULD NOT SEE ONE.
    #
    # `coverage` enumerates `integration_endpoints`; the out-of-band case's targets come from
    # `config.callback.probes`, which no endpoint row holds. Measured on three sessions that
    # differ only in what happened to that case — it ran, it was skipped because the arm had
    # no collector, it was never selected — the reports were BYTE-IDENTICAL: one row, one
    # `not_attempted`, the probe URL absent and `WSTG-INPV-19` absent. So the one check whose
    # whole purpose is to detect what an in-band response cannot show was invisible to the
    # report that exists to say what was tested.
    #
    # NOT FIXED BY GIVING THE PROBE AN ENDPOINT ROW, which is the fix that first suggests
    # itself and is the worse defect. Measured: `eligible_test_cases` returns 12 cases for a
    # URL carrying a parameter, so the probe would become a target for every catalogue check
    # — SQL injection, XSS, the client-side cases — at a URL the operator nominated for ONE
    # out-of-band payload, and those 12 would draw from a URL budget shared with the real
    # surface. A case testable somewhere it should not be is worse than a case nobody can see.
    #
    # So the probes are enumerated HERE, beside the endpoint rows and not inside them.
    # `integration_endpoints` is untouched, so nothing else that reads it changes: measured on
    # both recorded real stores, zero rows move.
    covered = {pair(row["url"], name, row["identity_id"])
               for row in grouped.values() for name in (row["parameters"] or [""])}

    out = []
    for row in list(grouped.values()) + [p for p in probes
                                         if pair(p["url"], p["parameters"][0],
                                                 p["identity_id"]) not in covered]:
        sources = sorted(row["sources"])
        names = row["parameters"] or [""]
        for name in names:
            records = list(seen.get(pair(row["url"], name, row["identity_id"]), []))
            for kind, case, reason, parameters in case_wide.get(row["identity_id"], []):
                # A case-wide refusal names the parameters it refused; a budget
                # truncation names none and applies to that case's OWN pairs.
                if parameters and name not in parameters:
                    continue
                # And only to pairs the case could have tested. Applying a truncation to
                # everything in the inventory labelled 41 pairs `not_run` on a Juice Shop
                # run where no selected case was eligible for them at all — "the budget
                # cut this" and "nothing selected tests this" are different answers, and
                # only the second is true there.
                # AN ARM-WIDE TRUNCATION IS ELIGIBLE FOR EVERYTHING, unlike a catalogue
                # case. The filter below exists because applying a case's budget truncation
                # to the whole inventory labelled 41 pairs `not_run` on a run where no
                # selected case was eligible for them — "the budget cut this" and "nothing
                # selected tests this" are different answers. The surface read is the
                # exception that proves the rule: its scope IS every in-scope URL, so its
                # truncation applies to every pair and `ERLIK-SURFACE-READ` is deliberately
                # absent from `eligible_test_cases`, which would otherwise have dropped it.
                # `eligible` is the declared-probe rows' own answer. `eligible_test_cases`
                # lists what the curl dialect can execute and deliberately never names a
                # COLLECTOR_CASE, so asking it about a probe row would filter out the very
                # case that owns the probe — including that case's own budget truncation.
                eligible = row.get("eligible")
                if eligible is None:
                    eligible = eligible_test_cases(row["url"], row["method"],
                                                   [name] if name else ())
                if kind not in ARM_WIDE_OBSERVATIONS and case and case not in eligible:
                    continue
                records.append((kind, case, reason, parameters))

            # An inferred route outranks a case-wide budget truncation. Nothing was
            # ever going to probe it — it is withheld from `parameters_by_url` by
            # design — so reporting `not_run` would tell an operator that a larger
            # `max_urls` covers it, and a larger budget changes nothing here. Only a
            # URL-SPECIFIC observation can override it, because that means something
            # did reach it after all.
            url_specific = bool(seen.get(pair(row["url"], name, row["identity_id"])))
            # A FINDING ON THIS PAIR OUTRANKS EVERY OTHER STATE, and it used to be reachable
            # only from `answered` — that is, only when a catalogue case had probed the pair and
            # got bytes back. The cross-arm authorization findings do not come out of a case;
            # they come from comparing what three arms recorded. So measured on a real run, the
            # operation carrying a HIGH `confirmed` privilege crossing was reported `not_run`,
            # which reads as outstanding work on the very pair the lane was most sure about.
            matched = findings.get(pair(row["url"], name, row["identity_id"]))
            if "javascript" in sources and not url_specific and not matched:
                state, case, reason = "inferred", "", (
                    "read out of a JavaScript body and not been requested by anything; "
                    "select it to test it")
            elif not records:
                state, case, reason = "not_attempted", "", (
                    "no catalogue check ran against this pair — it may not have been "
                    "selected, or no selected case tests a parameter")
                if row.get("eligible") is not None:
                    # A DECLARED PROBE WITH NO RECORD IS NOT "nothing tests this". The
                    # operator nominated it, so the only question is whether the case that
                    # drives it was selected — and the sentence above would blame the
                    # selection of cases that have nothing to do with it.
                    reason = row["declared_reason"]
                if matched:
                    state, reason = "verified", (
                        "a finding was made on this pair without a catalogue check running "
                        "against it: " + ", ".join(sorted(set(matched))))
            else:
                # AN ARM-WIDE RECORD LOSES EVERY TIE, and is APPENDED rather than chosen.
                #
                # Ranking on state alone let one displace a better reason: measured on the
                # real run, the 459 `not_run` rows carried "161 of 182 in-scope URLs were not
                # tested; this check's share of the budget is …" from `WSTG-INFO-03`, and
                # indexing the surface read's truncation replaced it with "2 of 30 object
                # instances … were not fetched" — the same state, a narrower fact, and it won
                # on insertion order. So the case-specific reason stays primary and the
                # arm-wide one is added to it.
                #
                # Adding rather than choosing is also the honest shape. The two say different
                # things: one catalogue case's share of the budget ran out, AND this arm's
                # surface read did not reach this URL — and it is the second that decides
                # whether the cross-arm authorization checks had any evidence here, which is
                # the question the report exists to answer.
                def _rank(record):
                    return (COVERAGE_STATES.index(state_of(record[0])),
                            record[0] in ARM_WIDE_OBSERVATIONS)

                ranked = sorted(records, key=_rank)
                kind, case, reason, _ = ranked[0]
                state = state_of(kind)
                arm_wide = [r for k, _c, r, _p in records
                            if k in ARM_WIDE_OBSERVATIONS and r and r != reason]
                if matched:
                    state = "verified"
                    reason = "a finding came out of this pair: " + ", ".join(sorted(set(matched)))
                elif state == "answered":
                    reason = reason or _ANSWERED_CAVEAT
                # ONLY WHERE NOTHING PROBED THE PAIR. `not_run` and `not_attempted` are the
                # two states that say "not reached" without saying what stopped the
                # authorization checks from seeing it. `unreachable` and `refused` are the
                # opposite: a check ran and decided something specific about this pair, and an
                # arm-wide truncation elsewhere does not explain its verdict — appending there
                # is noise, which a first version of this did for both.
                if arm_wide and state in ("not_run", "not_attempted"):
                    reason = "; also ".join([reason or ""] + sorted(set(arm_wide))).lstrip("; ")
            # THE ARM'S OWN STATE, on every row it could not speak for. Outside the `else`
            # above because a pair with NO record at all is the case that most needs it — that
            # is the branch whose reason blames the case selection.
            if state in ("not_run", "not_attempted") and row["identity_id"] in incomplete:
                stages = ", ".join(f"{adapter}: {status}" + (f", {why}" if why else "")
                                   for adapter, status, why in incomplete[row["identity_id"]])
                reason = (f"{reason or ''}; also this arm did not finish reading ({stages}), so "
                          f"a pair it never reached is not evidence that nothing tests it"
                          ).lstrip("; ")
            out.append({
                "operation": operation_key(row["url"], row["method"], [n for n in names if n]),
                "url": row["url"], "method": row["method"], "identity": row["identity_id"],
                "parameter": name, "sources": sorted(sources),
                "test_case_id": case, "state": state, "reason": reason,
            })
    return out


# Refusals `compare_arms` reports that are about ONE OPERATION, not the session. The
# cross-arm checks skip those operations instead of abandoning the comparison; see
# `compare_arms` for the measurement that forced the distinction.
PER_OPERATION_REFUSALS = ("arms_share_one_identity", "different_operations",
                          "per_arm_value_in_operation")


async def compare_arms(session_id, first_identity, second_identity) -> dict:
    """Do two identities describe the same surface? The R0 exit gate.

    §3 of docs/future-plan.md moved "identity isolation demonstrated" into R0
    because a differential run reported nine findings on a vulnerable DVWA level
    and one on a hardened one while the two arms shared ONE of eight
    (url, parameter) pairs. E-008: "a run that proves this by comparing arm
    surfaces is the demonstration R0 needs."

    WHAT THIS DOES NOT ESTABLISH, stated here because it is the trap: surface
    agreement is not differential validity. An independent pass measured a live
    run scoring a perfect shared-surface fraction of 1.0 in which **all eight
    probe sets received zero bytes** — the arms agreed about what existed and
    neither tested any of it. So `comparable` means "these two arms describe the
    same surface", never "a difference between their findings is about the
    application". Reach is a property of execution, which this function cannot
    see, and §E-030 records that the lane's own emptiness detector does not fire
    on a refusal either: a DVWA probe refused for want of a token answers HTTP 200
    with 389 bytes of PHP warnings.

    It refuses four things it CAN see, each because a run produced a wrong answer
    without it:

      - the two arms are one identity. Comparing an identity with itself agrees
        perfectly and proves nothing.
      - an operation only one arm saw. The original defect.
      - an operation both arms saw at DIFFERENT concrete URLs. This is the one the
        operation key introduces: keying on the injectable surface is what makes
        the DVWA arms agree, and it also means each arm may still have issued a
        different request — the hardened arm's carrying a single-use token that
        was stale by the time it ran. The URLs are reported with their values
        MASKED, because a companion value is target-controlled text and the
        divergence is in the field, not the secret.
      - no shared operations at all. Two arms that discovered nothing agree
        vacuously, and an empty intersection is the commonest way this gate gets
        reported as passed.
    """
    from urllib.parse import parse_qsl, urlsplit

    def shape(url: str) -> tuple:
        """A URL's query FIELDS, values discarded. What differs, not the secret."""
        return tuple(sorted(name for name, _ in parse_qsl(urlsplit(url).query)))

    left = await operations(session_id, first_identity)
    right = await operations(session_id, second_identity)
    only_left = sorted(set(left) - set(right))
    only_right = sorted(set(right) - set(left))
    shared = sorted(set(left) & set(right))

    # Same operation, different request. Reported per operation, with the fields
    # that differ named and every value withheld.
    per_arm_value = []
    for key in shared:
        first_urls = {o["url"] for o in left[key]["observations"]}
        second_urls = {o["url"] for o in right[key]["observations"]}
        if first_urls == second_urls:
            continue
        fields = sorted({f for url in first_urls ^ second_urls for f in shape(url)})
        per_arm_value.append({
            "operation": key,
            "differing_query_fields": fields,
            "detail": ("both arms reached this operation but not at the same URL; "
                       "each arm issued its own request, so a difference between "
                       "their results may be about the request and not the target"),
        })

    # WHY an operation is one-sided, when the data can say. "An operation only one
    # arm saw" is the sentence the lane prints both when a crawl missed a page and
    # when the application genuinely moved the surface, and an operator cannot act
    # on those the same way. E-008 asks for differences to be DISTINGUISHABLE.
    #
    # Measured on DVWA, and the two cases this separates: `/vulnerabilities/brute/`
    # is a GET form at `low` and a POST form at `impossible`, so the GET operation
    # genuinely disappears; `/vulnerabilities/csrf/` gains a `password_current`
    # input at `impossible`, so the injectable surface genuinely grows. Neither is a
    # defect in the lane, and both look identical to a set difference.
    def classify(entry, others, side):
        at_endpoint = [o for o in others.values() if o["endpoint"] == entry["endpoint"]]
        if not at_endpoint:
            return {"kind": "not_reached_by_other_arm", "operation": entry["operation"],
                    "endpoint": entry["endpoint"], "seen_by": side,
                    "detail": "the other arm reached nothing at this endpoint"}
        methods = {entry["method"].upper()} | {o["method"].upper() for o in at_endpoint}
        if entry["method"].upper() not in {o["method"].upper() for o in at_endpoint}:
            return {"kind": "method_changed", "operation": entry["operation"],
                    "endpoint": entry["endpoint"], "seen_by": side,
                    "methods": sorted(methods),
                    "detail": "both arms reached this endpoint, by different methods"}
        same_method = [o for o in at_endpoint
                       if o["method"].upper() == entry["method"].upper()]
        theirs = set().union(*(set(o["parameters"]) for o in same_method))
        mine = set(entry["parameters"])
        return {"kind": "parameters_changed", "operation": entry["operation"],
                "endpoint": entry["endpoint"], "seen_by": side,
                "only_in_first": sorted(mine - theirs) if side == "first" else sorted(theirs - mine),
                "only_in_second": sorted(mine - theirs) if side == "second" else sorted(theirs - mine),
                "detail": "both arms reached this endpoint with a different injectable surface"}

    divergence = ([classify(left[k], right, "first") for k in only_left]
                  + [classify(right[k], left, "second") for k in only_right])

    # DID THE TWO ARMS ASSESS THE SAME API? `SchemaInput` accepts a URL as well as
    # inline content, and `schema_file` fetches that document through the egress
    # proxy — which injects the identity's headers and cookies. So a target serving
    # a different OpenAPI document per role forks the schema-derived operations
    # exactly as a rendered form does.
    #
    # The information already existed and nothing compared it: the ZAP and
    # Schemathesis adapters both record `schema_sha256` in their stage metadata.
    # Detection rather than prevention, deliberately — refusing a per-identity fetch
    # would break a schema that is itself behind authentication, and fetching it once
    # anonymously would break it differently. An absent digest on ONE side is not
    # agreement either: a target that serves the document to one identity and refuses
    # it to another has given the arms different surfaces.
    async def schema_digest(identity_id):
        digests = set()
        for row in await db.rows(
                "SELECT result FROM integration_stages WHERE session_id=? AND identity_id=?",
                (session_id, identity_id)):
            try:
                metadata = json.loads(row["result"] or "{}").get("metadata") or {}
            except (ValueError, TypeError):
                continue
            if metadata.get("schema_sha256"):
                digests.add(metadata["schema_sha256"])
        return sorted(digests)

    schema = {}
    for identity_id in (first_identity, second_identity):
        found = await schema_digest(identity_id)
        if found:
            schema[identity_id] = found[0] if len(found) == 1 else found

    # The arms' declared roles and tenants, so a reader can see WHAT boundary the
    # differential crosses. E-011's acceptance names cross-user, cross-tenant and
    # privileged-function violations, and without the labels "cross-tenant" has to be
    # inferred from two opaque identity handles. The lane does not interpret them — an
    # operator chooses them — it reports them.
    roles, tenants = {}, {}
    for identity_id in (first_identity, second_identity):
        if identity_id == "anonymous":
            roles[identity_id] = "anonymous"
            continue
        try:
            from .security import SecretStore
            declared = SecretStore().get(identity_id)
        except Exception:
            continue
        if declared.get("role"):
            roles[identity_id] = declared["role"]
        if declared.get("tenant"):
            tenants[identity_id] = declared["tenant"]

    reasons = []
    if schema and (len(schema) != 2 or len(set(map(str, schema.values()))) != 1):
        reasons.append("different_schema")
    if first_identity == second_identity:
        reasons.append("arms_share_one_identity")
    if only_left or only_right:
        reasons.append("different_operations")
    if per_arm_value:
        reasons.append("per_arm_value_in_operation")
    if not shared:
        reasons.append("no_shared_operations")

    return {
        "identities": [first_identity, second_identity],
        "shared": shared,
        "only_in_first": only_left,
        "only_in_second": only_right,
        "per_arm_value_in_operation": per_arm_value,
        # Each one-sided operation with a reason, where the data supports one.
        "divergence": divergence,
        # The schema digest each arm was assessed against, when one was recorded.
        "schema": schema,
        "roles": roles,
        "tenants": tenants,
        # True only when BOTH arms declared a tenant and the two differ — an undeclared
        # tenant is not a tenant boundary, and guessing one would invent the finding.
        "cross_tenant": len(tenants) == 2 and len(set(tenants.values())) == 2,
        "comparable": not reasons,
        "refused_because": reasons,
        # Stated as a fraction because that is how the original defect was
        # reported — "one of eight" — and a reader should be able to see the same
        # shape improve rather than read a boolean.
        "summary": (f"{len(shared)} of {len(set(left) | set(right))} "
                    f"operations seen by both"),
        # Not a disclaimer. A caller that treats surface agreement as differential
        # validity reproduces the defect measured above.
        "establishes": "that the two arms describe the same surface, and nothing "
                       "about whether either arm reached it",
    }


# At most this many instances per collection. The bound is the flood control: a measured
# Juice Shop run holds 15 collections in its surface-read evidence and several return six or
# more rows, so an unbounded derivation would be 90+ extra requests per arm.
MAX_DERIVED_PER_COLLECTION = 3

# An id is used ONLY if it is structurally an identifier. Explicit `[0-9]`, never `\d`,
# because `\d` matches Arabic-Indic `١` and fullwidth `１` — which are not ASCII digits and
# would reach a path segment as multi-byte UTF-8.
_SAFE_ID = re.compile(
    r"\A(?:[0-9]{1,12}"                                      # a bounded integer key
    r"|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
    r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\Z")                    # or a canonical UUID


def safe_object_id(value) -> str:
    """The id as a path segment, or "" if it is not safely one.

    THE TARGET CHOOSES THESE VALUES, which is the sharpest hazard this codebase has: §the
    threat model records a planted `<a href="/search?219359=1">` turning a discovered
    parameter name into a CRITICAL template-injection finding against an application with no
    template engine. An id read out of a response body is the same kind of text.

    So the rule is a whitelist of SHAPES, not a blacklist of characters: a bounded run of
    ASCII digits, or a canonical UUID. Nothing else is an identifier for these purposes, and
    every injection shape — a dot segment, a slash, a percent escape, a space, a unicode
    digit, a URL — fails it. `True` needs no special case even though `isinstance(True, int)`
    is True in Python: it renders as "True", which is not an id shape.
    """
    if not isinstance(value, (int, str)):
        return ""
    text = value if isinstance(value, str) else str(value)
    return text if _SAFE_ID.match(text) else ""


# Headers that differ between two identical responses, so they cannot be part of "the same
# response". Everything else IS compared, including `Set-Cookie`, `Allow`, the CORS headers
# and the security headers — those are what the catalogue's header-reading evaluators decide
# on, and leaving them out would let pruning lose a finding that lives entirely in a header.
# Measured on a real run: comparing the stable headers as well as the body changed nothing
# (35 groups and 37 pruned either way), so the blind spot closes for free.
_VOLATILE_HEADERS = re.compile(
    r"(?i)^(date|content-length|etag|age|expires|last-modified|keep-alive|connection"
    r"|x-request-id|x-correlation-id|x-runtime|x-response-time|server-timing|report-to):")


def _signature(status, header_lines, body: str) -> str:
    """What makes two responses the same response: the status, the stable headers, the body."""
    stable = sorted(line.strip() for line in header_lines
                    if line.strip() and not _VOLATILE_HEADERS.match(line.strip()))
    material = f"{status}\n" + "\n".join(stable) + "\n\n" + (body or "")
    return hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()


def response_signature(capture: str) -> str:
    """The signature of a raw `curl -i` capture."""
    return _signature(http_capture.status(capture),
                      http_capture.headers(capture).splitlines()[1:],
                      http_capture.body(capture))


def worker_response_signature(response: dict) -> str:
    """The signature of the dict `worker.request` returns.

    The same rule by construction rather than by a second implementation: the adapter that
    evaluates SecurityAssertions never sees a raw capture, and two ways of deciding whether
    two responses are the same response would be one defect waiting to happen.
    """
    headers = (response or {}).get("headers") or {}
    return _signature(response.get("status"),
                      [f"{name}: {value}" for name, value in headers.items()],
                      response.get("body") or "")


def canonicality(url: str) -> tuple:
    """How canonical a spelling is, lowest first. Used to pick which of several spellings of
    one response survives.

    Alphabetical order picks the wrong one. Measured on DVWA, three spellings of one Apache
    resource that all return a byte-identical 5235-byte body:

        /./vulnerabilities/fi/?page=include.php     <- sorts first
        //vulnerabilities/fi/?page=include.php
        /vulnerabilities/fi/?page=include.php       <- the one the inventory knows about

    First-spelling-wins therefore kept a junk spelling and reported it as the representative of
    that response. Dot segments and empty segments are what make a spelling junk, so they rank
    last; length and then alphabetical order settle the rest, so the choice stays deterministic.
    """
    segments = (urlsplit(url).path or "/").split("/")
    # A TRAILING SLASH IS NOT JUNK. `/` splits to ["", ""], so counting every empty segment
    # penalised the ROOT as if it were a junk spelling and handed the survivor slot to
    # `/about` — and `/` is the one member of Juice Shop's 36-strong shell group where the
    # path-appending cases find anything at all (`/robots.txt`, `/.well-known/security.txt`).
    # Caught by the test that asserts `/` survives.
    if len(segments) > 1 and segments[-1] == "":
        segments = segments[:-1]
    odd = sum(1 for segment in segments[1:] if segment in ("", ".", ".."))
    return (odd, len(url), url)


def indistinct_urls(captures, keep=()) -> dict:
    """URLs whose response the lane has ALREADY SEEN, mapped to the URL that had it first.

    WHY THIS IS THE BINDING CONSTRAINT. Everything the lane does is rationed by `max_urls`,
    and on a real three-arm Juice Shop run HALF the surface read's budget bought the same
    document twice. 36 of 72 non-empty 2xx reads were byte-identical: `/`, `/Edge/`,
    `/Trident/`, `/.json`, `/%5C/index.html`, `/2fa/enter`, `/about`, `/accounting`,
    `/address/create` and 27 more all answer with the single-page application's shell, because
    an SPA serves `index.html` for any route its server does not know. `/Edge/` and `/Trident/`
    are browser-detection regex fragments katana mined out of a JavaScript bundle. A catalogue
    case probing those for injection cannot find anything, and a coverage report listing them
    as untested reads as work outstanding when there is none.

    THE RULE IS A COMPARISON, NOT A GUESS. Two URLs that answered with the same status and the
    same bytes produced one observation; the second is a spelling of the first. That also
    folds in the ordinary case — `/api/Feedbacks` and `/api/Feedbacks/` are separate endpoint
    rows with identical bodies.

    AN EMPTY BODY IS NOT EVIDENCE, and this is the clause a real measurement forced. On DVWA
    six genuinely different static files — `detail.png`, `overview.png`, `main.css`,
    `logo.png` — grouped together because the captures came from an `OPTIONS` probe and every
    body was 0 bytes. Pruning them would have discarded four real assets, so a body must carry
    something before its absence of difference means anything.

    Only 2xx, because a shared 401 or 404 is the application declining rather than answering,
    and every refusal looks alike.

    THE MOST CANONICAL SPELLING SURVIVES, not the first one read — see `canonicality`. And a URL
    in `keep` is never pruned: the caller passes the URLs it has discovered PARAMETERS for,
    because a spelling that carries a parameter is the one the lane knows something about.
    Measured on DVWA, both cases this protects: `/vulnerabilities/fi/` carries `page`, whose
    probe reads `/etc/passwd`, and `/vulnerabilities/xss_r/` carries `name`, whose probe
    reflects unencoded — and each is byte-identical to junk spellings that sort first. The
    parameter cases already build their targets from `parameters_by_url` and never consult this
    result, so this is belt and braces rather than the only guard; it makes the safety
    independent of that separation holding.

    "The same response" includes the STABLE HEADERS, not only the body — see
    `response_signature`. `WSTG-SESS-02` decides on `Set-Cookie` and `WSTG-CONF-06` on
    `Allow`, so a rule that compared bodies alone could prune the only URL whose finding lives
    in a header.
    """
    protected = set(keep)

    def outranks(candidate, incumbent) -> bool:
        """Should `candidate` replace `incumbent` as the spelling that survives?"""
        if (candidate in protected) != (incumbent in protected):
            return candidate in protected     # a parameter carrier outranks any spelling
        return canonicality(candidate) < canonicality(incumbent)

    survivor, duplicates = {}, {}
    for url, capture in captures:
        if not http_capture.ok(capture):
            continue
        if not http_capture.body(capture).strip():
            continue
        key = response_signature(capture)
        incumbent = survivor.get(key)
        if incumbent is None:
            survivor[key] = url
            continue
        if url == incumbent:
            continue
        if outranks(url, incumbent):
            survivor[key] = url
            duplicates[incumbent] = url
            # Everything that pointed at the old incumbent now points at the new survivor,
            # or a reader would be sent to a URL that is itself recorded as a duplicate.
            for earlier, same in list(duplicates.items()):
                if same == incumbent and earlier != url:
                    duplicates[earlier] = url
            duplicates.pop(url, None)
        else:
            duplicates[url] = incumbent
    # No filter for `protected` here: `outranks` already guarantees a protected URL wins
    # whenever it meets a plain spelling, so it can never become a key. A filter would be code
    # that cannot fire, which reads as a protection that is not there.
    return duplicates


def breadth_first(per_collection) -> list:
    """Every collection's first instance before any collection's second.

    Depth-first spends a tight budget on whichever collections sort first: measured on a real
    run, 30 candidates against a share of 28 dropped exactly `/api/Users/2` and
    `/api/Users/3`, because `/api/Users` comes last alphabetically — and `/api/Users/1` is the
    one instance that carries a known violation. Round-robin reaches the interesting
    collection whatever its name.
    """
    out, seen, depth = [], set(), 0
    longest = max((len(group) for group in per_collection), default=0)
    for depth in range(longest):
        for group in per_collection:
            if depth < len(group) and group[depth] not in seen:
                seen.add(group[depth])
                out.append(group[depth])
    return out


def instance_urls(collection_url: str, body: str,
                  limit: int = MAX_DERIVED_PER_COLLECTION) -> tuple:
    """Instance URLs a collection response names, by its own row ids.

    WHY THIS EXISTS. The lane discovers COLLECTIONS and not INSTANCES, and object-level
    authorization lives on instances. Measured on a real three-arm Juice Shop run:
    `/api/Users` and `/api/Cards` have endpoint rows, `/api/Users/1` and `/rest/basket/1`
    have none, and only 5 of 234 discovered URLs contain a numeric path segment. Three of
    the four known violations were unreachable for that reason alone.

    HOW THE URL CANNOT ESCAPE. The scheme and netloc are COPIED from the collection, the
    query and fragment are dropped, and the id is appended as one path segment after
    `safe_object_id` has restricted it to digits or a UUID. So a derived URL is always on the
    collection's own origin, always under its own path, and always a plain GET of one more
    segment. The query is dropped deliberately: a collection's filter is not an instance's.

    It will not derive from a URL whose last segment is already an id, so instances do not
    chain into `/api/Users/1/1`.
    """
    import posixpath

    parts = urlsplit(collection_url)
    path = (parts.path or "/").rstrip("/")
    # THE COLLECTION'S OWN PATH IS ALSO A TARGET-SUPPLIED STRING, and it was the real lever.
    # Appending to it is only sound if the path is already what curl will send. Measured on
    # the wire against DVWA with the pinned worker curl: a collection
    # `http://h/d22/x/../..` produced the recorded URL `/d22/x/../../7` while apache logged
    # `GET /7` — so the request was neither under the collection's path nor the URL written
    # into the endpoint row and the evidence key. `EgressPolicy.check` also matches
    # `excluded_paths` and `ends_the_session` against the RAW path, so `/x/../../logout`
    # passes that check while curl sends `/logout`.
    #
    # A path that needs normalising is not a sound base to extend, and an inventory should
    # not hold one: refused outright rather than normalised, because normalising would make
    # the lane probe a URL the crawler never reported. `%` likewise — an encoded separator in
    # a path about to gain a segment is ambiguous, and no path in the measured inventories
    # contains one.
    if "%" in path or posixpath.normpath(path or "/") != (path or "/"):
        return ()
    if safe_object_id(path.rsplit("/", 1)[-1]):
        return ()                   # already an instance
    try:
        document = json.loads(body)
    except (ValueError, TypeError):
        return ()
    rows = document.get("data") if isinstance(document, dict) else document
    if not isinstance(rows, list):
        return ()
    out, seen = [], set()
    for row in rows:
        if len(out) >= limit:
            break               # checked BEFORE appending, so limit=0 derives nothing
        if not isinstance(row, dict):
            continue
        identifier = safe_object_id(row.get("id"))
        if not identifier or identifier in seen:
            continue
        seen.add(identifier)
        out.append(urlunsplit((parts.scheme, parts.netloc, f"{path}/{identifier}", "", "")))
    return tuple(out)


def eligible_test_cases(url, method="GET", parameters=()):
    """Catalogue checks with a supported deterministic HTTP execution path.

    `parameters` is what was observed on THIS endpoint. A case that
    interpolates {{parameter}} is reported eligible only when there is one to
    give it — otherwise it would run the degenerate probe the unfilled-field
    rule exists to prevent.
    """
    if method != "GET":
        return []
    runnable = executable_test_cases()
    if parameters:
        return list(runnable)
    from orchestrator.testcase.loader import load_catalog
    catalog = load_catalog()
    return [case_id for case_id in runnable
            if not (catalog.get(case_id) and case_needs_parameter(catalog[case_id]))]
