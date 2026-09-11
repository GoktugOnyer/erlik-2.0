"""Identity-specific inventory shared by discovery and downstream testing."""
import json
import re
from functools import lru_cache
from urllib.parse import urldefrag, urlsplit, urlunsplit
from orchestrator.engagement import looks_injectable
from .contracts import PARAMETER_NAME, parameter_names
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
COVERAGE_STATES = ("verified", "answered", "unreachable", "refused", "not_run",
                   "inferred", "not_attempted")

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
        if case_needs_parameter(tc):
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
    }


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
            if kind not in ("test_case", "test_case_unreachable", "test_case_not_run",
                            "test_case_truncated", "parameter_refused", "form_url_withheld"):
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
                "parameter_refused": "refused", "form_url_withheld": "refused"}[kind]

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

    out = []
    for row in grouped.values():
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
                if case and case not in eligible_test_cases(
                        row["url"], row["method"], [name] if name else ()):
                    continue
                records.append((kind, case, reason, parameters))

            # An inferred route outranks a case-wide budget truncation. Nothing was
            # ever going to probe it — it is withheld from `parameters_by_url` by
            # design — so reporting `not_run` would tell an operator that a larger
            # `max_urls` covers it, and a larger budget changes nothing here. Only a
            # URL-SPECIFIC observation can override it, because that means something
            # did reach it after all.
            url_specific = bool(seen.get(pair(row["url"], name, row["identity_id"])))
            if "javascript" in sources and not url_specific:
                state, case, reason = "inferred", "", (
                    "read out of a JavaScript body and not been requested by anything; "
                    "select it to test it")
            elif not records:
                state, case, reason = "not_attempted", "", (
                    "no catalogue check ran against this pair — it may not have been "
                    "selected, or no selected case tests a parameter")
            else:
                ranked = sorted(records, key=lambda r: COVERAGE_STATES.index(state_of(r[0])))
                kind, case, reason, _ = ranked[0]
                state = state_of(kind)
                if state == "answered":
                    matched = findings.get(pair(row["url"], name, row["identity_id"]))
                    if matched:
                        state = "verified"
                        reason = "a finding came out of this probe: " + ", ".join(sorted(set(matched)))
                    else:
                        reason = reason or _ANSWERED_CAVEAT
            out.append({
                "operation": operation_key(row["url"], row["method"], [n for n in names if n]),
                "url": row["url"], "method": row["method"], "identity": row["identity_id"],
                "parameter": name, "sources": sorted(sources),
                "test_case_id": case, "state": state, "reason": reason,
            })
    return out


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
