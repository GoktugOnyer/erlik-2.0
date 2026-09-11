"""Identity-specific inventory shared by discovery and downstream testing."""
import hashlib
import json
import re
from functools import lru_cache
from urllib.parse import unquote_plus, urldefrag, urlsplit, urlunsplit
from orchestrator import http_capture
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


async def arm_responses(session_id, identity_id) -> tuple[dict, set]:
    """What one arm recorded, keyed by the REQUEST it recorded it for.

    Returns `({(url, test_case, step, parameter): output}, ambiguous)`.

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
    for key in ambiguous:
        out.pop(key, None)
    return out, ambiguous


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
    if not caller_subject:
        refused.append("caller_has_no_subject_id")
    if not owner_subject:
        refused.append("owner_has_no_subject_id")
    anonymous = _arm_name(anonymous)
    if anonymous is None:
        # The clause cannot be evaluated without the arm, and a clause nobody ran is not
        # a clause that passed.
        refused.append("no_anonymous_arm")

    surfaces = await compare_arms(session_id, caller, owner)
    refused += [reason for reason in surfaces["refused_because"]
                if reason not in PER_OPERATION_REFUSALS]

    caller_saw, caller_split = await arm_responses(session_id, caller)
    owner_saw, owner_split = await arm_responses(session_id, owner)
    anonymous_saw, anonymous_split = ((await arm_responses(session_id, anonymous))
                                      if anonymous is not None else ({}, set()))
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
            corroborating = owner_saw.get(key, "")
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
                "caller": caller, "caller_subject_id": caller_subject,
                "owner": owner, "asserted_owner": asserted,
                "detail": (f"the caller is declared to be {caller_subject!r} and the "
                           f"application attributed this object to {asserted!r}, which the "
                           f"declared owner corroborated; an anonymous arm did not receive "
                           f"it, so it is not published content"),
            })

    return {
        "findings": findings,
        "refused_because": refused,
        "checked": checked,
        "suppressed_declared_access": allowed,
        "not_comparable": not_comparable,
        "urls_not_shared_by_both_arms": not_shared,
        # Instances the lane derived, excluded because this check would read its own input
        # back as the asserted owner. The function-level check uses them.
        "derived_urls_excluded": len(invented),
        "ambiguous_evidence": ambiguous,
        "surfaces": surfaces["summary"],
        "establishes": ("nothing, when `refused_because` is non-empty — an empty findings "
                        "list is not a clean result unless the comparison actually ran"),
    }


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
        entitled = _declared_access(SecretStore().get(unprivileged)
                                   if unprivileged not in (None, "", "anonymous") else {})
    except Exception:
        entitled = ()
    high, low = role_of(privileged), role_of(unprivileged)
    if not high or not low:
        # Guessing which of two identities is privileged — from a name, from which was
        # passed first — would let the lane report a finding off its own assumption.
        refused.append("role_not_declared")
    elif high == low:
        # A privilege crossing needs two privilege levels. Two identities the operator
        # labelled the same way is a configuration mistake, and a finding drawn from it
        # would be reporting that mistake as a vulnerability. This also subsumes the
        # degenerate case of one identity passed twice.
        refused.append("arms_share_a_role")
    anonymous = _arm_name(anonymous)
    if anonymous is None:
        refused.append("no_anonymous_arm")

    surfaces = await compare_arms(session_id, privileged, unprivileged)
    refused += [reason for reason in surfaces["refused_because"]
                if reason not in PER_OPERATION_REFUSALS]

    privileged_saw, high_split = await arm_responses(session_id, privileged)
    unprivileged_saw, low_split = await arm_responses(session_id, unprivileged)
    anonymous_saw, anonymous_split = ((await arm_responses(session_id, anonymous))
                                      if anonymous is not None else ({}, set()))
    ambiguous = len(high_split | low_split | anonymous_split)
    if anonymous is not None and not anonymous_saw:
        refused.append("anonymous_arm_did_not_run")

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
            # 1. The privileged arm received the marked data, so there is a privileged
            #    function here to cross into. Without this the operator's declaration
            #    alone decides, and a marker naming something the endpoint never returns
            #    would be reported against every endpoint that denies the anonymous arm.
            if not carries(response):
                continue
            # 2. The unprivileged arm received the SAME marked data. This is the crossing,
            #    and it is also what makes a denial — in any dialect, at any status — not
            #    a finding, and a dead session not a finding either.
            if not carries(unprivileged_saw.get(key, "")):
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
                "privileged": privileged, "privileged_role": high,
                "unprivileged": unprivileged, "unprivileged_role": low,
                # The marker is NOT echoed. It is operator text describing the
                # application's private data — a real customer's address, an internal
                # identifier — and a finding travels into an export. The digest is here
                # so two markers used in one session can be told apart.
                "marker_sha256": hashlib.sha256(needle.encode()).hexdigest()[:12],
                "marker_not_quoted": ("the declared marker identifies privileged data and "
                                      "is recorded as a digest, not as text"),
                "detail": (f"the operator declared {low!r} to be less privileged than "
                           f"{high!r}; both arms received the marked data from this "
                           f"operation, and an anonymous arm asked for it and did not "
                           f"receive it, so it is not published content"),
            })

    return {
        "findings": findings,
        "refused_because": refused,
        "checked": checked,
        # Named and listed, not counted silently: these operations were NOT evaluated,
        # and a report that omitted them would read as a clean result for them.
        "skipped_reflected_marker": reflected,
        # Operations the operator declared this identity entitled to, via
        # `Identity.may_access`. Listed, because a suppression nobody can see is
        # indistinguishable from a check that never looked.
        "suppressed_declared_access": allowed,
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
                        "anonymous arm did not is the application's answer"),
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
