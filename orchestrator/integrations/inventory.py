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
    rows = await db.rows("SELECT url,method FROM integration_endpoints WHERE session_id=? AND identity_id=? ORDER BY url,method",
                         (context.session_id, context.identity_id))
    if not include_form_actions:
        actions = await form_urls(context)
        rows = [row for row in rows if row["url"] not in actions]
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
    return {row["url"] for row in rows
            if "form" in json.loads(row.get("sources") or "[]")}


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
        entry = found.setdefault(key, {
            "operation": key, "method": row["method"],
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

    reasons = []
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
