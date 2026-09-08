"""Identity-specific inventory shared by discovery and downstream testing."""
from functools import lru_cache
from urllib.parse import urldefrag
from orchestrator.engagement import looks_injectable
from . import persistence as db
from .egress_policy import EgressPolicy


async def seeds(context, policy):
    rows = await db.rows("SELECT url,method FROM integration_endpoints WHERE session_id=? AND identity_id=? ORDER BY url,method",
                         (context.session_id, context.identity_id))
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
LANE_TARGET_FIELDS = frozenset({"url"})

# Executed through the Interactsh collector rather than the curl dialect, so it
# is selectable without being parseable here (see CatalogueAdapter.run).
COLLECTOR_CASES = ("WSTG-INPV-19",)

# Placeholders that are SUPPOSED to render empty here: identity is attached
# per stage by the proxy, never by the case (curl_request refuses a case that
# carries its own credentials). Every other empty placeholder means the command
# is not the command its author wrote.
IDENTITY_FIELDS = frozenset({"cookie", "auth_header"})

_PROBE_URL = "https://erlik-capability-probe.invalid/"


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
        if field.startswith("step.") or field in IDENTITY_FIELDS:
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

    target = {"url": url}
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


def eligible_test_cases(url, method="GET"):
    """Catalogue checks with a supported deterministic HTTP execution path."""
    return list(executable_test_cases(url)) if method == "GET" else []
