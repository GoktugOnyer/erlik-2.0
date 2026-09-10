"""Pydantic schema for YAML-defined test cases."""

from typing import Literal, Optional, Any
from pydantic import BaseModel, Field, field_validator


class TargetSchema(BaseModel):
    """Declares what the caller must supply to run this test case.

    `required_any` is a list of GROUPS, each satisfied by any one member. It
    exists because a credential's material is not interchangeable: a bearer
    token and a session cookie both authenticate, but a cookie in a Bearer
    header authenticates nothing, so they cannot share one field name. Before
    it, WSTG-AUTHZ-04 required `low_priv_token`/`high_priv_token` and was
    therefore bearer-only by construction — a named skip on every recorded run
    against DVWA and against any other cookie-authenticated application.

    Alternation rather than a neutral `low_priv_auth` field, because the step
    still has to know WHICH it got: the command sends `-H "Authorization:
    Bearer ..."` for one and `-b ...` for the other.
    """
    required: list[str] = Field(default_factory=list)
    required_any: list[list[str]] = Field(default_factory=list)
    optional: list[str] = Field(default_factory=list)


# WHICH TARGET FIELD NAMES THE ENDPOINT. Most cases call it `url`; the
# access-control cases call it `url_template`, because they substitute an
# object id into it. Four places read `target["url"]` directly and every one of
# them was blind to the second name:
#
#   runner, execute_tool call   the host-rewriter got target_url=None, decided
#                               the exec host itself, and rewrote
#                               http://juice-shop:3000/... to
#                               host.docker.internal:80 — connection refused,
#                               zero bytes, and WSTG-AUTHZ-04 duly reported
#                               "inconclusive" for three empty responses.
#                               DVWA escaped it only because `dvwa` is not in
#                               the rewriter's alias list.
#   runner, scope check         primary_url=None, so the case's real endpoint
#                               was never checked against scope
#   persistence                 the finding attached to no asset
#   plan `where`                the operator saw the bare host, not the endpoint
#
# One definition, so a third field name is added here and nowhere else.
ENDPOINT_FIELDS = ("url", "url_template")


def endpoint_of(target: dict | None) -> str:
    """The URL a target actually points at, whatever the case calls it."""
    t = target or {}
    for f in ENDPOINT_FIELDS:
        v = t.get(f)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


class Evaluator(BaseModel):
    """A single check applied to a step's output.

    Three general kinds:
      - regex: match `pattern` against tool stdout/stderr
      - status_code: tool's exit code is in `expect`
      - llm: ask the configured LLM to judge ambiguous output

    ...and four typed ones, which exist because the general kinds cannot state
    the thing being checked. A regex over a Set-Cookie line cannot say "this
    cookie is a session cookie and it is missing HttpOnly"; a regex over a CORS
    header cannot say "and the origin it reflected was MINE". Each of these
    reads structure the regex evaluator can only approximate:
      - count: the same marker appears >= `min_count` times (race conditions)
      - cors: an attacker origin was reflected AND credentials are allowed
      - idor: the low-priv response matches the privileged BASELINE
      - cookie_attributes: a session cookie lacks HttpOnly/SameSite/Secure

    ...and two BLIND ones, which read no content at all. A blind injection
    changes nothing a pattern can match, so the verdict comes from comparing
    steps: `boolean_differential` from two responses that should be the same
    and are not, `timing` from a delay that tracks the one that was asked for.
    Both take a `control` pair that decides whether the comparison is even
    valid — see the fields below.
    """
    type: Literal[
        "regex", "status_code", "llm",
        "count", "cors", "idor", "cookie_attributes",
        "boolean_differential", "timing",
    ]

    # Conditional execution. Supported names (kept tiny on purpose):
    #   no_finding_yet, has_finding, previous_success, previous_failure
    when: Optional[str] = None

    # regex evaluator
    pattern: Optional[str] = None
    case_insensitive: bool = True

    # status_code evaluator
    expect: Optional[list[int]] = None

    # count evaluator — how many occurrences of the marker constitute a hit
    min_count: int = 2

    # llm evaluator — the model is asked to return JSON
    instruction: Optional[str] = None

    # blind evaluators — a verdict made by COMPARING steps rather than by
    # reading one response, because a blind injection changes nothing a regex
    # can see.
    #
    # `control` names two steps that MUST come back the same. They carry
    # different benign values, so if their responses differ the endpoint
    # reflects or is simply unstable, and no comparison downstream means
    # anything — the evaluator reports nothing rather than guessing. This is
    # the same shape as WSTG-AUTHZ-04's anonymous probe: a control that says
    # when the test itself is invalid.
    control: Optional[list[str]] = None
    # The step whose response this one must DIFFER from.
    #
    # For `boolean_differential` the difference IS the verdict. For `regex` it
    # is an ATTRIBUTION check on a verdict the pattern already reached: the
    # evidence has to have been caused by this step's payload, not merely be
    # present on the page. Measured against real MySQL 8.0 on an unquoted
    # numeric sink, which is the most exploitable shape there is: a benign
    # value already produces `Unknown column 'x' in 'where clause'` and the
    # payload produces `You have an error in your SQL syntax`. A check that
    # asked "is the signature present at baseline" would suppress that
    # parameter; asking "did the response CHANGE" reports it, and still drops
    # the documentation page that carries the same signature either way.
    #
    # A named step that did not run or came back empty is treated as differing,
    # so a failed baseline request never silently suppresses a finding.
    differs_from: Optional[str] = None
    # How much slower than every control this step must be, in milliseconds,
    # before a delay counts as caused (timing).
    delay_ms: Optional[int] = None

    # What to do on a positive match
    emit_finding: Optional[dict[str, Any]] = None
    chain_to: Optional[list[str]] = None
    stop_after: bool = False

    # What this evaluator DISCOVERS, as {target_field: regex_capture_group}.
    #
    # target_schema.required declares what a case CONSUMES; this is the missing
    # other half. Without it a case can only ever answer yes/no, and the
    # deterministic lane fires every case at whatever URL it was handed —
    # which is the same "cannot reach the endpoint" bottleneck measured in the
    # agent lane, arrived at from the other direction.
    #
    #   produces: {endpoint: 1}   with pattern ^Disallow:\s*(\S+)
    #
    # Group 0 (the whole match) is allowed but rarely what you want. Regex
    # evaluators only; an evaluator without `produces` behaves identically to
    # before.
    produces: Optional[dict[str, int]] = None

    @field_validator("pattern")
    @classmethod
    def _pattern_required_for_regex(cls, v, info):
        return v


class TestStep(BaseModel):
    name: str
    tool: str
    command: str  # {{var}} placeholders are filled from target + prior step outputs
    timeout: Optional[int] = None
    when: Optional[str] = None
    evaluators: list[Evaluator] = Field(default_factory=list)

    # Cases that describe this step's finding BETTER. When one of them reported
    # on the same (url, parameter), this step's finding is the vaguer account of
    # the same thing and is dropped.
    #
    # WSTG-INPV-11.2 exists to catch an interpreter error nothing has classified,
    # and its `single_quote` step sends the same payload to the same parameter as
    # WSTG-INPV-05.2's. Measured on 2026-09-10: every DVWA run shipped both, two
    # HIGH findings with byte-identical proof, one of them titled "unclassified
    # injection" while the other simultaneously classified it as SQL. A client
    # triages that twice and trusts it less for the contradiction.
    #
    # Declared per STEP, not per case: 11.2's XPath, CRLF and metacharacter steps
    # are not subsumed by anything, and a case-level flag would have dropped them
    # too. The step keeps running and keeps emitting — suppression happens at the
    # end, so a run where the more specific case was never selected, or never
    # fired, still reports this.
    subsumed_by: list[str] = Field(default_factory=list)


class ChainRule(BaseModel):
    """Test cases to schedule after this one, conditional on outcome."""
    on_finding: list[str] = Field(default_factory=list)
    always: list[str] = Field(default_factory=list)


class TestCase(BaseModel):
    id: str  # e.g. "WSTG-INPV-05"
    name: str
    category: str  # e.g. "Input Validation"
    severity: str = "medium"
    references: list[str] = Field(default_factory=list)
    target_schema: TargetSchema = Field(default_factory=TargetSchema)
    # Which attack CLASS this case proves, as a capabilities.CLASSES key.
    #
    # The case declares it, not the join table, because the join table got it
    # wrong in three places and nothing could tell: WSTG-INPV-19
    # ("Server-Side Request Forgery") was filed under `ssti`, WSTG-INPV-06
    # ("LDAP Injection") under `cmdi`, and WSTG-INPV-05.6 ("NoSQL Operator
    # Injection") under `sqli`. The Arsenal therefore told the operator that
    # SSRF, LDAP and NoSQL had no deterministic coverage while claiming SSTI
    # and command injection did — wrong in both directions at once.
    #
    # The existing integrity audit could not see it: it checked that every
    # declared id EXISTS and every case is claimed by SOMEONE, which was true
    # the whole time. Correct attribution needs a second opinion, and the case
    # itself is the one source that knows what it tests.
    attack_class: Optional[str] = None
    steps: list[TestStep]
    chain: Optional[ChainRule] = None

    # Deprecated freeform fallback — kept off by default
    legacy: bool = False
