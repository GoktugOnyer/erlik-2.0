"""Pydantic schema for YAML-defined test cases."""

from typing import Literal, Optional, Any
from pydantic import model_validator, BaseModel, Field, field_validator


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
      - ownership: the response ASSERTS an owner, and it is not the caller

    ...and two BLIND ones, which read no content at all. A blind injection
    changes nothing a pattern can match, so the verdict comes from comparing
    steps: `boolean_differential` from two responses that should be the same
    and are not, `timing` from a delay that tracks the one that was asked for.
    Both take a `control` pair that decides whether the comparison is even
    valid — see the fields below.
    """
    type: Literal[
        "regex", "status_code", "llm",
        "count", "cors", "idor", "cookie_attributes", "ownership",
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

    # ownership evaluator (E-011, object-level authorization)
    #
    # The field in the response body that names the object's owner, as a dotted
    # path: Juice Shop answers GET /rest/basket/1 with
    # {"status":"success","data":{"id":1,"UserId":1,...}}, so this is
    # "data.UserId". Measured, not assumed — see
    # tests/test_object_authorization.py.
    #
    # This is the ONE thing the target supplies to the verdict, and it is only
    # ever compared against an id the OPERATOR declared. A target that invents an
    # owner can therefore make the lane say "this is not yours", never "this is
    # yours", and the corroboration and anonymous clauses below remove even that.
    owner_field: Optional[str] = None

    # The step that re-reads the same object AS THE DECLARED OWNER. Without it a
    # target can name any owner it likes and the lane believes the claim. With
    # it, the named owner has to be able to read the object too.
    owner_step: Optional[str] = None

    # The step that requests the same object with NO credentials. This is the
    # clause that separates a leak from a publication: content the application
    # serves to anonymous callers is not a finding however it is attributed, and
    # a fixture written to forge ownership for everyone is refused here. It is
    # load-bearing — see test_a_target_that_forges_ownership_is_refused.
    anonymous_step: Optional[str] = None

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

    @model_validator(mode="after")
    def _no_evaluator_only_field_is_harvested(self):
        """A target must never be able to choose an evaluator-only value.

        `produces` lifts a value out of the TARGET'S OWN OUTPUT and carries it
        forward as a target field. The safety property of the authorization check is
        that `private_object_marker` is OURS while the responses are the target's —
        a target that could name the marker could name something it returns to
        everybody and so choose its own finding.

        Refused here rather than left to whoever writes the next case, because this
        codebase has shipped a target-chooses-the-evidence defect before.
        """
        from orchestrator.testcase.declared import EVALUATOR_ONLY

        harvested = sorted(set(self.produces or {}) & set(EVALUATOR_ONLY))
        if harvested:
            raise ValueError(
                "these fields are read by an evaluator and must never be harvested "
                "from a response, or the target chooses the verdict: "
                + ", ".join(harvested))
        return self

    @field_validator("pattern")
    @classmethod
    def _pattern_required_for_regex(cls, v, info):
        return v


class TestStep(BaseModel):
    name: str
    tool: str
    # This step plants an out-of-band payload and is meaningless without a
    # collaborator. Marked per STEP, not per case: WSTG-INPV-19 proves most of
    # its findings in band (a metadata document comes back in the response) and
    # only the blind probe needs OOB, so disabling the whole case when OAST is
    # off would lose coverage that works perfectly well without it.
    oob: bool = False
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

    # THE UNDO FOR WHAT THIS STEP LEAVES ON THE TARGET.
    #
    # E-033: no test case could clean up after itself. `TestCase` and `TestStep` had no
    # such field at either level across all 32 cases, and the only `cleanup` in the system
    # was `Workflow.cleanup` — the operator's declaration for the Schemathesis lane, not
    # the case author's for their own probe. BUSL-09's header tells a HUMAN to run
    # `find / -name 'erlik-upload-*'` afterwards, which is the honest admission that erlik
    # writes to a client's server on an authorised engagement and then forgets.
    #
    # THIS PERMITS NOTHING NEW. A cleanup runs only after a step that actually EXECUTED,
    # and a mutating step executes only where safe mode already allows it — that is,
    # `ERLIK_SAFE_MODE=0`, a deliberately authorised destructive engagement. With safe mode
    # on, the step is refused and its cleanup never runs, because there is nothing to undo.
    # The gate is untouched; what changes is what erlik leaves behind on the side of it
    # where it was already writing.
    #
    # It is held to the same scope check and the same safe-mode floor as any other command,
    # which costs nothing and closes the obvious abuse: a case declaring a plain GET step
    # with a `cleanup: curl -X DELETE …` would otherwise have smuggled a mutation past a
    # gate its own step could not pass.
    cleanup: Optional[str] = None


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

    # Hosts this case names as PAYLOAD, never as a destination.
    #
    # Some probes cannot be written without naming a host that is not the
    # target: CLNT-07 has to send an attacker `Origin:` or it is not testing
    # CORS, AUTHZ-05 has to offer an unregistered `redirect_uri`, and INPV-19
    # has to ask the target to fetch the cloud metadata address. In each case
    # erlik's own socket goes only to the in-scope target and the host appears
    # in a header or parameter VALUE.
    #
    # `scope.check_command` extracts every host-shaped substring of a rendered
    # command and refuses anything outside the engagement, which is right for a
    # guard on where erlik connects -- but it meant those three cases aborted
    # at their first step on every run and had never produced a result.
    #
    # A declaration here, in committed and reviewed YAML, is the narrow way to
    # say "this string is data". It is deliberately weak on purpose:
    #
    #   * exact hostnames only, no globs -- a wildcard is how a per-case
    #     allowance becomes a general bypass;
    #   * it never covers the case's own target, which is checked against the
    #     engagement scope as before;
    #   * `deny_hosts` still wins, so an operator's explicit refusal cannot be
    #     overridden by a case file;
    #   * it applies to THIS case only, and a declared host that no step
    #     actually names is a test failure, so unused permissions cannot
    #     accumulate.
    #
    # It does not, and cannot, prove the host is unreachable -- a case author
    # who wrote `curl http://declared-host/` would connect there. That is the
    # same trust already placed in the step's command itself.
    payload_hosts: list[str] = Field(default_factory=list)

    # This case can only PROVE its finding out of band.
    #
    # Blind SQLi beyond timing, blind SSRF, blind XXE, blind command injection:
    # the payload succeeds and the response is identical to a failure. The only
    # evidence is that the target contacted a name the tester controls.
    #
    # A case declaring this gets `{{collaborator_host}}` rendered as a unique
    # per-run subdomain, and its OOB steps are polled afterwards. With OAST
    # unconfigured the steps are NOT run: planting a payload nobody can read
    # back would produce a clean verdict for a check that was never performed,
    # so the case reports that out-of-band detection was unavailable instead.
    needs_collaborator: bool = False

    # What the TARGET must look like for this case to be worth planning.
    #
    # Only `scheme` today, and it earns its place: WSTG-CONF-07 was planned
    # against every base URL including plain http, where `plan_sweep` builds a
    # scope of allow_ports=[80] and the case's own HSTS probe -- which must
    # reach 443 -- is refused by the scope guard by construction. Measured
    # 2026-09-05:
    #
    #   base http://app.example.test
    #   tls_scan     ALLOWED   (90s of testssl against a port not in scope)
    #   hsts_header  REFUSED   port 443 not in allow_ports [80]
    #
    # So the expensive half ran against a service the operator did not declare
    # and the cheap half could not run at all. A case that cannot complete is
    # better named in `skipped` with the reason than planned and half-run.
    #
    # This is a PLANNING hint, not a security control. Nothing here relaxes the
    # scope guard; a case whose precondition passes is still bound by it.
    preconditions: dict[str, str] = Field(default_factory=dict)

    @field_validator("preconditions")
    @classmethod
    def _known_preconditions(cls, v: dict[str, str]) -> dict[str, str]:
        for k in v:
            if k != "scheme":
                raise ValueError(
                    f"unknown precondition {k!r}; only 'scheme' is understood, "
                    "and a precondition nothing evaluates would silently never "
                    "hold")
        return v

    @field_validator("payload_hosts")
    @classmethod
    def _payload_hosts_are_plain_exact_hosts(cls, v: list[str]) -> list[str]:
        out = []
        for h in v:
            h = (h or "").strip().lower()
            if not h:
                raise ValueError("payload_hosts entries must not be empty")
            if any(c in h for c in "*?["):
                raise ValueError(
                    f"payload_hosts must name exact hosts, not patterns: {h!r}. "
                    "A glob turns a per-case allowance into a general bypass."
                )
            if "://" in h or "/" in h or " " in h:
                raise ValueError(
                    f"payload_hosts takes a bare hostname, not a URL: {h!r}"
                )
            out.append(h)
        return out

    steps: list[TestStep]
    chain: Optional[ChainRule] = None

    @model_validator(mode="after")
    def _collaborator_declaration_matches_the_steps(self):
        """A case may not ADVERTISE out-of-band confirmation it never performs.

        `collaborator_host` sat in the optional target schema of three cases
        and appeared in no step command in the whole catalogue. An operator
        could declare a collaborator on any of them and every probe ignored it
        -- a field promising a capability that did not exist, which this
        project treats as the same defect class as a crash.

        Both directions are checked, because either one alone leaves a gap:

          * offering the field with no `oob:` step is the original defect;
          * an `oob:` step with the field un-offered means the operator has no
            way to supply their own collaborator, and the step silently only
            ever works off a minted name.

        `needs_collaborator` is tied to the same fact rather than trusted: it
        is what makes the runner mint a name, so a case with an OOB step and
        the flag unset would have its step skipped on every run.
        """
        oob_steps = [st.name for st in self.steps if st.oob]
        offered = "collaborator_host" in (self.target_schema.optional or [])
        if oob_steps and not offered:
            raise ValueError(
                f"{self.id}: steps {oob_steps} are out-of-band but "
                "'collaborator_host' is not in target_schema.optional, so an "
                "operator cannot supply their own collaborator")
        if offered and not oob_steps:
            raise ValueError(
                f"{self.id}: target_schema offers 'collaborator_host' and no "
                "step is marked `oob:`, so the field promises out-of-band "
                "confirmation the case never performs")
        if oob_steps and not self.needs_collaborator:
            raise ValueError(
                f"{self.id}: steps {oob_steps} are out-of-band but the case "
                "does not declare `needs_collaborator: true`, so no name is "
                "ever minted and they would be skipped on every run")
        if self.needs_collaborator and not oob_steps:
            raise ValueError(
                f"{self.id}: declares `needs_collaborator: true` and has no "
                "`oob:` step to use one")
        return self

    # Deprecated freeform fallback — kept off by default
    legacy: bool = False
