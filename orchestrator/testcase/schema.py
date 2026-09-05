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


class Evaluator(BaseModel):
    """A single check applied to a step's output.

    Three kinds:
      - regex: match `pattern` against tool stdout/stderr
      - status_code: tool's exit code is in `expect`
      - llm: ask the configured LLM to judge ambiguous output
    """
    type: Literal["regex", "status_code", "llm"]

    # Conditional execution. Supported names (kept tiny on purpose):
    #   no_finding_yet, has_finding, previous_success, previous_failure
    when: Optional[str] = None

    # regex evaluator
    pattern: Optional[str] = None
    case_insensitive: bool = True

    # status_code evaluator
    expect: Optional[list[int]] = None

    # llm evaluator — the model is asked to return JSON
    instruction: Optional[str] = None

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

    # Deprecated freeform fallback — kept off by default
    legacy: bool = False
