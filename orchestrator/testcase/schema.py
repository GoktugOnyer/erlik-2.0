"""Pydantic schema for YAML-defined test cases."""

from typing import Literal, Optional, Any
from pydantic import BaseModel, Field, field_validator


class TargetSchema(BaseModel):
    """Declares what the caller must supply to run this test case."""
    required: list[str] = Field(default_factory=list)
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
    steps: list[TestStep]
    chain: Optional[ChainRule] = None

    # Deprecated freeform fallback — kept off by default
    legacy: bool = False
