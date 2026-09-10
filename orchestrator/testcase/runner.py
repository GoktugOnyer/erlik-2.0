"""Execute a TestCase against a target and emit findings."""

import json
import re
import sys
import time
from typing import Any
from pydantic import BaseModel, Field

from orchestrator import llm_client
from orchestrator import credentials as _CRED
from orchestrator.testcase.schema import TestCase, TestStep, Evaluator
from orchestrator.testcase.scope import Scope, ScopeViolation, check_command, from_target
from orchestrator.tool_executor import execute_tool
from orchestrator.testcase.schema import endpoint_of
from urllib.parse import urlsplit


class Finding(BaseModel):
    test_case_id: str
    step: str
    vuln_type: str | None = None
    severity: str = "medium"
    url: str | None = None
    parameter: str | None = None
    evidence: str = ""
    # A header that COULD be exploitable and one that was PROVEN exploitable are
    # not the same claim, and a report that renders them identically is lying by
    # omission. `confidence` grades the claim; `basis` says what earned it.
    confidence: str = "suspected"
    basis: str = ""


class StepResult(BaseModel):
    step: str
    command: str
    success: bool
    output: str
    duration_ms: int
    error: str | None = None
    # The tool's REAL exit code. Before this the status_code evaluator collapsed
    # every non-zero code to "not 0", so a case asking for curl's exit 7
    # (connection refused) matched exit 28 (timeout) just as happily.
    exit_code: int | None = None
    # A step the caller's policy declined to run. Distinct from a step that ran
    # and failed: the first is "we chose not to", the second is evidence.
    skipped: bool = False


class RunResult(BaseModel):
    test_case_id: str
    target: dict[str, Any]
    findings: list[Finding] = Field(default_factory=list)
    steps: list[StepResult] = Field(default_factory=list)
    chain_next: list[str] = Field(default_factory=list)
    stopped_early: bool = False
    duration_ms: int = 0
    # Target fields this run DISCOVERED, e.g. {"endpoint": ["/admin", "/api"]}.
    # A case that finds three parameters can retarget three children; without
    # this the chain walker hands every child the same target it started with.
    produced: dict[str, list[str]] = Field(default_factory=dict)


_TOOLS_ALL = [
    "nmap", "nuclei", "nikto", "whatweb", "wafw00f", "arjun", "whois", "sslyze", "testssl",
    "ffuf", "gobuster", "dirb", "wfuzz",
    "sqlmap", "xsstrike", "dalfox", "commix", "crlfuzz",
    "hydra", "john", "hashcat", "jwt_tool",
    "playwright", "pw-crawl", "zap-cli",
    "curl", "netcat",
    "login-helper", "diff-view", "interactive-pw",
]


_TEMPLATE_RX = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_.]*)\s*\}\}")


def _render(template: str, ctx: dict[str, Any]) -> str:
    def repl(m: re.Match) -> str:
        key = m.group(1)
        # Support dotted lookups like step.baseline.output for prior step refs
        cur: Any = ctx
        for part in key.split("."):
            if isinstance(cur, dict):
                cur = cur.get(part, "")
            else:
                cur = getattr(cur, part, "")
        return str(cur if cur is not None else "")
    return _TEMPLATE_RX.sub(repl, template)


def _origin_fields(endpoint: str) -> dict[str, str]:
    """`origin` and `origin_host` for a target, derived from its own endpoint.

    Computed here rather than imported from orchestrator.integrations: that
    package imports this one, so reaching back into it makes a cycle — and the
    runner has no business depending on one lane's contracts to render a
    catalogue case.
    """
    if not endpoint:
        return {"origin": "", "origin_host": ""}
    parts = urlsplit(endpoint)
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return {"origin": "", "origin_host": ""}
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return {"origin": f"{parts.scheme.lower()}://{host}:{port}", "origin_host": host}


def _eval_when(when: str | None, findings: list[Finding], last: StepResult | None) -> bool:
    if not when:
        return True
    when = when.strip().lower()
    if when == "no_finding_yet":
        return len(findings) == 0
    if when == "has_finding":
        return len(findings) > 0
    if when == "previous_success":
        return last is not None and last.success
    if when == "previous_failure":
        return last is not None and not last.success
    # Unknown -> default to true (don't silently skip)
    return True


def _validate_target(tc: TestCase, target: dict[str, Any]) -> str | None:
    missing = [k for k in tc.target_schema.required if k not in target or target[k] in (None, "")]
    if missing:
        return f"Missing required target fields: {missing}"
    return None


# Bound on captured values. A crawl of a large site can emit thousands of
# paths; the cap keeps one step from planning an unbounded fan-out, and the
# truncation is reported rather than silent.
MAX_PRODUCED_PER_FIELD = 200


def _resolve_url(value: str, base: str) -> str | None:
    """Absolutise a produced URL, or None if it must not be used.

    robots.txt yields paths (`/admin`); sitemap.xml yields absolute URLs. Both
    have to become something the 18 cases that require `url` can consume, so a
    relative value is joined to the target's own URL.

    THE HOST CHECK IS THE POINT. A sitemap can list URLs on any host, and a
    target file is attacker-controlled: `<loc>https://evil.example/</loc>` in a
    customer's sitemap would otherwise retarget a chained case at a third party
    erlik was never authorised to touch. Same-host only, and no scheme other
    than http/https — `javascript:` and `data:` are not targets.
    """
    from urllib.parse import urljoin, urlparse

    if not base:
        return None
    try:
        absolute = urljoin(base, value)
        p, b = urlparse(absolute), urlparse(base)
    except ValueError:
        return None
    if p.scheme not in ("http", "https"):
        return None
    if (p.hostname or "").lower() != (b.hostname or "").lower():
        return None
    if (p.port or (443 if p.scheme == "https" else 80)) != \
       (b.port or (443 if b.scheme == "https" else 80)):
        return None
    return absolute


def _harvest(ev: Evaluator, output: str, flags: int,
             target: dict[str, Any] | None = None,
             pattern: str | None = None) -> dict[str, list[str]]:
    """Pull the values an evaluator declares it produces out of tool output.

    EVERY occurrence, not just the first: a robots.txt has many Disallow lines
    and a crawl emits many paths, and `re.search` would have found one and
    discarded the rest.

    Values are DROPPED, never escaped, if they do not survive the same
    injection gate the sweep planner applies. This text came from the target,
    and it is about to become a command argument.

    A produced `url` is additionally absolutised against the target and
    restricted to the SAME HOST — see _resolve_url.
    """
    if not ev.produces:
        return {}
    from orchestrator.engagement import looks_injectable

    base = endpoint_of(target)
    out: dict[str, list[str]] = {}
    for field, group in ev.produces.items():
        seen: list[str] = []
        for m in re.finditer(pattern if pattern is not None else (ev.pattern or ""), output, flags):
            try:
                value = m.group(group)
            except (IndexError, re.error):
                continue
            if not value:
                continue
            value = value.strip()
            if not value or looks_injectable(value):
                continue
            if field == "url":
                resolved = _resolve_url(value, base)
                if not resolved:
                    continue
                value = resolved
            if value not in seen:
                seen.append(value)
            if len(seen) >= MAX_PRODUCED_PER_FIELD:
                break
        if seen:
            out[field] = seen
    return out


def _render_pattern(pattern: str, target: dict[str, Any]) -> str | None:
    """Substitute {{field}} into a regex pattern, as a LITERAL.

    Two defects live here if you do it naively. WSTG-BUSL-04 wrote
    `{{success_marker}}` in an evaluator pattern and only the COMMAND renderer
    ever ran, so the case searched tool output for the eleven characters
    "{{success_marker}}" and reported clean on every race it actually won.

    Substituting without escaping trades that for a worse one: the value comes
    from the operator's target file, and `.*` in a marker would match anything.
    So every substitution is re.escape'd.

    Returns None when a placeholder resolves to nothing. An empty substitution
    turns `^(?:{{marker}})$` into a pattern that matches an empty line — a
    finding emitted because a field was MISSING. Refusing to match is the only
    honest answer.
    """
    missing = False

    def repl(m: re.Match) -> str:
        nonlocal missing
        value = target.get(m.group(1))
        if value is None or str(value) == "":
            missing = True
            return ""
        return re.escape(str(value))

    rendered = _TEMPLATE_RX.sub(repl, pattern)
    return None if missing else rendered


_VOLATILE_RX = re.compile(r"[0-9a-f]{32}")


def _comparable(output: str) -> str:
    """A response reduced to what should be stable between two probes.

    A 32-hex CSRF token and reformatted whitespace change on every request, so
    without stripping them no two responses ever match and every comparison
    reports a difference. This is the same normalisation WSTG-AUTHZ-04 applies
    before hashing, and it is deliberately narrow: it cannot mask a difference
    in the DATA, which is the whole thing being compared.
    """
    # Whitespace runs collapse to ONE space rather than vanishing: it is just
    # as stable against reformatting, and it keeps the evidence readable when
    # the difference is quoted back into the report.
    return _VOLATILE_RX.sub("", " ".join(output.split()))


def _blind_controls(ev: Evaluator, prior_steps: list[StepResult] | None):
    """The named control steps, or None when the comparison cannot be made.

    Returns None if a step is missing or produced nothing — a comparison
    against an empty response is not a weaker verdict, it is no verdict.
    """
    by_name = {s.step: s for s in (prior_steps or [])}
    steps = [by_name.get(name) for name in (ev.control or [])]
    if not steps or any(s is None or not s.output for s in steps):
        return None
    return steps


def _attributable(ev: Evaluator, step_result: StepResult,
                  prior_steps: list[StepResult] | None) -> bool:
    """Did THIS step's payload cause the difference, or was it already there?

    A step that never ran, or came back empty, cannot answer the question — and
    the safe answer to an unanswerable question here is to leave the finding
    alone rather than to suppress it silently.
    """
    other = {s.step: s for s in (prior_steps or [])}.get(ev.differs_from or "")
    if other is None or not other.output:
        return True
    return _comparable(step_result.output) != _comparable(other.output)


def _first_difference(a: str, b: str, window: int = 120) -> str:
    """The neighbourhood of the first character where two responses part.

    A blind finding's proof is the DIFFERENCE, and a reader handed the raw
    true-condition response sees an ordinary page with no way to tell why it
    was reported. This puts the two sides next to each other.
    """
    limit = min(len(a), len(b))
    i = next((n for n in range(limit) if a[n] != b[n]), limit)
    start = max(0, i - window // 4)
    return (f"    false: ...{a[start:start + window]}...\n"
            f"    true : ...{b[start:start + window]}...")


def _http_status_ok(output: str) -> bool:
    """True when the captured response line is a 2xx."""
    return bool(re.search(r"^HTTP/\S+\s+2\d\d", output, re.MULTILINE))


def _response_headers(output: str) -> str:
    """The header block only — never let a body echo fake a header match."""
    for sep in ("\r\n\r\n", "\n\n"):
        if sep in output:
            return output.split(sep, 1)[0]
    return output


async def _run_evaluator(
    ev: Evaluator,
    step_result: StepResult,
    tc: TestCase,
    target: dict[str, Any],
    provider: str | None,
    model: str | None,
    prior_steps: list[StepResult] | None = None,
) -> tuple[Finding | None, list[str], bool, dict[str, list[str]]]:
    """Apply one evaluator. Returns (finding_or_none, chain_to, stop, produced)."""
    matched = False
    produced: dict[str, list[str]] = {}
    # A blind evaluator's proof is a COMPARISON, not a response — the true
    # condition on its own is an ordinary page. These let those branches say
    # what they actually saw instead of handing a reader the raw body.
    evidence: str | None = None
    confidence: str | None = None
    basis: str | None = None

    if ev.type == "regex" and ev.pattern:
        # MULTILINE so anchors (^ $) work line-by-line — tool output is almost
        # always multi-line and patterns like "^Disallow:" expect line anchors.
        flags = re.MULTILINE
        if ev.case_insensitive:
            flags |= re.IGNORECASE
        pattern = _render_pattern(ev.pattern, target)
        if pattern is not None:
            # The Match used to be destroyed on the line that created it —
            # `bool(re.search(...))` — so every capture group a case wrote was
            # thrown away to keep a yes/no. Harvest first, then decide matched.
            produced = _harvest(ev, step_result.output, flags, target, pattern)
            matched = bool(produced) or bool(
                re.search(pattern, step_result.output, flags))
            if matched and ev.differs_from:
                # ATTRIBUTION. The pattern says the evidence is there; this says
                # the payload put it there. A page that carries the signature
                # before the payload was sent carries it for its own reasons.
                matched = _attributable(ev, step_result, prior_steps)
                if not matched:
                    produced = {}

    elif ev.type == "status_code" and ev.expect is not None:
        # The tool's real exit code, or no answer at all. Inferring it from the
        # success bool made every non-zero code equal to every other one.
        matched = step_result.exit_code is not None and step_result.exit_code in ev.expect

    elif ev.type == "count":
        # A race is won when the SAME success marker comes back more times than
        # the application should ever have allowed.
        marker = str(target.get("success_marker", "") or "")
        matched = bool(marker) and step_result.output.count(marker) >= ev.min_count

    elif ev.type == "cors":
        # `Access-Control-Allow-Origin: *` with credentials is NOT a credentialed
        # read: browsers refuse the wildcard the moment credentials are involved,
        # so reporting it as one is a false positive with a CVSS score attached.
        # What matters is the server reflecting OUR origin back.
        headers = _response_headers(step_result.output)
        origin = str(target.get("test_origin", "") or "https://evil.oast.test")
        matched = bool(
            re.search(r"(?im)^Access-Control-Allow-Origin:\s*" + re.escape(origin) + r"\s*$", headers)
            and re.search(r"(?im)^Access-Control-Allow-Credentials:\s*true\s*$", headers))

    elif ev.type == "idor":
        # An IDOR is a DIFFERENTIAL claim, and the low-privilege response alone
        # cannot make it. Three things have to hold together: the privileged
        # baseline really returned the object, the low-privilege request returned
        # the same object, and the two identities were actually different. Drop
        # any one and this reports "IDOR" on a target where nothing crossed.
        marker = str(target.get("private_object_marker", "") or "")
        baseline = next(
            (st for st in (prior_steps or [])
             if st.step == str(target.get("baseline_step", "") or "fetch_as_high_priv")),
            None)
        low, high = target.get("low_priv_token"), target.get("high_priv_token")
        matched = bool(
            marker and baseline is not None
            and _http_status_ok(baseline.output) and _http_status_ok(step_result.output)
            and marker in baseline.output and marker in step_result.output
            and low != high)

    elif ev.type == "cookie_attributes":
        # Structure, not a regex: a session cookie missing HttpOnly is the claim,
        # and only a parsed Set-Cookie can distinguish that from the word
        # "httponly" appearing somewhere else in the response.
        from http.cookies import SimpleCookie
        from urllib.parse import urlsplit
        is_https = urlsplit(endpoint_of(target)).scheme == "https"
        for value in re.findall(r"(?im)^Set-Cookie:\s*([^\r\n]+)", step_result.output):
            parsed = SimpleCookie()
            try:
                parsed.load(value)
            except Exception:
                continue
            for name, cookie in parsed.items():
                if not re.search(r"session|sid|token|jwt|auth", name, re.I):
                    continue
                if (not cookie["httponly"] or not cookie["samesite"]
                        or (is_https and not cookie["secure"])):
                    matched = True

    elif ev.type in ("boolean_differential", "timing") and not (
            step_result.success and step_result.output):
        # A step that timed out is the one input that turns BOTH blind
        # evaluators into false positives, and it does so in the confident
        # direction: curl's --max-time makes duration_ms the whole budget, so
        # a hung request looks exactly like a successful SLEEP(20); and its
        # empty body differs from every control, so it looks exactly like a
        # true condition. Neither is a measurement. Both branches are skipped.
        pass

    elif ev.type == "boolean_differential":
        # A blind injection leaves nothing to match, so the verdict is that two
        # responses which SHOULD be identical are not. The controls carry
        # different benign values: if they disagree the endpoint reflects its
        # input or is simply unstable, and no comparison downstream means
        # anything — so the evaluator reports nothing rather than reading noise
        # as a finding.
        controls = _blind_controls(ev, prior_steps)
        other = {s.step: s for s in (prior_steps or [])}.get(ev.differs_from or "")
        if controls and len(controls) >= 2 and other is not None and other.output:
            baseline = {_comparable(c.output) for c in controls}
            false_side, true_side = _comparable(other.output), _comparable(step_result.output)
            matched = len(baseline) == 1 and true_side != false_side
            if matched:
                # The FULL claim is that the false condition is
                # indistinguishable from a value that simply matches no row,
                # and the true condition is not. When the false side also sits
                # on the baseline, the injection is not merely suspected from a
                # difference — the whole boolean pair behaved as SQL.
                confidence = "confirmed" if false_side in baseline else "suspected"
                grade = ("both conditions behaved as SQL" if false_side in baseline
                         else "the false condition did not match the baseline")
                basis = (f"blind boolean: {len(controls)} controls agreed, "
                         f"{step_result.step} differs from {ev.differs_from} — {grade}")
                evidence = (
                    "blind boolean differential\n"
                    + "".join(f"    {c.step:<16} {len(c.output):>6} bytes  (control)\n"
                              for c in controls)
                    + f"    {other.step:<16} {len(other.output):>6} bytes  (false condition)\n"
                    + f"    {step_result.step:<16} {len(step_result.output):>6} bytes  DIFFERS\n"
                    + "  first difference:\n"
                    # The NORMALISED forms, because those are what the verdict
                    # was made on. Diffing the raw bodies pointed at the CSRF
                    # token — the one thing normalisation exists to ignore.
                    + _first_difference(false_side, true_side))

    elif ev.type == "timing":
        # The delay has to be CAUSED, not merely observed. The controls include
        # a probe asking for a SHORTER sleep, so the step must beat the one
        # that already carries part of the delay — a target that is uniformly
        # slow, or slow only while these probes run, moves the controls too.
        #
        # What one measurement cannot rule out is a single spike on this step
        # alone. That is why a timing finding is never graded `confirmed`, and
        # why the case chains to sqlmap, which retries.
        controls = _blind_controls(ev, prior_steps)
        if controls and ev.delay_ms:
            slowest = max(controls, key=lambda c: c.duration_ms)
            margin = step_result.duration_ms - slowest.duration_ms
            matched = margin >= ev.delay_ms
            if matched:
                basis = (f"blind timing: {step_result.duration_ms}ms against "
                         f"{slowest.duration_ms}ms for {slowest.step}, a {margin}ms "
                         f"margin over the required {ev.delay_ms}ms — ONE measurement")
                evidence = (
                    "blind timing differential\n"
                    + "".join(f"    {c.step:<16} {c.duration_ms:>6} ms  (control)\n"
                              for c in controls)
                    + f"    {step_result.step:<16} {step_result.duration_ms:>6} ms  "
                      f"{margin}ms slower than {slowest.step}\n")

    elif ev.type == "llm" and ev.instruction:
        # The target dict and the raw response both carry credentials, and this
        # is the one place in the runner where they would leave the process.
        # _CRED.scrub already cleaned resolved handles out of the OUTPUT; the
        # target dict itself was never covered by it.
        from orchestrator.integrations.security import redact, sensitive_values
        known = sensitive_values(target)
        prompt = (
            "You are evaluating tool output from a penetration test step.\n"
            f"Test case: {tc.id} — {tc.name}\n"
            f"Target: {json.dumps(redact(target, known))}\n"
            f"Step: {step_result.step}\n"
            f"Command: {redact(step_result.command, known)}\n"
            f"--- TOOL OUTPUT ---\n{redact(step_result.output, known)}\n--- END ---\n\n"
            f"Instruction: {ev.instruction}\n\n"
            'Respond with strict JSON: {"matched": true|false, "reason": "..."}'
        )
        try:
            data = await llm_client.chat_json(
                [{"role": "user", "content": prompt}],
                model=model,
            )
            # `is True`, because a model that answers {"matched": "no"} was
            # scoring a finding on a non-empty string.
            matched = bool(data and data.get("matched") is True)
        except Exception as e:
            matched = False
            print(f"[runner] llm evaluator error: {e}", file=sys.stderr)

    if not matched:
        return None, [], False, produced

    finding = None
    # `is not None`, not truthiness: `emit_finding: {}` is a case asking for a
    # finding with all-default fields, and the falsy check silently dropped it.
    if ev.emit_finding is not None:
        f = dict(ev.emit_finding)
        finding = Finding(
            test_case_id=tc.id,
            step=step_result.step,
            vuln_type=f.get("vuln_type"),
            severity=f.get("severity", tc.severity),
            # `url_template` is what the access-control cases name their
            # endpoint. Without this a finding from one carried NO url at all,
            # so it could not be attached to an asset, could not be
            # scope-audited, and rendered as N/A in the client report.
            url=target.get("url") or target.get("url_template"),
            parameter=target.get("parameter"),
            evidence=(evidence or step_result.output)[:1500],
            # Only the differential evaluators compared steps rather than
            # reading one response and inferring — which is a lead, not a proof.
            confidence=confidence or ("confirmed" if ev.type == "idor" else "suspected"),
            basis=basis or f"{ev.type} evaluator matched captured tool output",
        )
    return finding, ev.chain_to or [], ev.stop_after, produced


def _scrub_for_storage(result: RunResult, secrets: tuple[str, ...]) -> None:
    """Redact resolved credentials from everything that leaves this function.

    One pass, at the end, rather than per step as the output arrives — because
    the evaluators have to read what the application actually sent. A credential
    is removed by substring replacement, so scrubbing before evaluation made
    detection depend on the identity's secret values: a value of `SQL`, `error`
    or `near` disabled the error-based SQL injection case outright.

    Nothing has left the process before this runs: the command strings carry
    handles rather than secrets, and the RunResult is returned, persisted and
    reported only after it.
    """
    if not secrets:
        return
    for step in result.steps:
        step.output = _CRED.scrub(step.output, secrets)
        step.error = _CRED.scrub(step.error, secrets) if step.error else step.error
    for finding in result.findings:
        finding.evidence = _CRED.scrub(finding.evidence, secrets)
        finding.basis = _CRED.scrub(finding.basis, secrets)


async def run_test_case(
    tc: TestCase,
    target: dict[str, Any],
    provider: str | None = None,
    model: str | None = None,
    dry_run: bool = False,
    db: Any = None,
    *,
    executor=None,
    step_policy=None,
    command_checker=None,
    allow_llm: bool = True,
) -> RunResult:
    """Execute a TestCase. provider/model override env defaults for LLM evaluators.

    If dry_run=True, every step is rendered + scope-checked but never executed.
    Each StepResult carries the rendered command and a [DRY RUN] placeholder
    output. Evaluators are skipped (there is nothing to evaluate).

    The keyword-only seams exist so the integration runtime can run the SAME
    catalogue under its own rules rather than forking the runner:
      executor         — run commands through the egress-proxied Docker job
      step_policy      — return a reason to decline a step (mutating steps are
                         off unless the operator selected them for this run)
      command_checker  — the assessment's scope policy, which is stricter than
                         the case's own
      allow_llm        — off for reproducible runs; an LLM evaluator is not
                         deterministic and must not silently decide a finding
    """
    started = time.time()
    err = _validate_target(tc, target)
    if err:
        raise ValueError(err)

    # Provider override is per-call: temporarily swap module-level PROVIDER if asked.
    saved_provider = None
    if provider:
        saved_provider = llm_client.PROVIDER
        llm_client.PROVIDER = provider.lower()

    result = RunResult(test_case_id=tc.id, target=target)
    last_step: StepResult | None = None
    # Every secret any step resolved. Collected so the single redaction pass at
    # the end covers a value a later step never saw.
    resolved_secrets: list[str] = []
    chain_set: list[str] = []
    scope = from_target(target)
    try:
        for step in tc.steps:
            if not _eval_when(step.when, result.findings, last_step):
                continue

            # DERIVED from the endpoint, so every caller has them without
            # having to know they exist. WSTG-CLNT-04 needs the target's own
            # origin to build a bypass that carries an allow-listed string:
            # a naive validator asking "does the target contain our host" is
            # satisfied by `//marker/?x=<our origin>`, which redirects to the
            # marker. Deriving here rather than in one lane's adapter keeps the
            # case runnable from the sweep and the Test Lab too.
            derived = _origin_fields(endpoint_of(target))
            ctx: dict[str, Any] = {**derived, **target,
                                   "step": {s.step: s for s in result.steps}}
            if tc.id == "WSTG-BUSL-04":
                ctx["parallel_n"] = max(2, min(20, int(target.get("parallel_n", 2) or 2)))
            cmd = _render(step.command, ctx)

            # The caller's policy gets to decline before scope or exec. A declined
            # step is recorded, not dropped: a report that omits it reads as if
            # the case ran clean.
            if step_policy:
                reason = step_policy(step, cmd)
                if reason:
                    result.steps.append(StepResult(
                        step=step.name, command=cmd, success=False, output="",
                        duration_ms=0, error=reason, skipped=True))
                    continue

            # Safety floor: every command must pass scope check before exec.
            if scope is not None:
                try:
                    (command_checker or check_command)(cmd, scope, primary_url=endpoint_of(target))
                except ScopeViolation as e:
                    result.steps.append(StepResult(
                        step=step.name,
                        command=cmd,
                        success=False,
                        output="",
                        duration_ms=0,
                        error=f"scope violation: {e}",
                    ))
                    result.stopped_early = True
                    break

            if dry_run:
                sr = StepResult(
                    step=step.name,
                    command=cmd,
                    success=True,
                    output="[DRY RUN — command not executed]",
                    duration_ms=0,
                    error=None,
                )
                result.steps.append(sr)
                last_step = sr
                continue

            # AUTH RESOLUTION. `cmd` carries opaque handles; the secret exists
            # only in `live_cmd`, only for the duration of this call, and is
            # never stored. See credentials.HANDLE_RX.
            live_cmd, secret_values = cmd, []
            if _CRED.has_handle(cmd):
                if db is None:
                    sr = StepResult(
                        step=step.name, command=cmd, success=False, output="",
                        duration_ms=0,
                        error="this step needs an authenticated session and the "
                              "runner was given no credential store; refusing to "
                              "send the request unauthenticated")
                    result.steps.append(sr)
                    result.stopped_early = True
                    break
                live_cmd, secret_values = await _CRED.resolve(db, cmd)
                resolved_secrets.extend(secret_values)
                if _CRED.has_handle(live_cmd):
                    # A session was revoked, unverified, or deleted between
                    # planning and running. Sending the request anyway would
                    # produce an UNAUTHENTICATED result labelled authenticated —
                    # a false negative wearing a clean bill of health.
                    sr = StepResult(
                        step=step.name, command=cmd, success=False, output="",
                        duration_ms=0,
                        error="the session this step needs is no longer verified; "
                              "re-authenticate and re-run (refusing to fall back "
                              "to an unauthenticated request)")
                    result.steps.append(sr)
                    result.stopped_early = True
                    break

            t0 = time.time()
            raw = await (executor or execute_tool)(
                live_cmd,
                enabled_tools=_TOOLS_ALL,
                target_url=endpoint_of(target),
                no_timeout=False,
                tool_hint=step.tool,
                # Every case that declared `timeout:` in YAML was running on the
                # executor's default instead; the field parsed and went nowhere.
                custom_timeout=step.timeout,
            )
            sr = StepResult(
                step=step.name,
                command=cmd,                       # handles, never the secret
                success=bool(raw.get("success")),
                # RAW, deliberately. Redaction happens once at the end, over
                # everything that leaves this function — see _scrub_for_storage.
                # Scrubbing here meant the EVALUATOR read the redacted text, and
                # a credential is a substring match: an identity whose secret
                # value was `SQL`, `error` or `near` silently turned every real
                # SQL injection into a clean result. Measured on the 2026-09-10
                # lane run, where `security=low` rewrote DVWA's robots.txt as
                # `Disal[REDACTED]: /`. Detection must not depend on redaction.
                output=raw.get("output", "") or "",
                duration_ms=int((time.time() - t0) * 1000),
                error=raw.get("error") or None,
                exit_code=raw.get("exit_code"),
            )
            result.steps.append(sr)
            last_step = sr

            stop = False
            for ev in step.evaluators:
                if ev.type == "llm" and not allow_llm:
                    continue
                if not _eval_when(ev.when, result.findings, sr):
                    continue
                finding, chain_to, stop_after, produced = await _run_evaluator(
                    ev, sr, tc, target, provider, model, result.steps
                )
                for field, values in produced.items():
                    bucket = result.produced.setdefault(field, [])
                    for v in values:
                        if v not in bucket and len(bucket) < MAX_PRODUCED_PER_FIELD:
                            bucket.append(v)
                if finding:
                    result.findings.append(finding)
                for cid in chain_to:
                    if cid not in chain_set:
                        chain_set.append(cid)
                if stop_after:
                    stop = True
                    break
            if stop:
                result.stopped_early = True
                break

        # Static chain rules
        if tc.chain:
            if result.findings:
                for cid in tc.chain.on_finding:
                    if cid not in chain_set:
                        chain_set.append(cid)
            for cid in tc.chain.always:
                if cid not in chain_set:
                    chain_set.append(cid)

        result.chain_next = chain_set
    finally:
        if saved_provider is not None:
            llm_client.PROVIDER = saved_provider

    _scrub_for_storage(result, tuple(dict.fromkeys(resolved_secrets)))
    result.duration_ms = int((time.time() - started) * 1000)
    return result
