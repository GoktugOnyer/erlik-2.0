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
from orchestrator import collaborator as _oast
from orchestrator.testcase.scope import Scope, ScopeViolation, check_command, from_target
from orchestrator.tool_executor import execute_tool


class Finding(BaseModel):
    test_case_id: str
    step: str
    vuln_type: str | None = None
    severity: str = "medium"
    url: str | None = None
    parameter: str | None = None
    evidence: str = ""


class StepResult(BaseModel):
    step: str
    command: str
    success: bool
    output: str
    duration_ms: int
    error: str | None = None

    # WHETHER THE COMMAND EVER REACHED A SHELL, and whether a guard is why.
    #
    # `execute_tool` has returned both of these all along and this model threw
    # them away, leaving the human-readable message prefix as the only signal.
    # Everything downstream then had to match on prose: `case_baseline` knew two
    # of the five prefixes and filed an agent-lane scope refusal under "the
    # command did not work" in a committed baseline. A refusal and a breakage
    # are different facts about an engagement and must not be told apart by
    # reading English.
    executed: bool = True
    denied: bool = False


class NotAssessed(BaseModel):
    """An evaluator that could not reach a verdict, as opposed to one that
    reached "no".

    `matched = False` means both "checked, target is fine" and "could not
    check" unless they are kept apart. They were not: the llm branch caught its
    exception, set matched = False and printed to stderr, so a run with an
    unreachable LLM returned findings: [], success: true, error: null. On a
    client engagement that reports a control as sound when it was never tested.
    """

    step: str
    evaluator: str
    reason: str


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
    # Evaluators that could not run. Empty is the only honest way to read a
    # findings-free result as "nothing found here".
    not_assessed: list[NotAssessed] = Field(default_factory=list)


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


def _primary_url(target: dict[str, Any]) -> str | None:
    """The URL a step is actually aimed at, for cases that do not call it `url`.

    Four of the 29 cases name their target something else -- ATHN-01
    `login_url`, AUTHZ-04 `url_template`, BUSL-04 `request_template`, CONF-07
    `host` -- and `target.get("url")` is None for every one of them. That None
    reached `execute_tool`, whose `_sanitize_command` then had no destination to
    rewrite to and used its placeholder default, re-pointing the command at
    localhost:80 and downgrading https to http before it ran. `_sanitize_command`
    no longer invents a destination; this gives it the real one, so a loopback
    target under docker is still resolved to the host gateway for these cases
    as it always was for the other 25.

    Order matters only in that `url` stays first, so nothing changes for the
    cases that already worked.
    """
    for key in ("url", "login_url", "url_template", "base_url", "endpoint"):
        v = target.get(key)
        if isinstance(v, str) and "://" in v:
            return v
    host = target.get("host")
    if isinstance(host, str) and host:
        port = target.get("port")
        scheme = "https" if str(port) in ("443", "8443") else "http"
        return f"{scheme}://{host}" + (f":{port}" if port else "")
    # A raw request template carries its URL inside a shell command.
    tmpl = target.get("request_template")
    if isinstance(tmpl, str):
        m = re.search(r'https?://[^\s\'"\\<>|]+', tmpl)
        if m:
            return m.group(0)
    return None


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
             target: dict[str, Any] | None = None) -> dict[str, list[str]]:
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

    base = (target or {}).get("url") or ""
    out: dict[str, list[str]] = {}
    for field, group in ev.produces.items():
        seen: list[str] = []
        for m in re.finditer(ev.pattern or "", output, flags):
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


async def _run_evaluator(
    ev: Evaluator,
    step_result: StepResult,
    tc: TestCase,
    target: dict[str, Any],
    provider: str | None,
    model: str | None,
) -> tuple[Finding | None, list[str], bool, dict[str, list[str]], NotAssessed | None]:
    """Apply one evaluator.

    Returns (finding, chain_to, stop, produced, not_assessed). The last element
    is set when the evaluator could not reach a verdict at all; the caller must
    surface it rather than letting it read as a clean result.
    """
    matched = False
    produced: dict[str, list[str]] = {}
    unassessed: NotAssessed | None = None

    if ev.type == "regex" and ev.pattern:
        # MULTILINE so anchors (^ $) work line-by-line — tool output is almost
        # always multi-line and patterns like "^Disallow:" expect line anchors.
        flags = re.MULTILINE
        if ev.case_insensitive:
            flags |= re.IGNORECASE
        # The Match used to be destroyed on the line that created it —
        # `bool(re.search(...))` — so every capture group a case wrote was
        # thrown away to keep a yes/no. Harvest first, then decide matched.
        produced = _harvest(ev, step_result.output, flags, target)
        matched = bool(produced) or bool(
            re.search(ev.pattern, step_result.output, flags))

    elif ev.type == "status_code" and ev.expect is not None:
        # tool_executor doesn't return raw exit code, but encodes failure via success bool
        # Treat success=True as exit 0; failure as nonzero. Best-effort match.
        codes = ev.expect
        matched = (0 in codes and step_result.success) or (
            any(c != 0 for c in codes) and not step_result.success
        )

    elif ev.type == "llm" and ev.instruction:
        prompt = (
            "You are evaluating tool output from a penetration test step.\n"
            f"Test case: {tc.id} — {tc.name}\n"
            f"Target: {json.dumps(target)}\n"
            f"Step: {step_result.step}\n"
            f"Command: {step_result.command}\n"
            f"--- TOOL OUTPUT ---\n{step_result.output}\n--- END ---\n\n"
            f"Instruction: {ev.instruction}\n\n"
            'Respond with strict JSON: {"matched": true|false, "reason": "..."}'
        )
        try:
            data = await llm_client.chat_json(
                [{"role": "user", "content": prompt}],
                model=model,
            )
            matched = bool(data and data.get("matched"))
        except Exception as e:
            matched = False
            print(f"[runner] llm evaluator error: {e}", file=sys.stderr)
            unassessed = NotAssessed(
                step=step_result.step, evaluator="llm",
                reason=f"LLM evaluator could not run: {str(e)[:160]}")

    elif ev.type == "llm":
        # Declared llm with no instruction: nothing to ask, so nothing was
        # judged. Silently false would read as clean.
        unassessed = NotAssessed(step=step_result.step, evaluator="llm",
                                 reason="llm evaluator has no instruction")
    else:
        # An evaluator type no branch above handles -- a typo in a case, or a
        # type added to the schema before the runner learned it. It asserted
        # nothing, and must not be counted as having asserted "no".
        unassessed = NotAssessed(
            step=step_result.step, evaluator=str(ev.type),
            reason=f"unsupported evaluator type {ev.type!r}")

    if not matched:
        return None, [], False, produced, unassessed

    finding = None
    if ev.emit_finding:
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
            evidence=step_result.output[:1500],
        )
    return finding, ev.chain_to or [], ev.stop_after, produced, None


async def run_test_case(
    tc: TestCase,
    target: dict[str, Any],
    provider: str | None = None,
    model: str | None = None,
    dry_run: bool = False,
    db: Any = None,
) -> RunResult:
    """Execute a TestCase. provider/model override env defaults for LLM evaluators.

    If dry_run=True, every step is rendered + scope-checked but never executed.
    Each StepResult carries the rendered command and a [DRY RUN] placeholder
    output. Evaluators are skipped (there is nothing to evaluate)."""
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
    chain_set: list[str] = []
    scope = from_target(target)

    # A UNIQUE name per RUN, minted once and shared by every OOB step in it.
    # Per-run rather than per-step so several probes in one case correlate to
    # the same run, and per-run rather than global so an interaction identifies
    # WHICH run caused it -- a blind finding that cannot be attributed to a
    # payload is not evidence a client can act on.
    #
    # An operator-supplied `collaborator_host` wins: someone running their own
    # Burp Collaborator has a name erlik cannot mint.
    oast_token = ""
    oast_host = str(target.get("collaborator_host") or "")
    if tc.needs_collaborator and not oast_host and _oast.is_enabled():
        oast_token = _oast.new_token()
        try:
            oast_host = _oast.host_for(oast_token)
        except _oast.CollaboratorError:
            oast_token, oast_host = "", ""

    # THE COLLABORATOR IS A PAYLOAD HOST, and has to be declared as one or the
    # scope guard refuses the only step that can prove a blind finding: the
    # name is minted per run, so no case file could ever list it.
    #
    # It is not a hole in the guard. `payload_allowlist` still filters it
    # against `deny_hosts`, so an operator who excluded the domain keeps it
    # excluded; it does not touch `allow_hosts`, so it cannot widen where the
    # case is AIMED (the primary URL is checked against the engagement scope
    # alone); and the name only exists because the operator configured
    # ERLIK_OAST_DOMAIN or passed `collaborator_host` themselves. That
    # configuration IS the declaration.
    step_payload_hosts = list(tc.payload_hosts)
    if oast_host:
        step_payload_hosts.append(oast_host)

    # Whether a payload naming the collaborator was actually SENT. Not
    # `any(st.oob for st in tc.steps)`: a `when:` guard, a dry run or a scope
    # refusal all leave an OOB step un-sent, and reporting "payloads were sent,
    # go check your collaborator" for a probe that never left is the same class
    # of untrue interface label as the silence it replaces.
    #
    # Set AFTER the step runs and only when the executor says it ran. It was
    # first written just before the `execute_tool` call, which made it true for
    # a probe the executor then refused -- the exact untrue label this comment
    # claims it prevents, three lines above the bug.
    oob_sent = False
    try:
        for step in tc.steps:
            if not _eval_when(step.when, result.findings, last_step):
                continue

            # AN OOB STEP WITHOUT A COLLABORATOR IS NOT RUN.
            #
            # Its payload can only be proven by something contacting a name we
            # control; planting one nobody can read back would leave the case
            # reporting a clean verdict for a check that was never performed.
            # That is reported as not-assessed, which is the difference between
            # "no blind vulnerability" and "blind detection was off".
            if step.oob and not oast_host:
                result.not_assessed.append(NotAssessed(
                    step=step.name, evaluator="collaborator",
                    reason=_oast.status().get("reason", "out-of-band detection "
                                              "is unavailable")))
                continue

            ctx: dict[str, Any] = {**target, "step": {s.step: s for s in result.steps}}
            if oast_host:
                ctx["collaborator_host"] = oast_host
            cmd = _render(step.command, ctx)

            # Safety floor: every command must pass scope check before exec.
            if scope is not None:
                try:
                    check_command(cmd, scope, primary_url=_primary_url(target),
                                  payload_hosts=step_payload_hosts)
                except ScopeViolation as e:
                    result.steps.append(StepResult(
                        step=step.name,
                        command=cmd,
                        success=False,
                        output="",
                        duration_ms=0,
                        error=f"scope violation: {e}",
                        executed=False, denied=True,
                    ))
                    result.not_assessed.append(NotAssessed(
                        step=step.name, evaluator="scope",
                        reason=f"the step was refused before it ran, so nothing "
                               f"about it was assessed: {e}"))
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
                        duration_ms=0, executed=False, denied=True,
                        error="this step needs an authenticated session and the "
                              "runner was given no credential store; refusing to "
                              "send the request unauthenticated")
                    result.steps.append(sr)
                    result.stopped_early = True
                    break
                live_cmd, secret_values = await _CRED.resolve(db, cmd)
                if _CRED.has_handle(live_cmd):
                    # A session was revoked, unverified, or deleted between
                    # planning and running. Sending the request anyway would
                    # produce an UNAUTHENTICATED result labelled authenticated —
                    # a false negative wearing a clean bill of health.
                    sr = StepResult(
                        step=step.name, command=cmd, success=False, output="",
                        duration_ms=0,
                        executed=False, denied=True,
                        error="the session this step needs is no longer verified; "
                              "re-authenticate and re-run (refusing to fall back "
                              "to an unauthenticated request)")
                    result.steps.append(sr)
                    result.stopped_early = True
                    break

            t0 = time.time()
            raw = await execute_tool(
                live_cmd,
                enabled_tools=_TOOLS_ALL,
                target_url=_primary_url(target),
                no_timeout=False,
                tool_hint=step.tool,
                # The SAME list the case-lane guard was given, so the two
                # guards agree about what this case declared. Without it the
                # declaration was honoured by one and refused by the other, and
                # `payload_hosts` granted nothing it was not already given.
                payload_hosts=step_payload_hosts,
            )
            sr = StepResult(
                step=step.name,
                command=cmd,                       # handles, never the secret
                success=bool(raw.get("success")),
                output=_CRED.scrub(raw.get("output", "") or "", secret_values),
                duration_ms=int((time.time() - t0) * 1000),
                error=_CRED.scrub(raw.get("error") or "", secret_values) or None,
                executed=bool(raw.get("executed", True)),
                denied=bool(raw.get("denied")),
            )
            result.steps.append(sr)
            last_step = sr

            # A REFUSED STEP IS NOT EVIDENCE. `execute_tool`'s own docstring
            # says callers must skip detection when `executed` is False -- it
            # exists because a refusal string once became detection input -- and
            # this caller did not. The evaluators below ran against the refusal
            # message, so a guard's own words could match a pattern and be
            # emitted as a finding, and a case that was never allowed to run
            # reported a clean verdict rather than an unassessed one.
            if step.oob and sr.executed:
                oob_sent = True

            if not sr.executed:
                result.not_assessed.append(NotAssessed(
                    step=step.name,
                    evaluator="admission",
                    reason=f"the step was refused before it ran, so nothing "
                           f"about it was assessed: {sr.error or 'no reason given'}"))
                continue

            stop = False
            for ev in step.evaluators:
                if not _eval_when(ev.when, result.findings, sr):
                    continue
                finding, chain_to, stop_after, produced, unassessed = await _run_evaluator(
                    ev, sr, tc, target, provider, model
                )
                if unassessed:
                    result.not_assessed.append(unassessed)
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

    # OUT-OF-BAND EVIDENCE, collected after the probes have been sent.
    #
    # Polled once at the end rather than after each step: the target may take a
    # moment to make the call, and several probes in one case share the run's
    # token, so one poll answers for all of them.
    #
    # A collaborator erlik did not mint cannot be polled: the receiver API is
    # keyed by the token, and a Burp Collaborator instance has neither that
    # token nor this API. Without this branch the probe would be SENT and
    # nothing reported either way -- no finding, no not-assessed -- which is
    # the clean-looking non-result the rest of this file exists to prevent.
    # The operator has to read their own collaborator; the run says so.
    if oast_host and not oast_token and oob_sent:
        result.not_assessed.append(NotAssessed(
            step="collaborator_poll", evaluator="collaborator",
            reason=f"out-of-band payloads naming {oast_host} were sent, but "
                   f"that collaborator was supplied rather than minted by "
                   f"erlik, which cannot poll it — check it yourself for "
                   f"interactions from this run"))
    elif oast_token:
        try:
            hits = _oast.poll(oast_token)
        except _oast.CollaboratorError as e:
            # A receiver that is down must not read as "nothing called out".
            # Silence from an unreachable poller is exactly the clean-looking
            # non-result this project treats as equal to a crash.
            result.not_assessed.append(NotAssessed(
                step="collaborator_poll", evaluator="collaborator",
                reason=f"out-of-band payloads were planted but could not be "
                       f"read back: {e}"))
        else:
            if hits:
                result.findings.append(Finding(
                    test_case_id=tc.id,
                    step="collaborator_poll",
                    vuln_type=f"Out-of-Band Interaction ({tc.attack_class or 'blind'})",
                    severity=tc.severity,
                    url=target.get("url") or target.get("url_template"),
                    parameter=target.get("parameter"),
                    evidence=(f"The target contacted {oast_host}, which only "
                              f"this run's payload named.\n"
                              + _oast.describe(hits))[:1500],
                ))

    result.duration_ms = int((time.time() - started) * 1000)
    return result
