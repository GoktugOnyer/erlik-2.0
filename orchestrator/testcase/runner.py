"""Execute a TestCase against a target and emit findings."""

import json
import re
import sys
import time
from typing import Any
from pydantic import BaseModel, Field

from orchestrator import http_capture
from orchestrator import llm_client
from orchestrator import credentials as _CRED
from orchestrator.testcase.schema import TestCase, TestStep, Evaluator
from orchestrator.testcase.scope import Scope, ScopeViolation, check_command, from_target
from orchestrator.tool_executor import _safe_mode_violation, execute_tool
from orchestrator.testcase.schema import endpoint_of
from urllib.parse import unquote_plus, urlsplit


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
    # WHAT THE RUN UNDID, and what it could not. One entry per declared `TestStep.cleanup`
    # whose step actually executed. A FAILED cleanup is the important one: it is a file
    # still sitting on a client's server, and a run that stayed silent about it is how
    # BUSL-09 came to tell a human to go looking with `find`.
    cleanups: list[StepResult] = Field(default_factory=list)
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


MAX_EVIDENCE = 1500
# Cut the evidence window this much wider than it will finally be, so a
# credential is scrubbed BEFORE the window is trimmed to its final size.
#
# Truncating first breaks the scrub: a secret is removed by substring
# replacement, so cutting through the middle of one leaves a partial run that no
# longer matches the value being searched for. Produced live: a 32-character
# session id straddling the cut left a 30-character contiguous prefix of itself
# in evidence bound for a client's issue tracker. The margin covers any
# credential shorter than itself; the scrub happens in _scrub_for_storage and
# the trim happens after it.
SECRET_MARGIN = 1024


def _around(output: str, at: int, span: int = MAX_EVIDENCE + 2 * SECRET_MARGIN) -> str:
    """The neighbourhood of the MATCH, not the head of the response.

    Evidence used to be `output[:1500]`, which is the proof only when the thing
    that matched happens to be near the top. Measured: DVWA prints PHP's fatal
    error before the page, so it was — and a 2957-character body with the same
    error rendered at offset 2788, which is what an ordinary framework does,
    produced 1500 characters of page furniture proving nothing. A finding is
    worse for carrying evidence that does not contain its own match: it looks
    checkable and is not.

    The offset is named because the full response is stored separately, and a
    reader who wants the rest needs to know where this came from.
    """
    if len(output) <= span:
        return output
    start = max(0, at - span // 4)
    end = min(len(output), start + span)
    head = f"[excerpt of {len(output)} bytes, from offset {start}]\n" if start else ""
    return head + output[start:end] + ("…" if end < len(output) else "")


def _caused_occurrence(pattern, flags, step_result, ev, prior_steps):
    """The first match of `pattern` whose neighbourhood is NOT in the baseline."""
    other = {x.step: x for x in (prior_steps or [])}.get(ev.differs_from or "")
    if other is None or not other.output:
        return None
    baseline = _comparable(other.output)
    for candidate in re.finditer(pattern, step_result.output, flags):
        window = _comparable(step_result.output[candidate.start():candidate.end() + 120])
        if window and window not in baseline:
            return candidate
    return None


def _payload_of(command: str) -> str:
    """The value a step sent, lifted out of its rendered command.

    Without this the blind comparisons name their rows `control_a`,
    `false_string`, `mysql_quoted_short` — and a reader cannot replay any of
    them. The command carries credential HANDLES rather than secrets, so the
    payload is safe to quote; it is the one part of the request the reader needs
    and the only part that was missing.
    """
    found = re.findall(r"--data-urlencode\s+\"[^\"=]{1,64}=([^\"]{0,160})\"", command)
    return found[-1] if found else ""


def _sent(steps: list[StepResult]) -> str:
    """`step -> payload` for each step a comparison rests on."""
    lines = [f"    {s.step:<22} sent {_payload_of(s.command)!r}" for s in steps
             if _payload_of(s.command)]
    return "  requests:\n" + "\n".join(lines) + "\n" if lines else ""


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


def _asserted_owner(output: str, field: str):
    """The owner the TARGET claims, read from a JSON body, or None.

    `field` is a dotted path the OPERATOR supplies — "data.UserId" for Juice
    Shop. None means "this response asserts no owner", which is not a finding and
    must never be confused with "the owner is someone else":

      - GET /rest/basket/99999 answers HTTP 200 with {"data":null}. No object, no
        owner. Measured; a status-code check calls this a critical flaw.
      - GET /api/Products answers 200 with a list and no ownership field at all.
        Public content.

    Deliberately narrow. It parses the LAST JSON document in the output, because
    the lane's curl steps prepend response headers, and it walks only plain
    dicts, so a list or a string at any point in the path is "no assertion"
    rather than a guess. A container is never an owner: returning the owner of
    one element of a list the caller is allowed to see would invent a claim.
    """
    if not field:
        return None
    text = output or ""
    # The body is whatever follows the last blank line when headers are present.
    for separator in ("\r\n\r\n", "\n\n"):
        if separator in text:
            text = text.rsplit(separator, 1)[1]
            break
    start = min((i for i in (text.find("{"), text.find("[")) if i >= 0), default=-1)
    if start < 0:
        return None
    try:
        document = json.loads(text[start:])
    except (ValueError, TypeError):
        return None
    node = document
    for part in field.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    # Only a scalar identifies a principal. A dict or list here means the path
    # named a container, and treating that as an owner would be a fabrication.
    if isinstance(node, (dict, list)) or node is None or isinstance(node, bool):
        return None
    return node


def _http_status_ok(output: str) -> bool:
    """True when the final response was a 2xx.

    Delegates to `http_capture.ok`. It used to be
    `re.search(r"^HTTP/\\S+\\s+2\\d\\d", output, re.MULTILINE)`, which searched the
    whole capture — and the body is part of the capture and is written by the TARGET.
    A 403 whose body contained a line `HTTP/1.1 200 OK` read as a success, which let a
    target assert that its own refusal had succeeded. That is the one direction the
    safety asymmetry behind every authorization check is supposed to make impossible.
    """
    return http_capture.ok(output)


def _response_headers(output: str) -> str:
    """The header block only — never let a body echo fake a header match."""
    return http_capture.headers(output)


def _response_body(output: str) -> str:
    """The body only — the mirror of `_response_headers`, for the opposite reason.

    A marker is searched for in a response to decide whether privileged DATA came
    back. Searching the whole capture would let the headers answer: a reflected
    marker in a `Location:` redirect, or an echo of the request line, is not the
    application handing over a record.
    """
    return http_capture.body(output)


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
            hit = re.search(pattern, step_result.output, flags)
            matched = bool(produced) or bool(hit)
            if hit:
                # THE OCCURRENCE THE PAYLOAD CAUSED, not the leftmost one.
                #
                # Attribution is decided over the WHOLE response, so a page that
                # already prints one database error — a debug banner, a legacy
                # query notice — is still reported when a second, caused error
                # appears. But the window was cut at the FIRST match, which on
                # such a page is the permanent one: the client got 1500 bytes the
                # benign baseline returns too, which is the exact failure the
                # window was introduced to close, and it invites a reader to
                # dismiss a real finding.
                hit = _caused_occurrence(pattern, flags, step_result, ev, prior_steps) or hit
                evidence = _around(step_result.output, hit.start())
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
        reflected = re.search(r"(?im)^Access-Control-Allow-Origin:\s*" + re.escape(origin) + r"\s*$", headers)
        matched = bool(
            reflected and re.search(r"(?im)^Access-Control-Allow-Credentials:\s*true\s*$", headers))
        if matched:
            # The headers, not the body: the claim is about two header lines and
            # the body is irrelevant to it.
            evidence = _around(headers, reflected.start())

    elif ev.type == "ownership":
        # OBJECT-LEVEL AUTHORIZATION (E-011). The existing `idor` evaluator asks
        # whether two identities got the SAME BYTES; this one asks whether the
        # application itself says the object belongs to someone else.
        #
        # That is a sharper question on an API, where `idor`'s body comparison
        # cannot work: every JSON response carries timestamps and ids, so two
        # identities never produce identical bytes and a hash differential is
        # noise. Measured on Juice Shop, GET /rest/basket/1 as user 2 returns
        # 200 with {"data":{"id":1,"UserId":1,...}} — the target naming an owner
        # who is not the caller, which is the finding, stated by the application.
        #
        # E-011: "Compare ownership assertions and sensitive response markers,
        # not merely HTTP 200, response length, or a changed numeric ID." The
        # nonexistent-object case is why: Juice Shop answers
        # GET /rest/basket/99999 with HTTP 200 and {"data":null}, so a status-code
        # check reports a critical authorization flaw on an object that does not
        # exist.
        #
        # FOUR CLAUSES, ALL REQUIRED.
        #   1. the caller got the object, and the response ASSERTS an owner
        #   2. that owner is not the caller's own operator-declared id
        #   3. the declared owner can read it too, so the claim is corroborated
        #   4. an anonymous request is REFUSED, so it is not published content
        #
        # Clause 4 is what stops a target choosing its own finding. A fixture
        # that asserts one owner to every caller, anonymous included, is
        # published content however it is attributed; without this clause the
        # lane reports it as a critical leak. Clause 3 catches the other forgery:
        # an owner named who cannot actually read the object.
        #
        # The asymmetry is deliberate. `subject_id` — who the caller IS — comes
        # from the OPERATOR; the asserted owner comes from the TARGET. A target
        # can therefore push the lane towards "not yours" and never towards
        # "yours", so it can cost itself coverage and cannot manufacture a
        # finding. Both values coming from the target would be the forgery
        # primitive this codebase has shipped before.
        owner_field = str(ev.owner_field or "")
        subject = target.get("subject_id")
        owner_step = next((st for st in (prior_steps or []) if st.step == str(ev.owner_step or "")), None)
        anon_step = next((st for st in (prior_steps or []) if st.step == str(ev.anonymous_step or "")), None)

        asserted = _asserted_owner(step_result.output, owner_field) if owner_field else None
        corroborated = (owner_step is not None
                        and _http_status_ok(owner_step.output)
                        and _asserted_owner(owner_step.output, owner_field) == asserted)
        # "Refused" means REFUSED BY THE APPLICATION. An anonymous 200 is publication, an
        # anonymous step that never ran tells us nothing, and — the case this missed — an
        # arm the egress proxy refused or that timed out tells us nothing either, while
        # looking exactly like a refusal: `_http_status_ok("")` is False, and so is
        # `_http_status_ok` of erlik's own proxy-refusal text.
        anonymous_refused = (anon_step is not None
                             and http_capture.answered(anon_step.output)
                             and not _http_status_ok(anon_step.output))

        matched = bool(
            owner_field and subject not in (None, "")
            and _http_status_ok(step_result.output)
            and asserted not in (None, "")
            and str(asserted) != str(subject)
            and corroborated and anonymous_refused)
        if matched:
            evidence = (
                "erlik compared an ownership claim the application made against the "
                "identity it was\nmade to. The quoted fragments are the application's.\n"
                f"  the caller is declared to be:  {subject!r} (operator-supplied)\n"
                f"  the response attributes it to: {asserted!r} (read from {owner_field!r})\n"
                f"  {(owner_step.step if owner_step else '?'):<24} the declared owner could read it too\n"
                f"  {(anon_step.step if anon_step else '?'):<24} anonymous was refused, so it is not published\n\n"
                "the caller's response:\n"
                + _around(step_result.output, 0, 600)
                + "\n\nthe declared owner's response, for comparison:\n"
                + _around(owner_step.output, 0, 600))

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
        # WHAT COUNTS AS AN IDENTITY. This read `low_priv_token` and
        # `high_priv_token` only, so on DVWA — and on most PHP, Rails and Django
        # applications, where the session is a cookie — both were None,
        # `None != None` was False, and this evaluator could never fire at all.
        #
        # It is the same bearer-only assumption AUTHZ-04's YAML case was already
        # corrected for via `required_any`; the fix reached the case and not the
        # code beside it. `credentials.auth_inputs` offers `{role}_priv_token` OR
        # `{role}_priv_cookie` according to what the session actually is, and a
        # cookie authenticates exactly as much as a bearer token.
        #
        # The comparison itself stays, because an "IDOR" whose two arms carried
        # the SAME credential is one request reported twice. Both arms must also
        # have carried SOMETHING: two unauthenticated fetches agreeing proves the
        # page is public, which is the one thing the old `None != None`
        # accidentally got right.
        low = (target.get("low_priv_token"), target.get("low_priv_cookie"))
        high = (target.get("high_priv_token"), target.get("high_priv_cookie"))

        # THE MARKER MUST NOT BE THE CALLER'S OWN INPUT. The cross-arm check applies this
        # as its clause 0 and this evaluator — the only one hard-graded `confirmed`, which
        # sets `verified` on a client's tracker — had no equivalent. An endpoint that echoes
        # input satisfies every clause below without disclosing anything, because the target
        # would be supplying the evidence for its own verdict.
        #
        # Measured, both firing HIGH `confirmed` before this:
        #
        #     marker 99999 at /rest/track-order/99999 answering {"data":[{"orderId":"99999"}]}
        #     marker "Vulnerability: Reflected" at ?name=Vulnerability%3A+Reflected on DVWA
        #
        # `unquote_plus`, not `unquote`, for the second: a form-encoded marker carries `+`
        # for space. `url_template` as well as `url`, because the access-control cases name
        # their endpoint in the template and a marker reflected from it is reflected just
        # the same.
        probed = " ".join(str(target.get(field) or "") for field in ("url", "url_template"))
        reflected = bool(marker) and (marker in probed or marker in unquote_plus(probed))

        # THE ANONYMOUS ARM. "The low-privilege identity read the object" is only a
        # finding if reading it required BEING somebody. Without this clause the
        # evaluator reports public content as a critical authorization failure: on
        # Juice Shop, GET /rest/products/1/reviews returns the same reviews — author
        # addresses included — to admin, to jim and to nobody at all.
        #
        # Measured over 3 seeded violations and 11 negative controls:
        #
        #     the shipped body-hash verdict   5 false positives, 0 false negatives
        #     marker + this clause            0 false positives, 0 false negatives
        #     marker without this clause      3 false positives, 0 false negatives
        #
        # A case that declares no `anonymous_step` keeps the old behaviour, so this
        # is additive. A case that DOES declare one and whose step is missing gets no
        # finding: a clause nobody ran is not a clause that passed — the same rule
        # the `ownership` evaluator applies to its own arms.
        anonymous = next((st for st in (prior_steps or [])
                          if st.step == str(ev.anonymous_step or "")), None)
        if ev.anonymous_step:
            # THE ARM MUST HAVE ANSWERED. An arm that received nothing trivially does not
            # contain the marker, so this clause passed on silence: measured, a real
            # `curl --max-time 0.001` returning zero bytes produced a HIGH `confirmed`
            # Broken Access Control finding on Juice Shop's PUBLIC reviews endpoint — the
            # exact content this clause exists to refuse. And the marker is matched against
            # the BODY, because a marker echoed into a header is not disclosed data.
            anonymous_excluded = (anonymous is not None
                                  and http_capture.answered(anonymous.output)
                                  and marker not in _response_body(anonymous.output))
        else:
            anonymous_excluded = True

        # THE BODY, NOT THE CAPTURE. The anonymous clause above already reads the body and
        # says why — "a marker echoed into a header is not disclosed data" — and the
        # positive side did not, so the rule was applied to the arm that can only REFUSE a
        # finding and not to the arm that makes one. Measured: a marker echoed into an
        # `X-Requested-User:` header on both arms, with `{"data":{}}` — an empty record —
        # as the body, produced a HIGH `confirmed` Broken Access Control finding.
        #
        # This costs no true positive. `_http_status_ok` is already required of both arms
        # and is False for a capture with no status line, so a case whose curl omits `-i`
        # could never reach here in the first place; measured on all three arms of
        # tests_catalog/wstg/AUTHZ-04_idor.yaml, each of which passes `-i`.
        matched = bool(
            marker and baseline is not None
            and _http_status_ok(baseline.output) and _http_status_ok(step_result.output)
            and marker in _response_body(baseline.output)
            and marker in _response_body(step_result.output)
            and any(low) and any(high) and low != high
            and not reflected
            and anonymous_excluded)
        if matched:
            # A DIFFERENTIAL claim needs BOTH sides. This is the only evaluator
            # hard-graded `confirmed`, which sets `verified` on a client's
            # tracker, and it was falling through to the head of the
            # low-privilege response — one side of a two-sided claim, with the
            # privileged baseline named nowhere and the marker itself often past
            # the cut. A reader could not tell what crossed between identities.
            evidence = ("erlik comparison of two identities — the quoted fragments are the "
                        "application's\n"
                        f"  the private object is identified by: {marker!r}\n"
                        f"  {baseline.step:<26} as the privileged identity, "
                        f"{len(baseline.output)} bytes\n"
                        f"  {step_result.step:<26} as the low-privilege identity, "
                        f"{len(step_result.output)} bytes\n"
                        "  both returned it, and the two identities differ\n"
                        + (f"  {anonymous.step:<26} anonymous did NOT receive it, so it "
                           f"is not public\n" if ev.anonymous_step and anonymous else "")
                        + "\n"
                        "privileged response, around the object:\n"
                        + _around(baseline.output, baseline.output.index(marker), 600)
                        + "\n\nlow-privilege response, around the same object:\n"
                        + _around(step_result.output, step_result.output.index(marker), 600))

    elif ev.type == "cookie_attributes":
        # Structure, not a regex: a session cookie missing HttpOnly is the claim,
        # and only a parsed Set-Cookie can distinguish that from the word
        # "httponly" appearing somewhere else in the response.
        from http.cookies import SimpleCookie
        from urllib.parse import urlsplit
        is_https = urlsplit(endpoint_of(target)).scheme == "https"
        # THE HEADER BLOCK, not the whole capture. `_response_headers` exists in this file
        # for exactly this reason and this call did not use it: measured on DVWA,
        # `?name=%0ASet-Cookie:+JSESSIONID%3Dforged%0A` made the application print the line
        # into its BODY and this emitted a MEDIUM "Insecure Cookie Attributes" quoting a
        # cookie the server never set. WSTG-SESS-02 is the one case runnable without
        # `active`, and it runs against every discovered URL.
        for value in re.findall(r"(?im)^Set-Cookie:\s*([^\r\n]+)",
                                _response_headers(step_result.output)):
            parsed = SimpleCookie()
            try:
                parsed.load(value)
            except Exception:
                continue
            for name, cookie in parsed.items():
                if not re.search(r"session|sid|token|jwt|auth", name, re.I):
                    continue
                missing = [a for a in ("HttpOnly", "SameSite") if not cookie[a.lower()]]
                if is_https and not cookie["secure"]:
                    missing.append("Secure")
                if missing:
                    matched = True
                    # THE LINE THAT WAS JUDGED, and which attribute is absent.
                    # The whole header block was never the point, and a reader
                    # given it has to re-derive the judgement; a reader given
                    # this can check it. The cookie VALUE is redacted downstream
                    # and the attributes are not, which is why this is worth
                    # quoting at all.
                    evidence = (f"Set-Cookie: {value}\n\n"
                                f"cookie `{name}` reads as a session cookie and is missing: "
                                f"{', '.join(missing)}"
                                + (" (the endpoint is https, so Secure applies)" if is_https else ""))

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
                    "erlik comparison of four responses — the quoted fragments are the "
                    "application's\n"
                    + _sent(controls + [other, step_result])
                    + "blind boolean differential\n"
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
                    "erlik comparison of four responses — the durations are measured, not quoted\n"
                    + _sent(controls + [step_result])
                    + "blind timing differential\n"
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
            evidence=(evidence or _around(step_result.output, 0)),
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
    for step in result.steps:
        if secrets:
            step.output = _CRED.scrub(step.output, secrets)
            step.error = _CRED.scrub(step.error, secrets) if step.error else step.error
    for finding in result.findings:
        if secrets:
            finding.evidence = _CRED.scrub(finding.evidence, secrets)
            finding.basis = _CRED.scrub(finding.basis, secrets)
        # TRIM LAST, and never silently: a partial quote presented as a whole one
        # lets the target choose where the reader's view ends.
        if len(finding.evidence) > MAX_EVIDENCE:
            finding.evidence = (finding.evidence[:MAX_EVIDENCE]
                                + f"\n[truncated at {MAX_EVIDENCE} characters]")


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
    # (step, rendered context) for every step that EXECUTED and declared an undo. Populated
    # in the loop and drained in the `finally` below — see TestStep.cleanup.
    pending_cleanups: list[tuple] = []
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

            # SAFE MODE IS A FLOOR HERE, NOT ONLY INSIDE `execute_tool`.
            #
            # E-033 recorded the mutation refusal as "a lane opt-in, not the runner's floor",
            # and judged it acceptable because "safe mode now covers every lane, so this is
            # two gates agreeing". It does not. Safe mode lives in `execute_tool`, and a
            # caller that supplies its own `executor` never reaches it: the integration
            # lane's `execute` goes straight from `curl_request` to `sandbox.run`. So that
            # lane's ONLY mutation gate is `step_policy` — an optional keyword argument.
            #
            # Measured, with a recording executor that sends nothing, on a caller supplying
            # its own executor and no policy:
            #
            #     curl -X PUT     ...   SENT, refused by nothing
            #     curl -X DELETE  ...   SENT, refused by nothing
            #     curl -F @upload ...   refused, but by `curl_request`'s syntax rule
            #
            # The two that went through are exactly the two safe mode exists to stop. So the
            # floor is applied where every caller passes, whatever executor they brought.
            # It is deliberately redundant for the legacy lane, where `execute_tool` refuses
            # the same commands again — a second gate that never fires is the point of a
            # floor, and the reason text says which gate spoke.
            safe_reason = _safe_mode_violation(cmd)
            if safe_reason:
                result.steps.append(StepResult(
                    step=step.name, command=cmd, success=False, output="",
                    duration_ms=0, error=f"SAFE_MODE: {safe_reason}", skipped=True))
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
            if step.cleanup:
                # Only after a step that RAN. A skipped or refused step created nothing, and
                # undoing what was never done is a request to a client's server for no reason.
                pending_cleanups.append((step, ctx))
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
        # IN `finally`, because the artifact exists whether or not the case finished. A
        # cleanup that only ran on the happy path would be absent exactly when a run was
        # cut short mid-probe, which is when something is most likely left behind.
        #
        # Reverse order: a later step can depend on what an earlier one created, so undoing
        # forwards can remove the thing the next undo needs.
        for step, step_ctx in reversed(pending_cleanups):
            try:
                command = _render(step.cleanup, step_ctx)
            except Exception as exc:          # noqa: BLE001 — see the scope branch below
                result.cleanups.append(StepResult(
                    step=f"cleanup: {step.name}", command=step.cleanup, success=False,
                    output="", duration_ms=0, skipped=True,
                    error=f"could not be rendered: {type(exc).__name__}: {exc}"))
                continue
            outcome = StepResult(step=f"cleanup: {step.name}", command=command,
                                 success=False, output="", duration_ms=0)
            safe_reason = _safe_mode_violation(command)
            if safe_reason:
                # Cannot fire on a legitimate cleanup — the step it undoes only ran because
                # safe mode permitted the mutation in the first place — and stops a case
                # smuggling one past a gate its own step could not pass.
                outcome.skipped, outcome.error = True, f"SAFE_MODE: {safe_reason}"
                result.cleanups.append(outcome)
                continue
            if scope is not None:
                try:
                    (command_checker or check_command)(
                        command, scope, primary_url=endpoint_of(target))
                except ScopeViolation as exc:
                    outcome.skipped, outcome.error = True, f"scope violation: {exc}"
                    result.cleanups.append(outcome)
                    continue
                except Exception as exc:      # noqa: BLE001
                    # ONE FAILED UNDO MUST NOT STRAND THE REST — the lesson `service.release`
                    # already learned about collectors, and it applies harder here, because
                    # what is stranded is a file on a client's server. `Exception`, not
                    # `BaseException`: a cancellation or a KeyboardInterrupt is the operator
                    # stopping the run and must still propagate.
                    outcome.skipped = True
                    outcome.error = f"could not be checked: {type(exc).__name__}: {exc}"
                    result.cleanups.append(outcome)
                    continue
            try:
                raw = await (executor or execute_tool)(
                    command, enabled_tools=_TOOLS_ALL, target_url=endpoint_of(target),
                    no_timeout=False, tool_hint=step.tool, custom_timeout=step.timeout)
                outcome.success = bool(raw.get("success"))
                outcome.output = str(raw.get("output") or "")
                outcome.error = raw.get("error")
            except Exception as exc:      # noqa: BLE001 — a failed undo must be REPORTED
                outcome.error = f"{type(exc).__name__}: {exc}"
            result.cleanups.append(outcome)

    _scrub_for_storage(result, tuple(dict.fromkeys(resolved_secrets)))
    result.duration_ms = int((time.time() - started) * 1000)
    return result
