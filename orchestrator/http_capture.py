"""Reading a `curl -i` capture: the status, the headers, the body.

WHY THIS IS ITS OWN MODULE. Two lanes had each grown their own status parser and
both were forgeable by the target, in the same way and for the same reason — they
searched the WHOLE capture for a status line, and the body is part of the capture
and is written by the target:

    orchestrator/testcase/runner.py   re.search(r"^HTTP/\\S+\\s+2\\d\\d", out, M)
    orchestrator/detection.py         _STATUS_RX.findall(out)[-1]

Measured against the real functions, a refusal the application issued:

    HTTP/1.1 403 Forbidden
    Content-Type: application/json

    upstream said:
    HTTP/1.1 200 OK
    {"email":"admin@juice-sh.op"}

`_http_status_ok` returned **True** for that, and the 200 is a line the target
typed into its own body. Every authorization check in the product rests on this
primitive — the `ownership` and `idor` evaluators, and both cross-arm checks — so
a target could assert that its own refusal was a success, which is the one
direction the safety asymmetry is supposed to make impossible.

THE RULE. A status comes only from the first line of a HEADER BLOCK, walking
forward from the front of the capture and advancing ONLY across 3xx blocks. That
keeps `curl -i -L` working — it prints every header block and only the FINAL
body, so a redirect chain is header blocks back to back — while making the body
unreachable: the walk stops at the first non-redirect status, which is the real
response's own.
"""
from __future__ import annotations

import re

_STATUS_LINE = re.compile(r"HTTP/\S+\s+(\d{3})")
_BLOCK = re.compile(r"\r?\n\r?\n")


def status(output: str) -> int | None:
    """The final response's status code, or None when the capture has no status line.

    None is a real answer and is not 2xx: a probe that recorded no response line at
    all did not succeed, and treating an unparseable capture as a success is how a
    check reports on something that never happened.
    """
    code = None
    for block in _BLOCK.split(output or ""):
        first = block.split("\n", 1)[0].strip()
        found = _STATUS_LINE.match(first)
        if not found:
            break               # not a header block — everything after it is body
        code = int(found.group(1))
        if not 300 <= code < 400:
            break               # the final response; later blocks are its body
    return code


def ok(output: str) -> bool:
    """True when the final response was a 2xx."""
    code = status(output)
    return code is not None and 200 <= code < 300


# The header the egress proxy stamps on its OWN refusal (proxy_addon.Guard.request). A
# capture carrying it is erlik's answer, not the application's, whatever its status line
# says — and the 403 it comes with parses perfectly well as a response.
_OUR_BLOCK = re.compile(r"(?im)^x-erlik-blocked:\s*true")


def answered(output: str) -> bool:
    """Did the APPLICATION answer this probe at all?

    THIS IS THE CLAUSE FOUR CHECKS WERE MISSING, and the defect is the same every time: an
    arm that received NOTHING trivially does not contain the thing being looked for, so
    every "the anonymous arm did not get it" test passed on silence. Measured end to end:

      * `cross_arm_privileged_function` reported a finding on Juice Shop's
        `/rest/products/1/reviews` — content every arm can read — because the anonymous
        arm's stored capture was erlik's OWN proxy-refusal text;
      * the `idor` evaluator graded the same shape HIGH `confirmed` from a real
        `curl --max-time 0.001` that returned zero bytes.

    `deterministic.curl_request` hands an evaluator a NON-EMPTY string with no status line
    when the proxy refuses, and 29 of 60 probes were refused in one measured run, so this is
    the common case rather than an edge. A timeout, a reset and a proxy refusal all arrive
    here as "not a 2xx", which is indistinguishable from the target saying no — and only one
    of those is evidence about the application.

    An absence is only evidence when something was there to be absent FROM.
    """
    text = output or ""
    if not text.strip():
        return False
    # OUR OWN REFUSAL, WHICH DOES PARSE AS A RESPONSE. `deterministic.curl_request`
    # substitutes a status-line-less sentence today, which the `status()` test below catches
    # on its own — but a capture can also arrive with the proxy's real 403 in it, from any
    # job whose output is not routed through that substitution, and `HTTP/1.1 403 Forbidden`
    # parses exactly like the target saying no. The `X-Erlik-Blocked` header is the durable
    # marker, stamped by the proxy on its own refusals.
    if _OUR_BLOCK.search(headers(text)):
        return False
    return status(text) is not None


def headers(output: str) -> str:
    """The first header block only — never let a body echo fake a header match."""
    parts = _BLOCK.split(output or "", 1)
    return parts[0] if len(parts) > 1 else (output or "")


def body(output: str) -> str:
    """Everything after the header blocks, or "" when the capture has no body.

    "" rather than the whole capture in two cases, both because a false body is worse
    than no body: a header-only capture (nothing was disclosed, and returning the
    headers would let a marker reflected into one satisfy a disclosure check), and a
    capture with no response line at all (nothing here was parsed as a response).

    Known narrow limit, in the safe direction: a body whose FIRST line is itself a
    status line is walked past as though it were another header block, so such a body
    reads as empty. That loses a finding rather than inventing one.
    """
    text = output or ""
    if not _STATUS_LINE.match(text.split("\n", 1)[0].strip()):
        return ""
    while _STATUS_LINE.match(text.split("\n", 1)[0].strip()):
        parts = _BLOCK.split(text, 1)
        if len(parts) == 1:
            return ""           # a header block with nothing after it
        text = parts[1]
    return text
