"""Read-side primitive extraction: candidates lifted from one tool/HTTP response.

PURE. Given a raw response string and the host it came from, `extract` returns
the `Primitive` candidates found — bearer/Authorization tokens, Set-Cookie
session cookies, CSRF tokens (hidden input / meta / JSON field) and obvious
injection-point hints. It touches no database, no run config and no agent
state; attaching primitives and feeding them back to the model is the job of
other modules (`session_state.py`, the agent loop). This file only reads.

TWO RULES IT INHERITS FROM THE DETERMINISTIC LANE, because the same response is
forgeable in the same two ways:

1. HEADER SECRETS COME FROM THE HEADER BLOCK, NEVER THE BODY. The body is
   written by the target, so a target that prints `Set-Cookie: ...` or
   `Authorization: Bearer ...` into its own body must not have that read back
   as a credential it set. We split the capture with `http_capture` — the one
   parser both lanes share — and read cookies/auth headers only from the first
   header block. This mirrors `testcase/runner.py`'s cookie harvest, which was
   itself moved onto the header block after a reflected `Set-Cookie` in a DVWA
   body produced a cookie finding the server never set.

   A response with no HTTP framing at all (a bare HTML page from a tool that
   stripped the status line) has no trustworthy header block, so NO header
   secret is harvested from it — only body-sourced primitives (CSRF, form
   fields) are, and those are expected to live in the body.

2. VALUES ARE DROPPED, NEVER ESCAPED, IF THEY FAIL THE INJECTION GATE. Every
   candidate is about to become context the model may paste into a command, so
   each runs through `engagement.looks_injectable` — the same gate the sweep
   planner and `runner._harvest` apply — and an unsafe value is discarded, not
   quoted around. This text came from the target.
"""

from __future__ import annotations

import re
from http.cookies import SimpleCookie

from orchestrator import http_capture
from orchestrator.engagement import looks_injectable
from orchestrator.session_state import Primitive

# A cookie or token name that reads as a *session* credential, not an analytics
# or preference cookie. Identical to the filter `runner.py` applies before it
# will grade a cookie's attributes — a session cookie is the thing worth reusing
# and the thing worth flagging; a locale cookie is neither.
_SESSION_NAME = re.compile(r"session|sess|sid|token|jwt|auth|csrf|xsrf", re.I)

# A JWT: three base64url segments. Deliberately anchored on the `eyJ` header
# prefix (`{"` base64url-encoded) so arbitrary dotted strings are not swept up.
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b")

# Response headers that deliver a reusable credential in the header rather than
# the body — Keystone's `X-Subject-Token`, gateway/session token headers, or an
# `Authorization` line present in a framed header block. Matched only inside the
# header region, so a line a target printed into its body is never read as one.
# The name is kept alongside the value so the primitive replays verbatim.
_AUTH_HEADER = re.compile(
    r"(?im)^(Authorization|X-Subject-Token|X-Auth-Token|X-Amz-Security-Token)"
    r":\s*([^\r\n]+?)\s*$")

# Token-bearing JSON fields in a response body (a login endpoint's reply).
_JSON_TOKEN = re.compile(
    r'"(?:access_token|accessToken|authToken|id_token|idToken|bearer|token|jwt)"'
    r'\s*:\s*"([^"]{8,})"')

# CSRF delivered as a JSON field.
_JSON_CSRF = re.compile(
    r'"(?:csrf[_-]?token|_csrf|xsrf[_-]?token|csrfToken|xsrfToken)"'
    r'\s*:\s*"([^"]{6,})"', re.I)

# CSRF delivered in a <meta> tag. name/content order varies, so the tag is
# matched and its attributes read independently below.
_META_TAG = re.compile(r"(?is)<meta\b[^>]*>")
# Any <input ...> / <textarea ...> tag; attributes parsed order-independently.
_INPUT_TAG = re.compile(r"(?is)<(input|textarea|select)\b[^>]*>")


def _attr(tag: str, name: str) -> str:
    """One HTML attribute's value, quoted or bare, or "" when absent."""
    m = re.search(
        rf"""(?is)\b{name}\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))""", tag)
    if not m:
        return ""
    return (m.group(2) or m.group(3) or m.group(4) or "").strip()


def _safe(value: str) -> str:
    """The value if it survives the injection gate, else "". Strips surrounding
    whitespace first; a value that is empty after stripping is not a primitive."""
    v = (value or "").strip()
    if not v or looks_injectable(v):
        return ""
    return v


def _header_region(raw: str) -> str:
    """The trustworthy header block, or "" when the capture has no HTTP framing.

    `http_capture.headers` returns the whole string when there is no header/body
    split, which for an unframed HTML blob would be the body masquerading as
    headers — exactly the forgery this guards against. So a capture with no
    status line yields no header region at all.
    """
    if http_capture.status(raw) is None:
        return ""
    return http_capture.headers(raw)


def _body_region(raw: str) -> str:
    """The body to scan for CSRF / form fields.

    A framed capture's body comes from `http_capture.body`; an unframed blob
    (no status line) is treated as body in full, since that is where its CSRF
    and form fields live and there is no header block to confuse them with.
    """
    if http_capture.status(raw) is None:
        return raw or ""
    return http_capture.body(raw)


def extract(raw: str, source_host: str = "") -> list[Primitive]:
    """Primitive candidates found in one response. Pure; order is stable.

    `source_host` is recorded on each primitive as the reuse boundary — a
    captured session token belongs to the host that issued it and nowhere else.
    """
    if not raw:
        return []

    host = (source_host or "").strip()
    headers = _header_region(raw)
    body = _body_region(raw)

    out: list[Primitive] = []
    seen: set[tuple[str, str, str]] = set()

    def emit(kind: str, value: str, name: str = "", hint: str = "") -> None:
        key = (kind, name, value)
        if value and key not in seen:
            seen.add(key)
            out.append(Primitive(kind=kind, value=value, source_host=host,
                                  name=name, hint=hint))

    # -- header block: Set-Cookie session cookies, Authorization headers ----
    for line in re.findall(r"(?im)^Set-Cookie:\s*([^\r\n]+)", headers):
        jar = SimpleCookie()
        try:
            jar.load(line)
        except Exception:
            continue
        for name, morsel in jar.items():
            if not _SESSION_NAME.search(name):
                continue
            pair = _safe(f"{name}={morsel.value}")
            if pair:
                emit("cookie", pair, name=name,
                     hint='reuse as --cookie "<name=value>"')

    for hname, hval in _AUTH_HEADER.findall(headers):
        value = _safe(hval)
        if value:
            emit("header", value, name=hname,
                 hint=f'reuse as -H "{hname}: <value>"')

    # -- body: bearer/JWT/JSON tokens --------------------------------------
    for tok in _JWT.findall(body):
        value = _safe(tok)
        if value:
            emit("token", value, hint='reuse as -H "Authorization: Bearer <token>"')

    for tok in _JSON_TOKEN.findall(body):
        value = _safe(tok)
        if value:
            emit("token", value, hint='reuse as -H "Authorization: Bearer <token>"')

    # -- body: CSRF tokens (hidden input / meta / json) --------------------
    for tag in _META_TAG.findall(body):
        name = _attr(tag, "name") or _attr(tag, "property")
        if name and _is_csrf_name(name):
            value = _safe(_attr(tag, "content"))
            if value:
                emit("csrf", value, name=name,
                     hint="send as the CSRF token on state-changing requests")

    for cval in _JSON_CSRF.findall(body):
        value = _safe(cval)
        if value:
            emit("csrf", value, hint="send as the CSRF token on state-changing requests")

    # -- body: form fields -> CSRF (hidden) or injection-point (editable) --
    for m in _INPUT_TAG.finditer(body):
        tag = m.group(0)
        kind_tag = m.group(1).lower()
        name = _attr(tag, "name")
        if not name:
            continue
        itype = (_attr(tag, "type") or ("textarea" if kind_tag == "textarea" else "text")).lower()
        if _is_csrf_name(name):
            value = _safe(_attr(tag, "value"))
            if value:
                emit("csrf", value, name=name,
                     hint="send as the CSRF token on state-changing requests")
            continue
        # Editable, user-controllable field names are the obvious injection
        # points. Non-interactive field types (hidden/submit/button/…) are not,
        # and are skipped — a hidden field without a CSRF-ish name is state the
        # user does not type into.
        if itype in ("hidden", "submit", "button", "image", "reset", "file"):
            continue
        safe_name = _safe(name)
        if safe_name:
            emit("injection_point", safe_name, name=safe_name,
                 hint=f"user-controllable `{kind_tag}` field — candidate injection point")

    return out


def _is_csrf_name(name: str) -> bool:
    return bool(re.search(r"csrf|xsrf", name or "", re.I))
