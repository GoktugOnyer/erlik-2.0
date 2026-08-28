"""Perform a login and capture the session, so later cases can run authenticated.

The secret is decrypted for exactly the duration of one request and never
appears in a stored command, a log line, a step record or a report. That is why
the request is made by httpx here rather than by shelling out to curl: a curl
command line carrying a password would be written into `steps.tool_input` and
read back by anything that renders a run.

VERIFICATION IS PART OF ACQUISITION. A token that was returned is not a token
that works — a login form that answers 200 with "invalid credentials" would
otherwise be stored as a valid session and every downstream case would run
unauthenticated while claiming otherwise. A session is only marked `verified`
when a probe with it reaches a protected resource.
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from orchestrator import credentials as C
from orchestrator import secrets as S

# Where a token tends to be in a JSON login response. Checked in order.
_TOKEN_PATHS = ("token", "access_token", "accessToken", "jwt", "id_token",
                "authentication.token", "data.token")

_BEARER_RX = re.compile(r"^[A-Za-z0-9._~+/=-]{8,4096}$")

# Hidden form inputs, for CSRF tokens. Most real login forms carry one, and a
# POST without it is rejected — DVWA's `user_token` is why erlik's first
# authenticated run against it never authenticated anything.
_HIDDEN_RX = re.compile(
    r"""<input\b[^>]*\btype\s*=\s*['"]?hidden['"]?[^>]*>""", re.I)
_ATTR_RX = re.compile(r"""\b(name|value)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]*))""", re.I)

# Bounds. The page is attacker-controlled on a pentest; a login form does not
# legitimately carry hundreds of hidden fields or a megabyte token.
MAX_HIDDEN_FIELDS = 20
MAX_HIDDEN_VALUE = 4096


def hidden_fields(html: str) -> dict[str, str]:
    """Hidden inputs from a login page, for CSRF tokens.

    These are values the TARGET chose, echoed straight back to it in a
    form-encoded POST body. They never reach a shell, a command line or a
    template, so they are bounded rather than validated for injection — a CSRF
    token is opaque by design and a character allowlist would break real ones.
    """
    out: dict[str, str] = {}
    for tag in _HIDDEN_RX.findall(html or "")[:MAX_HIDDEN_FIELDS * 4]:
        attrs = {}
        for m in _ATTR_RX.finditer(tag):
            attrs[m.group(1).lower()] = m.group(2) or m.group(3) or m.group(4) or ""
        name = attrs.get("name", "")
        if name and len(attrs.get("value", "")) <= MAX_HIDDEN_VALUE:
            out[name] = attrs.get("value", "")
        if len(out) >= MAX_HIDDEN_FIELDS:
            break
    return out


def _dig(data: Any, path: str) -> str:
    cur = data
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return ""
        cur = cur[part]
    return cur if isinstance(cur, str) else ""


def extract_token(body: str) -> str:
    """A bearer token from a login response, or ''.

    Shape-checked before it is stored: a token is about to be interpolated into
    an Authorization header, and an error page is not a credential.
    """
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return ""
    for path in _TOKEN_PATHS:
        tok = _dig(data, path).strip()
        if tok.startswith("Bearer "):
            tok = tok[7:].strip()
        if tok and _BEARER_RX.match(tok):
            return tok
    return ""


async def authenticate(db, credential_id: str, *, verify_url: str = "",
                       timeout: float = 20.0) -> dict[str, Any]:
    """Log in with a stored credential and record the session.

    Returns a report with NO secret in it. `status` is 'verified' only when a
    probe with the captured session actually reached a protected resource.
    """
    row, password = await C._secret_of(db, credential_id)
    login_url = row.get("login_url") or ""
    if not login_url:
        return {"ok": False, "reason": "credential has no login_url"}

    kind = (row.get("kind") or "form").lower()
    user_field = row.get("username_field") or "username"
    pass_field = row.get("password_field") or "password"
    payload = {user_field: row.get("username") or "", pass_field: password}

    token, cookie, note = "", "", ""
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as cli:
            if kind == "json":
                r = await cli.post(login_url, json=payload)
            elif kind == "basic":
                r = await cli.get(login_url,
                                  auth=(row.get("username") or "", password))
            else:
                # GET the form first. Two reasons, and both are required for a
                # real login: the CSRF token has to be harvested, and it is
                # bound to the session cookie the same GET sets — which is why
                # this uses ONE client rather than a bare POST.
                #
                # The operator's own field values always win over harvested
                # ones, so a hidden input named `password` cannot displace the
                # credential.
                try:
                    form = await cli.get(login_url)
                    hidden = hidden_fields(form.text or "")
                except Exception:  # noqa: BLE001
                    hidden = {}
                if hidden:
                    note = f"sent {len(hidden)} hidden field(s); "
                r = await cli.post(login_url, data={**hidden, **payload})
            body = r.text or ""
            token = extract_token(body)
            jar = "; ".join(f"{k}={v}" for k, v in r.cookies.items())
            cookie = jar
            note = f"{note}HTTP {r.status_code}"
    except Exception as e:  # noqa: BLE001 — the message must not carry the payload
        return {"ok": False, "reason": f"login request failed: {type(e).__name__}"}
    finally:
        password = ""     # not a guarantee in CPython, but it shortens the window

    if not token and not cookie:
        return {"ok": False, "reason": f"no token or cookie in the response ({note})"}

    status = "unverified"
    if verify_url:
        status = "verified" if await _verify(verify_url, token, cookie,
                                             row.get("header_name") or "Authorization",
                                             timeout) else "rejected"
    sid = await C.save_session(db, credential_id, row["target_key"],
                               token=token, cookie=cookie, status=status)
    await db.commit()
    return {"ok": status != "rejected", "session_id": sid, "status": status,
            "has_token": bool(token), "has_cookie": bool(cookie), "note": note}


def _fingerprint(r: "httpx.Response") -> tuple:
    """What a response looks like, for comparison. Length is bucketed because
    a page can carry a username or a CSRF token and differ trivially."""
    return (r.status_code,
            (r.headers.get("location") or "").split("?")[0],
            len(r.content) // 512)


async def _verify(url: str, token: str, cookie: str, header_name: str,
                  timeout: float) -> bool:
    """Did the captured session actually reach a protected resource?

    DIFFERENTIAL, not a status allowlist. The first version returned True for
    anything that was not 401/403 — and DVWA answers an unauthenticated
    /index.php with `302 -> login.php`, so it stored a session that had never
    authenticated anything as `verified`. That is the exact failure this
    function exists to prevent, and a status allowlist cannot see it: the
    "protected" response and the rejection are both perfectly ordinary.

    So the probe is made TWICE, with and without the session, and the session
    is verified only when it CHANGES the answer. A response identical to the
    anonymous one proves the credentials did nothing, whatever its status code.
    """
    headers = {}
    if token:
        headers[header_name] = f"Bearer {token}"
    if cookie:
        headers["Cookie"] = cookie
    if not headers:
        return False
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as cli:
            with_session = await cli.get(url, headers=headers)
            anonymous = await cli.get(url)
    except Exception:  # noqa: BLE001
        return False
    if with_session.status_code in (401, 403):
        return False
    return _fingerprint(with_session) != _fingerprint(anonymous)
