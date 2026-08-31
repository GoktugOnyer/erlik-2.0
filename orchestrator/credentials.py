"""Credentials and captured sessions, per target.

WHY THIS UNBLOCKS THE MOST
Broken Access Control is 6 of the 35 ground-truth items on the benchmark
target, and neither lane has ever matched one: WSTG-AUTHZ-04 needs a LOW and a
HIGH privilege session to compare, and has been a named skip on every recorded
run for want of them. Broken Authentication (5 more items) is only partially
reachable for the same reason, and most of a real client's application sits
behind a login that erlik could not pass.

WHAT IS STORED AND WHAT IS NOT
The password is encrypted (see orchestrator/secrets.py) and so is any captured
token or cookie. Nothing here returns a secret: `listing()` yields a masked
view, and the raw value is reachable only through `_secret_of`, which the login
executor calls at the moment it authenticates.

A credential is keyed on target_key (host:port), the same key recon_context,
the handoff and target_endpoints use, so it works with or without an
engagement record.
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any

from orchestrator import secrets as S
from orchestrator.testcase.endpoints import target_key

ROLES = ("low", "high", "user", "admin")


async def store(db, target: str, label: str, username: str, secret: str, *,
                role: str = "user", kind: str = "form",
                login_url: str = "", username_field: str = "username",
                password_field: str = "password",
                engagement_id: str | None = None,
                extra: dict[str, Any] | None = None) -> str:
    """Save a credential. Raises SecretError rather than storing readable text.

    The refusal is the point: falling back to plaintext when the key is
    unavailable looks identical from the outside and is exactly the failure
    encryption exists to prevent.
    """
    tk = target_key(target)
    if not tk:
        raise ValueError("cannot derive a target from %r" % (target,))
    if not label:
        raise ValueError("a credential needs a label")
    enc = S.encrypt(secret)          # raises if the key is unavailable
    cid = str(uuid.uuid4())[:12]
    await db.execute(
        "INSERT OR REPLACE INTO engagement_credentials "
        "(id, engagement_id, target_key, label, role, kind, username, secret_enc, "
        " login_url, username_field, password_field, extra) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (cid, engagement_id, tk, label, role, kind, username, enc,
         login_url, username_field, password_field,
         json.dumps(extra) if extra else None))
    return cid


def _view(row: dict) -> dict:
    """The masked shape. `secret_enc` is dropped entirely rather than masked —
    a field that is absent cannot be accidentally serialised later."""
    out = {k: v for k, v in row.items() if k not in ("secret_enc", "token_enc",
                                                     "cookie_enc")}
    out["secret"] = S.masked()
    out["has_secret"] = bool(row.get("secret_enc"))
    return out


async def listing(db, target: str | None = None) -> list[dict]:
    """Credentials an operator may read — never their secrets."""
    if target:
        cur = await db.execute(
            "SELECT * FROM engagement_credentials WHERE target_key = ? ORDER BY role, label",
            (target_key(target),))
    else:
        cur = await db.execute(
            "SELECT * FROM engagement_credentials ORDER BY target_key, role, label")
    return [_view(dict(r)) for r in await cur.fetchall()]


async def _secret_of(db, credential_id: str) -> tuple[dict, str]:
    """(row, plaintext) for the login executor. The ONLY path to a secret."""
    cur = await db.execute(
        "SELECT * FROM engagement_credentials WHERE id = ?", (credential_id,))
    row = await cur.fetchone()
    if not row:
        raise KeyError(credential_id)
    d = dict(row)
    return d, S.decrypt(d.get("secret_enc"))


async def save_session(db, credential_id: str, target_key_: str, *,
                       token: str = "", cookie: str = "",
                       header_name: str = "Authorization",
                       status: str = "unverified") -> str:
    sid = str(uuid.uuid4())[:12]
    await db.execute(
        "INSERT INTO engagement_sessions (id, credential_id, target_key, "
        "token_enc, cookie_enc, header_name, status, verified_at) "
        "VALUES (?,?,?,?,?,?,?, CASE WHEN ?='verified' THEN datetime('now') END)",
        (sid, credential_id, target_key_,
         S.encrypt(token) if token else None,
         S.encrypt(cookie) if cookie else None,
         header_name, status, status))
    return sid


async def latest_session(db, credential_id: str) -> dict | None:
    cur = await db.execute(
        "SELECT * FROM engagement_sessions WHERE credential_id = ? "
        "ORDER BY acquired_at DESC, rowid DESC LIMIT 1", (credential_id,))
    row = await cur.fetchone()
    return dict(row) if row else None


# A secret NEVER travels as plaintext through a plan, a target dict, a rendered
# command, or a stored step result. It travels as an opaque HANDLE, and is
# resolved in the single instant between "command rendered" and "command
# executed".
#
# This is not belt-and-braces. The plan is returned by /api/v2/sweep/plan and
# rendered in the browser, and `StepResult.command` is the RENDERED command,
# which is written to the database and shown in the run detail view. Putting a
# live session token in the target dict would leak it to both, and this project
# has already shipped exactly that bug once: a credential pair reached an export
# because one field sat on a masking exemption list. Handles remove the
# exemption question entirely — there is nothing to mask, because the plaintext
# was never in the object.
#
# `.` separates, because a session id contains `-` and a field name contains
# `_`, and neither contains a dot. The whole token is shell-inert.
HANDLE_PREFIX = "ERLIK_SECRET"
HANDLE_RX = re.compile(rf"{HANDLE_PREFIX}\.([0-9a-fA-F-]{{1,36}})\.([a-z_]+)")


def handle(session_id: str, field: str) -> str:
    return f"{HANDLE_PREFIX}.{session_id}.{field}"


def has_handle(text: str) -> bool:
    return bool(HANDLE_RX.search(text or ""))


async def auth_inputs(db, target: str) -> dict[str, str]:
    """Target fields a sweep can fill from verified sessions — AS HANDLES.

    Returns only what is actually available, so a case still SKIPS OUT LOUD
    when the session it needs is missing rather than running unauthenticated
    and reporting a clean result — an authenticated test run without
    authentication is a false negative with extra steps.

    `low_priv_token` / `high_priv_token` are what WSTG-AUTHZ-04 has always
    been skipping for.

    Only VERIFIED sessions are offered, and verification is differential (see
    login._verify): a session that does not change the server's answer is not a
    session, and DVWA proved a status-code allowlist cannot tell the difference.
    """
    tk = target_key(target)
    if not tk:
        return {}
    cur = await db.execute(
        "SELECT c.id, c.role, s.id sid, s.token_enc, s.cookie_enc, s.header_name, "
        "s.status FROM engagement_credentials c "
        "JOIN engagement_sessions s ON s.credential_id = c.id "
        "WHERE c.target_key = ? AND s.status = 'verified' "
        "ORDER BY s.acquired_at DESC", (tk,))
    by_role: dict[str, dict] = {}
    for r in await cur.fetchall():
        d = dict(r)
        by_role.setdefault(d["role"], d)

    out: dict[str, str] = {}
    for role, field in (("low", "low_priv_token"), ("high", "high_priv_token")):
        row = by_role.get(role)
        if row and row.get("token_enc"):
            out[field] = handle(row["sid"], field)

    primary = (by_role.get("high") or by_role.get("user")
               or by_role.get("admin") or by_role.get("low"))
    if primary:
        if primary.get("token_enc"):
            out["auth_header"] = handle(primary["sid"], "auth_header")
            out["jwt"] = handle(primary["sid"], "jwt")
            # Not a secret: the NAME of the header. Useful to show in a plan.
            out["auth_header_name"] = primary.get("header_name") or "Authorization"
        if primary.get("cookie_enc"):
            out["cookie"] = handle(primary["sid"], "cookie")
    return out


async def _plaintext(db, session_id: str, field: str) -> str | None:
    """The one function that turns a handle back into a secret."""
    cur = await db.execute(
        "SELECT token_enc, cookie_enc, header_name, status FROM engagement_sessions "
        "WHERE id = ?", (session_id,))
    row = await cur.fetchone()
    if not row:
        return None
    d = dict(row)
    if d.get("status") != "verified":
        return None
    token = S.decrypt(d["token_enc"]) if d.get("token_enc") else ""
    cookie = S.decrypt(d["cookie_enc"]) if d.get("cookie_enc") else ""
    name = d.get("header_name") or "Authorization"
    if field in ("jwt", "low_priv_token", "high_priv_token"):
        return token or None
    if field == "auth_header":
        return f"{name}: Bearer {token}" if token else None
    if field == "cookie":
        return cookie or None
    return None


async def resolve(db, text: str) -> tuple[str, list[str]]:
    """(command_with_secrets, plaintext_values). Called ONLY at execution.

    An unresolvable handle is left in place deliberately. The caller checks for
    that and fails the step, because the alternative — stripping it and sending
    the request anyway — is an unauthenticated request reported as an
    authenticated one, the precise false negative this module exists to remove.
    """
    values: list[str] = []
    out = text or ""
    for m in list(HANDLE_RX.finditer(out)):
        secret = await _plaintext(db, m.group(1), m.group(2))
        if secret:
            out = out.replace(m.group(0), secret)
            values.append(secret)
    return out, values


def scrub(text: str, values: list[str]) -> str:
    """Remove any plaintext that came back in tool output."""
    for v in values:
        if v and len(v) >= 4:
            text = text.replace(v, S.masked())
    return text
