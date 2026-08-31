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
from orchestrator.engagement import looks_injectable
from orchestrator.testcase.endpoints import target_key

ROLES = ("low", "high", "user", "admin")


KINDS = ("form", "json", "basic")

# Hosts a credential may be SENT to. `login.authenticate` POSTs the decrypted
# password to `login_url`, and nothing constrained it — so a stored credential
# was a general-purpose relay for whatever host was typed.
#
# Same-host-as-target is too strict and would break the workflow this exists
# for: tools run inside the kali container and address `http://dvwa`, while
# login.py runs in-process on the HOST where that name does not resolve
# (`http://127.0.0.1:8081`). `target_key` differs legitimately.
#
# So the rule is about SHAPE, not identity — reject the things that are never
# a real login endpoint and are always an exfiltration attempt or a typo.
def check_destination(url: str) -> str:
    """'' if this is a plausible place to send a credential, else the reason."""
    from urllib.parse import urlparse
    u = (url or "").strip()
    if not u:
        return "is empty"
    if looks_injectable(u):
        return looks_injectable(u)
    p = urlparse(u)
    if p.scheme not in ("http", "https"):
        return "must be an http:// or https:// URL"
    # `urlparse('http://127.0.0.1@evil.test/').hostname` is 'evil.test'. A
    # userinfo section exists only to make a URL read as one host and resolve
    # to another, so it is refused rather than parsed.
    if "@" in (p.netloc or ""):
        return "must not contain a userinfo section (user@host)"
    if not p.hostname:
        return "has no host"
    return ""


async def store(db, target: str, label: str, username: str, secret: str, *,
                role: str = "user", kind: str = "form",
                login_url: str = "", verify_url: str = "",
                username_field: str = "username",
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
    # ROLES existed and nothing consumed it. `role="Low"` was stored happily,
    # and `auth_state` then reported "authenticated" with verified_roles
    # ["Low"] while `auth_inputs` produced NO low_priv_token — because it
    # matches the lowercase literal. So WSTG-AUTHZ-04 kept skipping under a
    # green badge: confident output from a path not doing what it claims.
    if role not in ROLES:
        raise ValueError(f"role must be one of {', '.join(ROLES)} (got {role!r})")
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {', '.join(KINDS)} (got {kind!r})")
    if login_url:
        why = check_destination(login_url)
        if why:
            raise ValueError(f"login_url {why}")
    if verify_url:
        why = check_destination(verify_url)
        if why:
            raise ValueError(f"verify_url {why}")

    enc = S.encrypt(secret)          # raises if the key is unavailable
    cid = str(uuid.uuid4())[:12]
    # UPSERT THAT KEEPS THE ID. This was `INSERT OR REPLACE` with a fresh uuid,
    # so re-storing the same (target_key, label) — which is just "the password
    # changed" — deleted the old row, minted a new id, and ORPHANED every
    # session pointing at the old one. Measured: auth_state fell from
    # "authenticated" to "credentials only" and auth_inputs from 5 handles to
    # 0, with no error; and because `_plaintext` keys on session id alone, the
    # orphaned session went on resolving to the plaintext cookie forever while
    # no read path in the product could see it any more.
    cur = await db.execute(
        "SELECT id FROM engagement_credentials WHERE target_key = ? AND label = ?",
        (tk, label))
    existing = await cur.fetchone()
    if existing:
        cid = existing[0]
        await db.execute(
            "UPDATE engagement_credentials SET role=?, kind=?, username=?, "
            "secret_enc=?, login_url=?, verify_url=?, username_field=?, "
            "password_field=?, engagement_id=COALESCE(?, engagement_id) "
            "WHERE id = ?",
            (role, kind, username, enc, login_url, verify_url, username_field,
             password_field, engagement_id, cid))
        # A new password invalidates the sessions the old one bought. Revoked,
        # not deleted: a revoked session is inert everywhere (`_plaintext`
        # gates on status) and the row remains as a record that it existed.
        await db.execute(
            "UPDATE engagement_sessions SET status = 'revoked' "
            "WHERE credential_id = ? AND status = 'verified'", (cid,))
        return cid

    await db.execute(
        "INSERT INTO engagement_credentials "
        "(id, engagement_id, target_key, label, role, kind, username, secret_enc, "
        " login_url, verify_url, username_field, password_field, extra) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (cid, engagement_id, tk, label, role, kind, username, enc,
         login_url, verify_url, username_field, password_field,
         json.dumps(extra) if extra else None))
    return cid


def _view(row: dict) -> dict:
    """The masked shape. `secret_enc` is dropped entirely rather than masked —
    a field that is absent cannot be accidentally serialised later."""
    # `extra` goes too. It is free-form JSON that `store` writes and NOTHING in
    # the tree reads, so it is a plaintext sink with no consumer — exactly the
    # place a secret ends up by accident. Dropped rather than masked, for the
    # same reason as the ciphertext columns.
    out = {k: v for k, v in row.items() if k not in ("secret_enc", "token_enc",
                                                     "cookie_enc", "extra")}
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
                       status: str = "unverified",
                       verify_url: str = "") -> str:
    sid = str(uuid.uuid4())[:12]
    await db.execute(
        "INSERT INTO engagement_sessions (id, credential_id, target_key, "
        "token_enc, cookie_enc, header_name, status, verify_url, verified_at) "
        "VALUES (?,?,?,?,?,?,?,?, CASE WHEN ?='verified' THEN datetime('now') END)",
        (sid, credential_id, target_key_,
         S.encrypt(token) if token else None,
         S.encrypt(cookie) if cookie else None,
         header_name, status, verify_url or None, status))
    return sid


def session_view(row: dict) -> dict:
    """A session an operator may read — never its material.

    `latest_session` returns the RAW row, token_enc and cookie_enc included,
    so anything serialising it straight to the page would ship encrypted
    session material into the DOM. Same discipline as `_view`: the columns are
    DROPPED, not masked, because a field that is absent cannot be serialised
    by accident later.
    """
    out = {k: v for k, v in row.items()
           if k not in ("token_enc", "cookie_enc")}
    out["has_token"] = bool(row.get("token_enc"))
    out["has_cookie"] = bool(row.get("cookie_enc"))
    return out


async def sessions_for(db, credential_id: str) -> list[dict]:
    """Every session this credential has produced, newest first, masked."""
    cur = await db.execute(
        "SELECT * FROM engagement_sessions WHERE credential_id = ? "
        "ORDER BY acquired_at DESC, rowid DESC", (credential_id,))
    return [session_view(dict(r)) for r in await cur.fetchall()]


async def revoke_session(db, session_id: str) -> bool:
    """Stop a session being usable. Keeps the row.

    Needs no new column: every consumer gates on status == 'verified', and
    `_plaintext` refuses to decrypt anything else — so the handle stops
    resolving and the runner fails the step rather than silently sending it
    unauthenticated.
    """
    cur = await db.execute(
        "UPDATE engagement_sessions SET status = 'revoked' "
        "WHERE id = ? AND status != 'revoked'", (session_id,))
    return bool(cur.rowcount)


async def destroy(db, credential_id: str, *, by: str = "") -> bool:
    """Destroy a credential and every session it produced.

    THE ONE PLACE THIS PROJECT DELETES. Elsewhere the rule is deprecate-never-
    delete, and it holds for identifiers — but this row holds a CLIENT'S
    PASSWORD, and an operator must be able to honour a request to destroy it.
    The identifier survives in `destroyed_credentials`, which has no column
    ending in `_enc`; the liability does not.

    SESSIONS FIRST, and that ordering is the point. `_plaintext` looks a
    session up BY ID with no join to its credential, so deleting the
    credential alone leaves the token and cookie fully resolvable while
    `listing`, `auth_state` and `auth_inputs` have all gone blind to them —
    strictly worse than doing nothing.
    """
    cur = await db.execute(
        "SELECT id, target_key, label, role FROM engagement_credentials WHERE id = ?",
        (credential_id,))
    row = await cur.fetchone()
    if not row:
        return False
    await db.execute("DELETE FROM engagement_sessions WHERE credential_id = ?",
                     (credential_id,))
    await db.execute("DELETE FROM engagement_credentials WHERE id = ?",
                     (credential_id,))
    await db.execute(
        "INSERT OR REPLACE INTO destroyed_credentials "
        "(id, target_key, label, role, destroyed_by) VALUES (?,?,?,?,?)",
        (row[0], row[1], row[2], row[3], by))
    return True


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
        # rowid breaks the tie, as `latest_session` already does. acquired_at
        # is CURRENT_TIMESTAMP at SECOND granularity, so two logins in the same
        # second returned the OLDER session here while latest_session returned
        # the newer — and a re-login usually happens BECAUSE the old session
        # died, so the sweep ran on the dead one, still marked verified.
        "ORDER BY s.acquired_at DESC, s.rowid DESC", (tk,))
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


async def auth_state(db, target: str) -> dict:
    """What erlik can actually authenticate as against this target, right now.

    DERIVED, never stored. `engagement_targets.auth_state` is a column that was
    displayed on the engagement page and written by nothing, so every target
    read "auth: none" for ever — including ones erlik held a verified session
    for. Storing it would have been worse than leaving it empty: a flag saying
    "session verified" outlives the session that justified it, and a stale
    reassurance is the failure this project keeps removing.

    "verified" means the session passed the DIFFERENTIAL check in login._verify
    — it changed the server's answer — not merely that a login returned 200.
    """
    tk = target_key(target)
    if not tk:
        return {"state": "unknown", "detail": "no host could be parsed",
                "roles": [], "verified_roles": []}
    cur = await db.execute(
        "SELECT c.role, c.label, s.status, "
        "       s.token_enc IS NOT NULL AS has_token "
        "FROM engagement_credentials c "
        "LEFT JOIN engagement_sessions s ON s.credential_id = c.id "
        "WHERE c.target_key = ?", (tk,))
    rows = [dict(r) for r in await cur.fetchall()]
    if not rows:
        return {"state": "none", "detail": "no credential stored for this target",
                "roles": [], "verified_roles": []}

    roles = sorted({r["role"] for r in rows if r.get("role")})
    verified = sorted({r["role"] for r in rows
                       if r.get("status") == "verified" and r.get("role")})
    if not verified:
        return {"state": "credentials only",
                "detail": f"{len(rows)} credential(s) stored, none with a verified session",
                "roles": roles, "verified_roles": []}
    # WSTG-AUTHZ-04 needs a LOW and a HIGH session and has been a named skip on
    # every recorded run for want of them — but having both roles is not
    # enough, and claiming it was made this badge disagree with the planner.
    #
    # Measured: two verified DVWA sessions, one low one high, badge reading
    # "access-control testing is possible", and AUTHZ-04 still skipped with
    # "needs two authenticated accounts". The case sends
    # `-H "Authorization: Bearer {{low_priv_token}}"`, so it is BEARER-ONLY by
    # construction; `auth_inputs` correctly withholds those handles for a
    # cookie session, because a cookie in a Bearer header authenticates
    # nothing. DVWA — and most PHP/Rails/Django apps — authenticate by cookie,
    # so no number of verified sessions can satisfy that case.
    #
    # The badge was the thing that was wrong. It now says what is true, and
    # names the gap when the sessions cannot carry what the case needs.
    tokened = sorted({r["role"] for r in rows
                      if r.get("status") == "verified" and r.get("role")
                      and r.get("has_token")})
    both_roles = {"low", "high"} <= set(verified)
    both_usable = {"low", "high"} <= set(tokened)
    if both_usable:
        detail = ("low- and high-privilege sessions verified — access-control "
                  "testing is possible")
    elif both_roles:
        detail = ("low and high verified, but as COOKIE sessions — "
                  "WSTG-AUTHZ-04 sends a bearer token, so it still skips")
    else:
        detail = f"verified session(s) as: {', '.join(verified)}"
    return {"state": "authenticated", "detail": detail,
            "roles": roles, "verified_roles": verified,
            "access_control_ready": both_usable}


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
