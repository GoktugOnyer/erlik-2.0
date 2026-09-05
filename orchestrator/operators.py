"""Who ran this test.

`ERLIK_API_TOKEN` is one shared secret. It authenticates a REQUEST and
identifies NOBODY, so no run, finding or engagement edit in the database can be
attributed to a person. For a lab that is a shrug. For a paid engagement it is
an evidentiary gap: a client asking "who ran this test against our production
estate, and who changed the authorisation record" cannot be answered from the
data at all -- `engagement_revisions` records the field, the old value, the new
value and the timestamp, and no actor.

This module is the identity half. An operator is a named row with their own
token; the middleware resolves a presented token to one and stamps its id on
what follows.

WHY A PLAIN SHA-256 AND NOT BCRYPT. These are not passwords. A token is 256
bits from `secrets.token_hex`, so there is no dictionary to run and no
plausible brute force -- the work factor a password hash buys protects
low-entropy human input, which this is not. A deterministic hash also lets the
lookup be a single indexed query rather than a scan comparing every row. This
is what GitHub and GitLab do with personal access tokens, and for the same
reason. Comparison is still constant-time, because the lookup key is derived
from attacker-supplied input.

WHAT THIS IS NOT. There is no login, no password, no session cookie and no
rotation policy. A token is bearer material: whoever holds it is that operator.
That is a real limitation and `SECURITY.md` states it rather than implying an
account model that does not exist.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import uuid

# A recognisable prefix, so a leaked token is greppable and can be redacted on
# sight rather than having to be recognised as "some hex string".
TOKEN_PREFIX = "erlik_pat_"
TOKEN_RX = re.compile(rf"{TOKEN_PREFIX}[0-9a-f]{{64}}")

# The identity a request carries when it authenticated with the shared
# ERLIK_API_TOKEN rather than an operator's own token.
#
# It is a real row so that foreign keys and joins do not have to special-case
# NULL, and it is named for what it is. Nothing may render it as a person: a
# run stamped with this was authenticated, and was NOT attributed. Presenting
# it as an operator would be the interface describing something that did not
# happen.
SHARED_TOKEN_OPERATOR = "opr_shared_token"
SHARED_TOKEN_LABEL = "shared token (not attributed to a person)"

# The identity a request carries when no token is configured at all -- the
# loopback development path, which stays open by design.
UNAUTHENTICATED_OPERATOR = "opr_unauthenticated"
UNAUTHENTICATED_LABEL = "unauthenticated (no token configured)"

ROLE_ADMIN = "admin"
ROLE_OPERATOR = "operator"
ROLES = (ROLE_ADMIN, ROLE_OPERATOR)

SYNTHETIC = {
    SHARED_TOKEN_OPERATOR: SHARED_TOKEN_LABEL,
    UNAUTHENTICATED_OPERATOR: UNAUTHENTICATED_LABEL,
}


def is_attributable(operator_id: str | None) -> bool:
    """Whether this id names a PERSON.

    The two synthetic ids authenticate a request without identifying anyone.
    Every report and export path must ask this before printing a name, or it
    will present "shared token" as though it were an operator.
    """
    return bool(operator_id) and operator_id not in SYNTHETIC


def new_token() -> str:
    """A fresh operator token. Returned once, never stored in plaintext."""
    return TOKEN_PREFIX + secrets.token_hex(32)


def token_hash(token: str) -> str:
    """The stored form of a token. See the module docstring on why SHA-256."""
    return hashlib.sha256((token or "").strip().encode()).hexdigest()


def new_operator_id() -> str:
    return "opr_" + uuid.uuid4().hex[:16]


def looks_like_token(value: str | None) -> bool:
    return bool(value) and bool(TOKEN_RX.fullmatch(value.strip()))


def redact(text: str | None) -> str:
    """Mask any operator token appearing in `text`.

    Tokens reach logs and step output by ordinary accident -- an operator
    pastes a curl command into a mission, a tool echoes its own argv. The
    prefix is what makes that recoverable.
    """
    if not text:
        return text or ""
    return TOKEN_RX.sub(f"{TOKEN_PREFIX}<redacted>", text)


async def resolve(db, presented: str | None
                  ) -> tuple[str | None, str | None, str | None]:
    """Map a presented token to (operator_id, name, role), or three Nones.

    Returns None for an unknown or revoked token; the caller decides what that
    means. A revoked operator is NOT resolved, which is the difference between
    an account model and a shared secret: access can be withdrawn from one
    person without rotating everyone else's token.
    """
    presented = (presented or "").strip()
    if not looks_like_token(presented):
        return None, None, None
    cur = await db.execute(
        "SELECT id, name, token_hash, status, role FROM operators "
        "WHERE token_hash = ?",
        (token_hash(presented),),
    )
    row = await cur.fetchone()
    if not row:
        return None, None, None
    op_id, name, stored, status, role = row[0], row[1], row[2], row[3], row[4]
    # The lookup already matched on the hash; this is the constant-time
    # confirmation, so a timing signal cannot distinguish a near-miss.
    if not hmac.compare_digest(stored, token_hash(presented)):
        return None, None, None
    if (status or "active") != "active":
        return None, None, None
    return op_id, name, (role or ROLE_OPERATOR)


async def touch(db, operator_id: str) -> None:
    """Record that this operator was seen. Best effort; never fails a request."""
    try:
        await db.execute(
            "UPDATE operators SET last_seen_at = datetime('now') WHERE id = ?",
            (operator_id,),
        )
        await db.commit()
    except Exception:
        pass


def bootstrap_token() -> str:
    return os.environ.get("ERLIK_API_TOKEN", "").strip()


async def create(db, name: str, created_by: str | None = None,
                 role: str = ROLE_OPERATOR) -> dict:
    """Mint an operator. The token is returned ONCE and never stored.

    `created_by` matters more than it looks. Any authenticated caller can add
    an operator, so without a provenance column someone holding the shared
    token could create a name and have every later action attributed to it
    with nothing to trace it back to.
    """
    name = (name or "").strip()
    if not name:
        raise ValueError("an operator needs a name")
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}, got {role!r}")
    op_id, token = new_operator_id(), new_token()
    await db.execute(
        "INSERT INTO operators (id, name, token_hash, status, created_by, role, "
        "role_changed_by, role_changed_at) "
        "VALUES (?, ?, ?, 'active', ?, ?, ?, datetime('now'))",
        (op_id, name, token_hash(token), created_by, role, created_by),
    )
    await db.commit()
    return {"id": op_id, "name": name, "token": token, "created_by": created_by,
            "role": role}


async def revoke(db, operator_id: str) -> bool:
    """Withdraw one operator's access without rotating anyone else's token.

    The row is kept, always. Rows in `sessions`, `v2_runs` and
    `engagement_revisions` point at it, and deleting it would turn a run that
    IS attributable into one that reads as unattributed -- destroying the
    record rather than ending the access.
    """
    if operator_id in SYNTHETIC:
        return False           # the synthetic identities are not accounts
    if await _would_strand(db, operator_id):
        raise LastAdminError(
            "this is the last active admin; promote another operator first. "
            "Revoking it would leave nobody able to mint or revoke anyone, "
            "recoverable only by setting ERLIK_API_TOKEN again")
    cur = await db.execute(
        "UPDATE operators SET status = 'revoked' WHERE id = ? AND status = 'active'",
        (operator_id,),
    )
    await db.commit()
    return cur.rowcount > 0


async def listing(db) -> list[dict]:
    """Every operator, with what they have done. Never returns a token hash."""
    cur = await db.execute(
        "SELECT o.id, o.name, o.status, o.role, o.created_at, o.last_seen_at, "
        "  o.created_by, o.role_changed_by, o.role_changed_at, "
        "  (SELECT COUNT(*) FROM sessions s  WHERE s.operator_id  = o.id) AS n_sessions, "
        "  (SELECT COUNT(*) FROM v2_runs  v  WHERE v.operator_id  = o.id) AS n_runs, "
        "  (SELECT COUNT(*) FROM engagement_revisions r WHERE r.operator_id = o.id) "
        "    AS n_engagement_edits "
        "FROM operators o ORDER BY o.created_at"
    )
    rows = [dict(r) for r in await cur.fetchall()]
    for r in rows:
        r["attributable"] = is_attributable(r["id"])
    return rows

class LastAdminError(RuntimeError):
    """Raised rather than leaving an instance nobody can administer."""


async def _real_admins(db, exclude: str | None = None) -> int:
    """Active admins who are actual PEOPLE.

    The synthetic identities are excluded deliberately. `opr_shared_token` is
    admin so it can mint the first real one, but counting it here would let the
    last human admin be removed on the grounds that the shared secret could
    still do it -- and the whole point of an admin role is that the deployment
    can eventually unset that secret. Counting it would make the guard weakest
    exactly where the instance is most locked down.
    """
    cur = await db.execute(
        "SELECT COUNT(*) FROM operators "
        "WHERE role = ? AND status = 'active' AND id NOT IN (?, ?) "
        "AND (? IS NULL OR id != ?)",
        (ROLE_ADMIN, SHARED_TOKEN_OPERATOR, UNAUTHENTICATED_OPERATOR,
         exclude, exclude),
    )
    return (await cur.fetchone())[0]


async def _would_strand(db, operator_id: str) -> bool:
    """Whether removing this operator's admin leaves no human admin at all."""
    cur = await db.execute(
        "SELECT role, status FROM operators WHERE id = ?", (operator_id,))
    row = await cur.fetchone()
    if not row or row[0] != ROLE_ADMIN or (row[1] or "active") != "active":
        return False
    return await _real_admins(db, exclude=operator_id) == 0


async def is_admin(db, operator_id: str | None) -> bool:
    """Whether this identity may mint, revoke or promote."""
    if not operator_id:
        return False
    cur = await db.execute(
        "SELECT role, status FROM operators WHERE id = ?", (operator_id,))
    row = await cur.fetchone()
    return bool(row) and row[0] == ROLE_ADMIN and (row[1] or "active") == "active"


async def set_role(db, operator_id: str, role: str,
                   changed_by: str | None = None) -> bool:
    """Promote or demote. Refuses to remove the last human admin.

    Demotion is guarded for the same reason as revocation: an admin who demotes
    themselves while alone leaves an instance nobody can administer, recoverable
    only by setting ERLIK_API_TOKEN again -- which is the credential the role
    model exists to let a deployment retire.
    """
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}, got {role!r}")
    if operator_id in SYNTHETIC:
        raise ValueError("the synthetic identities are not accounts and have "
                         "no role to grant")
    if role != ROLE_ADMIN and await _would_strand(db, operator_id):
        raise LastAdminError(
            "this is the last active admin; promote another operator first")
    cur = await db.execute(
        "UPDATE operators SET role = ?, role_changed_by = ?, "
        "role_changed_at = datetime('now') WHERE id = ? AND status = 'active'",
        (role, changed_by, operator_id),
    )
    await db.commit()
    return cur.rowcount > 0
