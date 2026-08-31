"""Operator-declared per-case targeting: what PROFILES holds, as data.

`sweep.PROFILES` is per-application endpoint knowledge written in Python —
"on DVWA, WSTG-INPV-05 goes to /vulnerabilities/sqli/ with parameter id". It
has two entries, `juiceshop` and `dvwa`, both local lab targets, and its own
comment has said since it was written that this belongs in the database so an
operator can enter it for their own customer instead of editing source.

Until then, an operator running erlik against a real client could not supply
it. And `build_target` REFUSES TO GUESS a required `parameter` or `login_url`
— correctly, because inventing one produced 22 confident negative verdicts
that assessed nothing. So on any real target the SQLi, XSS, SSRF and
open-redirect cases were all named skips, and the only way to change that was
to edit Python and restart.

WHY A NEW TABLE AND NOT `target_endpoints`
==========================================

They are different relations, and the difference is not cosmetic:

  target_endpoints    a resource INVENTORY — one row per discovered path.
                      No column says WHICH target-schema field a value fills,
                      so `login_url` and DVWA's `submit: "Upload=Upload"` have
                      nowhere to live. Its dedup is (target_key, path), so the
                      second case to learn a path is silently dropped. And its
                      reader, `as_sweep_inputs`, discards `test_case_id`
                      entirely.

  this table          a per-case FIELD BINDING — one row per (case, field).
                      Exactly the shape `build_target`'s `profile` argument
                      already takes.

Routing declarations through the discovery pipe would inherit that pipe's
cross-case bleed: a parameter an operator entered for one case would be fanned
across every unrelated path on the host.

WHY host:port AND NOT AN ENGAGEMENT
===================================

The deterministic lane usually runs with no engagement at all. `target_endpoints`
was keyed on `engagement_targets.id` and sat empty for exactly that reason —
the post-mortem is in database.py. The engagement id is carried when there is
one, and is never the lookup key.

THE GATE RUNS TWICE
===================

`validate` is applied on WRITE and again on READ. A database is a trust
boundary: these values are substituted into `bash -c '...'` command templates,
so a row that became unsafe after it was stored must not be trusted because it
was checked once. On read a bad row is RETURNED as a refusal, never dropped —
an operator who typed something and sees it silently vanish learns nothing.
"""

from __future__ import annotations

from typing import Any

from orchestrator.engagement import looks_injectable
from orchestrator.testcase.endpoints import target_key

# Fields an operator may declare. Deliberately a whitelist rather than "any
# key in the case's target_schema":
#
#   host / port  are DERIVED from the base URL the operator is already
#                targeting. A declared `host` would let a case name a
#                different machine, and for a case whose only required field
#                is `host` there is then no URL for the scope check to catch
#                — a schemeless value like `internal-db:5432` is refused by
#                nothing downstream.
#   the secrets  jwt, low_priv_token, high_priv_token and the rest arrive as
#                HANDLES from the credential store and resolve at execution.
#                A plaintext secret must never sit in a plan row.
DECLARABLE = (
    "url", "login_url", "parameter", "submit", "method",
    "username_field", "password_field", "object_ids", "client_id",
    "collaborator_host", "auth_header_name",
)

# Values for these are stored as a PATH and rendered under the operator's base
# URL. A declaration therefore cannot name a host at all — structurally
# stronger than comparing one afterwards.
PATH_FIELDS = ("url", "login_url")

MAX_VALUE = 512


def validate(field: str, value: Any) -> str:
    """'' if this declaration is safe to render, else the reason.

    Run on write AND on read.
    """
    if field not in DECLARABLE:
        if field in ("host", "port"):
            return (f"{field!r} is derived from the target URL and cannot be "
                    f"declared — it would let a case name a different machine")
        return f"{field!r} is not a declarable field"
    if not isinstance(value, str):
        return f"must be text, not {type(value).__name__}"
    v = value.strip()
    if not v:
        return "is empty"
    if len(v) > MAX_VALUE:
        return f"is longer than {MAX_VALUE} characters"
    bad = looks_injectable(v)
    if bad:
        return bad
    # `{base}` is substituted by a plain str.replace in build_target, so braces
    # are not a format-string hazard today. They are refused anyway: the
    # operator writes a path, and a stray brace is a mistake worth naming
    # rather than a literal worth rendering.
    if "{" in v or "}" in v:
        return "must not contain braces — write a path, the base URL is added"
    if field in PATH_FIELDS:
        if "://" in v or v.startswith("//") or "@" in v:
            return ("must be a path on the target, not a URL — the base URL "
                    "you are testing is prepended")
        if not v.startswith("/"):
            return "must start with '/'"
    return ""


def render(field: str, value: str, base: str) -> str:
    """The value as `build_target` should see it, under the caller's base."""
    if field in PATH_FIELDS:
        return f"{(base or '').rstrip('/')}{value}"
    return value


async def declare(db, target: str, test_case_id: str, field: str, value: str,
                  *, engagement_target_id: str = "", declared_by: str = "",
                  notes: str = "") -> tuple[bool, str]:
    """(ok, reason). Upserts one (case, field) binding for a target."""
    tk = target_key(target)
    if not tk:
        return False, "no host could be parsed from the target"
    if not (test_case_id or "").strip():
        return False, "test case id is required"
    why = validate(field, value)
    if why:
        return False, f"{field}: {why}"
    await db.execute(
        "INSERT INTO target_case_inputs (target_key, engagement_target_id, "
        "test_case_id, field, value, declared_by, notes) VALUES (?,?,?,?,?,?,?) "
        "ON CONFLICT(target_key, test_case_id, field) DO UPDATE SET "
        "value = excluded.value, declared_by = excluded.declared_by, "
        "notes = excluded.notes, retired_at = NULL",
        (tk, engagement_target_id, test_case_id.strip(), field,
         value.strip(), declared_by, notes))
    return True, ""


async def retire(db, target: str, test_case_id: str, field: str) -> bool:
    """Stop applying a declaration. Never deletes it."""
    tk = target_key(target)
    if not tk:
        return False
    cur = await db.execute(
        "UPDATE target_case_inputs SET retired_at = datetime('now') "
        "WHERE target_key = ? AND test_case_id = ? AND field = ? "
        "AND retired_at IS NULL", (tk, test_case_id, field))
    return bool(cur.rowcount)


async def rows_for(db, target: str) -> list[dict[str, Any]]:
    """Every live declaration for this target, as stored."""
    tk = target_key(target)
    if not tk:
        return []
    cur = await db.execute(
        "SELECT test_case_id, field, value, source, declared_by, notes, "
        "created_at FROM target_case_inputs WHERE target_key = ? "
        "AND retired_at IS NULL ORDER BY test_case_id, field", (tk,))
    return [dict(r) for r in await cur.fetchall()]


async def profile_for(db, target: str, base: str) -> tuple[dict, list[dict]]:
    """(profile, refused) — the shape `build_target`'s `profile` argument takes.

    `refused` holds rows that failed the gate on the way out. They are reported,
    not dropped: a declaration that silently stops applying is indistinguishable
    from one that was never saved.
    """
    profile: dict[str, dict[str, str]] = {}
    refused: list[dict] = []
    for r in await rows_for(db, target):
        why = validate(r["field"], r["value"])
        if why:
            refused.append({**r, "reason": why})
            continue
        profile.setdefault(r["test_case_id"], {})[r["field"]] = render(
            r["field"], r["value"], base)
    return profile, refused


def merge(builtin: dict, declared: dict) -> dict:
    """Declared over builtin, per (case, field).

    Per FIELD, not per case: an operator correcting one stale parameter must
    not silently discard the rest of a profile's knowledge about that case.
    """
    out = {cid: dict(fields) for cid, fields in (builtin or {}).items()}
    for cid, fields in (declared or {}).items():
        out.setdefault(cid, {}).update(fields)
    return out
