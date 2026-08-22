"""Engagements: the customer a run belongs to, and the boundary it may not cross.

Nothing in erlik's schema had a customer concept. 108 sessions and 91
deterministic runs were keyed only by target URL, and scope was declared per
session and retyped every run.

Scope is not bookkeeping. It is the LEGAL BOUNDARY of the test — the set of
assets the customer authorised someone to attack — so it belongs to the
engagement, stated once with an authorisation window and inherited by everything
run beneath it.

THREE RULES THIS MODULE ENFORCES, each because the failure is not recoverable:

1. DENY WINS. An explicit out-of-scope entry beats any in-scope match. A
   customer who says "*.acme.com, but never prod.acme.com" has drawn a line that
   no wildcard may cross.

2. DISCOVERED IS NOT AUTHORISED. A host found by enumeration is a CANDIDATE.
   Passive subdomain results routinely include shared hosting, CDN endpoints and
   parked names belonging to other people. Until a human approves the row it is
   out of scope, and `in_scope` alone is not enough to authorise it.

3. NOTHING IS IN SCOPE BY DEFAULT. An engagement with no scope rows authorises
   nothing. The failure mode of the opposite default — attacking an asset nobody
   authorised — is one this tool should make impossible, not merely unlikely.
"""

from __future__ import annotations

import ipaddress
import uuid
from typing import Any
from urllib.parse import urlparse


# Characters that can BREAK OUT of the quoting the test-case templates actually
# use. Verified against every template in tests_catalog/wstg/: each value is
# interpolated inside DOUBLE quotes, inside an outer `bash -c '...'`. So:
#
#   "   closes the inner double quote
#   '   closes the OUTER single quote of bash -c
#   $   parameter and command expansion, still live inside double quotes
#   `   command substitution, still live inside double quotes
#   \   escape
#   newline / CR / NUL
#
# Deliberately NOT rejected: & ; | < > — these are literal inside double quotes
# and appear in ordinary URLs ("?a=1&b=2"). Rejecting them would refuse
# legitimate customer targets, which is a correctness failure dressed as
# security. The set is narrow because it is derived from the actual quoting,
# not from a generic list of scary characters.
_SHELL_META = set("\"'`$\\\n\r\x00")


def looks_injectable(value: str) -> str:
    """'' if the value is safe to render into a command, else the reason."""
    v = str(value or "")
    bad = sorted(_SHELL_META & set(v))
    if bad:
        return f"contains shell metacharacter(s): {' '.join(repr(c) for c in bad)}"
    if "\x00" in v:
        return "contains a null byte"
    return ""


def _host_of(value: str) -> str:
    """Bare hostname from a URL, host:port, or hostname."""
    v = (value or "").strip()
    if not v:
        return ""
    if "://" not in v:
        v = f"//{v}"
    host = urlparse(v).hostname or ""
    return host.lower().rstrip(".")


def _is_subdomain_of(host: str, domain: str) -> bool:
    """True for the domain itself and anything under it.

    Compared label-wise, never as a string suffix: `notacme.com`.endswith(
    `acme.com`) is True and would put an unrelated company inside the
    customer's scope.
    """
    if not host or not domain:
        return False
    h = host.lower().rstrip(".").split(".")
    d = domain.lower().rstrip(".").lstrip("*.").split(".")
    return len(h) >= len(d) and h[-len(d):] == d


def _matches(pattern: str, kind: str, host: str, url: str = "") -> bool:
    kind = (kind or "domain").lower()
    pattern = (pattern or "").strip().lower()
    if not pattern:
        return False
    if kind == "domain":
        return _is_subdomain_of(host, pattern)
    if kind in ("host", "subdomain"):
        return host == pattern.lstrip("*.").rstrip(".")
    if kind == "ip":
        return host == pattern
    if kind == "cidr":
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(pattern, strict=False)
        except ValueError:
            return False
    if kind == "url":
        # Host equality FIRST, then the path prefix. A bare string prefix let
        # pattern "https://acme.com" authorise "https://acme.com.evil.net",
        # which is the same label-boundary mistake as a suffix match on a
        # domain, pointing the other way.
        if _host_of(pattern) != host:
            return False
        return (url or "").lower().rstrip("/").startswith(pattern.rstrip("/"))
    return False


def evaluate_scope(rows: list[dict], target: str) -> tuple[bool, str]:
    """(allowed, reason) for one target against an engagement's scope rows.

    `rows` are dicts with pattern / kind / in_scope / source / approved_at.
    Pure — no database — so it is cheap to test exhaustively and cannot be
    accidentally coupled to request state.
    """
    host = _host_of(target)
    if not host:
        return False, "no host could be parsed from the target"

    denies = [r for r in rows if not int(r.get("in_scope", 1))]
    for r in denies:
        if _matches(r.get("pattern", ""), r.get("kind", "domain"), host, target):
            return False, f"explicitly out of scope: {r.get('pattern')}"

    for r in rows:
        if not int(r.get("in_scope", 1)):
            continue
        if not _matches(r.get("pattern", ""), r.get("kind", "domain"), host, target):
            continue
        if (r.get("source") or "declared") != "declared" and not r.get("approved_at"):
            # Matched, but by a row nobody approved. Not an authorisation.
            return False, (f"{host} was discovered, not declared, and has not been "
                           f"approved for testing")
        return True, f"in scope via {r.get('pattern')}"

    return False, f"{host} matches no in-scope rule for this engagement"


async def create(db, client_name: str, root_domain: str = "", **kw) -> str:
    eid = str(uuid.uuid4())[:12]
    await db.execute(
        "INSERT INTO engagements (id, client_name, root_domain, authorised_by, "
        "authorised_from, authorised_until, notes) VALUES (?,?,?,?,?,?,?)",
        (eid, client_name, (root_domain or "").strip().lower() or None,
         kw.get("authorised_by"), kw.get("authorised_from"),
         kw.get("authorised_until"), kw.get("notes")))
    if root_domain:
        await add_scope(db, eid, root_domain, kind="domain", source="declared")
    await db.commit()
    return eid


async def add_scope(db, engagement_id: str, pattern: str, kind: str = "domain",
                    in_scope: bool = True, source: str = "declared",
                    approved_by: str | None = None) -> None:
    """Declared rows are authorised on entry; discovered rows are not."""
    approved = "datetime('now')" if source == "declared" else "NULL"
    await db.execute(
        f"INSERT OR IGNORE INTO engagement_scope "
        f"(engagement_id, pattern, kind, in_scope, source, approved_at, approved_by) "
        f"VALUES (?,?,?,?,?,{approved},?)",
        (engagement_id, (pattern or "").strip().lower(), kind,
         1 if in_scope else 0, source, approved_by))


async def approve_scope(db, engagement_id: str, pattern: str,
                        approved_by: str = "operator") -> int:
    cur = await db.execute(
        "UPDATE engagement_scope SET approved_at = datetime('now'), approved_by = ? "
        "WHERE engagement_id = ? AND pattern = ? AND approved_at IS NULL",
        (approved_by, engagement_id, (pattern or "").strip().lower()))
    return cur.rowcount


async def scope_rows(db, engagement_id: str) -> list[dict]:
    cur = await db.execute(
        "SELECT pattern, kind, in_scope, source, approved_at, approved_by "
        "FROM engagement_scope WHERE engagement_id = ? ORDER BY in_scope, pattern",
        (engagement_id,))
    return [dict(r) for r in await cur.fetchall()]


async def check(db, engagement_id: str, target: str) -> tuple[bool, str]:
    return evaluate_scope(await scope_rows(db, engagement_id), target)


async def add_target(db, engagement_id: str, base_url: str, **kw) -> str:
    tid = str(uuid.uuid4())[:12]
    await db.execute(
        "INSERT INTO engagement_targets (id, engagement_id, base_url, title, tech, notes) "
        "VALUES (?,?,?,?,?,?)",
        (tid, engagement_id, base_url.rstrip("/"), kw.get("title"),
         kw.get("tech"), kw.get("notes")))
    await db.commit()
    return tid


async def summary(db, engagement_id: str) -> dict[str, Any]:
    """Everything recorded under one customer — the customer page's data."""
    e = await (await db.execute(
        "SELECT * FROM engagements WHERE id = ?", (engagement_id,))).fetchone()
    if not e:
        return {}
    out: dict[str, Any] = {"engagement": dict(e)}
    out["scope"] = await scope_rows(db, engagement_id)
    out["pending_scope"] = [r for r in out["scope"]
                            if (r.get("source") or "declared") != "declared"
                            and not r.get("approved_at")]
    out["targets"] = [dict(r) for r in await (await db.execute(
        "SELECT * FROM engagement_targets WHERE engagement_id = ? ORDER BY base_url",
        (engagement_id,))).fetchall()]
    out["sessions"] = [dict(r) for r in await (await db.execute(
        "SELECT id, target_url, status, created_at, total_steps FROM sessions "
        "WHERE engagement_id = ? ORDER BY created_at DESC LIMIT 200",
        (engagement_id,))).fetchall()]
    out["v2_runs"] = [dict(r) for r in await (await db.execute(
        "SELECT id, test_case_id, created_at FROM v2_runs "
        "WHERE engagement_id = ? ORDER BY created_at DESC LIMIT 200",
        (engagement_id,))).fetchall()]
    sev = await (await db.execute(
        "SELECT f.severity, COUNT(*) c FROM findings f JOIN sessions s ON s.id = f.session_id "
        "WHERE s.engagement_id = ? GROUP BY f.severity", (engagement_id,))).fetchall()
    out["findings_by_severity"] = {r[0] or "unknown": r[1] for r in sev}
    out["counts"] = {"targets": len(out["targets"]), "sessions": len(out["sessions"]),
                     "v2_runs": len(out["v2_runs"]),
                     "findings": sum(out["findings_by_severity"].values()),
                     "pending_scope": len(out["pending_scope"])}
    return out


async def list_all(db) -> list[dict]:
    cur = await db.execute(
        "SELECT e.*, "
        "(SELECT COUNT(*) FROM engagement_targets t WHERE t.engagement_id = e.id) AS n_targets, "
        "(SELECT COUNT(*) FROM sessions s WHERE s.engagement_id = e.id) AS n_sessions, "
        "(SELECT COUNT(*) FROM engagement_scope sc WHERE sc.engagement_id = e.id "
        " AND sc.source != 'declared' AND sc.approved_at IS NULL) AS n_pending "
        "FROM engagements e ORDER BY e.created_at DESC")
    return [dict(r) for r in await cur.fetchall()]
