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


def window_status(engagement: dict, now=None) -> tuple[bool, str]:
    """Is the engagement's authorisation window open right now?

    `authorised_from` / `authorised_until` were stored, editable, and displayed
    on the engagement page — and read by NO gate. An engagement whose window
    closed last month still authorised runs today. That is the same shape as
    the scope gate that could never fire, except this one is a date on a
    contract: testing outside the authorised period is the thing the window
    exists to prevent.

    RULES, and the two that are easy to get wrong:

      * `until` is INCLUSIVE to the end of that day. A date-only
        "2026-08-31" means through 23:59:59 on the 31st, not midnight at its
        start — otherwise the last authorised day is silently lost.
      * An UNREADABLE date FAILS CLOSED. A legal boundary must not become
        "unlimited" because someone typed the month wrong. Absent is unlimited;
        unparseable is not the same thing as absent.

    Both bounds are compared in UTC.
    """
    from datetime import datetime, timezone

    now = now or datetime.now(timezone.utc)

    def _parse(raw: str, end_of_day: bool):
        text = (raw or "").strip()
        if not text:
            return None, None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            if fmt == "%Y-%m-%d" and end_of_day:
                dt = dt.replace(hour=23, minute=59, second=59)
            return dt, None
        return None, text

    start, bad_from = _parse(engagement.get("authorised_from"), end_of_day=False)
    end, bad_until = _parse(engagement.get("authorised_until"), end_of_day=True)

    if bad_from or bad_until:
        return False, (f"authorisation window is unreadable "
                       f"({'authorised_from=' + repr(bad_from) if bad_from else ''}"
                       f"{' ' if bad_from and bad_until else ''}"
                       f"{'authorised_until=' + repr(bad_until) if bad_until else ''})"
                       " — expected YYYY-MM-DD")
    if start and now < start:
        return False, f"authorisation begins {start.date().isoformat()}"
    if end and now > end:
        return False, f"authorisation ended {end.date().isoformat()}"
    return True, "within the authorised window"


async def authorisation(db, engagement_id: str) -> dict:
    """Everything a gate needs to authorise work: the record and its scope.

    One loader, so the API gate and the tool executor decide on the same facts.
    They previously took different inputs — the executor got scope rows alone,
    which is why the window could not be enforced there at all.
    """
    row = await (await db.execute(
        "SELECT * FROM engagements WHERE id = ?", (engagement_id,))).fetchone()
    return {"engagement": dict(row) if row else None,
            "rows": await scope_rows(db, engagement_id)}


def evaluate_authorisation(auth: dict, target: str, now=None) -> tuple[bool, str]:
    """The whole question: is this engagement live, and is the target in scope?

    Window FIRST. An expired engagement authorises nothing, so reporting "in
    scope via acme.com" for it would name the wrong reason for a decision the
    operator is about to act on.
    """
    e = (auth or {}).get("engagement")
    if not e:
        return False, "engagement not found"
    ok, why = window_status(e, now=now)
    if not ok:
        return False, why
    return evaluate_scope((auth or {}).get("rows") or [], target)


async def check(db, engagement_id: str, target: str) -> tuple[bool, str]:
    """Scope AND window. Delegates, so every caller gets both checks."""
    return evaluate_authorisation(await authorisation(db, engagement_id), target)


async def add_target(db, engagement_id: str, base_url: str, **kw) -> str:
    tid = str(uuid.uuid4())[:12]
    await db.execute(
        "INSERT INTO engagement_targets (id, engagement_id, base_url, title, tech, notes) "
        "VALUES (?,?,?,?,?,?)",
        (tid, engagement_id, base_url.rstrip("/"), kw.get("title"),
         kw.get("tech"), kw.get("notes")))
    await db.commit()
    return tid


# How many rows the summary returns per list. Named, and reported back to the
# caller in `returned`, because a cap the UI cannot see is a cap the UI cannot
# label — and an unlabelled truncation reads as the complete set.
SUMMARY_ROW_LIMIT = 200


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
    # duration and tool count come along so the workspace can show an
    # execution table rather than a bare list of ids.
    out["sessions"] = [dict(r) for r in await (await db.execute(
        "SELECT id, target_url, status, created_at, total_steps, total_duration_ms, "
        "session_type, model FROM sessions "
        f"WHERE engagement_id = ? ORDER BY created_at DESC LIMIT {SUMMARY_ROW_LIMIT}",
        (engagement_id,))).fetchall()]
    out["v2_runs"] = [dict(r) for r in await (await db.execute(
        "SELECT id, test_case_id, created_at, duration_ms, model, stopped_early "
        f"FROM v2_runs WHERE engagement_id = ? ORDER BY created_at DESC LIMIT {SUMMARY_ROW_LIMIT}",
        (engagement_id,))).fetchall()]
    # Severity is EFFECTIVE severity, and rejected findings are excluded.
    #
    # Two defects, both of which made a badge contradict the operator:
    #
    #   * the rollup grouped on the raw `severity` column, ignoring
    #     `severity_override` and `calibrated_severity`. Someone triages a
    #     critical down to low and the sidebar keeps saying critical, for ever.
    #     `submission_policy.current_severity` is the one definition of what a
    #     report would show, so it is used here rather than re-derived.
    #   * a finding marked a false positive still counted. A triaged engagement
    #     showed its original count until someone deleted rows, which is the
    #     opposite of what triage is for.
    #
    # Both totals are returned: `findings_by_severity` is OPEN work, and
    # `findings_total` is everything ever recorded, so "3 of 14" is expressible
    # and nothing looks deleted.
    from orchestrator.submission_policy import current_severity
    rows = await (await db.execute(
        "SELECT f.severity, f.calibrated_severity, f.severity_override, f.triage_status "
        "FROM findings f JOIN sessions s ON s.id = f.session_id "
        "WHERE s.engagement_id = ?", (engagement_id,))).fetchall()
    open_sev: dict[str, int] = {}
    rejected = 0
    for r in rows:
        d = dict(r)
        if (d.get("triage_status") or "").lower() in ("rejected", "false_positive"):
            rejected += 1
            continue
        key = current_severity(d) or "unknown"
        open_sev[key] = open_sev.get(key, 0) + 1
    out["findings_by_severity"] = open_sev
    out["findings_total"] = len(rows)
    out["findings_rejected"] = rejected
    from orchestrator import assets as _A
    out["assets"] = await _A.tree(db, engagement_id)
    out["asset_counts"] = await _A.counts(db, engagement_id)
    out["asset_severity"] = _A.rollup(out["assets"])
    # TOTALS, separate from the rows returned. Both list queries above are
    # capped at 200; without the real totals the dashboard cannot tell an
    # engagement with 200 sessions from one with 4,000, and a capped list
    # renders identically to a complete one.
    totals = {}
    for key, table in (("sessions", "sessions"), ("v2_runs", "v2_runs")):
        row = await (await db.execute(
            f"SELECT COUNT(*) FROM {table} WHERE engagement_id = ?",
            (engagement_id,))).fetchone()
        totals[key] = row[0] if row else 0

    out["counts"] = {"assets": sum(out["asset_counts"].values()),
                     "targets": len(out["targets"]),
                     "sessions": totals["sessions"],
                     "v2_runs": totals["v2_runs"],
                     "findings": sum(out["findings_by_severity"].values()),
                     "findings_total": out["findings_total"],
                     "findings_rejected": out["findings_rejected"],
                     "pending_scope": len(out["pending_scope"])}
    # What the caller actually received, and the cap that produced it, so the
    # UI can say "showing 200 of 4,000" rather than implying it has them all.
    # The window, as the UI must show it: whether it is open, why, and the
    # bounds themselves. Computed by the same function the gates use, so the
    # page cannot say "authorised" about an engagement a run would be refused
    # for.
    _open, _why = window_status(out["engagement"])
    out["window"] = {"open": _open, "reason": _why,
                     "from": out["engagement"].get("authorised_from"),
                     "until": out["engagement"].get("authorised_until")}
    out["returned"] = {"sessions": len(out["sessions"]),
                       "v2_runs": len(out["v2_runs"]),
                       "row_limit": SUMMARY_ROW_LIMIT}
    return out


# Fields an operator may correct. `client_name` is included because a typo in
# a customer name was otherwise permanent; `status` is not, because archiving
# goes through `archive()` so the transition is explicit and auditable.
EDITABLE = ("client_name", "root_domain", "authorised_by",
            "authorised_from", "authorised_until", "notes")


async def update(db, engagement_id: str, patch: dict) -> dict:
    """Apply an explicit edit, retaining every previous value.

    Returns {changed: [...], ignored: [...]}. Unknown keys are IGNORED rather
    than written: a typo in a field name must not silently create a column's
    worth of data nobody asked for, and must not look like it succeeded.
    """
    row = await (await db.execute(
        "SELECT * FROM engagements WHERE id = ?", (engagement_id,))).fetchone()
    if not row:
        raise KeyError(engagement_id)
    before = dict(row)

    changed, ignored = [], []
    for key, value in (patch or {}).items():
        if key not in EDITABLE:
            ignored.append(key)
            continue
        new = None if value is None else str(value).strip()
        old = before.get(key)
        if (old or "") == (new or ""):
            continue          # a no-op edit is not a revision
        await db.execute(
            "INSERT INTO engagement_revisions (engagement_id, field, old_value, new_value) "
            "VALUES (?,?,?,?)", (engagement_id, key, old, new))
        await db.execute(f"UPDATE engagements SET {key} = ? WHERE id = ?",
                         (new, engagement_id))
        changed.append(key)
    return {"changed": changed, "ignored": ignored}


async def archive(db, engagement_id: str, archived: bool = True) -> bool:
    """Close an engagement without destroying it.

    Never a DELETE. Sessions, findings, scope rules and assets all reference
    this row, and the project's rule is that an identifier is deprecated, not
    removed. `status` had no writer at all before this.
    """
    row = await (await db.execute(
        "SELECT status FROM engagements WHERE id = ?", (engagement_id,))).fetchone()
    if not row:
        return False
    old = row[0] or "active"
    new = "archived" if archived else "active"
    if old == new:
        return True
    await db.execute(
        "INSERT INTO engagement_revisions (engagement_id, field, old_value, new_value) "
        "VALUES (?,?,?,?)", (engagement_id, "status", old, new))
    await db.execute("UPDATE engagements SET status = ? WHERE id = ?", (new, engagement_id))
    return True


async def revisions(db, engagement_id: str, limit: int = 100) -> list[dict]:
    """The edit history, newest first."""
    cur = await db.execute(
        "SELECT field, old_value, new_value, changed_at FROM engagement_revisions "
        "WHERE engagement_id = ? ORDER BY id DESC LIMIT ?", (engagement_id, limit))
    return [dict(r) for r in await cur.fetchall()]


async def list_all(db) -> list[dict]:
    cur = await db.execute(
        "SELECT e.*, "
        "(SELECT COUNT(*) FROM engagement_targets t WHERE t.engagement_id = e.id) AS n_targets, "
        "(SELECT COUNT(*) FROM sessions s WHERE s.engagement_id = e.id) AS n_sessions, "
        "(SELECT COUNT(*) FROM engagement_scope sc WHERE sc.engagement_id = e.id "
        " AND sc.source != 'declared' AND sc.approved_at IS NULL) AS n_pending "
        "FROM engagements e ORDER BY e.created_at DESC")
    return [dict(r) for r in await cur.fetchall()]
