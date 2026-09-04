"""Assets: the things findings are ABOUT.

Findings were keyed only by a URL string, so 167 Information Disclosure rows in
the corpus could describe a handful of facts about a handful of hosts with
nothing tying them together. A client asks "what did you find on our
infrastructure", and a flat list of 453 URLs is not an answer to that question.

An asset is a TREE, because that is how a target decomposes:

    host  ->  port  ->  service / technology  ->  endpoint

Idea taken from Rekono (GPL-3.0), which attaches every finding to the host, port
or technology where it was found. This implementation is original — erlik is MIT
and cannot take GPL-licensed code.

TWO RULES.

1. CONSOLIDATE FOR PRESENTATION, NEVER DESTROY ROWS. `findings` rows are
   untouched and still counted exactly as before, so every recorded metric
   holds. Grouping happens on read. This is the same discipline the submission
   policy uses — demote, never suppress — and for the same reason: an earlier
   design that removed rows made the deliverable disagree with the measurement.

2. AN ASSET MUST BE IN SCOPE. Creating an asset records that erlik touched a
   host on this engagement. A host the customer did not authorise must not
   silently acquire a row in their inventory, so every write is scope-checked
   against the engagement.
"""

from __future__ import annotations

import uuid
from typing import Any
from urllib.parse import urlparse

from orchestrator.engagement import evaluate_scope, scope_rows

# The tree, outermost first. Order is meaningful: `path_for_url` builds parents
# before children, and the UI renders in this order.
KINDS = ("host", "port", "service", "technology", "endpoint")


def decompose(url: str) -> list[tuple[str, str]]:
    """A URL as an ordered [(kind, value)] chain. Pure — no database.

    Deliberately shallow: host and port always, endpoint only when the URL
    carries a real path. Inventing a `service` or `technology` from a URL alone
    would be a guess, and an inventory of guesses is worse than a short one.
    Those kinds are filled in by whatever actually observed them (whatweb, a
    test case, the operator).
    """
    u = (url or "").strip()
    if not u:
        return []
    if "://" not in u:
        u = f"http://{u}"
    p = urlparse(u)
    host = (p.hostname or "").lower().rstrip(".")
    if not host:
        return []
    port = p.port or (443 if p.scheme == "https" else 80)
    chain = [("host", host), ("port", str(port))]
    path = (p.path or "").rstrip("/")
    if path and path != "":
        chain.append(("endpoint", path))
    return chain


async def _upsert(db, engagement_id: str, kind: str, value: str,
                  parent_id: str | None, source: str) -> str:
    """Insert-or-touch one asset, returning its id."""
    cur = await db.execute(
        "SELECT id FROM engagement_assets WHERE engagement_id = ? AND kind = ? "
        "AND value = ? AND parent_id IS ?",
        (engagement_id, kind, value, parent_id))
    row = await cur.fetchone()
    if row:
        await db.execute(
            "UPDATE engagement_assets SET last_seen = datetime('now') WHERE id = ?",
            (row[0],))
        return row[0]
    aid = str(uuid.uuid4())[:12]
    await db.execute(
        "INSERT INTO engagement_assets (id, engagement_id, parent_id, kind, "
        "value, source) VALUES (?,?,?,?,?,?)",
        (aid, engagement_id, parent_id, kind, value, source))
    return aid


async def path_for_url(db, engagement_id: str, url: str,
                       source: str = "observed") -> tuple[str | None, str]:
    """(leaf_asset_id, reason). None when the URL is out of the engagement's scope.

    Scope-checked because creating an asset RECORDS that erlik touched this
    host on this customer's engagement. A host they did not authorise must not
    acquire a row in their inventory as a side effect of a stray finding.
    """
    chain = decompose(url)
    if not chain:
        return None, "no host could be parsed"
    allowed, why = evaluate_scope(await scope_rows(db, engagement_id), url)
    if not allowed:
        return None, why
    parent = None
    for kind, value in chain:
        parent = await _upsert(db, engagement_id, kind, value, parent, source)
    return parent, "ok"


async def record_observation(db, engagement_id: str, url: str, kind: str,
                             value: str, source: str = "observed") -> str | None:
    """Attach a service/technology observation under a URL's host:port."""
    if kind not in KINDS:
        return None
    chain = decompose(url)
    if not chain:
        return None
    allowed, _ = evaluate_scope(await scope_rows(db, engagement_id), url)
    if not allowed:
        return None
    parent = None
    for k, v in chain[:2]:           # host, port — attach beneath the port
        parent = await _upsert(db, engagement_id, k, v, parent, source)
    return await _upsert(db, engagement_id, kind, value, parent, source)


def _norm_sev(value: str | None) -> str:
    """One definition of severity, shared with the report and the badges."""
    from orchestrator.submission_policy import normalise_severity
    return normalise_severity(value)


async def tree(db, engagement_id: str) -> list[dict[str, Any]]:
    """The inventory, nested, with each asset's findings rolled up.

    This is the CONSOLIDATION: one row per distinct (vuln_type, severity) per
    asset, with a count. The underlying `findings` rows are untouched — a client
    table showing "SQL Injection ×3 on app.acme.com:443" and a metric counting
    three findings are both correct, and they no longer have to be the same
    number.
    """
    cur = await db.execute(
        "SELECT id, parent_id, kind, value, source, first_seen, last_seen "
        "FROM engagement_assets WHERE engagement_id = ? "
        "ORDER BY kind, value", (engagement_id,))
    rows = [dict(r) for r in await cur.fetchall()]
    if not rows:
        return []

    # BOTH lanes. This read only `findings` — the agent lane — so a host the
    # DETERMINISTIC lane found something on rendered with no findings at all.
    # v2_findings has carried an asset_id since the v2 run learned its
    # engagement, and nothing consumed it.
    #
    # `lane` is kept on each row rather than merged away: "SQL Injection x3"
    # means something different when a detector proved it than when a model
    # asserted it, and a client table that flattens the two cannot be
    # un-flattened later.
    by_asset: dict[str, list[dict]] = {}
    for table, lane in (("findings", "agent"), ("v2_findings", "deterministic")):
        cur = await db.execute(
            f"SELECT asset_id, vuln_type, severity, COUNT(*) n FROM {table} "
            "WHERE asset_id IN (SELECT id FROM engagement_assets WHERE engagement_id = ?) "
            "GROUP BY asset_id, vuln_type, severity", (engagement_id,))
        for r in await cur.fetchall():
            by_asset.setdefault(r[0], []).append(
                {"vuln_type": r[1],
                 # Normalised for the same reason the sidebar counts are: the
                 # corpus contains '** CRITICAL' and 'CRITICAL' alongside
                 # 'critical', and a tree that shows all three is not a summary.
                 "severity": _norm_sev(r[2]),
                 "count": r[3], "lane": lane})

    node = {r["id"]: {**r, "findings": by_asset.get(r["id"], []), "children": []}
            for r in rows}
    roots = []
    for n in node.values():
        parent = node.get(n["parent_id"])
        (parent["children"] if parent else roots).append(n)
    return roots


def rollup(nodes: list[dict]) -> dict[str, int]:
    """Severity totals across a subtree, so a host shows what is beneath it."""
    out: dict[str, int] = {}
    def walk(ns):
        for n in ns:
            for f in n.get("findings") or []:
                sev = f.get("severity") or "info"
                out[sev] = out.get(sev, 0) + f.get("count", 1)
            walk(n.get("children") or [])
    walk(nodes)
    return out


async def counts(db, engagement_id: str) -> dict[str, int]:
    cur = await db.execute(
        "SELECT kind, COUNT(*) FROM engagement_assets WHERE engagement_id = ? "
        "GROUP BY kind", (engagement_id,))
    return {r[0]: r[1] for r in await cur.fetchall()}
