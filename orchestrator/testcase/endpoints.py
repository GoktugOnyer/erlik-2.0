"""Discovered endpoints, persisted so the next run starts where the last ended.

`RunResult.produced` holds what a test case discovered — the paths robots.txt
names, the URLs a sitemap lists. Inside one chain run those values retarget
children, and then they die with the run. The next sweep starts from the same
bare URL it always did.

That is the gap this closes. `target_endpoints` has existed since the
engagement work and had ZERO writers and ZERO readers: its only two references
in the repository were its own CREATE TABLE and its index. It is exactly the
right shape for what a producer emits, and nothing had ever put a row in it.

WHY THE KEY IS host:port RATHER THAN AN ENGAGEMENT TARGET
The table was written keyed on `engagement_targets.id`, and the deterministic
lane usually runs with no engagement at all — so under that key it could never
have been filled by the lane that discovers things. It now also carries the
`target_key` (host:port) that recon_context and the handoff already use, which
works with or without a customer record.

WHAT IS AND IS NOT STORED
Paths, not absolute URLs: the scheme and authority come from whatever base a
later sweep is planning against, so a path recorded against juice-shop:3000 is
reusable and cannot smuggle in a different host. Every stored value has already
passed the injection gate and the same-host check in runner._resolve_url before
it got here; this module re-checks the shape anyway, because a database is a
trust boundary too.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse


def target_key(url: str) -> str:
    """Normalised host:port. Must match handoff.target_key."""
    p = urlparse(url if "://" in (url or "") else f"http://{url}")
    host = (p.hostname or "").lower()
    if not host:
        return ""
    return f"{host}:{p.port or (443 if p.scheme == 'https' else 80)}"


def _path_of(value: str) -> str:
    """The path a produced URL refers to, or '' if it has none worth storing."""
    v = (value or "").strip()
    if not v:
        return ""
    p = urlparse(v if "://" in v else f"http://x{v if v.startswith('/') else '/' + v}")
    path = (p.path or "").rstrip("/")
    if p.query:
        path = f"{path}?{p.query}"
    return path if path.startswith("/") else ""


async def record(db, url: str, test_case_id: str | None,
                 produced: dict[str, list[str]], source: str = "testcase",
                 engagement_target_id: str = "") -> int:
    """Persist what a run discovered. Returns rows written.

    Idempotent per (target_key, path): a sweep that revisits a site does not
    multiply its own inventory.
    """
    tk = target_key(url)
    if not tk or not produced:
        return 0

    from orchestrator.engagement import looks_injectable

    params = [p for p in (produced.get("parameter") or [])
              if p and not looks_injectable(p)]
    written = 0
    for value in (produced.get("url") or []):
        path = _path_of(value)
        if not path or looks_injectable(path):
            continue
        cur = await db.execute(
            "SELECT 1 FROM target_endpoints WHERE target_key = ? AND path = ? LIMIT 1",
            (tk, path))
        if await cur.fetchone():
            continue
        await db.execute(
            "INSERT INTO target_endpoints (target_id, target_key, test_case_id, "
            "path, method, params, source) VALUES (?,?,?,?,?,?,?)",
            (engagement_target_id, tk, test_case_id, path, "GET",
             json.dumps(params) if params else None, source))
        written += 1
    return written


async def known(db, url: str) -> list[dict[str, Any]]:
    """Everything discovered for this target, newest last."""
    tk = target_key(url)
    if not tk:
        return []
    cur = await db.execute(
        "SELECT path, method, params, source, test_case_id FROM target_endpoints "
        "WHERE target_key = ? ORDER BY id", (tk,))
    out = []
    for row in await cur.fetchall():
        d = dict(row)
        try:
            d["params"] = json.loads(d["params"]) if d["params"] else []
        except (ValueError, TypeError):
            d["params"] = []
        out.append(d)
    return out


def as_sweep_inputs(rows: list[dict], base: str) -> dict[str, list[str]]:
    """Reshape stored rows into {url: [...], parameter: [...]} for the planner.

    Absolute URLs are rebuilt from the CALLER's base, never from anything
    stored, so an endpoint recorded on one host can never retarget a sweep at
    another.
    """
    base = (base or "").rstrip("/")
    urls, params = [], []
    for r in rows:
        path = r.get("path") or ""
        if path.startswith("/"):
            u = f"{base}{path}"
            if u not in urls:
                urls.append(u)
        for p in r.get("params") or []:
            if p not in params:
                params.append(p)
    out: dict[str, list[str]] = {}
    if urls:
        out["url"] = urls
    if params:
        out["parameter"] = params
    return out
