"""Deterministic findings become the AI agent's starting point.

erlik has two execution lanes and, until this module, no path between them:

    deterministic (orchestrator/testcase/)  ->  v2_findings
    AI agent      (orchestrator/main.py)    ->  findings, recon_context

`main.py` referenced `v2_findings` ZERO times and the v2 lane wrote
`recon_context` ZERO times. A deterministic run produced facts that no agent
ever saw, and every agent run started from nothing but a URL — rediscovering
ports, endpoints and technologies that a scan had already established.

This writes deterministic results into `recon_context`, which the agent already
reads through `_get_target_memory_context` (keyed on `target_key`, so it
survives across sessions against the same host). Nothing in the agent loop
changes: it gains a starting context because the store it already consults now
has something in it.

DESIGN NOTE — why not copy into `findings`:
`findings` is what recall and precision are computed from. Copying deterministic
results there would inflate every recorded metric by counting one finding twice
and make agent-lane numbers incomparable with every run before it. The handoff
is CONTEXT, not credit: the agent is told what is already known so it can go
further, and anything it then confirms it records itself.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse


def target_key(target_url: str) -> str:
    """Normalised host:port. Must match main._target_key or the agent will not
    find what the deterministic lane wrote."""
    p = urlparse(target_url if "://" in (target_url or "") else f"http://{target_url}")
    host = (p.hostname or "").lower()
    if not host:
        return ""
    port = p.port or (443 if p.scheme == "https" else 80)
    return f"{host}:{port}"


def _classify(vuln_type: str) -> str:
    """Which recon_context bucket a deterministic result belongs in.

    The agent's context formatter groups by these, so a result filed as
    `finding` reads as "already established" while one filed as `endpoint`
    reads as "somewhere to look".
    """
    v = (vuln_type or "").lower()
    if any(k in v for k in ("disclosed", "exposed", "reachable", "readable",
                            "index", "version")):
        return "endpoint"
    return "finding"


async def bridge_run(db, run_id: str, target_url: str, findings: list) -> int:
    """Write one deterministic run's findings into the shared context store.

    Returns the number of rows written. Idempotent per (session, key): a rerun
    of the same case does not multiply the context.
    """
    tk = target_key(target_url)
    if not tk:
        return 0
    written = 0
    for f in findings:
        vt = getattr(f, "vuln_type", None) or (f.get("vuln_type") if isinstance(f, dict) else None)
        url = getattr(f, "url", None) or (f.get("url") if isinstance(f, dict) else None) or ""
        ev = getattr(f, "evidence", None) or (f.get("evidence") if isinstance(f, dict) else None) or ""
        tcid = (getattr(f, "test_case_id", None)
                or (f.get("test_case_id") if isinstance(f, dict) else None) or "wstg")
        if not vt:
            continue
        key = f"{tcid}:{vt}"[:200]
        cur = await db.execute(
            "SELECT 1 FROM recon_context WHERE session_id = ? AND key = ? LIMIT 1",
            (run_id, key))
        if await cur.fetchone():
            continue
        await db.execute(
            "INSERT INTO recon_context (session_id, context_type, key, value, "
            "source_tool, target_key) VALUES (?, ?, ?, ?, ?, ?)",
            (run_id, _classify(vt), key, f"{url} {ev}".strip()[:500],
             f"wstg:{tcid}", tk))
        written += 1
    return written


def _evidence(val: str | None, limit: int = 110) -> str:
    """One clean line of evidence.

    The raw value is whatever the test case captured, which for an error-based
    check is a full HTML error page. Injected verbatim that was multi-line
    markup inside the prompt — and injected volume is the one variable measured
    to cost recall dose-dependently, so noise here is not merely untidy.
    Keeps the URL and the human-readable remainder; drops tags and whitespace.
    """
    t = re.sub(r"<[^>]{0,200}>", " ", str(val or ""))
    t = t.replace("&quot;", '"').replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    t = " ".join(t.split())
    return t[:limit]


def format_for_agent(rows: list) -> str:
    """Render deterministic results as a starting brief for the agent.

    Deliberately states what was ALREADY CONFIRMED and asks for what is not
    covered, rather than restating methodology. A measured 12-run experiment
    found injected guidance costs recall dose-dependently, so this stays short
    and factual — it is evidence, not instruction.
    """
    if not rows:
        return ""
    lines = ["DETERMINISTIC SCAN RESULTS (already confirmed — do not re-verify):"]
    for r in rows[:20]:
        ct = r["context_type"] if not isinstance(r, dict) else r.get("context_type")
        key = r["key"] if not isinstance(r, dict) else r.get("key")
        val = r["value"] if not isinstance(r, dict) else r.get("value")
        lines.append(f"  [{ct}] {key} — {_evidence(val)}")
    lines.append("")
    lines.append("These are established facts. Spend your turns on what they do NOT cover.")
    return "\n".join(lines)
