"""Stateful exploit-primitive store.

Captures reusable primitives — JWTs, bearer/cookie/session tokens, basic-auth
blobs — from tool output DURING a run, so later steps can re-attach them instead
of re-authenticating. This is the plumbing for multi-step exploitation (the audit
flagged "no stateful chaining / auth context not propagated" as a top gap).

Pure extraction + formatting here; persistence and agent-loop injection live in
main.py. Gated by the per-session run config (`primitives`) / ERLIK_PRIMITIVES.
"""

from __future__ import annotations

import re

_PATTERNS = [
    # (kind, regex, group, reuse hint)
    ("jwt",
     re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\b"),
     0, 'reuse: -H "Authorization: Bearer <jwt>"'),
    ("bearer",
     re.compile(r"[Bb]earer\s+([A-Za-z0-9._~+/=-]{12,})"),
     1, 'reuse: -H "Authorization: Bearer <token>"'),
    ("cookie",
     re.compile(r"[Ss]et-[Cc]ookie:\s*([^\r\n;]+)"),
     1, 'reuse: --cookie "<cookie>"'),
    ("token",
     re.compile(r'"(?:token|access_token|authToken|jwt|apiKey|api_key|sessionId|session)"\s*:\s*"([^"]{8,})"'),
     1, 'reuse: -H "Authorization: Bearer <token>"'),
    ("basic_auth",
     re.compile(r"[Aa]uthorization:\s*Basic\s+([A-Za-z0-9+/=]{8,})"),
     1, 'reuse: -H "Authorization: Basic <b64>"'),
    ("csrf",
     re.compile(r'(?:csrf[-_]?token|_csrf|xsrf[-_]?token)["\']?\s*[:=]\s*["\']?([A-Za-z0-9._-]{8,})', re.IGNORECASE),
     1, 'reuse: send as the CSRF token header/param on state-changing requests'),
]


def extract_primitives(output: str, tool_name: str = "") -> list[dict]:
    """Return the reusable primitives found in `output` (deduped)."""
    if not output:
        return []
    prims: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for kind, rx, grp, hint in _PATTERNS:
        for m in rx.finditer(output):
            val = (m.group(grp) if grp else m.group(0)).strip().strip('"\'')
            if not val or len(val) < 6:
                continue
            key = (kind, val)
            if key in seen:
                continue
            seen.add(key)
            prims.append({"kind": kind, "value": val[:400], "hint": hint, "tool": tool_name})
    return prims


def format_for_agent(prims: list[dict], limit: int = 12) -> str:
    """Compact reuse reminder injected into the agent's tool feedback."""
    if not prims:
        return ""
    lines = ["[PRIMITIVES] Credentials/tokens captured from earlier steps — REUSE these "
             "on subsequent requests instead of re-authenticating:"]
    for p in prims[:limit]:
        v = p["value"]
        disp = v if len(v) <= 64 else v[:61] + "…"
        lines.append(f"  - {p['kind']}: {disp}   ({p['hint']})")
    return "\n".join(lines)
