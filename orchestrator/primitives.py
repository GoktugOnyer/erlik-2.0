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


# How each tool takes an already-captured credential. Only tools that speak HTTP
# and accept a header or cookie flag are listed; anything absent is left alone.
_AUTH_FLAGS = {
    "curl":    {"bearer": '-H "Authorization: Bearer {v}"', "cookie": '-b "{v}"'},
    "sqlmap":  {"bearer": '--headers="Authorization: Bearer {v}"', "cookie": '--cookie="{v}"'},
    "ffuf":    {"bearer": '-H "Authorization: Bearer {v}"', "cookie": '-H "Cookie: {v}"'},
    "gobuster": {"bearer": '-H "Authorization: Bearer {v}"', "cookie": '-c "{v}"'},
    "dalfox":  {"bearer": '-H "Authorization: Bearer {v}"', "cookie": '-C "{v}"'},
    "xsstrike": {"cookie": '--headers "Cookie: {v}"'},
    "nuclei":  {"bearer": '-H "Authorization: Bearer {v}"', "cookie": '-H "Cookie: {v}"'},
    "arjun":   {"bearer": '--headers "Authorization: Bearer {v}"', "cookie": '--headers "Cookie: {v}"'},
    "nikto":   {"cookie": '-id "{v}"'},
    "wfuzz":   {"bearer": '-H "Authorization: Bearer {v}"', "cookie": '-b "{v}"'},
    "commix":  {"bearer": '--headers="Authorization: Bearer {v}"', "cookie": '--cookie="{v}"'},
}

# Already-authenticated commands must be left untouched — re-adding would either
# duplicate the header or override a credential the agent chose deliberately.
_ALREADY_AUTHED = re.compile(
    r"(-H\s+['\"]?Authorization|--headers?[= ]['\"]?[^'\"]*Authorization|"
    r"-b\s|--cookie|-C\s|-c\s+['\"]|Cookie:|-id\s)", re.IGNORECASE)


def best_credentials(prims: list[dict]) -> dict:
    """The strongest bearer token and cookie available, newest first.

    A JWT beats an opaque bearer beats a generic token, because a JWT is
    unambiguous evidence of a session; cookies are taken as-is.
    """
    order = {"jwt": 0, "bearer": 1, "token": 2}
    out: dict = {}
    for p in sorted(prims or [], key=lambda p: order.get(p.get("kind"), 9)):
        kind, val = p.get("kind"), (p.get("value") or "").strip()
        if not val:
            continue
        if kind in order and "bearer" not in out:
            out["bearer"] = val
        elif kind == "cookie" and "cookie" not in out:
            out["cookie"] = val
    return out


def inject_credentials(command: str, prims: list[dict],
                       target_host: str | None = None) -> tuple[str, str | None]:
    """Add a captured credential to a command that has none.

    Returns (command, note) — note is None when nothing was changed.

    Announcing a credential once in the agent's context is not enough: across two
    real runs the model captured a session cookie and then never sent it, so
    every request stayed anonymous and the whole authenticated surface was
    invisible. This makes reuse automatic rather than hoping the model remembers.

    SAFETY: refuses when the command targets a host other than the session
    target. A captured session token must never be attached to a request to some
    other site just because a URL appeared in the command — that would be
    credential exfiltration performed by our own tool.
    """
    if not command or not prims:
        return command, None

    tool = command.strip().split()[0].lower() if command.strip() else ""
    flags = _AUTH_FLAGS.get(tool)
    if not flags:
        return command, None
    if _ALREADY_AUTHED.search(command):
        return command, None

    if target_host:
        hosts = set(re.findall(r"https?://([^/\s'\"]+)", command))
        # Compare on hostname only; a port difference is still the same host.
        want = target_host.split(":")[0].lower()
        for h in hosts:
            if h.split(":")[0].lower() != want:
                return command, None
        if not hosts:
            return command, None      # no explicit target — do not guess

    creds = best_credentials(prims)
    for kind in ("bearer", "cookie"):
        if kind in creds and kind in flags:
            return (f"{command} {flags[kind].format(v=creds[kind])}",
                    f"reused captured {kind}")
    return command, None


def format_for_agent(prims: list[dict], limit: int = 12, header: str | None = None) -> str:
    """Compact reuse reminder injected into the agent's tool feedback.

    `header` overrides the default lead-in — used when replaying the accumulated
    store into a new session's system prompt, where "earlier steps" would be
    wrong (the primitives came from earlier chain phases, not this run's turns).
    """
    if not prims:
        return ""
    lines = [header or
             "[PRIMITIVES] Credentials/tokens captured from earlier steps — REUSE these "
             "on subsequent requests instead of re-authenticating:"]
    for p in prims[:limit]:
        v = p["value"]
        disp = v if len(v) <= 64 else v[:61] + "…"
        lines.append(f"  - {p['kind']}: {disp}   ({p['hint']})")
    return "\n".join(lines)
