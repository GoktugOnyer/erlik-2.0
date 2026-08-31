"""The single redaction authority for anything that leaves erlik.

`review.redact_secrets` only ever ran on the AI-review path, and it reuses
`primitives._PATTERNS` — an EXTRACTOR's patterns, which match what a secret
looks like in a RESPONSE. But `primitives.inject_credentials` writes secrets
into REQUESTS, in shapes those patterns do not describe. Measured against the
live function: 11 of the 20 templates in `primitives._AUTH_FLAGS` leaked the
secret verbatim — every cookie form, because the `cookie` pattern only matches
`Set-Cookie:`. The lever that manufactures the leak and the redactor that
should catch it were describing different halves of the same exchange.

Three design points that are easy to get wrong:

1. DISTINCTNESS. Replacing a whole secret with a constant collapses two
   DIFFERENT secrets into one identical string, which silently merges two
   distinct commands during dedup. Each placeholder therefore carries a short
   digest of the secret: `<jwt:redacted:a3f9>`. A digest, not a prefix — the
   first characters of a session cookie are often the cookie NAME, and this is
   a security tool.

2. IDEMPOTENCE MUST BE OVERLAP-BASED. Checking `m.group(0) != placeholder` is
   not enough: on `Set-Cookie: sid=abc` the old rule fires and the new
   `Cookie:` rule then matches the RESULT within the same pass, starting
   INSIDE the placeholder. Placeholder spans are computed up front and any
   candidate overlapping one is skipped.

3. THE CENSUS COUNTS DISTINCT SECRETS, NOT SUBSTITUTIONS. On
   `{"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjF9.abcd"}` the `jwt` pattern
   fires first and the `token` pattern then re-matches the placeholder and
   overwrites it — one secret, naively reported as two of the wrong kinds.
   Matches are collected from the ORIGINAL text and deduped by (kind, value)
   before substitution. Tests assert exact equality, never `>=`, because
   `counts['jwt'] >= 1` passes on the double-counting bug.
"""

from __future__ import annotations

import hashlib
import re

PLACEHOLDER_RX = re.compile(r"<[a-z_]+:redacted:[0-9a-f]{4}>")

MIN_SECRET_LEN = 6

# Request-side shapes. `primitives._PATTERNS` covers the response side and is
# appended to this at match time.
#
# Anchoring matters more than it looks: an unanchored `-b|-c|-C` matches inside
# ordinary tokens, so `app-bundle.js?v=1`, `sub-category=1` and
# `--connect-timeout=10` would all be treated as credentials.
_REQUEST_PATTERNS: list[tuple[str, re.Pattern, int]] = [
    # curl -b / gobuster -c / dalfox -C / --cookie=
    ("cookie", re.compile(
        r"""(?:^|\s)(?:-b|-c|-C|--cookie)(?:=|\s+)["']?([^"'\s]{%d,})""" % MIN_SECRET_LEN), 1),
    # Cookie: request header. Terminates at a quote as well as CR/LF — an
    # `([^\r\n]+)` capture swallows the closing quote and the rest of the
    # command, which matches 19 real rows in data/pentest.db.
    ("cookie", re.compile(r"""[Cc]ookie:\s*([^"'\r\n]{%d,})""" % MIN_SECRET_LEN), 1),
    # nikto's -id is a CREDENTIAL (user:pass). nuclei's -id is a template name,
    # so this is scoped to a line that actually invokes nikto — otherwise it
    # masks `nuclei -id CVE-2021-41773`.
    ("basic_auth", re.compile(
        r"""nikto\b[^\n]*?\s-id(?:=|\s+)["']?([^"'\s]{%d,})""" % MIN_SECRET_LEN), 1),
    # "JWT weak secret cracked: hunter2" — a cracked secret announced in tool
    # output. `secret\s*[:=]` cannot match this: the words " cracked" sit
    # between `secret` and the colon.
    ("secret", re.compile(
        r"""(?:secret|password|passphrase)[A-Za-z ]{0,16}[:=]\s*["']?"""
        r"""([A-Za-z0-9._~+/=-]{%d,})""" % MIN_SECRET_LEN), 1),
]

# Placeholders and well-known non-secrets that must never be masked. Hydra form
# specs are the important one: 18 of 540 real `steps.tool_input` rows contain
# `password=^PASS^:Invalid credentials` — a placeholder and a failure string,
# and masking it destroys the only reproduction detail in a brute-force finding.
_NEVER_MASK = re.compile(r"""^(?:\^[A-Z]+\^|[Nn]/?[Aa]|null|none|true|false)$""")


def _digest(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8", "replace")).hexdigest()[:4]


def _all_patterns():
    from orchestrator.primitives import _PATTERNS
    pats = [(kind, rx, grp) for kind, rx, grp, _hint in _PATTERNS]
    return _REQUEST_PATTERNS + pats


def _candidates(text: str) -> list[tuple[str, str]]:
    """(kind, secret) pairs found in the ORIGINAL text, deduped, order-stable."""
    spans = [m.span() for m in PLACEHOLDER_RX.finditer(text)]

    def inside_placeholder(a: int, b: int) -> bool:
        return any(a < pe and ps < b for ps, pe in spans)

    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for kind, rx, grp in _all_patterns():
        for m in rx.finditer(text):
            secret = m.group(grp) if grp else m.group(0)
            if not secret or len(secret) < MIN_SECRET_LEN:
                continue
            if _NEVER_MASK.match(secret) or "^PASS^" in secret or "^USER^" in secret:
                continue
            s, e = m.span(grp) if grp else m.span()
            if inside_placeholder(s, e):
                continue
            key = (kind, secret)
            if key in seen:
                continue
            seen.add(key)
            out.append(key)
    return out


def mask(text: str | None) -> str | None:
    """Replace every credential with a distinct placeholder. None-preserving.

    None in, None out: 58 of 216 findings have `impact IS NULL`, and coercing
    those to "" writes empty strings into an export for 27% of findings while
    `reporting.py`'s `or ""` absorbs it, so nothing fails and the artifact is
    quietly wrong.
    """
    if text is None:
        return None
    out = text
    for kind, secret in _candidates(text):
        out = out.replace(secret, f"<{kind}:redacted:{_digest(secret)}>")
    return out


def census(text: str | None) -> dict[str, int]:
    """Count DISTINCT secrets by kind. Counts substitutions of the same secret
    once, and never double-counts one secret under two patterns."""
    counts: dict[str, int] = {}
    if not text:
        return counts
    claimed: set[str] = set()
    for kind, secret in _candidates(text):
        if secret in claimed:
            continue          # first pattern to claim a value owns it
        claimed.add(secret)
        counts[kind] = counts.get(kind, 0) + 1
    return counts


def mask_url(url: str | None) -> str | None:
    """Mask query-parameter VALUES only, keeping the URL parseable.

    A masked URL becomes the SARIF `artifactLocation.uri` and the DefectDojo
    endpoint, both of which must still urlparse — so the scheme, host and path
    are never touched.
    """
    if not url or "?" not in url:
        return url
    base, _, query = url.partition("?")
    parts = []
    for kv in query.split("&"):
        k, sep, v = kv.partition("=")
        if sep and v and len(v) >= MIN_SECRET_LEN and mask(v) != v:
            parts.append(f"{k}={mask(v)}")
        else:
            parts.append(kv)
    return f"{base}?{'&'.join(parts)}"


# Characters that do not belong in a vulnerability CLASS name. A controlled
# vocabulary field holds "SQL Injection", not an assignment.
_LABEL_FORBIDDEN = ('"', "'", "=", "\n", "\r", "\x00")

LABEL_REDACTED = "Redacted (label contained a secret)"


def safe_label(text: str | None, limit: int = 120) -> str:
    """Sanitise a CONTROLLED-VOCABULARY value, e.g. findings.vuln_type.

    WHY THIS EXISTS. `vuln_type` sits in _EXPORT_STRUCTURAL, which exempts it
    from export masking on the grounds that it is a controlled vocabulary. That
    exemption is correct in principle and false in practice: the value is
    frequently written by a model, which can put anything there. Three rows in
    the corpus have the vuln_type

        password="password",username="admin"

    at severity `critical` — a credential pair sitting in the one finding field
    that is deliberately never masked, and which is also broadcast to the
    dashboard and printed into client reports.

    Rather than start masking the field (which would turn every readable class
    name into a hash and break the ground-truth matcher), the write path
    guarantees the exemption's premise: a label carrying a secret, or shaped
    like an assignment rather than a class name, is replaced outright. The
    original text is not lost — it remains in `evidence`, which IS masked on
    export.

    Legitimate class names pass through untouched.
    """
    t = (text or "").strip()
    if not t:
        return ""
    if any(ch in t for ch in _LABEL_FORBIDDEN):
        return LABEL_REDACTED
    if census(t).get("secret"):
        return LABEL_REDACTED
    if mask(t) != t:
        return LABEL_REDACTED
    return t[:limit]
