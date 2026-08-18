"""Exploit playbooks: how to attack a class, on ANY target.

WHAT CHANGED AND WHY

This module used to hold six playbooks naming OWASP Juice Shop's exact
endpoints — `POST /profile/image/url`, `GET /redirect?to=`,
`PUT /api/Users/:id` — and its own docstring said so. They were injected
wholesale (~9 KB) whenever playbooks were enabled. On any target that is not
Juice Shop those paths do not exist, so the agent was being told to attack
endpoints that were never there.

Two measurements shaped the replacement:

  * `playbook_only` scored recall 0.1143 against `none` at 0.1429 — the
    playbooks cost recall even on their native target.
  * Injected guidance costs recall dose-dependently (0.1429 / 0.0857 / 0.0714 /
    0.0428 for 0 / 1 / 2 / 3 sheets).

So the generic playbooks are SHORT and ROUTED: only classes the mission
actually names are injected, and each is a few hundred characters describing
how to RECOGNISE the endpoint shape rather than asserting where it is.

Target-specific knowledge still has a home — `playbook_catalog/<name>.yaml`.
Juice Shop's exact endpoints live there now, selected explicitly with
`playbooks: juiceshop`, which keeps every recorded run reproducible.
"""

from __future__ import annotations

import os
from pathlib import Path

CATALOG = Path(__file__).resolve().parent.parent / "playbook_catalog"

# Generic playbooks. Each says: how to SPOT the shape, what to send, how to
# know it worked. No path is asserted to exist — the agent supplies that from
# its own recon, which is the part that transfers between targets.
GENERIC = {
    "ssrf": """SSRF — any parameter the SERVER fetches.
Spot it: a field taking a URL/host (imageUrl, avatar, webhook, callback, feed,
proxy, url, next, redirect_uri) where the RESPONSE reflects fetched content or
timing changes.
Try: internal loopback (http://127.0.0.1:<common ports>), cloud metadata
(http://169.254.169.254/latest/meta-data/), file:///etc/passwd, and a
collaborator host for blind cases.
Confirms when: the response contains content only the server could reach, or an
out-of-band callback fires. A connection error alone is not a finding.""",

    "open_redirect": """Open Redirect — a parameter that sets Location.
Spot it: any redirect/next/return/url/continue/dest parameter, or a /redirect,
/out, /link path.
Try: absolute off-origin URL; scheme-relative //evil.test; allowlist bypasses —
trusted-host as a substring (https://evil.test?trusted.test), as a fragment
(https://evil.test#trusted.test), as userinfo (https://trusted.test@evil.test);
and a double-encoded form.
Confirms when: the Location header points to a host OUTSIDE the target origin.
A same-origin redirect is ordinary behaviour, not a finding.""",

    "file_upload": """Malicious File Upload — validation that can be bypassed.
Spot it: any multipart endpoint (avatar, attachment, import, document, profile
picture) and whatever it says it accepts.
Try: double extension (x.php.png), null byte (x.php%00.png), case variation,
content-type spoof with a valid magic header, an archive containing ../ paths,
and an SVG carrying script.
Confirms when: the stored file is retrievable AND is served as its dangerous
type, or its content executes. An accepted upload alone is not a finding —
fetch it back and check the response Content-Type.""",

    "xxe": """XXE — an XML parser with external entities enabled.
Spot it: any endpoint taking XML, or a format that IS XML underneath (DOCX,
XLSX, SVG, RSS, SOAP, SAML).
Try: a DOCTYPE with a SYSTEM entity reading file:///etc/passwd; if output is not
reflected, an out-of-band parameter entity to a collaborator host.
Confirms when: file content appears in the response, or the callback fires. A
parser error mentioning the entity is suggestive, not proof.""",

    "prototype_pollution": """Prototype Pollution — a merge that trusts __proto__.
Spot it: any JSON body merged into an object — profile update, settings, config,
bulk edit.
Try: {"__proto__":{"polluted":"yes"}} and the constructor.prototype form; then
request an UNRELATED endpoint and look for the injected key.
Confirms when: a property you injected appears somewhere you never sent it, or
server behaviour changes for a different request. Acceptance of the payload is
not by itself a finding.""",

    "stored_xss": """Stored XSS — input rendered later, unescaped.
Spot it: any field shown back to a DIFFERENT view or user — display name,
comment, review, filename, support ticket.
Try: a payload that survives round-trip; check the RENDERED page, not the API
echo. Prefer attribute-breaking and event-handler forms over bare <script>.
Confirms when: the payload appears unescaped in HTML context on retrieval. A
reflection in a JSON response is not stored XSS.""",
}

# Mission phrases -> playbook key. Deliberately narrow: a playbook is only worth
# its prompt cost when the mission actually names the class.
_ROUTE = {
    "ssrf": ("ssrf", "server-side request forgery", "request forgery"),
    "open_redirect": ("open redirect", "redirect"),
    "file_upload": ("file upload", "upload", "unrestricted file"),
    "xxe": ("xxe", "xml external", "external entity"),
    "prototype_pollution": ("prototype pollution", "prototype", "__proto__"),
    "stored_xss": ("stored xss", "xss", "cross-site scripting"),
}

MAX_PLAYBOOKS = int(os.environ.get("ERLIK_MAX_PLAYBOOKS", "2"))


def available_profiles() -> list[str]:
    if not CATALOG.exists():
        return []
    return sorted(p.stem for p in CATALOG.glob("*.yaml"))


def load_profile(name: str) -> dict:
    """Target-specific playbooks from playbook_catalog/<name>.yaml. {} if absent."""
    p = CATALOG / f"{name}.yaml"
    if not p.exists():
        return {}
    try:
        import yaml
        doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        return doc.get("playbooks") or {}
    except Exception:  # noqa: BLE001 — a broken profile must not break a run
        return {}


def select_playbooks(mission: str, max_n: int = MAX_PLAYBOOKS) -> list[str]:
    """Which classes the mission actually names, most specific first."""
    m = (mission or "").lower()
    hits = []
    for key, phrases in _ROUTE.items():
        if any(ph in m for ph in phrases):
            hits.append((max(len(ph) for ph in phrases if ph in m), key))
    return [k for _, k in sorted(hits, reverse=True)][:max_n]


def get_playbook_context(target_url: str, mode: str | None = None,
                         mission: str = "") -> str:
    """The playbook block to inject.

    mode:
      ""/None  off (also the env default)
      "auto"   generic playbooks for the classes the mission names
      "<name>" a target profile from playbook_catalog/, generic as fallback

    Never auto-triggered by URL heuristics: a profile naming another app's
    endpoints must be chosen deliberately, not guessed from a port number.
    """
    effective = (mode if mode is not None
                 else os.environ.get("ERLIK_PLAYBOOKS", "")).strip().lower()
    if not effective or effective in ("0", "off", "false", "none"):
        return ""

    keys = select_playbooks(mission) or (
        list(GENERIC)[:MAX_PLAYBOOKS] if effective == "auto" else list(GENERIC)[:MAX_PLAYBOOKS])

    profile = {} if effective == "auto" else load_profile(effective)
    parts = []
    for k in keys:
        body = profile.get(k) or GENERIC.get(k)
        if body:
            parts.append(body.replace("{target_url}", (target_url or "").rstrip("/")))
    if not parts:
        return ""

    src = "target profile: " + effective if profile else "generic techniques"
    header = (
        "═══════════════════════════════════════════════════════════════\n"
        f"EXPLOIT PLAYBOOKS ({src})\n"
        "═══════════════════════════════════════════════════════════════\n"
        "How to recognise and confirm these classes. Endpoints come from YOUR\n"
        "recon — nothing below asserts a path exists on this target.\n"
    )
    return f"{header}\n" + "\n\n".join(parts) + "\n"


# Back-compat: callers and recorded run configs reference ALL_PLAYBOOKS.
ALL_PLAYBOOKS = GENERIC
