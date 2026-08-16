"""Operator-authored skill sheets. Ships DISABLED.

This writes attacker-influenceable text to disk, and that text is later
INJECTED INTO THE SYSTEM PROMPT of an agent that executes shell commands inside
a privileged container, bounded by a scope guard that is a legal boundary on a
client engagement. It is the single most dangerous surface in erlik, so it is
off by default and refuses loudly rather than degrading.

WHY THERE IS NO CONTENT FILTER
The original design screened authored text for dangerous patterns in two tiers.
Every deny pattern was code-shaped, so three backticks nullified the whole
tier — and more fundamentally, filtering here is not possible in principle: an
exfiltration one-liner is textually indistinguishable from a legitimate SSRF
cheat sheet, because payload text is what these files ARE. Pretending otherwise
would buy a false sense of safety.

What ships instead is `content_signals`: every URL, bare host, IP literal and
exec verb is EXTRACTED AND SHOWN, for the operator to read before saving. An
inventory a human reviews, not a regex a rephrase defeats. It never blocks a
save; the operator is the review step and the UI says so.

The bounds that actually hold are elsewhere: the untrusted-data delimiter and
per-file provenance header, the repaired scope guard and per-segment tool
allowlist, safe mode, the container boundary, MAX_FILE_EXCERPT, and the fact
that authored files live outside every licensed corpus directory.
"""

from __future__ import annotations

import os
import re
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Outside skills_catalog/ on purpose. The licence of a corpus file must stay
# answerable from its PATH; dropping operator text into a vendored directory
# would destroy that for every file beside it. data/ is already gitignored.
LOCAL_ROOT_NAME = Path("data") / "skills_local"

MAX_BYTES = 64 * 1024
_NAME_RX = re.compile(r"^[a-z0-9][a-z0-9._-]{0,79}\.md$")
_RESERVED = {"notice.md", "index.md", "skill.md", "readme.md"}


class AuthoringDisabled(RuntimeError):
    """The feature is off, or the deployment is not safe enough to enable it."""


class InvalidSkillRef(ValueError):
    def __init__(self, rule: str, detail: str = ""):
        super().__init__(f"{rule}: {detail}" if detail else rule)
        self.rule = rule


def local_root() -> Path:
    """A FUNCTION, not an import-time constant, so tests can relocate it."""
    return ROOT / LOCAL_ROOT_NAME


# ── gates ──────────────────────────────────────────────────────────────────
def _truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def gate_status() -> dict:
    """Every gate's state, for an operator to see WHY it is refusing."""
    return {
        "authoring_flag": _truthy("ERLIK_SKILL_AUTHORING"),
        "api_token_set": bool(os.environ.get("ERLIK_API_TOKEN", "").strip()),
        "native_mode": bool(os.environ.get("ERLIK_NATIVE", "").strip()),
    }


def assert_enabled(*, client_host: str | None = None,
                   headers: dict | None = None) -> None:
    """Raise AuthoringDisabled unless every gate passes.

    Gates are checked in order of how badly they fail, so the message names the
    first thing an operator must fix.
    """
    g = gate_status()
    if not g["authoring_flag"]:
        raise AuthoringDisabled(
            "skill authoring is disabled. Set ERLIK_SKILL_AUTHORING=1 to enable "
            "it, and read SECURITY.md first: authored text is injected into the "
            "system prompt of an agent that executes shell commands.")
    if not g["api_token_set"]:
        # Deliberately stricter than the rest of the API. _api_token_guard is
        # OFF unless ERLIK_API_TOKEN is set, which is a reasonable default for
        # reads and an unacceptable one for a route that writes files into an
        # agent's prompt.
        raise AuthoringDisabled(
            "writes_require_token: ERLIK_API_TOKEN is not set, so this endpoint "
            "would be unauthenticated. Set it before enabling authoring.")
    if g["native_mode"]:
        raise AuthoringDisabled(
            "ERLIK_NATIVE=1 runs tools as your own user with no container "
            "boundary. Authoring is refused in that mode.")

    hdrs = {k.lower(): v for k, v in (headers or {}).items()}
    # uvicorn runs without --proxy-headers today, so XFF is untrusted. If anyone
    # adds it, request.client.host becomes attacker-controlled and a
    # "we ignore XFF" claim would silently go false — so refuse outright.
    for h in ("x-forwarded-for", "forwarded", "x-real-ip"):
        if h in hdrs:
            raise AuthoringDisabled(
                f"refusing: {h} present. erlik is not configured to run behind a "
                f"proxy, so a forwarded client address cannot be trusted.")
    host = (hdrs.get("host") or "").split(":")[0].strip("[]").lower()
    if host and host not in ("127.0.0.1", "localhost", "::1", ""):
        # Blocks DNS rebinding: an attacker page resolving its own name to
        # 127.0.0.1 still sends its own Host header.
        raise AuthoringDisabled(
            f"refusing Host {host!r}; authoring is reachable on loopback only.")
    if client_host and client_host not in ("127.0.0.1", "::1", "localhost"):
        raise AuthoringDisabled(
            f"refusing: request came from {client_host}, not loopback.")


# ── validation ─────────────────────────────────────────────────────────────
def validate_name(raw: str) -> str:
    """The ONE choke point turning operator input into a filename.

    Rejects on structure, never on a blocklist of bad strings.
    """
    if raw is None:
        raise InvalidSkillRef("missing", "no filename given")
    name = unicodedata.normalize("NFC", str(raw)).strip()
    if not name:
        raise InvalidSkillRef("missing", "empty filename")
    if "\x00" in name:
        raise InvalidSkillRef("nul_byte")
    if "/" in name or "\\" in name:
        raise InvalidSkillRef("separator", "filename may not contain a path")
    if name != name.lower():
        raise InvalidSkillRef("case", "use lowercase; APFS is case-insensitive "
                                      "and Foo.md would clobber foo.md")
    if name in (".", "..") or name.startswith("."):
        raise InvalidSkillRef("dotfile")
    if not name.endswith(".md"):
        raise InvalidSkillRef("extension", "must end in .md")
    if name in _RESERVED:
        raise InvalidSkillRef("reserved", f"{name} has meaning to the loader")
    if name.endswith("-index.md"):
        raise InvalidSkillRef("reserved", "-index.md is skipped by the router")
    if not _NAME_RX.match(name):
        raise InvalidSkillRef("charset", "use a-z 0-9 . _ - only")
    return name


def resolve_target(name: str) -> Path:
    """Validated absolute path inside the local root. Never escapes it."""
    root = local_root().resolve()
    p = (root / validate_name(name))
    # Check every component for a symlink BEFORE resolve(), because resolve()
    # would silently follow one out of the root and then is_relative_to passes.
    cur = root
    for part in p.relative_to(root).parts:
        cur = cur / part
        if cur.is_symlink():
            raise InvalidSkillRef("symlink", f"{part} is a symlink")
    final = p.resolve() if p.exists() else p
    if not final.is_relative_to(root):
        raise InvalidSkillRef("escape", "resolves outside the local corpus")
    return final


# ── content signals (shown, never enforced) ────────────────────────────────
_URL_RX = re.compile(r"https?://[^\s'\"`<>)\]]+", re.I)
_HOST_RX = re.compile(r"(?<![\w.-])(?:[a-z0-9-]+\.)+[a-z]{2,}(?![\w-])", re.I)
_IP_RX = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_EXEC_RX = re.compile(
    r"(?<![\w-])(curl|wget|nc|ncat|netcat|socat|bash|sh|zsh|python[23]?|perl|ruby|"
    r"php|base64|xxd|docker|kubectl|ssh|scp|chmod|chown|rm|dd|mkfs)(?![\w-])", re.I)


def content_signals(text: str) -> dict:
    """Everything worth a human glance before this text enters a prompt.

    Reported, never blocked. A filter here is defeated by a rephrase; an
    inventory is not, because the reviewer is a person.
    """
    text = text or ""
    urls = sorted(set(_URL_RX.findall(text)))
    hosts = sorted({h.lower() for h in _HOST_RX.findall(_URL_RX.sub(" ", text))})
    ips = sorted(set(_IP_RX.findall(text)))
    verbs = sorted({v.lower() for v in _EXEC_RX.findall(text)})
    return {
        "urls": urls, "hosts": hosts, "ips": ips, "exec_verbs": verbs,
        "total": len(urls) + len(hosts) + len(ips) + len(verbs),
        "note": ("These are shown for you to review, not blocked. Filtering is "
                 "not possible here: an exfiltration one-liner is textually "
                 "identical to a legitimate cheat sheet, because payload text "
                 "is what these files are. You are the review step."),
    }


def validate_body(text: str) -> None:
    if text is None:
        raise InvalidSkillRef("missing", "no content")
    raw = text.encode("utf-8", "surrogatepass")
    if not raw.strip():
        raise InvalidSkillRef("empty", "content is blank")
    if len(raw) > MAX_BYTES:
        raise InvalidSkillRef("too_large",
                              f"{len(raw)} bytes exceeds the {MAX_BYTES} limit")


# ── write / delete ─────────────────────────────────────────────────────────
def save(name: str, body: str, *, overwrite: bool = False) -> Path:
    """Atomically write an authored sheet. Returns its path."""
    validate_body(body)
    target = resolve_target(name)
    root = local_root()
    root.mkdir(parents=True, exist_ok=True)
    _ensure_notice(root)

    # APFS is case-insensitive: `Foo.md` and `foo.md` are one file. validate_name
    # forces lowercase, so a collision here is a genuine duplicate.
    if target.exists() and not overwrite:
        raise InvalidSkillRef("exists", f"{target.name} already exists")

    tmp = target.with_name(target.name + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(body)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
    os.replace(tmp, target)
    return target


def soft_delete(name: str) -> Path:
    """Move out of BOTH corpus roots rather than unlinking.

    A `.trash` directory *under* a root is still rglob'd and still injected, and
    `-` boundary matching means a timestamped name like `1755-sql-injection`
    still matches the `sqli` class.
    """
    target = resolve_target(name)
    if not target.exists():
        raise InvalidSkillRef("missing", f"{target.name} does not exist")
    trash = ROOT / "data" / "skills_trash"
    trash.mkdir(parents=True, exist_ok=True)
    dest = trash / target.name
    i = 1
    while dest.exists():
        dest = trash / f"{target.stem}.{i}{target.suffix}"
        i += 1
    os.replace(target, dest)
    return dest


_NOTICE = """# Operator-authored skills

Files here were written by an operator through the dashboard, NOT vendored from
any upstream project. They carry no third-party licence.

They are injected into the system prompt of an agent that executes shell
commands. erlik does not filter their content — it cannot: an exfiltration
one-liner is textually identical to a legitimate cheat sheet. Review them the
way you would review code that runs as you.

This directory is outside `skills_catalog/` on purpose, so the licence of every
vendored file stays answerable from its path.
"""


def _ensure_notice(root: Path) -> None:
    n = root / "NOTICE.md"
    if not n.exists():
        n.write_text(_NOTICE, encoding="utf-8")


def listing() -> list[dict]:
    root = local_root()
    if not root.exists():
        return []
    return [{"name": p.name, "bytes": p.stat().st_size}
            for p in sorted(root.glob("*.md")) if p.name != "NOTICE.md"]
