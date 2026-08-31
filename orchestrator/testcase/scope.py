"""Per-run authorization scope. Blocks any tool invocation whose target
URL is not in the explicit allowlist.

This is the safety floor for full-auto exploitation mode: even if the LLM
or a mutator generates a command targeting a different host, the runner
refuses to execute it. There is no opt-out.
"""

import fnmatch
import re
from urllib.parse import urlparse
from pydantic import BaseModel, Field


class Scope(BaseModel):
    """Allowlist of hosts a run is authorized to target.

    `allow_hosts` accepts exact hostnames and glob patterns (e.g.
    'app.example.com', '*.example.com'). `allow_ports` is optional; if
    empty, all ports are allowed for an allowed host.
    `deny_hosts` is checked first and always wins.
    """
    allow_hosts: list[str] = Field(default_factory=list)
    deny_hosts: list[str] = Field(default_factory=list)
    allow_ports: list[int] = Field(default_factory=list)


class ScopeViolation(RuntimeError):
    """Raised when a command would touch an out-of-scope target."""


def _host_matches(host: str, patterns: list[str]) -> bool:
    h = host.lower()
    return any(fnmatch.fnmatchcase(h, p.lower()) for p in patterns)


def check_url(url: str, scope: Scope) -> None:
    """Raise ScopeViolation if `url` is out of scope. No return value."""
    if not url:
        raise ScopeViolation("empty URL")
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = parsed.hostname or ""
    if not host:
        raise ScopeViolation(f"could not parse host from URL: {url!r}")
    if _host_matches(host, scope.deny_hosts):
        raise ScopeViolation(f"host {host!r} is explicitly denied")
    if not scope.allow_hosts:
        raise ScopeViolation("scope has no allow_hosts — refusing all targets")
    if not _host_matches(host, scope.allow_hosts):
        raise ScopeViolation(f"host {host!r} is not in allow_hosts {scope.allow_hosts}")
    if scope.allow_ports:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if port not in scope.allow_ports:
            raise ScopeViolation(f"port {port} not in allow_ports {scope.allow_ports}")


# Naive URL extractor. We over-extract on purpose: every plausible URL in a
# rendered command must clear the scope check, including ones embedded in
# Burp-style query strings or in --data payloads. Better to reject a
# borderline command than to silently let one through.
_URL_RX = re.compile(r"https?://[^\s'\"\\<>|]+", re.IGNORECASE)
_BARE_HOST_RX = re.compile(
    r"(?<![\w./])(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d{1,5})?(?![\w./])",
    re.IGNORECASE,
)


def check_command(command: str, scope: Scope, primary_url: str | None = None) -> None:
    """Validate every URL-shaped substring in `command` against `scope`.

    Always checks the primary target URL first if supplied. Bare hostnames
    are checked too — most pentest tools accept `-t target.com` without a
    scheme, and we must not let those through.
    """
    if primary_url:
        check_url(primary_url, scope)

    for m in _URL_RX.finditer(command):
        check_url(m.group(0), scope)

    # Extract bare hostnames only outside of already-matched URLs to avoid
    # double-counting the host portion of an http://… URL we just validated.
    masked = _URL_RX.sub(" ", command)
    for m in _BARE_HOST_RX.finditer(masked):
        try:
            check_url(m.group(0), scope)
        except ScopeViolation:
            # Bare-host matches frequently catch wordlist filenames like
            # /usr/share/wordlists/common.txt — only fail if the candidate
            # looks like a plausible hostname (has a TLD-shaped suffix and
            # is not a filesystem path).
            # Same predicate as the agent lane's guard, imported rather than
            # re-listed: this copy knew only .txt and .json, so a command the
            # other guard allowed was refused here purely by which lane ran it.
            from orchestrator.tool_executor import looks_like_filename
            if looks_like_filename(m.group(0)):
                continue
            raise


def from_target(target: dict) -> Scope | None:
    """Build a Scope from the target dict if it carries scope fields, else None."""
    if "scope" not in target:
        return None
    return Scope(**target["scope"])
