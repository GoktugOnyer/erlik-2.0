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



def _safe_host(url: str) -> str | None:
    """The hostname of `url`, or None if it cannot be parsed. Never raises."""
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        return (parsed.hostname or "").lower() or None
    except ValueError:
        return None


def payload_allowlist(declared: list[str] | None, scope: Scope) -> set[str]:
    """The declared payload hosts that are actually permitted for this run.

    A case declares hosts it names as DATA -- an attacker `Origin:`, an
    unregistered `redirect_uri`, the cloud metadata address a target is asked
    to fetch. See TestCase.payload_hosts for why that declaration exists.

    One thing is enforced here rather than in the schema, because it depends
    on the run's scope rather than on the case:

      * `deny_hosts` wins. An operator who explicitly excluded a host must not
        have that reversed by a case file. This is the one direction the
        declaration must never move.

    A declared host that is ALREADY in `allow_hosts` is kept rather than
    filtered out, because it costs nothing: `check_url` succeeds on it before
    the allowance is ever consulted, so the entry is inert either way.
    """
    out: set[str] = set()
    for h in declared or []:
        h = (h or "").strip().lower()
        if not h or _host_matches(h, scope.deny_hosts):
            continue
        out.add(h)
    return out


def _is_declared_payload(host: str, permitted: set[str]) -> bool:
    """Whether `host` is a declared payload host, or a name UNDER one.

    Subdomains are included, and that is not a glob: `a.b.example` is permitted
    by a declaration of `b.example`, and nothing else is -- not a sibling, not
    a different TLD, not a name that merely contains the string. Two probes
    need it and neither can be written with an exact host:

      * AUTHZ-05's suffix-confusion probe offers
        `redirect_uri={{url}}.erlik-not-registered.example`, so the host it
        names depends on the target and cannot be written down in advance;
      * OAST works by assigning a unique subdomain per probe, so an exact-host
        declaration would have to be edited every time.

    `deny_hosts` has already removed anything the operator excluded, and it is
    matched against the full host below as well, so denying one subdomain of a
    declared domain still works.
    """
    h = (host or "").lower()
    return any(h == d or h.endswith("." + d) for d in permitted)


def check_url(url: str, scope: Scope) -> None:
    """Raise ScopeViolation if `url` is out of scope. No return value."""
    if not url:
        raise ScopeViolation("empty URL")
    # urlparse RAISES on some malformed inputs rather than returning an empty
    # host -- `ValueError: Invalid IPv6 URL` for anything with an unbalanced
    # `[` after the scheme. _URL_RX over-extracts on purpose, so a bracket
    # expression in a step's own grep pattern reaches here as a "URL":
    #
    #   grep -Eio "action=[\"']?http://[^\" >]*"
    #
    # produced `http://[^\"` and killed the entire run with a traceback --
    # not a refusal, not a result, no finding either way. An unparseable URL
    # must be REFUSED, the same as any other host that cannot be shown to be
    # in scope; this guard exists to fail closed.
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
    except ValueError as e:
        raise ScopeViolation(f"could not parse URL {url!r}: {e}") from e
    host = parsed.hostname or ""
    if not host:
        raise ScopeViolation(f"could not parse host from URL: {url!r}")
    try:
        parsed.port          # also raises ValueError on a bad port
    except ValueError as e:
        raise ScopeViolation(f"could not parse port from URL {url!r}: {e}") from e
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


def check_command(command: str, scope: Scope, primary_url: str | None = None,
                  payload_hosts: list[str] | None = None) -> None:
    """Validate every URL-shaped substring in `command` against `scope`.

    Always checks the primary target URL first if supplied. Bare hostnames
    are checked too — most pentest tools accept `-t target.com` without a
    scheme, and we must not let those through.
    """
    # The primary target is checked against the engagement scope alone. A
    # payload declaration says "this string is data"; it must never widen where
    # the case is aimed.
    if primary_url:
        check_url(primary_url, scope)

    permitted = payload_allowlist(payload_hosts, scope)

    def _check(candidate: str) -> None:
        try:
            check_url(candidate, scope)
        except ScopeViolation:
            host = _safe_host(candidate)
            if (host is not None and _is_declared_payload(host, permitted)
                    and not _host_matches(host, scope.deny_hosts)):
                return
            raise

    for m in _URL_RX.finditer(command):
        _check(m.group(0))

    # Extract bare hostnames only outside of already-matched URLs to avoid
    # double-counting the host portion of an http://… URL we just validated.
    masked = _URL_RX.sub(" ", command)
    # A CREDENTIAL HANDLE is not a hostname. `ERLIK_SECRET.<session>.<field>`
    # ends in a dotted word, and `_BARE_HOST_RX` read `3fd.cookie` as a host
    # with a six-letter TLD — so every authenticated step died as
    # "scope violation: host '3fd.cookie' is not in allow_hosts". Scope is
    # checked BEFORE resolution, deliberately, so that the plaintext secret is
    # never handed to this function; that makes masking the handle here the
    # only place the two designs can be reconciled. Measured: with this line
    # absent, no step carrying a session can run at all, which is why
    # authenticated testing had never once worked end to end.
    from orchestrator.credentials import HANDLE_RX
    masked = HANDLE_RX.sub(" ", masked)
    for m in _BARE_HOST_RX.finditer(masked):
        try:
            _check(m.group(0))
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
