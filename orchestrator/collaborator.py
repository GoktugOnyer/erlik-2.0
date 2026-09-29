"""Out-of-band interaction detection.

A whole class of vulnerability produces NO in-band evidence. Blind SQL
injection beyond timing, blind SSRF, blind XXE, blind command injection,
stored/blind XSS -- in each the payload succeeds and the response looks
identical to a failure. The only proof is that the TARGET reached out to a
server the tester controls, so detection is: mint a unique name, put it in the
payload, and afterwards ask whether anything contacted it.

erlik advertised this and delivered none of it. `collaborator_host` was an
optional target field on WSTG-INPV-07, WSTG-INPV-19 and WSTG-AUTHZ-05, and
`declared.DECLARABLE` let an operator configure one -- and NO step command
referenced `{{collaborator_host}}` anywhere in the catalogue. An operator could
declare a collaborator and every probe would ignore it.

WHAT THIS DOES NOT DO. It does not speak interact.sh's or Burp Collaborator's
wire protocol. Those involve key exchange and polling semantics this has never
been run against, and shipping an untested integration of someone else's
protocol is how a tool ends up confidently reporting nothing. The backend is an
INTERFACE with two implementations:

  none  the default. OAST is off, and a case that needs it says so rather than
        running a probe whose result nobody can observe.
  http  a receiver exposing the small documented API below. That is what a
        self-hosted collaborator needs to expose, and it is what the test
        harness implements, so the whole loop -- mint, inject, target fetches,
        poll, correlate -- is exercised end to end.

An interact.sh adapter belongs here later, written against a real instance.

THE RECEIVER API (GET {base}/interactions?token=<t>) returns:

    {"interactions": [{"token": "...", "protocol": "http",
                       "remote_addr": "...", "at": "...", "detail": "..."}]}

An empty list means "nothing has contacted it", which is NOT the same as "the
receiver is unreachable" -- the poller distinguishes them, because a receiver
that is down would otherwise turn every blind case into a clean result.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request

# A token is the correlation key: it goes into the payload and comes back in
# the interaction. Hex so it survives DNS labels, URLs and XML entities without
# escaping, and long enough that an unrelated hit cannot be mistaken for ours.
TOKEN_RX = re.compile(r"^[0-9a-f]{16}$")


class CollaboratorError(RuntimeError):
    """The receiver could not be reached. NOT the same as no interactions."""


def new_token() -> str:
    return secrets.token_hex(8)


def is_enabled() -> bool:
    return bool(configured_domain())


def configured_domain() -> str:
    """The collaborator domain, or '' when OAST is off."""
    return os.environ.get("ERLIK_OAST_DOMAIN", "").strip().lower()


def configured_receiver() -> str:
    """Base URL of the interaction API, or '' when polling is unavailable."""
    return os.environ.get("ERLIK_OAST_RECEIVER", "").strip().rstrip("/")


def host_for(token: str) -> str:
    """The name to embed in a payload: `<token>.<domain>`.

    A per-probe subdomain rather than one shared host, because the point is
    correlation: with one host an interaction proves SOMETHING called out and
    not WHICH probe caused it, and a blind finding you cannot attribute to a
    payload is not evidence a client can act on.
    """
    domain = configured_domain()
    if not domain:
        raise CollaboratorError("no ERLIK_OAST_DOMAIN configured")
    if not TOKEN_RX.match(token or ""):
        raise ValueError(f"not a collaborator token: {token!r}")
    return f"{token}.{domain}"


def poll(token: str, timeout: float = 10.0) -> list[dict]:
    """Interactions recorded for `token`.

    Raises CollaboratorError when the receiver cannot be reached. Returning []
    there would report "no interaction" for a poll that never happened, which
    turns every blind case into a clean result the moment the receiver is down
    -- the exact failure this codebase treats as equal to a crash.
    """
    base = configured_receiver()
    if not base:
        raise CollaboratorError("no ERLIK_OAST_RECEIVER configured")
    url = f"{base}/interactions?token={urllib.parse.quote(token)}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            payload = json.loads(r.read().decode() or "{}")
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise CollaboratorError(f"receiver at {base} is unreachable: {e}") from e
    out = [i for i in (payload.get("interactions") or [])
           if isinstance(i, dict) and i.get("token") == token]
    return out


def describe(interactions: list[dict]) -> str:
    """One line per interaction, for a finding's evidence."""
    lines = []
    for i in interactions[:10]:
        lines.append(f"{i.get('protocol', '?')} from {i.get('remote_addr', '?')}"
                     f" at {i.get('at', '?')}"
                     + (f" — {i['detail']}" if i.get("detail") else ""))
    return "\n".join(lines)


def status() -> dict:
    """What OAST can and cannot do right now.

    Surfaced rather than inferred: an operator has to be able to tell "no blind
    findings" from "blind detection was never running".
    """
    domain, receiver = configured_domain(), configured_receiver()
    if not domain:
        return {"enabled": False,
                "reason": "ERLIK_OAST_DOMAIN is not set, so blind findings "
                          "cannot be proven and out-of-band steps do not run"}
    if not receiver:
        return {"enabled": False, "domain": domain,
                "reason": "ERLIK_OAST_DOMAIN is set but ERLIK_OAST_RECEIVER is "
                          "not, so payloads could be planted and never read back"}
    return {"enabled": True, "domain": domain, "receiver": receiver}
