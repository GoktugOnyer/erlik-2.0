"""A payload host a case names must be one the scope guard permits.

Several cases send a canary hostname the target is expected to contact or
reflect: an open-redirect destination, a CORS Origin, an SSRF callback. The
scope guard refuses a command NAMING an unrelated public host, so such a
hostname has to come from `_OAST_DOMAINS` or the case cannot run at all.

WSTG-CLNT-07 used `evil.oast.test`, which is not in that tuple. Its own comment
said "An OAST-marked origin so scope enforcement permits the payload host" --
the intent was right and the domain was not. Every CORS test was refused before
it ran:

    SCOPE: out-of-scope host 'evil.oast.test' (target '127.0.0.1')

and the operator saw a failed step, never a verdict. WSTG-CLNT-04 named
`erlik-redir.oast.test` and escaped only because its canary sits in a query
value rather than a header, where the guard does not read it as a destination
-- the same latent defect, working by position.

This test binds the catalogue to the allowlist so neither can drift back.
"""

import pathlib
import re

import pytest

from orchestrator.tool_executor import _OAST_DOMAINS

WSTG = pathlib.Path(__file__).resolve().parents[1] / "tests_catalog" / "wstg"

# Hostnames in a payload position look like OAST callbacks. Matching on the
# shape rather than a fixed list means a NEW canary domain is caught too.
_CANARY = re.compile(r"\b([a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.(?:oast|interact|"
                     r"burpcollaborator|oastify|canarytokens)\.[a-z]+)\b", re.I)


def _canaries():
    """{case file: {hostname, ...}} for every OAST-shaped host in the catalogue.

    Comment lines are skipped: a comment explaining a domain that was REMOVED
    must not count as the catalogue still naming it.
    """
    out = {}
    for p in sorted(WSTG.glob("*.yaml")):
        body = "\n".join(l for l in p.read_text().splitlines()
                         if not l.lstrip().startswith("#"))
        hosts = {m.group(1).lower() for m in _CANARY.finditer(body)}
        if hosts:
            out[p.name] = hosts
    return out


def test_the_scan_finds_something():
    """Guard on the guard: if the regex stops matching, every assertion below
    passes against a catalogue full of unusable domains."""
    found = _canaries()
    assert found, "no canary hostnames found -- the pattern or catalogue changed"


@pytest.mark.parametrize("case,hosts", sorted(_canaries().items()))
def test_every_canary_host_is_one_the_scope_guard_permits(case, hosts):
    for h in hosts:
        assert any(h == d or h.endswith("." + d) for d in _OAST_DOMAINS), (
            f"{case} names {h!r}, which is not under any domain in "
            f"_OAST_DOMAINS {_OAST_DOMAINS}. The scope guard will refuse the "
            f"command and the case cannot run."
        )


def test_the_allowlist_is_not_empty():
    assert _OAST_DOMAINS, "an empty allowlist would make the check vacuous"
