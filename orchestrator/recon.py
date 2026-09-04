"""Domain recon: find the customer's attack surface, touch nothing unauthorised.

Given an engagement's declared root domain, this enumerates subdomains, resolves
them, and probes the ones it is allowed to probe. What it finds becomes either
an ASSET (when the customer already authorised it) or a PENDING SCOPE CANDIDATE
(when they did not), and the difference is the whole point of the module.

THE DISTINCTION THAT MATTERS
============================

Not every step here touches the customer, and the ones that do are gated
differently from the ones that do not:

  subfinder   PASSIVE. Queries third-party datasets — certificate transparency,
              public DNS archives. Never contacts the customer's infrastructure.
  dnsx        DNS resolution. Touches resolvers, not the host.
  httpx       ACTIVE. Opens a connection TO THE HOST. This is the line.
  katana      ACTIVE, and heavier — it crawls.

So enumeration runs against the declared root domain, and every ACTIVE step is
scope-checked per host. A name that passive enumeration returned is a claim by a
third party that something exists; it is not permission to connect to it.

WHY DISCOVERED HOSTS STAY INERT
===============================

Passive subdomain results routinely include shared hosting, CDN endpoints,
parked names and hosts belonging to entirely different companies that happen to
share infrastructure. `evaluate_scope` already refuses a discovered row until a
human approves it, so this module writes candidates and stops. Nothing here can
widen an engagement's boundary on its own.

A host DOES get probed without extra approval when a DECLARED rule already
covers it — if the customer authorised `acme.com` as a domain, `vpn.acme.com` is
inside what they signed. That is the customer's decision, not erlik's.
"""

from __future__ import annotations

import json
import re
import shlex
from typing import Any

from orchestrator import engagement as E
from orchestrator import assets as A

# Each tool, whether running it CONTACTS the target, and whether this module
# actually invokes it.
#
# `invoked` is not decoration. Only subfinder (enumerate_subdomains) and httpx
# (probe_hosts) reach execute_tool; dnsx and katana are declared here and never
# called. Without the flag the UI counted `active` and told the operator that
# DISCOVER SUBDOMAINS "runs 2 tool(s) that connect to the customer's hosts",
# which promised a katana crawl that never happens.
TOOLS: dict[str, dict[str, Any]] = {
    "subfinder": {"active": False, "invoked": True,
                  "what": "passive subdomain enumeration"},
    "dnsx":      {"active": False, "invoked": False,
                  "what": "DNS resolution"},
    "httpx":     {"active": True,  "invoked": True,
                  "what": "liveness probe — connects to the host"},
    "katana":    {"active": True,  "invoked": False,
                  "what": "crawl — connects to the host"},
}

# A dot is NOT required. Single-label names — `intranet`, `jira`, `vpn` — are
# ordinary targets on a client's internal network, and refusing them would make
# recon unusable on exactly the engagements where it matters most. Requiring a
# dot also bought nothing for safety: this regex is the SHELL-INJECTION gate,
# and it excludes every metacharacter either way. What may be CONTACTED is
# decided by scope, not by how many labels a name has.
_HOST_RX = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")


def valid_hostname(name: str) -> bool:
    """A hostname erlik is willing to act on.

    Tool output is untrusted: it comes from third-party datasets, and a name is
    rendered into a shell command downstream. Anything that is not a plain
    hostname is dropped rather than sanitised — there is no legitimate
    enumeration result that needs a quote in it.
    """
    n = (name or "").strip().lower().rstrip(".")
    return bool(n) and len(n) <= 253 and bool(_HOST_RX.match(n))


async def tool_available(tool: str) -> bool:
    """Is the tool present AND runnable?

    Asks the TOOL ITSELF for its version rather than running `which`. Two
    reasons, and the first is not theoretical: `which` is not in the toolset or
    in _SAFE_FILTERS, so erlik's own scope guard REFUSED the probe — every
    availability check returned False while all four binaries sat in the
    container, and recon would have reported "not installed" forever.

    Invoking the tool is also the stronger check: a binary present but not
    executable (wrong arch, truncated download) fails here rather than at the
    first real scan.
    """
    from orchestrator.tool_executor import check_container_running, execute_tool
    if tool not in TOOLS:
        return False
    if not await check_container_running():
        return False
    r = await execute_tool(f"{shlex.quote(tool)} -version", [tool],
                           tool_hint=tool, custom_timeout=30)
    if not r.get("executed"):
        print(f"[recon] availability probe for {tool!r} was REFUSED, not answered: "
              f"{(r.get('output') or '')[:120]}", flush=True)
        return False
    out = (r.get("output") or "").lower()
    return bool(re.search(r"\d+\.\d+\.\d+", out)) or tool in out


async def enumerate_passive(domain: str, timeout: int = 180,
                            engagement_rows=None) -> tuple[list[str], str]:
    """(hostnames, note). Passive only — contacts third parties, not the customer."""
    from orchestrator.tool_executor import execute_tool
    if not valid_hostname(domain):
        return [], f"{domain!r} is not a hostname"
    if not await tool_available("subfinder"):
        return [], "subfinder is not installed in the kali image"
    r = await execute_tool(
        f"subfinder -d {shlex.quote(domain)} -silent -all",
        ["subfinder"], tool_hint="subfinder", custom_timeout=timeout,
        engagement_rows=engagement_rows)
    if not r.get("success"):
        return [], f"subfinder failed: {(r.get('output') or '')[:160]}"
    found = {h for h in (l.strip().lower() for l in (r.get("output") or "").splitlines())
             if valid_hostname(h)}
    # A result that is not under the domain we asked about is a dataset
    # artefact, not this customer's asset.
    kept = sorted(h for h in found if E._is_subdomain_of(h, domain))
    dropped = len(found) - len(kept)
    note = f"{len(kept)} name(s)" + (f", {dropped} outside {domain} discarded" if dropped else "")
    return kept, note


async def probe_live(hosts: list[str], timeout: int = 180,
                     engagement_rows=None) -> dict[str, dict]:
    """httpx over hosts the CALLER has already scope-checked. ACTIVE.

    VERIFIED IN THIS CONTAINER (v1.10.0, arm64):
      * the binary runs and reports its version;
      * HTTP probing works — `-u http://192.168.107.4` returns `[302]`;
      * DNS for CONTAINER-INTERNAL names does NOT work. `-u http://dvwa`
        returns nothing even with the right nameserver passed via `-r` and an
        explicit /etc/hosts entry, because ProjectDiscovery's resolver layer
        does not consult /etc/hosts.

    So on a real engagement, where targets are public names in public DNS, this
    works. On the local docker lab, service names (juice-shop, dvwa) do not
    resolve for httpx and probing them returns {}. NOT verified: a public
    domain, because that would mean scanning a host nobody authorised.

    Also note httpx probes 80/443 by default, so juice-shop on :3000 returns
    nothing even by IP. That is correct behaviour, not a failure.
    """
    from orchestrator.tool_executor import execute_tool
    hosts = [h for h in hosts if valid_hostname(h)]
    if not hosts:
        return {}
    if not await tool_available("httpx"):
        return {}
    listed = " ".join(shlex.quote(h) for h in hosts[:200])
    r = await execute_tool(
        f"printf '%s\\n' {listed} | httpx -silent -json -title -tech-detect -status-code",
        ["httpx"], tool_hint="httpx", custom_timeout=timeout,
        engagement_rows=engagement_rows)
    out: dict[str, dict] = {}
    for line in (r.get("output") or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        host = (d.get("host") or d.get("input") or "").strip().lower()
        if valid_hostname(host):
            out[host] = {"url": d.get("url"), "status": d.get("status_code"),
                         "title": d.get("title"), "tech": d.get("tech") or []}
    return out


async def run(db, engagement_id: str, *, probe: bool = True) -> dict[str, Any]:
    """Enumerate an engagement's root domain and record what was found.

    Returns a report naming, for every host: whether it is already authorised,
    and whether it was probed. Nothing is probed that scope does not allow, and
    nothing becomes authorised as a side effect of being found.
    """
    row = await (await db.execute(
        "SELECT root_domain FROM engagements WHERE id = ?", (engagement_id,))).fetchone()
    if not row:
        return {"error": "engagement not found"}
    domain = (row[0] or "").strip().lower()
    if not domain:
        return {"error": "engagement has no root domain to enumerate"}

    # These calls pass NO target_url, so the executor's session-target
    # heuristic returned "no opinion" and enumeration ran with no scope check
    # at all. The engagement's own rules are the check that belongs here.
    _rows = await E.scope_rows(db, engagement_id)
    hosts, note = await enumerate_passive(domain, engagement_rows=_rows)
    report: dict[str, Any] = {
        "domain": domain, "enumerated": len(hosts), "note": note,
        "authorised": [], "pending": [], "probed": [], "assets_created": 0,
    }
    if not hosts:
        return report

    rows = _rows
    allowed_hosts = []
    for h in hosts:
        ok, why = E.evaluate_scope(rows, f"http://{h}")
        if ok:
            report["authorised"].append(h)
            allowed_hosts.append(h)
        else:
            # Recorded as a CANDIDATE, unapproved. It authorises nothing, and
            # is never probed on this pass.
            await E.add_scope(db, engagement_id, h, kind="host", source="discovered")
            report["pending"].append({"host": h, "why": why})
    await db.commit()

    if probe and allowed_hosts:
        live = await probe_live(allowed_hosts, engagement_rows=rows)
        for host, info in live.items():
            url = info.get("url") or f"http://{host}"
            aid, _ = await A.path_for_url(db, engagement_id, url, source="recon")
            if aid:
                report["assets_created"] += 1
            for tech in (info.get("tech") or [])[:12]:
                await A.record_observation(db, engagement_id, url, "technology",
                                           str(tech)[:120], source="recon")
            report["probed"].append(
                {"host": host, "status": info.get("status"), "title": info.get("title"),
                 "tech": info.get("tech") or []})
        await db.commit()

    return report
