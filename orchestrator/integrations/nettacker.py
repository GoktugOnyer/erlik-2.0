"""Deterministic pre-scan via OWASP Nettacker (https://github.com/OWASP/Nettacker).

Nettacker (Apache-2.0) is an automated recon / vuln-scanning framework. erlik
*invokes* it as an external scanner (it is NOT vendored) to produce deterministic,
non-AI data — open ports, services, detected tech, exposed paths, header/TLS/CVE
hits — which is then injected into the agent loop as a starting point so the LLM
does less blind exploration. The same data can be emitted as deterministic
findings (opt-in) or consumed by any other pipeline via the CLI below.

Gated by ``ERLIK_NETTACKER`` (default off). Nothing here runs — and the import is
free — unless explicitly enabled. The runner never raises into the agent loop;
failures degrade to an empty result.

Config (env):
  ERLIK_NETTACKER            "1"/"true" to enable injection in the agent loop
  ERLIK_NETTACKER_CMD        launch prefix (default "nettacker"); e.g.
                             "python -m nettacker.main", or a docker wrapper
  ERLIK_NETTACKER_SCENARIO   named run mode (see SCENARIOS); default "recon"
  ERLIK_NETTACKER_PROFILE    raw Nettacker --profile X (overrides SCENARIO)
  ERLIK_NETTACKER_MODULES    raw -m module list (overrides SCENARIO; advanced)
  ERLIK_NETTACKER_OUTDIR     dir for the JSON output file (default: temp)
  ERLIK_NETTACKER_TIMEOUT    seconds before the scan is killed (default 300)
  ERLIK_NETTACKER_FINDINGS   "1" to also persist deterministic findings

Selection precedence: PROFILE > MODULES > SCENARIO > default("recon").
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse

# Named run modes ("scenarios"), each mapping to a stable Nettacker --profile
# (profile names are version-stable; raw module names carry a category suffix and
# drift between releases). Pick one with ERLIK_NETTACKER_SCENARIO, or override
# entirely with ERLIK_NETTACKER_PROFILE / ERLIK_NETTACKER_MODULES.
SCENARIOS: dict[str, dict] = {
    "recon":     {"profile": "scan",             "desc": "Ports, dirs, tech, subdomains, versions, WAF — fast & safe. DEFAULT."},
    "info":      {"profile": "scan,info",        "desc": "Recon plus information gathering."},
    "web":       {"profile": "http",             "desc": "All HTTP/HTTPS checks (broad, heavier)."},
    "tls":       {"profile": "ssl",              "desc": "TLS/SSL certificate, cipher and version checks."},
    "cves":      {"profile": "cve",              "desc": "All CVE vulnerability checks (~61 modules)."},
    "kev":       {"profile": "cisa_kev",         "desc": "CISA Known-Exploited-Vulnerabilities subset."},
    "critical":  {"profile": "critical_severity","desc": "Only critical-severity modules."},
    "wordpress": {"profile": "wordpress",        "desc": "WordPress core / plugin / theme checks."},
    "brute":     {"profile": "brute",            "desc": "Credential brute-force — needs -u/-p; CAN LOCK ACCOUNTS."},
    "full":      {"profile": "all",              "desc": "Every module — slow and noisy."},
}
DEFAULT_SCENARIO = "recon"


def list_scenarios() -> dict[str, str]:
    """Friendly run modes → one-line description (for UIs / the CLI)."""
    return {k: v["desc"] for k, v in SCENARIOS.items()}


def nettacker_enabled() -> bool:
    return os.environ.get("ERLIK_NETTACKER", "").strip().lower() in ("1", "true", "yes", "on")


def findings_enabled() -> bool:
    return os.environ.get("ERLIK_NETTACKER_FINDINGS", "").strip().lower() in ("1", "true", "yes", "on")


def _target_arg(target_url: str) -> str:
    """Nettacker's -i accepts a host, IP, or URL. Prefer the bare host."""
    p = urlparse(target_url if "://" in (target_url or "") else f"//{target_url}")
    return p.hostname or (target_url or "").strip()


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #

def _build_command(target_url: str, outfile: str) -> list[str]:
    base = shlex.split(os.environ.get("ERLIK_NETTACKER_CMD", "nettacker"))
    cmd = base + ["-i", _target_arg(target_url)]
    profile = os.environ.get("ERLIK_NETTACKER_PROFILE", "").strip()
    modules = os.environ.get("ERLIK_NETTACKER_MODULES", "").strip()
    if profile:                                   # explicit profile wins
        cmd += ["--profile", profile]
    elif modules:                                 # explicit module list
        cmd += ["-m", modules]
    else:                                         # named scenario (default recon)
        scen = os.environ.get("ERLIK_NETTACKER_SCENARIO", "").strip().lower() or DEFAULT_SCENARIO
        sc = SCENARIOS.get(scen, SCENARIOS[DEFAULT_SCENARIO])
        if sc.get("profile"):
            cmd += ["--profile", sc["profile"]]
        else:
            cmd += ["-m", sc["modules"]]
    cmd += ["-o", outfile]
    return cmd


def _run_sync(target_url: str) -> dict:
    outdir = os.environ.get("ERLIK_NETTACKER_OUTDIR") or tempfile.mkdtemp(prefix="erlik_nettacker_")
    Path(outdir).mkdir(parents=True, exist_ok=True)
    outfile = str(Path(outdir) / "nettacker_scan.json")
    try:
        timeout = int(os.environ.get("ERLIK_NETTACKER_TIMEOUT", "300"))
    except ValueError:
        timeout = 300
    cmd = _build_command(target_url, outfile)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return {"error": f"nettacker not found (cmd={cmd[0]!r}); install it or set "
                         f"ERLIK_NETTACKER_CMD", "events": []}
    except subprocess.TimeoutExpired:
        return {"error": f"nettacker timed out after {timeout}s", "events": []}
    except Exception as e:  # noqa: BLE001
        return {"error": f"nettacker failed: {e}", "events": []}

    # Nettacker writes a JSON array to the -o file. Read it back.
    try:
        raw = Path(outfile).read_text(encoding="utf-8", errors="replace").strip()
        events = json.loads(raw) if raw else []
        if not isinstance(events, list):
            events = []
    except FileNotFoundError:
        return {"error": "nettacker produced no output file",
                "events": [], "stderr": (proc.stderr or "")[-500:]}
    except json.JSONDecodeError as e:
        return {"error": f"could not parse nettacker JSON: {e}", "events": []}
    return {"error": None, "events": events, "returncode": proc.returncode}


async def run_nettacker(target_url: str) -> dict:
    """Run a Nettacker scan and return {error, events:[...]}. Never raises."""
    try:
        return await asyncio.get_event_loop().run_in_executor(None, _run_sync, target_url)
    except Exception as e:  # noqa: BLE001
        return {"error": f"nettacker runner error: {e}", "events": []}


# --------------------------------------------------------------------------- #
# Parsing / classification (defensive — module event shapes vary)
# --------------------------------------------------------------------------- #

def _norm_module(name: str) -> str:
    # Nettacker reports e.g. "port_scan_scan" / "ssh_brute_brute"; trim the
    # trailing category suffix so checks read on the logical module name.
    for suffix in ("_scan", "_brute", "_vuln"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _flatten(ev: dict) -> dict:
    """Merge event + json_event into one detail dict for opportunistic reads."""
    out = {}
    for key in ("event", "json_event"):
        v = ev.get(key)
        if isinstance(v, dict):
            out.update(v)
        elif isinstance(v, str) and v:
            out.setdefault("_text", v)
    return out


# module → (vuln_type, severity). Recon-only modules map to None (no finding).
_FINDING_RULES = [
    ("subdomain_takeover", ("Subdomain Takeover", "high")),
    ("http_cors", ("CORS Misconfiguration", "medium")),
    ("config_file", ("Exposed Configuration File", "medium")),
    ("clickjacking", ("Missing Anti-Clickjacking Header", "low")),
    ("content_security_policy", ("Missing/Weak Content-Security-Policy", "low")),
    ("strict_transport_security", ("Missing HSTS", "low")),
    ("x_xss_protection", ("Missing X-XSS-Protection", "low")),
    ("x_powered_by", ("Information Disclosure (X-Powered-By)", "low")),
    ("server_version", ("Information Disclosure (Server banner)", "low")),
]


def _classify(module: str, flat: dict) -> tuple[str, str] | None:
    """Return (vuln_type, severity) for a finding-worthy event, else None."""
    m = _norm_module(module)
    if m.endswith("_brute") or "brute" in module:
        # only a successful auth is a finding
        status = str(flat.get("status", flat.get("authenticated", ""))).lower()
        if "success" in status or status == "true" or flat.get("password"):
            return ("Weak/Default Credentials", "critical")
        return None
    if "cve" in m or "log4j" in m or "proxylogon" in m:
        sev = "critical" if ("rce" in m or "log4j" in m or "44228" in m) else "high"
        return (f"Known CVE: {m}", sev)
    if m.startswith("ssl") or "tls" in m or "certificate" in m or "cipher" in m:
        return ("Weak TLS/SSL Configuration", "medium")
    for needle, vt_sev in _FINDING_RULES:
        if needle in m:
            return vt_sev
    return None


def parse_events(events: list[dict], target_url: str = "") -> dict:
    """Group raw Nettacker events into recon buckets + deterministic findings."""
    open_ports: list[dict] = []
    tech: list[str] = []
    paths: list[str] = []
    findings: list[dict] = []
    seen_port = set()
    seen_tech = set()
    seen_path = set()
    seen_find = set()

    for ev in events:
        if not isinstance(ev, dict):
            continue
        module = str(ev.get("module_name", ""))
        m = _norm_module(module)
        target = ev.get("target", target_url)
        flat = _flatten(ev)
        port_obj = ev.get("port") if isinstance(ev.get("port"), dict) else {}
        port = port_obj.get("port") or flat.get("port")
        proto = port_obj.get("protocol") or flat.get("protocol") or "tcp"

        # Open ports / services
        if "port_scan" in module:
            key = (target, port, proto)
            if port and key not in seen_port:
                seen_port.add(key)
                svc = flat.get("service") or flat.get("status") or ""
                open_ports.append({"target": target, "port": port,
                                   "protocol": proto, "service": svc})
            continue

        # Tech / version fingerprints
        if m.endswith("_version") or "html_title" in m or "http_status" in m:
            detail = (flat.get("version") or flat.get("title")
                      or flat.get("status") or flat.get("banner") or "")
            label = f"{m.replace('_version','')}: {detail}".strip().strip(":")
            if detail and label not in seen_tech:
                seen_tech.add(label)
                tech.append(label)
            continue

        # Discovered paths / dirs
        if "dir_scan" in module or m == "config_file":
            loc = (flat.get("url") or flat.get("path") or flat.get("_text") or "")
            if loc and loc not in seen_path:
                seen_path.add(loc)
                paths.append(loc)
            # config_file is also a finding (below) — fall through.

        # Deterministic findings
        cls = _classify(module, flat)
        if cls:
            vuln_type, severity = cls
            url = (flat.get("url") or target_url
                   or (f"{target}:{port}" if port else str(target)))
            ev_detail = json.dumps({k: v for k, v in flat.items() if k != "_text"},
                                   default=str)[:600] or flat.get("_text", "")
            fkey = (vuln_type, str(url))
            if fkey not in seen_find:
                seen_find.add(fkey)
                findings.append({
                    "vuln_type": vuln_type,
                    "severity": severity,
                    "url": str(url),
                    "parameter": str(port or ""),
                    "evidence": f"OWASP Nettacker [{module}]: {ev_detail}"[:1800],
                })

    return {"open_ports": open_ports, "tech": tech, "paths": paths, "findings": findings}


def summarize_for_agent(parsed: dict, max_items: int = 20) -> str:
    """Compact deterministic recon block for the agent's system prompt."""
    op, tech, paths, finds = (parsed.get("open_ports", []), parsed.get("tech", []),
                              parsed.get("paths", []), parsed.get("findings", []))
    if not any((op, tech, paths, finds)):
        return ""
    lines = [
        "═══════════════════════════════════════════════════════════════",
        "DETERMINISTIC PRE-SCAN (OWASP Nettacker) — verified facts, not guesses",
        "═══════════════════════════════════════════════════════════════",
        "A non-AI scanner already gathered the data below. START from it — do "
        "NOT re-discover these. Focus your testing on confirming/exploiting and "
        "on areas the scan did not cover.",
    ]
    if op:
        lines.append("\nOPEN PORTS / SERVICES:")
        for p in op[:max_items]:
            lines.append(f"  - {p['target']}:{p['port']}/{p['protocol']} {p.get('service','')}".rstrip())
    if tech:
        lines.append("\nDETECTED TECH / VERSIONS:")
        for t in tech[:max_items]:
            lines.append(f"  - {t}")
    if paths:
        lines.append("\nDISCOVERED PATHS:")
        for p in paths[:max_items]:
            lines.append(f"  - {p}")
    if finds:
        lines.append("\nDETERMINISTIC FINDINGS (already confirmed by the scanner):")
        for f in finds[:max_items]:
            lines.append(f"  - [{f['severity'].upper()}] {f['vuln_type']} @ {f['url']}")
    return "\n".join(lines) + "\n"


def _cli(argv: list[str] | None = None) -> int:
    """Standalone: run a scan and print the recon summary (or --json events).

        python -m orchestrator.integrations.nettacker http://target [--json]
    """
    import argparse

    ap = argparse.ArgumentParser(
        prog="orchestrator.integrations.nettacker",
        description="Run an OWASP Nettacker pre-scan and print deterministic recon "
                    "data (usable by erlik or any other pipeline/model).",
    )
    ap.add_argument("target", nargs="?", help="target host or URL")
    ap.add_argument("--scenario", help="run mode (see --scenarios), default 'recon'")
    ap.add_argument("--scenarios", action="store_true", help="list available scenarios and exit")
    ap.add_argument("--json", action="store_true", help="print raw parsed buckets as JSON")
    ns = ap.parse_args(argv)

    if ns.scenarios:
        print("Nettacker scenarios (ERLIK_NETTACKER_SCENARIO):")
        for name, desc in list_scenarios().items():
            mark = "  (default)" if name == DEFAULT_SCENARIO else ""
            print(f"  {name:10} {desc}{mark}")
        return 0
    if not ns.target:
        ap.error("target is required (or use --scenarios)")
    if ns.scenario:
        os.environ["ERLIK_NETTACKER_SCENARIO"] = ns.scenario

    res = asyncio.run(run_nettacker(ns.target))
    if res.get("error"):
        print(f"error: {res['error']}")
        return 1
    parsed = parse_events(res["events"], target_url=ns.target)
    if ns.json:
        print(json.dumps(parsed, indent=2, default=str))
    else:
        out = summarize_for_agent(parsed)
        print(out or "(nettacker returned no usable events)")
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
