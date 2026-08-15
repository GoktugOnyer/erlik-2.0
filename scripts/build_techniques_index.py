#!/usr/bin/env python3
"""Generate techniques_catalog/index.yaml from a local HackTricks clone.

WHY AN INDEX AND NOT A VENDORED CORPUS
--------------------------------------
skills_catalog/ could be vendored verbatim because its upstream is MIT.
HackTricks is CC BY-NC 4.0 — NonCommercial — and erlik is MIT. Copying that
text into this repository would publish NC-restricted material under an MIT
grant, contradicting our own LICENSE and binding downstream users to terms we
did not choose.

So this script commits only FACTS about each technique: which environment it
belongs to, which TCP/UDP ports it concerns, its title, routing tags, and a
citation URL. Facts and citations are not the licensed expression. The prose
itself is never copied — it is read at run time from the reader's own clone,
located via ERLIK_HACKTRICKS_PATH (see orchestrator/techniques.py).

Usage:
    python scripts/build_techniques_index.py [--hacktricks PATH] [--out PATH]

Re-running is idempotent for a given upstream commit; the index records that
commit so a result can be tied to an exact corpus revision.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

SITE = "https://book.hacktricks.wiki/en"

# Top-level HackTricks directory -> the environment erlik routes on. Anything
# not listed is skipped: banners/images/todo carry no technique content.
ENVIRONMENTS = {
    "network-services-pentesting": "service",
    "pentesting-web": "web",
    "windows-hardening": "windows",
    "linux-hardening": "linux",
    "macos-hardening": "macos",
    "mobile-pentesting": "mobile",
    "binary-exploitation": "binary",
    "AI": "ai",
    "blockchain": "blockchain",
    "crypto": "crypto",
    "reversing": "reversing",
    "stego": "stego",
    "hardware-physical-access": "hardware",
    "generic-methodologies-and-resources": "generic",
    "generic-hacking": "generic",
}

SKIP_DIRS = {"banners", "images", "todo", "welcome", "files"}
SKIP_NAMES = {"README.md", "SUMMARY.md", "LICENSE.md"}

# Leading port group in a service filename: "27017-27018-mongodb.md",
# "5671-5672-pentesting-amqp.md", "3702-udp-pentesting-ws-discovery.md".
_PORT_RX = re.compile(r"^(\d{1,5}(?:[-,]\d{1,5})*)\b")
# Trailing/embedded port: "pentesting-kerberos-88.md".
_PORT_ANY_RX = re.compile(r"(?:^|[-_])(\d{2,5})(?:[-_]|$)")

# IANA defaults for services HackTricks names without a number in the path
# ("pentesting-ftp", "pentesting-smb"). These are the most commonly exposed
# services, so without this the port routing misses precisely the cases a
# pre-scan is most likely to turn up.
_WELL_KNOWN = {
    "ftp": [21], "ssh": [22], "telnet": [23], "smtp": [25], "whois": [43],
    "dns": [53], "tftp": [69], "finger": [79], "kerberos": [88], "pop3": [110],
    "rpcbind": [111], "ident": [113], "ntp": [123], "netbios": [137, 138, 139],
    "imap": [143], "snmp": [161, 162], "ldap": [389], "smb": [445],
    "rexec": [512], "rlogin": [513], "rsh": [514], "syslog": [514],
    "lpd": [515], "afp": [548], "rtsp": [554], "ipp": [631], "ldaps": [636],
    "mssql": [1433], "oracle": [1521], "nfs": [2049], "mysql": [3306],
    "rdp": [3389], "sip": [5060], "voip": [5060], "postgresql": [5432],
    "amqp": [5672], "vnc": [5900], "couchdb": [5984], "redis": [6379],
    "elasticsearch": [9200], "memcache": [11211], "mongodb": [27017],
    "web": [80, 443], "http": [80], "https": [443],
    "cassandra": [9042], "irc": [6667], "modbus": [502], "pop": [110],
    "ipsec": [500], "ike": [500], "jdwp": [8000], "gdbserver": [2345],
}

# Words that carry no routing signal.
_STOP = {
    "pentesting", "udp", "tcp", "and", "the", "for", "with", "to", "of", "a",
    "an", "in", "on", "from", "md", "hacking", "attacks", "attack", "abusing",
    "basic", "information", "index",
}


def _git_rev(root: Path) -> str:
    try:
        out = subprocess.run(["git", "-C", str(root), "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, timeout=15)
        return out.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def _slug_title(path: Path) -> str:
    return path.stem.replace("-", " ").replace("_", " ").strip()[:160]


def _title(path: Path) -> str:
    """First H1, cleaned — a short factual heading, never a sentence.

    A few upstream pages open with a prose line that parses as an H1. Copying one
    into the committed index would put authored expression in a file that is
    supposed to hold facts only, so anything sentence-length falls back to the
    filename. Real headings here run to about a dozen words (port lists, tool
    names, exploit chains); 14 separates them cleanly.
    """
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for _ in range(60):
                line = fh.readline()
                if not line:
                    break
                if line.startswith("# "):
                    t = re.sub(r"\{\{#.*?\}\}", "", line[2:].strip()).strip()
                    if not t:
                        continue
                    if len(t.split()) > 14:
                        return _slug_title(path)
                    return t[:160]
    except Exception:
        pass
    return _slug_title(path)


def _ports(rel: Path) -> list[int]:
    """Ports a service page concerns, by three strategies in confidence order.

    Tried against the file stem and then every ancestor directory, nearest first,
    because a page may live as "27017-27018-mongodb.md", inside "11211-memcache/",
    or nested deeper ("pentesting-web/drupal/drupal-rce.md" -> the web ports).
    """
    def _clean(nums) -> list[int]:
        out: list[int] = []
        for n in nums:
            n = int(n)
            if 0 < n <= 65535 and n not in out:
                out.append(n)
        return out

    candidates = [rel.stem] + [p.name for p in rel.parents if p.name]
    for name in candidates:
        if not name:
            continue
        # 1. leading group — the dominant convention
        m = _PORT_RX.match(name)
        if m:
            got = _clean(c for c in re.split(r"[-,]", m.group(1)) if c.isdigit())
            if got:
                return got
        # 2. a number anywhere in the slug ("pentesting-kerberos-88")
        got = _clean(_PORT_ANY_RX.findall(name))
        if got:
            return got
        # 3. a known service name with no number at all ("pentesting-smb")
        for token in re.split(r"[^a-z0-9]+", name.lower()):
            if token in _WELL_KNOWN:
                return list(_WELL_KNOWN[token])
    return []


def _protocol(name: str) -> str:
    return "udp" if re.search(r"\budp\b", name, re.IGNORECASE) else "tcp"


def _tags(rel: Path, title: str) -> list[str]:
    """Routing tokens from the path and title — how the router matches a hint."""
    raw = f"{rel.parent.name} {rel.stem} {title}".lower()
    toks: list[str] = []
    for t in re.split(r"[^a-z0-9+]+", raw):
        if len(t) < 2 or t.isdigit() or t in _STOP or t in toks:
            continue
        toks.append(t)
    return toks[:14]


def _source_url(rel: Path) -> str:
    return f"{SITE}/{rel.as_posix()[:-3] if rel.suffix == '.md' else rel.as_posix()}"


def _yaml_str(s: str) -> str:
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'


def build(hacktricks: Path) -> tuple[list[dict], str]:
    src = hacktricks / "src"
    if not src.is_dir():
        raise SystemExit(f"not a HackTricks clone (no src/): {hacktricks}")

    entries: list[dict] = []
    seen_ids: set[str] = set()

    for path in sorted(src.rglob("*.md")):
        rel = path.relative_to(src)
        if rel.name in SKIP_NAMES or rel.parts[0] in SKIP_DIRS:
            continue
        env = ENVIRONMENTS.get(rel.parts[0])
        if env is None:
            continue

        title = _title(path)
        ports = _ports(rel) if env == "service" else []
        tid = "ht-" + re.sub(r"[^a-z0-9]+", "-", rel.as_posix()[:-3].lower()).strip("-")
        if tid in seen_ids:
            continue
        seen_ids.add(tid)

        entries.append({
            "id": tid,
            "env": env,
            "title": title,
            "path": rel.as_posix(),
            "ports": ports,
            "protocol": _protocol(rel.name) if ports else "",
            "tags": _tags(rel, title),
            "source": _source_url(rel),
        })

    return entries, _git_rev(hacktricks)


def render(entries: list[dict], revision: str) -> str:
    by_env: dict[str, int] = {}
    for e in entries:
        by_env[e["env"]] = by_env.get(e["env"], 0) + 1

    L = [
        "# Technique index derived from HackTricks (CC BY-NC 4.0).",
        "#",
        "# GENERATED — do not edit by hand. Regenerate with:",
        "#     python scripts/build_techniques_index.py --hacktricks <clone>",
        "#",
        "# This file deliberately contains NO HackTricks prose. Only facts about",
        "# each technique — environment, ports, title, routing tags and a citation",
        "# URL — because HackTricks is NonCommercial and erlik is MIT. The text is",
        "# read at run time from the reader's own clone (ERLIK_HACKTRICKS_PATH).",
        "#",
        "# HackTricks by Carlos Polop — https://github.com/carlospolop/hacktricks",
        "# Licensed CC BY-NC 4.0: https://creativecommons.org/licenses/by-nc/4.0/",
        f"upstream_revision: {_yaml_str(revision)}",
        f"count: {len(entries)}",
        "counts_by_env:",
    ]
    for env in sorted(by_env):
        L.append(f"  {env}: {by_env[env]}")
    L.append("techniques:")
    for e in entries:
        L.append(f"  - id: {_yaml_str(e['id'])}")
        L.append(f"    env: {_yaml_str(e['env'])}")
        L.append(f"    title: {_yaml_str(e['title'])}")
        L.append(f"    path: {_yaml_str(e['path'])}")
        if e["ports"]:
            L.append(f"    ports: [{', '.join(str(p) for p in e['ports'])}]")
            L.append(f"    protocol: {_yaml_str(e['protocol'])}")
        L.append(f"    tags: [{', '.join(_yaml_str(t) for t in e['tags'])}]")
        L.append(f"    source: {_yaml_str(e['source'])}")
    return "\n".join(L) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hacktricks", default=os.environ.get("ERLIK_HACKTRICKS_PATH", ""),
                    help="path to a HackTricks clone (or set ERLIK_HACKTRICKS_PATH)")
    ap.add_argument("--out", default="techniques_catalog/index.yaml")
    ns = ap.parse_args(argv)

    if not ns.hacktricks:
        print("error: pass --hacktricks PATH or set ERLIK_HACKTRICKS_PATH", file=sys.stderr)
        return 2

    entries, rev = build(Path(ns.hacktricks).expanduser().resolve())
    out = Path(ns.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(entries, rev), encoding="utf-8")

    by_env: dict[str, int] = {}
    for e in entries:
        by_env[e["env"]] = by_env.get(e["env"], 0) + 1
    print(f"[+] {len(entries)} techniques -> {out}  (upstream {rev})")
    for env in sorted(by_env, key=lambda k: -by_env[k]):
        print(f"      {by_env[env]:>4}  {env}")
    ported = sum(1 for e in entries if e["ports"])
    print(f"[+] {ported} port-keyed (routable straight off a Nettacker pre-scan)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
