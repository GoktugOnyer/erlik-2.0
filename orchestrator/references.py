"""Deterministic reference and ATT&CK derivation for findings.

Both the `mitre` and `ref_links` columns existed on the findings table, were
declared on the model, and were read by the report builder — but nothing ever
wrote them. `mitre` was passed a hardcoded None by the only UPDATE that touched
it, and `ref_links` had no writer at all, so ReportFinding.references was always
empty and the HTML report's References section never rendered.

These are derived here rather than asked of the model on purpose. Every value is
CONSTRUCTED from data already on the row (CWE, CVE, OWASP category, vuln type),
so a link is correct by construction and can be checked by eye. A language model
asked for "references" will happily emit plausible, dead advisory URLs, and a
fabricated citation in a client-ready security report is worse than no citation.

Pure functions — no I/O, no DB. Persistence lives in main.py.
"""

from __future__ import annotations

import re

# OWASP Top 10:2021 — the category string the report LLM is asked to emit
# ("A03:2021 - Injection") carries the rank, which is all we need to build the URL.
_OWASP_2021 = {
    "A01": "A01_2021-Broken_Access_Control",
    "A02": "A02_2021-Cryptographic_Failures",
    "A03": "A03_2021-Injection",
    "A04": "A04_2021-Insecure_Design",
    "A05": "A05_2021-Security_Misconfiguration",
    "A06": "A06_2021-Vulnerable_and_Outdated_Components",
    "A07": "A07_2021-Identification_and_Authentication_Failures",
    "A08": "A08_2021-Software_and_Data_Integrity_Failures",
    "A09": "A09_2021-Security_Logging_and_Monitoring_Failures",
    "A10": "A10_2021-Server-Side_Request_Forgery_%28SSRF%29",
}

# MITRE ATT&CK (Enterprise) techniques. Deliberately conservative: a class is
# mapped only where the technique is a defensible fit, and anything unrecognised
# returns None rather than being forced into a bucket. T1190 recurs because
# "Exploit Public-Facing Application" genuinely is the initial-access technique
# for most server-side web vulnerabilities.
_ATTACK = [
    # (substring matched against a lowercased vuln_type, technique)
    ("sql injection",            "T1190 — Exploit Public-Facing Application"),
    ("sqli",                     "T1190 — Exploit Public-Facing Application"),
    ("command injection",        "T1059 — Command and Scripting Interpreter"),
    ("remote code execution",    "T1059 — Command and Scripting Interpreter"),
    ("rce",                      "T1059 — Command and Scripting Interpreter"),
    ("cross-site scripting",     "T1059.007 — Command and Scripting Interpreter: JavaScript"),
    ("xss",                      "T1059.007 — Command and Scripting Interpreter: JavaScript"),
    ("server-side request",      "T1190 — Exploit Public-Facing Application"),
    ("ssrf",                     "T1190 — Exploit Public-Facing Application"),
    ("xml external entity",      "T1190 — Exploit Public-Facing Application"),
    ("xxe",                      "T1190 — Exploit Public-Facing Application"),
    ("deserializ",               "T1190 — Exploit Public-Facing Application"),
    ("file upload",              "T1505.003 — Server Software Component: Web Shell"),
    ("web shell",                "T1505.003 — Server Software Component: Web Shell"),
    ("brute force",              "T1110 — Brute Force"),
    ("weak password",            "T1110 — Brute Force"),
    ("default credential",       "T1078 — Valid Accounts"),
    ("json web token",           "T1550.001 — Use Alternate Authentication Material: "
                                 "Application Access Token"),
    ("jwt",                      "T1550.001 — Use Alternate Authentication Material: "
                                 "Application Access Token"),
    ("session",                  "T1539 — Steal Web Session Cookie"),
    ("broken authentication",    "T1078 — Valid Accounts"),
    ("authentication bypass",    "T1078 — Valid Accounts"),
    ("broken access control",    "T1190 — Exploit Public-Facing Application"),
    ("insecure direct object",   "T1190 — Exploit Public-Facing Application"),
    ("idor",                     "T1190 — Exploit Public-Facing Application"),
    ("privilege escalation",     "T1068 — Exploitation for Privilege Escalation"),
    ("sensitive data",           "T1213 — Data from Information Repositories"),
    ("information disclosure",   "T1213 — Data from Information Repositories"),
    ("open redirect",            "T1204.001 — User Execution: Malicious Link"),
    ("security misconfiguration", "T1190 — Exploit Public-Facing Application"),
]


def cwe_url(cwe: str | None) -> str | None:
    """https://cwe.mitre.org/... for a 'CWE-89' / '89' style identifier."""
    if not cwe:
        return None
    m = re.search(r"(\d+)", str(cwe))
    return f"https://cwe.mitre.org/data/definitions/{m.group(1)}.html" if m else None


def cve_url(cve_id: str | None) -> str | None:
    """NVD detail page for a well-formed CVE id.

    Same form as NVD_WEB_URL in orchestrator/enrichment/nvd.py; kept as a literal
    so this module stays free of the HTTP-capable enrichment import. (NVD answers
    scripted HEAD requests with 403 bot protection — the page itself is fine.)
    """
    if not cve_id:
        return None
    m = re.search(r"(CVE-\d{4}-\d{4,})", str(cve_id), re.IGNORECASE)
    return f"https://nvd.nist.gov/vuln/detail/{m.group(1).upper()}" if m else None


def owasp_url(owasp_category: str | None) -> str | None:
    """OWASP Top 10:2021 page for an 'A03:2021 - Injection' style category."""
    if not owasp_category:
        return None
    m = re.search(r"\bA(\d{2})\b", str(owasp_category))
    if not m:
        return None
    slug = _OWASP_2021.get(f"A{m.group(1)}")
    return f"https://owasp.org/Top10/{slug}/" if slug else None


def build_ref_links(cwe: str | None = None, cve_id: str | None = None,
                    owasp_category: str | None = None) -> list[str]:
    """Every reference URL derivable from a finding, deduped and ordered."""
    out: list[str] = []
    for url in (cwe_url(cwe), cve_url(cve_id), owasp_url(owasp_category)):
        if url and url not in out:
            out.append(url)
    return out


def mitre_for(vuln_type: str | None) -> str | None:
    """ATT&CK technique for a vuln class, or None when there is no defensible fit.

    Longest match wins, so 'sql injection' is not shadowed by a shorter entry.
    """
    if not vuln_type:
        return None
    vt = str(vuln_type).lower()
    best: tuple[int, str] | None = None
    for needle, technique in _ATTACK:
        if needle in vt and (best is None or len(needle) > best[0]):
            best = (len(needle), technique)
    return best[1] if best else None


def serialise_ref_links(urls: list[str]) -> str:
    """Storage form for the ref_links column.

    Comma-separated because that is what _build_report_json already splits on;
    none of the generated URLs contain a comma.
    """
    return ",".join(urls)
