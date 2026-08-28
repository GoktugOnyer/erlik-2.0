"""The attack-class index behind the ARSENAL dashboard view.

erlik's capabilities live in five catalogues that share nothing in the UI:
179 skill sheets, 22 deterministic WSTG cases, 24 detection rules, a HackTricks
technique index, and run-config presets. This joins them by ATTACK CLASS, so
"what can erlik actually do about SSRF, and which part of that is deterministic
rather than model-driven?" has one answer.

EVERY EDGE IS HAND-DECLARED. Auto-joining was measured on the real catalogues
and is not close to usable: matching techniques by tag produced 30 false edges
out of 35 (CSTI, CRLF, LDAP and Same-Site Leaks all matched a query for SQL
injection, because tags are mechanically tokenised from page titles), and
joining WSTG cases by the router's own regex produced 4 wrong out of 5. A guide
that confidently states a wrong relationship is worse than one that says
nothing, so `audit()` is a hard test failure in BOTH directions: a declared id
that does not exist, and a catalogue entry no class claims.

TWO VERDICTS PER CLASS, NEVER ONE. `agent_session` and `wstg_engine` are
separate execution paths that never meet — `run_test_case` is reachable only
from POST /api/v2/testcases/{id}/run, never from the agent loop. A single
"verified" badge spanning both would assert coverage that no single run can
deliver.
"""

from __future__ import annotations

import functools
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WSTG_DIR = ROOT / "tests_catalog" / "wstg"


# key: the routing class in skills._CLASS_PATTERNS (None = no skill routing)
# wstg: deterministic test-case ids that test this class
# detectors: `tool:rule` names from detection.py that can CONFIRM it
CLASSES: list[dict] = [
    {"key": "sqli", "label": "SQL Injection", "owasp": "A03:2021 Injection",
     "wstg": ["WSTG-INPV-05"],
     "detectors": ["sqlmap:_detect_sqlmap", "curl:_curl_sqli_login"]},
    {"key": "xss", "label": "Cross-Site Scripting", "owasp": "A03:2021 Injection",
     "wstg": ["WSTG-INPV-01", "WSTG-CLNT-04"],
     "detectors": ["xsstrike:_detect_xss_tools", "dalfox:_detect_xss_tools"]},
    {"key": "cmdi", "label": "Command Injection", "owasp": "A03:2021 Injection",
     "wstg": [], "detectors": ["commix:_detect_commix"]},
    {"key": "ssti", "label": "Server-Side Template Injection",
     "owasp": "A03:2021 Injection", "wstg": [], "detectors": []},
    {"key": "xxe", "label": "XML External Entity", "owasp": "A05:2021 Misconfiguration",
     "wstg": [], "detectors": []},
    {"key": "ldap", "label": "LDAP Injection", "owasp": "A03:2021 Injection",
     "wstg": ["WSTG-INPV-06"], "detectors": []},
    {"key": "nosql", "label": "NoSQL Injection", "owasp": "A03:2021 Injection",
     "wstg": ["WSTG-INPV-05.6"], "detectors": []},
    {"key": "authz", "label": "Broken Access Control / IDOR",
     "owasp": "A01:2021 Broken Access Control",
     "wstg": ["WSTG-AUTHZ-04"],
     "detectors": ["curl:_curl_api_users_bac", "curl:_curl_idor_basket",
                   "curl:_curl_idor_order"]},
    {"key": "authn", "label": "Authentication Weakness",
     "owasp": "A07:2021 Identification & Authentication Failures",
     "wstg": ["WSTG-ATHN-01"], "detectors": ["hydra:_detect_hydra"]},
    {"key": "jwt", "label": "JWT Weakness",
     "owasp": "A02:2021 Cryptographic Failures",
     "wstg": ["WSTG-SESS-10"], "detectors": ["jwt_tool:_detect_jwt_tool"]},
    {"key": "oauth", "label": "OAuth / SSO Flow", "owasp": "A07:2021 Auth Failures",
     "wstg": [], "detectors": []},
    {"key": "csrf", "label": "Cross-Site Request Forgery",
     "owasp": "A01:2021 Broken Access Control",
     "wstg": ["WSTG-SESS-02"], "detectors": []},
    {"key": "cors", "label": "CORS Misconfiguration",
     "owasp": "A05:2021 Security Misconfiguration",
     "wstg": ["WSTG-CLNT-07", "WSTG-CLNT-07b"], "detectors": ["curl:_curl_cors"]},
    {"key": "ssrf", "label": "Server-Side Request Forgery", "owasp": "A10:2021 SSRF",
     "wstg": ["WSTG-INPV-19"], "detectors": []},
    {"key": "path", "label": "Path Traversal / File Inclusion",
     "owasp": "A01:2021 Broken Access Control",
     "wstg": ["WSTG-INPV-15"], "detectors": ["curl:_curl_null_byte"]},
    {"key": "upload", "label": "Unrestricted File Upload",
     "owasp": "A04:2021 Insecure Design", "wstg": [], "detectors": []},
    {"key": "deserialize", "label": "Insecure Deserialization",
     "owasp": "A08:2021 Software & Data Integrity", "wstg": [], "detectors": []},
    {"key": "logic", "label": "Business Logic Flaw",
     "owasp": "A04:2021 Insecure Design",
     "wstg": ["WSTG-BUSL-04"], "detectors": ["curl:_curl_forged_feedback"]},
    {"key": "disclosure", "label": "Information Disclosure",
     "owasp": "A05:2021 Security Misconfiguration",
     "wstg": ["WSTG-ERRH-01", "WSTG-INFO-02", "WSTG-INFO-03", "WSTG-CONF-02"],
     "detectors": ["curl:_curl_stack_trace", "curl:_curl_server_header",
                   "curl:_curl_exposed_user_data", "nikto:_detect_nikto"]},
    {"key": "recon", "label": "Recon & Content Discovery",
     "owasp": "—",
     "wstg": ["WSTG-CONF-04", "WSTG-CONF-06", "WSTG-CONF-07", "WSTG-CLNT-09"],
     "detectors": ["gobuster:_detect_content_discovery",
                   "ffuf:_detect_content_discovery",
                   "dirb:_detect_content_discovery",
                   "wfuzz:_detect_content_discovery",
                   "curl:_curl_swagger", "curl:_curl_metrics", "curl:_curl_ftp",
                   "curl:_curl_missing_headers", "curl:_curl_open_redirect",
                   "nuclei:_detect_nuclei", "zap-cli:_detect_zap_cli"]},
    {"key": "injection_generic", "label": "Injection (unclassified)",
     "owasp": "A03:2021 Injection", "wstg": [], "detectors": []},
]


@functools.lru_cache(maxsize=1)
def wstg_ids() -> frozenset[str]:
    import yaml
    ids = set()
    for p in sorted(WSTG_DIR.glob("*.yaml")):
        try:
            doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except Exception:
            continue
        if doc.get("id"):
            ids.add(str(doc["id"]))
    return frozenset(ids)


def detector_names() -> frozenset[str]:
    from orchestrator.bench.cleanroom import all_rule_names
    return frozenset(all_rule_names())


def routing_class_keys() -> frozenset[str]:
    from orchestrator.skills import _CLASS_PATTERNS
    return frozenset(c[0] for c in _CLASS_PATTERNS)


def skills_for(key: str) -> list[dict]:
    """Sheets the ROUTER would actually select for this class.

    Calls the real selector rather than reimplementing ranking: a second
    implementation drifts, and then the guide shows something the runs do not do.
    """
    from orchestrator.skills import select_skill_files, license_of, SKILLS_ROOT
    label = next((c["label"] for c in CLASSES if c["key"] == key), key)
    out = []
    for p in select_skill_files(label):
        out.append({"path": str(p.relative_to(SKILLS_ROOT)),
                    "stem": p.stem,
                    "licence": license_of(p),
                    "bytes": p.stat().st_size})
    return out


def verdicts(cls: dict) -> dict:
    """What each EXECUTION PATH can do for this class — reported separately.

    agent_session : only a detector produces deterministic evidence in an agent
                    run. No detector means every claim in that class is a model
                    assertion nobody re-checked.
    wstg_engine   : deterministic, but reachable only via the v2 endpoint.
    """
    return {
        "agent_session": "confirmable" if cls["detectors"] else "model-only",
        "wstg_engine": "deterministic" if cls["wstg"] else "not covered",
    }


def case_declared_classes() -> dict[str, str]:
    """{case id: the class the CASE FILE says it proves}."""
    import yaml
    out: dict[str, str] = {}
    for p in sorted(WSTG_DIR.glob("*.yaml")):
        try:
            doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except Exception:
            continue
        if doc.get("id") and doc.get("attack_class"):
            out[str(doc["id"])] = str(doc["attack_class"])
    return out


def _misattributed() -> list[dict]:
    """Cases whose declaring class disagrees with the class claiming them."""
    declared = case_declared_classes()
    claimed: dict[str, str] = {}
    for c in CLASSES:
        for w in (c.get("wstg") or []):
            claimed[w] = c["key"]
    out = []
    for cid, says in sorted(declared.items()):
        by = claimed.get(cid)
        if by != says:
            out.append({"case": cid, "case_declares": says, "claimed_by": by})
    return out


def audit() -> dict:
    """Every declared id must exist, and every catalogue entry must be claimed.

    Fails in BOTH directions on purpose: a dangling id makes the guide lie, and
    an unclaimed detector means a capability the guide silently omits.
    """
    ids, dets, keys = wstg_ids(), detector_names(), routing_class_keys()
    declared_w = {w for c in CLASSES for w in c["wstg"]}
    declared_d = {d for c in CLASSES for d in c["detectors"]}
    declared_k = {c["key"] for c in CLASSES}
    return {
        "wstg_declared_missing": sorted(declared_w - ids),
        "wstg_unclaimed": sorted(ids - declared_w),
        # Existence is not correctness. Every check above passed while three
        # cases were filed under the wrong class — WSTG-INPV-19 ("Server-Side
        # Request Forgery") under `ssti`, WSTG-INPV-06 ("LDAP Injection") under
        # `cmdi`, WSTG-INPV-05.6 ("NoSQL Operator Injection") under `sqli` — so
        # the Arsenal reported no deterministic coverage for SSRF, LDAP and
        # NoSQL while claiming it for SSTI and command injection. Every id
        # existed and every case was claimed by SOMEONE, which is all the old
        # audit asked.
        "wstg_misattributed": _misattributed(),
        "detectors_declared_missing": sorted(declared_d - dets),
        "detectors_unclaimed": sorted(dets - declared_d),
        "class_keys_unknown": sorted(declared_k - keys),
        "class_keys_unclaimed": sorted(keys - declared_k),
    }


def overview() -> dict:
    from orchestrator.skills import _catalog, SKILLS_ROOT, skills_enabled
    cat = _catalog()
    listed = sum(1 for _ in SKILLS_ROOT.rglob("*.md")) if SKILLS_ROOT.exists() else 0
    gaps = [c["key"] for c in CLASSES if not c["detectors"]]
    return {
        "skills": {"listed": listed, "routable": len(cat),
                   "note": "listed counts every .md; routable excludes "
                           "NOTICE/INDEX/SKILL files the router skips"},
        "skills_enabled": skills_enabled(),
        "wstg_cases": len(wstg_ids()),
        "detectors": len(detector_names()),
        "classes": len(CLASSES),
        "model_only_classes": gaps,
        "model_only_note": "classes with skills but NO detector — an agent run "
                           "can claim these but cannot deterministically confirm them",
    }


def class_detail(key: str) -> dict | None:
    cls = next((c for c in CLASSES if c["key"] == key), None)
    if cls is None:
        return None
    return {**cls, "verdicts": verdicts(cls), "skills": skills_for(key)}
