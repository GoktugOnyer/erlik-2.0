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
     "wstg": ["WSTG-INPV-05", "WSTG-INPV-05.2", "WSTG-INPV-05.3", "WSTG-INPV-05.4"],

     # injection: see API_UNMAPPED_REASON
     "api": [],
     "detectors": ["sqlmap:_detect_sqlmap", "curl:_curl_sqli_login"]},
    {"key": "xss", "label": "Cross-Site Scripting", "owasp": "A03:2021 Injection",
     "wstg": ["WSTG-INPV-01", "WSTG-CLNT-04"],

     # injection: see API_UNMAPPED_REASON
     "api": [],
     "detectors": ["xsstrike:_detect_xss_tools", "dalfox:_detect_xss_tools"]},
    {"key": "cmdi", "label": "Command Injection", "owasp": "A03:2021 Injection",
     "wstg": [],
     # injection: see API_UNMAPPED_REASON
     "api": [],
     "detectors": ["commix:_detect_commix"]},
    {"key": "ssti", "label": "Server-Side Template Injection",
     "owasp": "A03:2021 Injection", "wstg": ["WSTG-INPV-18"],
     # injection: see API_UNMAPPED_REASON
     "api": [],
     "detectors": []},
    {"key": "xxe", "label": "XML External Entity", "owasp": "A05:2021 Misconfiguration",
     "wstg": ["WSTG-INPV-07"],
     # an XML parser resolving external entities is a parser misconfiguration
     "api": ["API8:2023"],
     "detectors": []},
    {"key": "ldap", "label": "LDAP Injection", "owasp": "A03:2021 Injection",
     "wstg": ["WSTG-INPV-06"],
     # injection: see API_UNMAPPED_REASON
     "api": [],
     "detectors": []},
    {"key": "nosql", "label": "NoSQL Injection", "owasp": "A03:2021 Injection",
     "wstg": ["WSTG-INPV-05.6"],
     # injection: see API_UNMAPPED_REASON
     "api": [],
     "detectors": []},
    {"key": "authz", "label": "Broken Access Control / IDOR",
     "owasp": "A01:2021 Broken Access Control",
     "wstg": ["WSTG-AUTHZ-04"],

     # THE split: cross_arm_authorization is object level, cross_arm_privileged_function is function level
     "api": ["API1:2023", "API5:2023"],
     "detectors": ["curl:_curl_api_users_bac", "curl:_curl_idor_basket",
                   "curl:_curl_idor_order"]},
    {"key": "authn", "label": "Authentication Weakness",
     "owasp": "A07:2021 Identification & Authentication Failures",
     "wstg": ["WSTG-ATHN-01"], "api": ["API2:2023"], "detectors": ["hydra:_detect_hydra"]},
    {"key": "jwt", "label": "JWT Weakness",
     "owasp": "A02:2021 Cryptographic Failures",
     "wstg": ["WSTG-SESS-10"],
     # a forgeable or unverified token is broken authentication, whatever the web list files the crypto under
     "api": ["API2:2023"],
     "detectors": ["jwt_tool:_detect_jwt_tool"]},
    {"key": "oauth", "label": "OAuth / SSO Flow", "owasp": "A07:2021 Auth Failures",
     "wstg": ["WSTG-AUTHZ-05"], "api": ["API2:2023"], "detectors": []},
    {"key": "csrf", "label": "Cross-Site Request Forgery",
     "owasp": "A01:2021 Broken Access Control",
     "wstg": ["WSTG-SESS-02"],
     # no API 2023 category. a token-authenticated API is not CSRF-shaped, and claiming API8 for it would overstate
     "api": [],
     "detectors": []},
    {"key": "cors", "label": "CORS Misconfiguration",
     "owasp": "A05:2021 Security Misconfiguration",
     "wstg": ["WSTG-CLNT-07", "WSTG-CLNT-07b"], "api": ["API8:2023"], "detectors": ["curl:_curl_cors"]},
    {"key": "ssrf", "label": "Server-Side Request Forgery", "owasp": "A10:2021 SSRF",
     "wstg": ["WSTG-INPV-19"], "api": ["API7:2023"], "detectors": []},
    # WSTG-AUTHZ-01, not WSTG-INPV-15. This class is labelled "Path Traversal
    # / File Inclusion" and its only case was Hop-by-Hop Header Handling — so
    # erlik advertised a path-traversal capability it did not have, and the
    # catalogue had no case for the thing the label names. AUTHZ-01 is that
    # case. INPV-15 moved to `smuggling`, which is what its own WSTG reference
    # (15-Testing_for_HTTP_Splitting_Smuggling) actually points at.
    {"key": "path", "label": "Path Traversal / File Inclusion",
     "owasp": "A01:2021 Broken Access Control",
     "wstg": ["WSTG-AUTHZ-01"],

     # traversal reaches FILES, not API objects. claiming API1 would overstate a file read as an object-authorization crossing
     "api": [],
     "detectors": ["curl:_curl_null_byte"]},
    {"key": "smuggling", "label": "HTTP Splitting / Smuggling",
     "owasp": "A05:2021 Security Misconfiguration",
     "wstg": ["WSTG-INPV-15"],
     "api": ["API8:2023"], "detectors": []},

    {"key": "upload", "label": "Unrestricted File Upload",
     "owasp": "A04:2021 Insecure Design", "wstg": ["WSTG-BUSL-09"],
     # unrestricted upload is not a misconfiguration and has no 2023 category
     "api": [],
     "detectors": []},
    {"key": "deserialize", "label": "Insecure Deserialization",
     "owasp": "A08:2021 Software & Data Integrity", "wstg": ["WSTG-INPV-11"],

     # API10 is about what the target consumes from its upstreams, not about deserializing attacker input
     "api": [],
     "detectors": []},
    {"key": "logic", "label": "Business Logic Flaw",
     "owasp": "A04:2021 Insecure Design",
     # BUSL-06 is ordering, BUSL-04 is timing. Both are business logic and neither
     # substitutes for the other: a burst finds the race and misses the skipped step.
     "wstg": ["WSTG-BUSL-04", "WSTG-BUSL-06"], "api": ["API6:2023"],
     "detectors": ["curl:_curl_forged_feedback"]},
    {"key": "disclosure", "label": "Information Disclosure",
     "owasp": "A05:2021 Security Misconfiguration",
     "wstg": ["WSTG-ERRH-01", "WSTG-INFO-02", "WSTG-INFO-03", "WSTG-CONF-02"],

     # excessive data exposure is object PROPERTY level
     "api": ["API3:2023"],
     "detectors": ["curl:_curl_stack_trace", "curl:_curl_server_header",
                   "curl:_curl_exposed_user_data", "nikto:_detect_nikto"]},
    {"key": "recon", "label": "Recon & Content Discovery",
     "owasp": "—",
     "wstg": ["WSTG-CONF-04", "WSTG-CONF-06", "WSTG-CONF-07", "WSTG-CLNT-09"],

     # endpoint and shadow-API discovery is inventory management
     "api": ["API9:2023"],
     "detectors": ["gobuster:_detect_content_discovery",
                   "ffuf:_detect_content_discovery",
                   "dirb:_detect_content_discovery",
                   "wfuzz:_detect_content_discovery",
                   "curl:_curl_swagger", "curl:_curl_metrics", "curl:_curl_ftp",
                   "curl:_curl_missing_headers", "curl:_curl_open_redirect",
                   "nuclei:_detect_nuclei", "zap-cli:_detect_zap_cli"]},
    {"key": "injection_generic", "label": "Injection (unclassified)",
     "owasp": "A03:2021 Injection", "wstg": ["WSTG-INPV-11.2"],
     # injection: see API_UNMAPPED_REASON
     "api": [],
     "detectors": []},
]


# ---------------------------------------------------------------- OWASP API Security
# E-011's acceptance asks for coverage mapped to "relevant WSTG and API Security
# categories", and the WSTG half was the only half that existed. `owasp` above is the
# WEB Top 10 (A01:2021); this is the API Top 10 2023, which is a DIFFERENT taxonomy with
# a different shape, not a renaming of the same one.
#
# The difference that matters here: the web list has ONE "A01 Broken Access Control",
# while the API list splits access control into OBJECT level (API1) and FUNCTION level
# (API5) — and erlik already makes exactly that split in code, as
# `cross_arm_authorization` and `cross_arm_privileged_function`. So this mapping is not
# relabelling; it is the first place the product's own split is reported as coverage.
API_CATEGORIES: dict[str, str] = {
    "API1:2023": "Broken Object Level Authorization",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Authorization",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization",
    "API6:2023": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023": "Server Side Request Forgery",
    "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management",
    "API10:2023": "Unsafe Consumption of APIs",
}

# Categories NO erlik class claims, declared with a reason rather than left to be
# inferred from an absence. Without this the audit cannot tell "erlik has no capability
# here" from "someone forgot to map it", and an unclaimed category would either read as
# a defect forever or be silently dropped — the same two bad options the WSTG audit
# already refuses.
API_NOT_COVERED: dict[str, str] = {
    "API4:2023": "rate limiting and resource exhaustion are load-shaped tests. erlik is "
                 "explicitly read-only against a target by default and has no throttling "
                 "or flood capability, so nothing here could be confirmed.",
    "API10:2023": "this is about what the target consumes from ITS upstreams, which is "
                  "not observable from the outside. erlik tests the API in front of it.",
}

# INJECTION IS DELIBERATELY UNMAPPED, and this is the non-obvious fact in the table.
# Injection was API8:2019 and was REMOVED as a standalone category in the 2023 list. Six
# erlik classes (sqli, xss, cmdi, ssti, ldap, nosql, injection_generic) therefore declare
# no API category — not because they are uncovered, but because the taxonomy stopped
# having a box for them. Mapping them to "API8 Security Misconfiguration" because the
# number is familiar would be precisely the confidently-wrong relationship this module's
# header refuses to auto-generate.
API_UNMAPPED_REASON = ("injection has no standalone category in the API Top 10 2023; it "
                       "was API8:2019 and was removed in the 2023 revision")


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
    # `.get`, not `["api"]`: a class dict missing the key crashed audit() with a KeyError
    # instead of reporting it, which the existing join-integrity test caught by injecting
    # exactly such a class. A malformed entry must make the audit FAIL, not raise — the
    # endpoint turns this dict into an `ok` verdict and an exception is not a verdict.
    declared_a = {a for c in CLASSES for a in c.get("api", ())}
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
        # The API taxonomy, on the same terms. `api_unaccounted` is the direction that
        # matters: a category that no class claims AND no reason declares uncovered is a
        # hole in the guide, while one with a declared reason is an honest "erlik does not
        # do this". Without the second list the first can only be empty by pretending.
        "api_declared_missing": sorted(declared_a - set(API_CATEGORIES)),
        "api_unaccounted": sorted(set(API_CATEGORIES) - declared_a - set(API_NOT_COVERED)),
        # A category cannot be both claimed by a class and declared uncovered. The two
        # directions above cannot see that case: a contradicting category is present in
        # `declared_a`, so it is neither missing nor unaccounted, and the join reads clean
        # while the table contradicts itself. It has never fired — it is here because the
        # two lists are edited independently and nothing else compares them.
        "api_claimed_yet_declared_uncovered": sorted(declared_a & set(API_NOT_COVERED)),
        # Tolerating the absence quietly would let a class drop its mapping unnoticed
        # whenever another class happens to claim the same category — `jwt` losing API2
        # while `authn` still claims it leaves every other check clean.
        "classes_missing_api": sorted(c["key"] for c in CLASSES if "api" not in c),
    }


def api_coverage() -> dict:
    """Coverage against the OWASP API Security Top 10 2023, per category.

    Answers the question E-011's acceptance actually asks — "which API Security
    categories can erlik demonstrate, and by which execution path" — rather than printing
    a count. Every category appears, including the ones nothing covers: a coverage report
    that lists only what it found is the shape that reads as complete when it is not.

    `verdicts` is reused rather than recomputed, so a category's verdict cannot drift from
    the class's. It keeps the two-path rule the module header states: `agent_session` and
    `wstg_engine` are separate and never merge into one badge.
    """
    out = []
    for cid, title in API_CATEGORIES.items():
        classes = [c for c in CLASSES if cid in c["api"]]
        out.append({
            "id": cid,
            "title": title,
            "classes": [{"key": c["key"], "label": c["label"],
                         "verdicts": verdicts(c)} for c in classes],
            "covered": bool(classes),
            # Present ONLY when nothing covers it, and then never empty: an uncovered
            # category without a reason is a gap in the guide, and `audit()` fails on it.
            "not_covered_reason": None if classes else API_NOT_COVERED.get(cid),
        })
    return {
        "taxonomy": "OWASP API Security Top 10 2023",
        "reference": "https://github.com/OWASP/API-Security",
        "categories": out,
        "covered": sum(1 for c in out if c["covered"]),
        "total": len(API_CATEGORIES),
        # The fact an operator would otherwise have to infer from six empty lists.
        "injection_note": API_UNMAPPED_REASON,
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
