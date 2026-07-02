"""Programmatic, evidence-gated vulnerability detection from tool output.

Extracted from ``main.py`` so the "scientific instrument" — the code that
decides what counts as a confirmed finding, and the reason erlik's precision is
model-independent — lives in one small, independently testable module instead
of buried in the web app.

Structure: each supported tool maps to a detector callable in ``_DETECTORS``.
A detector receives a :class:`DetectContext` and returns a list of finding
dicts. ``curl`` fires many independent sub-checks against a single response, so
it composes a list of small rule functions (``_CURL_RULES``) — adding a new
curl detector is appending one function to that list, not editing a 200-line
branch.

Behaviour is intentionally identical to the original
``main._auto_detect_findings``; ``tests/test_auto_detect.py`` pins it.

A finding dict has the shape::

    {"vuln_type": str, "severity": str, "url": str,
     "parameter": str, "evidence": str}
"""

import json
import re

Finding = dict


class DetectContext:
    """Everything a detector needs about one tool invocation (computed once)."""

    __slots__ = ("tool_name", "output", "command", "output_lower",
                 "command_lower", "url")

    def __init__(self, tool_name: str, output: str, command: str):
        self.tool_name = tool_name
        self.output = output
        self.command = command
        self.output_lower = output.lower()
        self.command_lower = command.lower()
        # Generic URL used by the curl detectors: first http(s) token in the cmd.
        m = re.search(r'(https?://\S+)', command)
        self.url = m.group(1) if m else ""


def _url_from_dash_u(command: str) -> str:
    """URL from a ``-u "<url>"`` style argument (sqlmap / commix)."""
    m = re.search(r'-u\s+"?([^"\s]+)', command)
    return m.group(1) if m else ""


# ── sqlmap ────────────────────────────────────────────────────────────────
def _detect_sqlmap(ctx: DetectContext) -> list[Finding]:
    sqli_confirmed = False
    dbms = ""
    payload_lines: list[str] = []
    param = ""
    for line in ctx.output.split("\n"):
        if "injection point" in line.lower() or "is vulnerable" in line.lower():
            sqli_confirmed = True
        if "back-end DBMS" in line and ":" in line:
            dbms = line.split(":")[-1].strip()
        if "Parameter:" in line:
            pm = re.search(r'Parameter:\s*(\S+)', line)
            if pm:
                param = pm.group(1)
        if "Payload:" in line:
            payload_lines.append(line.strip())
    if not sqli_confirmed:
        return []
    url = _url_from_dash_u(ctx.command)
    evidence = f"DBMS: {dbms}" if dbms else "SQL injection confirmed by sqlmap"
    if payload_lines:
        evidence += "\n" + "\n".join(payload_lines[:3])
    return [{
        "vuln_type": "SQL Injection", "severity": "high",
        "url": url, "parameter": param, "evidence": evidence,
    }]


# ── nuclei ──────────────────────────────────────────────────────────────────
def _detect_nuclei(ctx: DetectContext) -> list[Finding]:
    findings: list[Finding] = []
    for line in ctx.output.split("\n"):
        line_lower = line.lower()
        if "[critical]" in line_lower or "[high]" in line_lower:
            # Parse nuclei output format: [template-id] [protocol] [severity] url
            parts = re.findall(r'\[([^\]]+)\]', line)
            sev = "high"
            vuln_type = "Nuclei Finding"
            url = ""
            for p in parts:
                if p.lower() in ("critical", "high"):
                    sev = p.lower()
                elif p not in ("http", "https", "tcp", "dns", "ssl"):
                    vuln_type = p
            url_match = re.search(r'(https?://\S+)', line)
            if url_match:
                url = url_match.group(1)
            findings.append({
                "vuln_type": vuln_type, "severity": sev, "url": url,
                "parameter": "", "evidence": line.strip()[:500],
            })
    return findings


# ── xsstrike / dalfox ───────────────────────────────────────────────────────
# dalfox/xsstrike confirm a hit with explicit success markers ([POC], [VULN],
# "triggered", "poc:") or by stating the payload is vulnerable/confirmed. The
# reflected+xss pair is a secondary signal. All are strong, evidence-gated
# tokens, so precision is preserved.
_XSS_MARKERS = ("[poc]", "[vuln]", "triggered", "poc:", "vulnerable", "confirmed")


def _detect_xss_tools(ctx: DetectContext) -> list[Finding]:
    for line in ctx.output.split("\n"):
        line_lower = line.lower()
        if (any(tok in line_lower for tok in _XSS_MARKERS) or
                ("reflected" in line_lower and "xss" in line_lower)):
            url_match = (re.search(r'-u\s+"?([^"\s]+)', ctx.command)
                         or re.search(r'url\s+"?([^"\s]+)', ctx.command))
            url = url_match.group(1) if url_match else ""
            return [{
                "vuln_type": "Cross-Site Scripting (XSS)", "severity": "medium",
                "url": url, "parameter": "", "evidence": line.strip()[:500],
            }]
    return []


# ── curl sub-rules ──────────────────────────────────────────────────────────
def _curl_exposed_user_data(ctx: DetectContext) -> list[Finding]:
    ol = ctx.output_lower
    if (('"email"' in ol and '"password"' in ol) or
            ('"email"' in ol and ('"role"' in ol or '"isadmin"' in ol))):
        emails = re.findall(r'"email"\s*:\s*"([^"]+)"', ctx.output)
        evidence = f"API exposes user data: {len(emails)} user records found"
        if emails:
            evidence += f"\nSample: {emails[0]}"
        return [{
            "vuln_type": "Sensitive Data Exposure", "severity": "medium",
            "url": ctx.url, "parameter": "", "evidence": evidence,
        }]
    return []


def _curl_api_users_bac(ctx: DetectContext) -> list[Finding]:
    if "/api/users" in ctx.url.lower() and '"email"' in ctx.output_lower:
        emails = re.findall(r'"email"\s*:\s*"([^"]+)"', ctx.output)
        if emails:
            return [{
                "vuln_type": "Broken Access Control", "severity": "high",
                "url": ctx.url, "parameter": "",
                "evidence": f"User enumeration: GET /api/Users returns {len(emails)} user records without auth",
            }]
    return []


def _curl_idor_basket(ctx: DetectContext) -> list[Finding]:
    if "/rest/basket/" in ctx.url.lower() and '"products"' in ctx.output_lower:
        basket_id = re.search(r'/rest/basket/(\d+)', ctx.url)
        if basket_id:
            return [{
                "vuln_type": "Broken Access Control", "severity": "critical",
                "url": ctx.url, "parameter": "id",
                "evidence": f"IDOR: basket {basket_id.group(1)} accessible — response contains product data",
            }]
    return []


def _curl_idor_order(ctx: DetectContext) -> list[Finding]:
    if "/api/orders" in ctx.url.lower() and ('"totalprice"' in ctx.output_lower or '"products"' in ctx.output_lower):
        order_id = re.search(r'/api/orders/(\w+)', ctx.url, re.IGNORECASE)
        if order_id:
            return [{
                "vuln_type": "Broken Access Control", "severity": "high",
                "url": ctx.url, "parameter": "id",
                "evidence": f"IDOR: order {order_id.group(1)} data accessible",
            }]
    return []


def _curl_sqli_login(ctx: DetectContext) -> list[Finding]:
    if "/rest/user/login" in ctx.url.lower() and '"token"' in ctx.output_lower:
        sqli_patterns = ["or 1=1", "' or", "\"or", "1=1--", "admin'--", "' --"]
        if any(p in ctx.command_lower for p in sqli_patterns):
            token_match = re.search(r'"token"\s*:\s*"([^"]{20,})"', ctx.output)
            evidence = "SQL injection on login: server returned JWT token"
            if token_match:
                evidence += f"\nToken: {token_match.group(1)[:50]}..."
            return [{
                "vuln_type": "SQL Injection", "severity": "critical",
                "url": ctx.url, "parameter": "email", "evidence": evidence,
            }]
    return []


def _curl_cors(ctx: DetectContext) -> list[Finding]:
    if "access-control-allow-origin" not in ctx.output_lower:
        return []
    cors_match = re.search(r'access-control-allow-origin:\s*(\S+)', ctx.output, re.IGNORECASE)
    if cors_match and cors_match.group(1).strip() == "*":
        return [{
            "vuln_type": "CORS Misconfiguration", "severity": "medium",
            "url": ctx.url, "parameter": "",
            "evidence": "Access-Control-Allow-Origin: * — allows any domain to read responses",
        }]
    if cors_match and "evil" in cors_match.group(1).lower():
        return [{
            "vuln_type": "CORS Misconfiguration", "severity": "high",
            "url": ctx.url, "parameter": "",
            "evidence": f"Server reflects arbitrary Origin: {cors_match.group(1)}",
        }]
    return []


def _curl_missing_headers(ctx: DetectContext) -> list[Finding]:
    if not (ctx.command.strip().startswith("curl -s") and
            ("-I" in ctx.command or "-i" in ctx.command or "--head" in ctx.command)):
        return []
    headers_lower = ctx.output_lower
    missing = []
    if "content-security-policy" not in headers_lower:
        missing.append("Content-Security-Policy")
    if "x-frame-options" not in headers_lower:
        missing.append("X-Frame-Options")
    if "strict-transport-security" not in headers_lower:
        missing.append("Strict-Transport-Security")
    if "x-content-type-options" not in headers_lower:
        missing.append("X-Content-Type-Options")
    if missing and len(missing) >= 2:
        return [{
            "vuln_type": "Security Misconfiguration", "severity": "medium",
            "url": ctx.url, "parameter": "",
            "evidence": f"Missing security headers: {', '.join(missing)}",
        }]
    return []


def _curl_server_header(ctx: DetectContext) -> list[Finding]:
    if "x-powered-by:" in ctx.output_lower or ("server:" in ctx.output_lower and "express" in ctx.output_lower):
        server_match = re.search(r'(?:x-powered-by|server):\s*(.+)', ctx.output, re.IGNORECASE)
        if server_match:
            return [{
                "vuln_type": "Information Disclosure", "severity": "medium",
                "url": ctx.url, "parameter": "",
                "evidence": f"Server header exposes: {server_match.group(1).strip()}",
            }]
    return []


def _curl_swagger(ctx: DetectContext) -> list[Finding]:
    if "/api-docs" in ctx.url.lower() and ("swagger" in ctx.output_lower or '"paths"' in ctx.output_lower or '"openapi"' in ctx.output_lower):
        return [{
            "vuln_type": "Security Misconfiguration", "severity": "medium",
            "url": ctx.url, "parameter": "",
            "evidence": "Swagger/OpenAPI documentation exposed — reveals all API endpoints",
        }]
    return []


def _curl_metrics(ctx: DetectContext) -> list[Finding]:
    if "/metrics" in ctx.url.lower() and ("process_" in ctx.output_lower or "nodejs_" in ctx.output_lower or "http_request" in ctx.output_lower):
        return [{
            "vuln_type": "Security Misconfiguration", "severity": "low",
            "url": ctx.url, "parameter": "",
            "evidence": "Prometheus metrics endpoint exposed — reveals internal server state",
        }]
    return []


def _curl_ftp(ctx: DetectContext) -> list[Finding]:
    if "/ftp" in ctx.url.lower() and ("acquisitions" in ctx.output_lower or ".md" in ctx.output_lower or ".bak" in ctx.output_lower):
        return [{
            "vuln_type": "Sensitive Data Exposure", "severity": "medium",
            "url": ctx.url, "parameter": "",
            "evidence": "FTP directory listing exposes sensitive files",
        }]
    return []


def _curl_null_byte(ctx: DetectContext) -> list[Finding]:
    if "%2500" in ctx.url or "%00" in ctx.url:
        if len(ctx.output.strip()) > 50 and "error" not in ctx.output_lower[:100]:
            return [{
                "vuln_type": "Sensitive Data Exposure", "severity": "high",
                "url": ctx.url, "parameter": "",
                "evidence": f"Null byte bypass successful — restricted file accessible ({len(ctx.output)} bytes returned)",
            }]
    return []


def _curl_open_redirect(ctx: DetectContext) -> list[Finding]:
    if "/redirect" not in ctx.url.lower():
        return []
    if "301" in ctx.output or "302" in ctx.output or "location:" in ctx.output_lower:
        loc_match = re.search(r'location:\s*(\S+)', ctx.output, re.IGNORECASE)
        if loc_match and ("evil" in loc_match.group(1).lower() or
                          "http" in loc_match.group(1).lower() and "juice" not in loc_match.group(1).lower()):
            return [{
                "vuln_type": "Open Redirect", "severity": "medium",
                "url": ctx.url, "parameter": "to",
                "evidence": f"Open redirect: server redirects to {loc_match.group(1)}",
            }]
    return []


def _curl_forged_feedback(ctx: DetectContext) -> list[Finding]:
    if "/api/feedbacks" in ctx.url.lower() and '"userid"' in ctx.output_lower and "POST" in ctx.command.upper():
        return [{
            "vuln_type": "Broken Access Control", "severity": "high",
            "url": ctx.url, "parameter": "UserId",
            "evidence": "Forged feedback accepted — server allows setting arbitrary UserId",
        }]
    return []


# A 500 Express page by itself is NOT a finding. Require evidence of actual
# internal information leakage: stack frames, filesystem paths, or line-numbered
# source frames.
_STACKTRACE_MARKERS = ("stacktrace", "stack trace", "traceback")
_FILESYSTEM_MARKERS = ("/node_modules/", "/usr/", "/home/", "/root/",
                       "/app/", "/var/", "/juice-shop/")


def _curl_stack_trace(ctx: DetectContext) -> list[Finding]:
    frame_pattern = re.search(r'\.(?:js|ts|py|rb|php):\d+:\d+', ctx.output)
    has_stacktrace = any(m in ctx.output_lower for m in _STACKTRACE_MARKERS)
    has_fs_path = any(m in ctx.output for m in _FILESYSTEM_MARKERS)
    has_frame = bool(frame_pattern)
    if has_stacktrace or has_fs_path or has_frame:
        err_match = re.search(r'<h2><em>\d+</em>\s*(.+?)</h2>', ctx.output)
        err_msg = err_match.group(1).strip() if err_match else "Server error with stack trace"
        return [{
            "vuln_type": "Information Disclosure", "severity": "info",
            "url": ctx.url, "parameter": "", "evidence": err_msg[:300],
        }]
    return []


# Order matters: it is the emission order of the original if-ladder, which some
# tests assert exactly. Append new curl detectors to the end.
_CURL_RULES = (
    _curl_exposed_user_data,
    _curl_api_users_bac,
    _curl_idor_basket,
    _curl_idor_order,
    _curl_sqli_login,
    _curl_cors,
    _curl_missing_headers,
    _curl_server_header,
    _curl_swagger,
    _curl_metrics,
    _curl_ftp,
    _curl_null_byte,
    _curl_open_redirect,
    _curl_forged_feedback,
    _curl_stack_trace,
)


def _detect_curl(ctx: DetectContext) -> list[Finding]:
    findings: list[Finding] = []
    for rule in _CURL_RULES:
        findings.extend(rule(ctx))
    return findings


# ── jwt_tool ────────────────────────────────────────────────────────────────
def _detect_jwt_tool(ctx: DetectContext) -> list[Finding]:
    ol = ctx.output_lower
    findings: list[Finding] = []
    # Require an explicit crack signal — a bare "found" matches ordinary banner
    # text ("Token found in header") and emitted a phantom finding.
    if "secret key" in ol or "cracked" in ol or "correct key" in ol:
        secret_match = re.search(r'(?:secret|key|found)[:\s]+["\']?(\S+)', ctx.output, re.IGNORECASE)
        findings.append({
            "vuln_type": "Broken Authentication", "severity": "critical",
            "url": "", "parameter": "",
            "evidence": f"JWT weak secret cracked: {secret_match.group(1) if secret_match else 'key found'}",
        })
    if "none" in ol and ("accepted" in ol or "bypass" in ol or "success" in ol):
        findings.append({
            "vuln_type": "Broken Authentication", "severity": "critical",
            "url": "", "parameter": "",
            "evidence": "JWT none algorithm attack successful — server accepts unsigned tokens",
        })
    return findings


# ── hydra ────────────────────────────────────────────────────────────────────
def _detect_hydra(ctx: DetectContext) -> list[Finding]:
    for line in ctx.output.split("\n"):
        if "host:" in line.lower() and ("login:" in line.lower() or "password:" in line.lower()):
            return [{
                "vuln_type": "Broken Authentication", "severity": "high",
                "url": "", "parameter": "",
                "evidence": f"Brute force success: {line.strip()[:300]}",
            }]
    return []


# ── nikto ────────────────────────────────────────────────────────────────────
def _detect_nikto(ctx: DetectContext) -> list[Finding]:
    findings: list[Finding] = []
    for line in ctx.output.split("\n"):
        if line.strip().startswith("+ ") and ("OSVDB" in line or "vulnerability" in line.lower()
                                               or "outdated" in line.lower() or "XSS" in line):
            findings.append({
                "vuln_type": "Nikto Finding", "severity": "info",
                "url": "", "parameter": "", "evidence": line.strip()[:300],
            })
    return findings


# ── commix ───────────────────────────────────────────────────────────────────
def _detect_commix(ctx: DetectContext) -> list[Finding]:
    for line in ctx.output.split("\n"):
        if "injectable" in line.lower() or "is vulnerable" in line.lower():
            url = _url_from_dash_u(ctx.command)
            return [{
                "vuln_type": "Command Injection", "severity": "critical",
                "url": url, "parameter": "", "evidence": line.strip()[:500],
            }]
    return []


# ── zap-cli ──────────────────────────────────────────────────────────────────
def _detect_zap_cli(ctx: DetectContext) -> list[Finding]:
    findings: list[Finding] = []
    try:
        data = json.loads(ctx.output)
        alerts = data.get("alerts", [])
        seen = set()  # deduplicate by (name, url)
        for alert in alerts:
            risk = (alert.get("risk") or "").lower()
            name = alert.get("name") or alert.get("alert") or "ZAP Finding"
            url = alert.get("url") or ""
            evidence = alert.get("evidence") or ""
            desc = alert.get("description") or ""
            param = alert.get("param") or ""

            sev_map = {"high": "high", "medium": "medium", "low": "low", "informational": "info"}
            severity = sev_map.get(risk, "info")

            # Only auto-report medium+ findings
            if severity not in ("high", "medium", "critical"):
                continue

            dedup_key = (name, url)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            evidence_str = f"{name}"
            if evidence:
                evidence_str += f"\nEvidence: {evidence[:200]}"
            if desc:
                evidence_str += f"\nDescription: {desc[:200]}"

            findings.append({
                "vuln_type": name, "severity": severity, "url": url,
                "parameter": param, "evidence": evidence_str[:500],
            })
    except (json.JSONDecodeError, TypeError, KeyError):
        pass  # Not JSON alerts output (could be spider/scan status)
    return findings


# ── content discovery (gobuster / ffuf / dirb / wfuzz) ──────────────────────
# These tools discover paths but previously emitted no findings — a live 200 on
# a known-sensitive path was surfaced to the LLM only as text, so unless the
# agent followed up with an exact-matching curl the exposure was a silent miss.
# We map a small allowlist of sensitive paths to findings. Matching is on the
# path SEGMENT (not a loose substring) and only for status 200/301/302, so a
# hit is a real exposure, not a guess — precision-safe.
#
# Each entry: (marker, is_dir, vuln_type, severity, note). Directory markers
# match the exact segment ("/ftp", "/ftp/…"); filename markers match the path
# suffix ("…/robots.txt", "….map").
_SENSITIVE_PATHS = (
    ("security.txt", False, "Information Disclosure", "info",
     "security.txt policy file exposed"),
    ("/api-docs", True, "Security Misconfiguration", "medium",
     "Swagger/OpenAPI documentation endpoint exposed"),
    ("/metrics", True, "Security Misconfiguration", "low",
     "Prometheus metrics endpoint exposed"),
    ("robots.txt", False, "Security Misconfiguration", "info",
     "robots.txt exposed (may reveal hidden paths)"),
    ("/ftp", True, "Sensitive Data Exposure", "medium",
     "FTP file directory exposed"),
    (".map", False, "Sensitive Data Exposure", "medium",
     "JavaScript source map exposed (leaks application source)"),
)


def _content_discovery_pairs(output: str):
    """Yield (raw_path, status) from gobuster/ffuf/dirb/wfuzz output.

    Mirrors main._parse_tool_output's extraction so the detector and the LLM
    summary agree on what was discovered.
    """
    for line in output.split("\n"):
        m = (re.search(r'(/?\S+)\s+\(Status:\s*(\d+)\)', line)          # gobuster
             or re.search(r'(\S+)\s+\[Status:\s*(\d+)', line)           # ffuf
             or re.search(r'(https?://\S+)\s+\(CODE:(\d+)', line))      # dirb
        if not m:
            continue
        path = m.group(1)
        if path in ("Progress:", "::", "---", "===") or path.startswith("==="):
            continue
        yield path, m.group(2)


def _normalize_disc_path(path: str) -> str:
    """Reduce a discovered path (possibly a full dirb URL) to a lowercase,
    leading-slash path component."""
    url_m = re.match(r'https?://[^/]+(/\S*)', path)
    if url_m:
        path = url_m.group(1)
    path = path.split("?", 1)[0].lower()
    if not path.startswith("/"):
        path = "/" + path
    return path


def _path_hits(norm_path: str, marker: str, is_dir: bool) -> bool:
    if is_dir:
        return norm_path == marker or norm_path.startswith(marker + "/")
    return norm_path.endswith(marker) or ("/" + marker.lstrip("/")) in norm_path


def _detect_content_discovery(ctx: DetectContext) -> list[Finding]:
    # Discovered paths are relative to the target root, so anchor the finding
    # URL to the origin (scheme://host) — the command URL may carry a path or a
    # FUZZ placeholder (e.g. ffuf's `-u http://host/FUZZ`).
    origin_m = re.match(r'(https?://[^/]+)', ctx.url)
    base = origin_m.group(1) if origin_m else ""
    findings: list[Finding] = []
    seen = set()
    for raw_path, status in _content_discovery_pairs(ctx.output):
        if status not in ("200", "301", "302"):
            continue
        norm = _normalize_disc_path(raw_path)
        for marker, is_dir, vuln_type, severity, note in _SENSITIVE_PATHS:
            if not _path_hits(norm, marker, is_dir):
                continue
            key = (vuln_type, norm)
            if key in seen:
                break
            seen.add(key)
            findings.append({
                "vuln_type": vuln_type, "severity": severity,
                "url": (base + norm) if base else norm, "parameter": "",
                "evidence": f"Content discovery: {norm} (HTTP {status}) — {note}",
            })
            break  # one finding per discovered path
    return findings


# ── dispatch ─────────────────────────────────────────────────────────────────
_DETECTORS = {
    "sqlmap": _detect_sqlmap,
    "nuclei": _detect_nuclei,
    "xsstrike": _detect_xss_tools,
    "dalfox": _detect_xss_tools,
    "curl": _detect_curl,
    "jwt_tool": _detect_jwt_tool,
    "hydra": _detect_hydra,
    "nikto": _detect_nikto,
    "commix": _detect_commix,
    "zap-cli": _detect_zap_cli,
    "gobuster": _detect_content_discovery,
    "ffuf": _detect_content_discovery,
    "dirb": _detect_content_discovery,
    "wfuzz": _detect_content_discovery,
}


def auto_detect_findings(tool_name: str, output: str, command: str) -> list[Finding]:
    """Programmatically detect confirmed vulnerabilities from tool output.

    Returns a list of finding dicts ready to save to the DB. This removes the
    dependence on the LLM to report findings and is why precision is
    model-independent. Unhandled tools return an empty list.
    """
    detector = _DETECTORS.get(tool_name)
    if detector is None:
        return []
    return detector(DetectContext(tool_name, output, command))
