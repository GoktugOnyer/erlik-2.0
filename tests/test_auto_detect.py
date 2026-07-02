"""Characterization tests for _auto_detect_findings (main.py ~730).

This is the programmatic, evidence-gated finding emitter — the reason erlik's
precision is model-independent (97-99%) and, equally, the main place recall is
lost (a tool whose output has no matching pattern emits nothing). These tests
lock the per-tool behaviour so the planned refactor into a declarative rule
table cannot change what counts as a finding.

Two KNOWN DEFECTS surfaced by the recall audit are encoded as strict xfail:
they express the DESIRED behaviour, currently fail (so the suite stays green),
and will flip to xpass — failing the strict marker and prompting removal — the
moment the recall roadmap fixes them.
"""

import json
import pytest

import orchestrator.main as m


def detect(tool, output, command=""):
    return m._auto_detect_findings(tool, output, command)


def types(findings):
    return [f["vuln_type"] for f in findings]


# ── sqlmap ───────────────────────────────────────────────────────────────
class TestSqlmap:
    def test_confirmed_injection(self):
        out = (
            "sqlmap identified the following injection point(s):\n"
            "Parameter: q (GET)\n"
            "    Type: boolean-based blind\n"
            "    Payload: q=1 AND 1=1\n"
            "the back-end DBMS is SQLite\n"
            "back-end DBMS: SQLite\n"
        )
        cmd = 'sqlmap -u "http://juice-shop:3000/rest/products/search?q=1" --batch'
        findings = detect("sqlmap", out, cmd)
        assert len(findings) == 1
        f = findings[0]
        assert f["vuln_type"] == "SQL Injection"
        assert f["severity"] == "high"
        assert f["parameter"] == "q"
        assert "/rest/products/search" in f["url"]
        assert "SQLite" in f["evidence"]

    def test_no_injection_found(self):
        out = "all tested parameters do not appear to be injectable."
        assert detect("sqlmap", out, 'sqlmap -u "http://x?q=1"') == []


# ── nuclei ────────────────────────────────────────────────────────────────
class TestNuclei:
    def test_high_and_critical_emit(self):
        out = (
            "[CVE-2021-44228] [http] [critical] http://juice-shop:3000/vuln\n"
            "[exposed-panel] [http] [high] http://juice-shop:3000/admin\n"
        )
        findings = detect("nuclei", out, "nuclei -u http://juice-shop:3000")
        assert len(findings) == 2
        assert findings[0]["vuln_type"] == "CVE-2021-44228"
        assert findings[0]["severity"] == "critical"
        assert "http://juice-shop:3000/vuln" in findings[0]["url"]

    def test_medium_and_low_are_ignored(self):
        out = (
            "[tech-detect] [http] [info] http://x\n"
            "[weak-cipher] [http] [medium] http://x\n"
            "[missing-header] [http] [low] http://x\n"
        )
        assert detect("nuclei", out, "nuclei -u http://x") == []


# ── xsstrike / dalfox (XSS) ────────────────────────────────────────────────
class TestXssTools:
    def test_literal_vulnerable_marker_is_detected(self):
        out = "[POC] the payload is vulnerable and fired"
        findings = detect("dalfox", out, 'dalfox url "http://juice-shop:3000/?q=1"')
        assert len(findings) == 1
        assert findings[0]["vuln_type"] == "Cross-Site Scripting (XSS)"
        assert "juice-shop" in findings[0]["url"]

    def test_reflected_alone_does_not_trigger(self):
        """Operator-precedence characterization: the trigger is
        `vulnerable OR confirmed OR (reflected AND xss)`, so 'reflected'
        without 'xss' on the same line does NOT emit."""
        out = "the marker was reflected in the response body"
        assert detect("dalfox", out, 'dalfox url "http://x?q=1"') == []

    def test_reflected_and_xss_together_trigger(self):
        out = "reflected context: xss executes here"
        findings = detect("dalfox", out, 'dalfox url "http://x?q=1"')
        assert len(findings) == 1

    @pytest.mark.xfail(strict=True, reason=(
        "Known recall bug (recall roadmap Wave 1 #3): dalfox/xsstrike report "
        "confirmed XSS with [POC]/[VULN]/[G] markers and by echoing the fired "
        "payload, none of which contain the literal words 'vulnerable'/"
        "'confirmed'. These real success signatures are silently dropped. When "
        "the trigger set is broadened this test flips to xpass."))
    def test_poc_marker_should_be_detected(self):
        out = "[POC][G] http://juice-shop:3000/?q=<svg/onload=alert(1)>  grep-verified"
        findings = detect("dalfox", out, 'dalfox url "http://juice-shop:3000/?q=1"')
        assert len(findings) == 1  # DESIRED: a confirmed XSS finding.


# ── curl (multi-pattern) ───────────────────────────────────────────────────
class TestCurl:
    def test_exposed_user_data(self):
        out = '[{"email":"admin@juice-sh.op","password":"0192023a7bbd7325"}]'
        findings = detect("curl", out, "curl -s http://juice-shop:3000/rest/products/reviews")
        assert "Sensitive Data Exposure" in types(findings)

    def test_api_users_broken_access_control(self):
        out = '[{"id":1,"email":"admin@juice-sh.op"},{"id":2,"email":"jim@juice-sh.op"}]'
        findings = detect("curl", out, "curl http://juice-shop:3000/api/Users")
        assert "Broken Access Control" in types(findings)
        bac = next(f for f in findings if f["vuln_type"] == "Broken Access Control")
        assert bac["severity"] == "high"

    def test_cors_wildcard(self):
        # No `curl -s ... -I` so the missing-headers branch stays out of the way.
        out = "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *\n"
        findings = detect("curl", out, 'curl http://juice-shop:3000/ -H "Origin: x"')
        assert types(findings) == ["CORS Misconfiguration"]
        assert findings[0]["severity"] == "medium"

    def test_cors_reflected_arbitrary_origin_is_high(self):
        out = "Access-Control-Allow-Origin: https://evil.test\n"
        findings = detect("curl", out, 'curl http://juice-shop:3000/ -H "Origin: https://evil.test"')
        assert findings[0]["vuln_type"] == "CORS Misconfiguration"
        assert findings[0]["severity"] == "high"

    def test_missing_security_headers(self):
        out = "HTTP/1.1 200 OK\nContent-Type: text/html\nDate: today\n"
        findings = detect("curl", out, "curl -s -I http://juice-shop:3000/")
        assert "Security Misconfiguration" in types(findings)

    def test_open_redirect(self):
        out = "HTTP/1.1 302 Found\nLocation: http://evil.test/\n"
        # Avoid `curl -s ... -I` to isolate the redirect finding.
        findings = detect("curl", out, 'curl "http://juice-shop:3000/redirect?to=http://evil.test"')
        assert types(findings) == ["Open Redirect"]
        assert findings[0]["parameter"] == "to"

    def test_plain_500_without_leak_is_not_a_finding(self):
        out = "HTTP/1.1 500 Internal Server Error\n\nInternal Server Error"
        assert detect("curl", out, "curl http://juice-shop:3000/boom") == []

    def test_stack_trace_disclosure(self):
        out = "Error: boom\n    at /juice-shop/routes/order.js:42:13\n"
        findings = detect("curl", out, "curl http://juice-shop:3000/boom")
        assert "Information Disclosure" in types(findings)


# ── jwt_tool ────────────────────────────────────────────────────────────────
class TestJwtTool:
    def test_secret_cracked(self):
        out = "[+] secret key found: secretkey123"
        findings = detect("jwt_tool", out)
        assert len(findings) == 1
        assert findings[0]["vuln_type"] == "Broken Authentication"
        assert findings[0]["severity"] == "critical"

    def test_none_algorithm_accepted(self):
        out = "Testing none algorithm... token accepted by server (bypass successful)"
        findings = detect("jwt_tool", out)
        assert any("none algorithm" in f["evidence"].lower() for f in findings)

    @pytest.mark.xfail(strict=True, reason=(
        "Known precision risk (recall roadmap Wave 1 #11): the weak-secret "
        "branch fires on a bare 'found' anywhere in output, so ordinary banner "
        "text like 'Token found in header' emits a false Broken Authentication "
        "finding. Desired behaviour: no finding without an actual crack. When "
        "the trigger is tightened this flips to xpass."))
    def test_banner_found_should_not_emit(self):
        out = "Token found in header. Analysing claims..."
        assert detect("jwt_tool", out) == []  # DESIRED: no false positive.


# ── hydra / nikto / commix ──────────────────────────────────────────────────
class TestOtherTools:
    def test_hydra_success(self):
        out = "[80][http-post-form] host: 10.0.0.1   login: admin   password: admin123"
        findings = detect("hydra", out)
        assert len(findings) == 1
        assert findings[0]["vuln_type"] == "Broken Authentication"

    def test_nikto_finding(self):
        out = "+ OSVDB-3092: /admin/: This might be interesting.\n+ Server: Apache"
        findings = detect("nikto", out)
        assert len(findings) == 1
        assert findings[0]["vuln_type"] == "Nikto Finding"

    def test_commix_injectable(self):
        out = "(!) The (GET) parameter 'x' seems injectable."
        findings = detect("commix", out, 'commix -u "http://x?x=1"')
        assert findings[0]["vuln_type"] == "Command Injection"
        assert findings[0]["severity"] == "critical"


# ── zap-cli (JSON alerts) ────────────────────────────────────────────────────
class TestZapCli:
    def test_medium_plus_alerts_emit_low_ignored(self):
        payload = {"alerts": [
            {"risk": "High", "name": "SQL Injection", "url": "http://x/a", "param": "id"},
            {"risk": "Low", "name": "Cookie No HttpOnly", "url": "http://x/b"},
        ]}
        findings = detect("zap-cli", json.dumps(payload))
        assert types(findings) == ["SQL Injection"]

    def test_duplicate_alerts_deduped(self):
        payload = {"alerts": [
            {"risk": "High", "name": "XSS", "url": "http://x/a"},
            {"risk": "High", "name": "XSS", "url": "http://x/a"},
        ]}
        assert len(detect("zap-cli", json.dumps(payload))) == 1

    def test_alert_evidence_and_description_are_included(self):
        payload = {"alerts": [{
            "risk": "Medium", "name": "CSP Missing", "url": "http://x/a",
            "evidence": "no Content-Security-Policy header",
            "description": "Content Security Policy is not set",
        }]}
        f = detect("zap-cli", json.dumps(payload))[0]
        assert "no Content-Security-Policy header" in f["evidence"]
        assert "Content Security Policy is not set" in f["evidence"]

    def test_non_json_output_is_safe(self):
        assert detect("zap-cli", "Spider progress: 42%") == []


# ── curl: access-control / exposure branches (full-coverage additions) ──────
class TestCurlAccessControl:
    def test_idor_basket(self):
        out = '{"status":"success","data":{"products":[{"id":1,"name":"Apple Juice"}]}}'
        findings = detect("curl", out, "curl http://juice-shop:3000/rest/basket/2")
        bac = next(f for f in findings if f["vuln_type"] == "Broken Access Control")
        assert bac["severity"] == "critical"
        assert "basket 2" in bac["evidence"]

    def test_idor_order_via_products(self):
        out = '{"orderId":"abc","products":[{"name":"apple"}]}'
        findings = detect("curl", out, "curl http://juice-shop:3000/api/orders/abc")
        assert "Broken Access Control" in types(findings)

    @pytest.mark.xfail(strict=True, reason=(
        "Latent bug (main.py:858): the clause `'\"totalPrice\"' in output_lower` "
        "compares a mixed-case literal against output that was already "
        "lowercased at line 813, so it can never match — an order response whose "
        "only IDOR signal is totalPrice is silently missed; only a '\"products\"' "
        "key triggers the finding. Flips to xpass when the literal is lowercased."))
    def test_idor_order_via_totalprice_only(self):
        out = '{"orderId":"abc","totalPrice":42.5}'
        findings = detect("curl", out, "curl http://juice-shop:3000/api/orders/abc")
        assert "Broken Access Control" in types(findings)  # DESIRED

    def test_sql_injection_login_bypass(self):
        out = '{"authentication":{"token":"eyJ0eXA00000000000000000000abcDEF","bid":1}}'
        cmd = "curl -X POST http://juice-shop:3000/rest/user/login -d \"email=' or 1=1--&password=x\""
        findings = detect("curl", out, cmd)
        f = next(x for x in findings if x["vuln_type"] == "SQL Injection")
        assert f["severity"] == "critical"
        assert f["parameter"] == "email"

    def test_forged_feedback_userid(self):
        out = '{"data":{"UserId":2,"comment":"nice","rating":5}}'
        cmd = 'curl -X POST http://juice-shop:3000/api/feedbacks -d "{...}"'
        findings = detect("curl", out, cmd)
        assert "Broken Access Control" in types(findings)


class TestCurlExposure:
    def test_server_header_disclosure(self):
        out = "HTTP/1.1 200 OK\nX-Powered-By: Express\n"
        findings = detect("curl", out, "curl http://juice-shop:3000/")
        assert "Information Disclosure" in types(findings)

    def test_swagger_api_docs_exposed(self):
        out = '{"openapi":"3.0.0","paths":{"/rest":{}}}'
        findings = detect("curl", out, "curl http://juice-shop:3000/api-docs")
        assert "Security Misconfiguration" in types(findings)

    def test_metrics_endpoint_exposed(self):
        out = "process_cpu_seconds_total 1.23\nnodejs_heap_size_total_bytes 100"
        findings = detect("curl", out, "curl http://juice-shop:3000/metrics")
        f = next(x for x in findings if x["vuln_type"] == "Security Misconfiguration")
        assert f["severity"] == "low"

    def test_ftp_directory_listing(self):
        out = '<a href="acquisitions.md">acquisitions.md</a>'
        findings = detect("curl", out, "curl http://juice-shop:3000/ftp")
        assert "Sensitive Data Exposure" in types(findings)

    def test_null_byte_bypass(self):
        out = '{"name":"juice-shop","version":"1.0","deps":{"a":"1","b":"2","c":"3"}}'
        cmd = 'curl "http://juice-shop:3000/ftp/package.json.bak%2500.md"'
        findings = detect("curl", out, cmd)
        f = next(x for x in findings if x["vuln_type"] == "Sensitive Data Exposure")
        assert f["severity"] == "high"


# ── unhandled tools / empty output ──────────────────────────────────────────
class TestNoOp:
    def test_unregistered_tool_returns_empty(self):
        assert detect("whatweb", "WordPress 6.1 detected", "whatweb http://x") == []

    def test_empty_output_returns_empty(self):
        for tool in ("sqlmap", "nuclei", "curl", "dalfox", "jwt_tool", "hydra"):
            assert detect(tool, "", "") == []
