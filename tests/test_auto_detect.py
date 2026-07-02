"""Characterization tests for _auto_detect_findings (main.py ~730).

This is the programmatic, evidence-gated finding emitter — the reason erlik's
precision is model-independent (97-99%) and, equally, the main place recall is
lost (a tool whose output has no matching pattern emits nothing). These tests
lock the per-tool behaviour so the planned refactor into a declarative rule
table cannot change what counts as a finding.

Three defects surfaced by the recall audit have now been fixed and are pinned
here as regression tests (dalfox [POC]/[VULN]/'triggered' markers detected;
jwt_tool no longer fires on a bare 'found'; the /api/orders totalPrice clause
is case-correct). Each fix keeps a companion precision-guard test so the
broadened/tightened trigger cannot regress in the other direction.
"""

import json

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

    def test_poc_marker_is_detected(self):
        """Fixed (recall roadmap Wave 1 #3): dalfox confirms hits with [POC]/
        [VULN]/'triggered' markers, which are now recognised."""
        out = "[POC][G] http://juice-shop:3000/?q=<svg/onload=alert(1)>  grep-verified"
        findings = detect("dalfox", out, 'dalfox url "http://juice-shop:3000/?q=1"')
        assert len(findings) == 1
        assert findings[0]["vuln_type"] == "Cross-Site Scripting (XSS)"

    def test_benign_output_still_does_not_trigger(self):
        """Precision guard: the broadened marker set must not fire on ordinary
        scan chatter that carries none of the success tokens."""
        out = "Scanning parameter q ...\n0 potential issues after analysis"
        assert detect("dalfox", out, 'dalfox url "http://x?q=1"') == []


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

    def test_banner_found_does_not_emit(self):
        """Fixed (recall roadmap Wave 1 #11): a bare 'found' in banner text no
        longer triggers a phantom Broken Authentication finding."""
        out = "Token found in header. Analysing claims..."
        assert detect("jwt_tool", out) == []

    def test_correct_key_crack_is_detected(self):
        """The tightened trigger still catches a real crack via 'correct key'."""
        out = "[+] secretkey123 is the CORRECT key!"
        findings = detect("jwt_tool", out)
        assert len(findings) == 1
        assert findings[0]["vuln_type"] == "Broken Authentication"


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

    def test_idor_order_via_totalprice_only(self):
        """Fixed (main.py:858): the totalPrice clause is now lowercased, so an
        order response whose only IDOR signal is totalPrice is detected."""
        out = '{"orderId":"abc","totalPrice":42.5}'
        findings = detect("curl", out, "curl http://juice-shop:3000/api/orders/abc")
        assert "Broken Access Control" in types(findings)

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


# ── precision fall-throughs (a matched outer condition that must NOT emit) ──
class TestDetectorNegatives:
    def test_cors_specific_origin_not_flagged(self):
        """ACAO present but reflecting a specific, non-evil origin is not the
        wildcard/arbitrary-reflection bug — no finding."""
        out = "Access-Control-Allow-Origin: https://trusted.example.com\n"
        findings = detect("curl", out, 'curl http://juice-shop:3000/ -H "Origin: y"')
        assert "CORS Misconfiguration" not in types(findings)

    def test_all_security_headers_present_no_finding(self):
        out = ("HTTP/1.1 200 OK\nContent-Security-Policy: default-src 'self'\n"
               "X-Frame-Options: DENY\nStrict-Transport-Security: max-age=1\n"
               "X-Content-Type-Options: nosniff\n")
        assert detect("curl", out, "curl -s -I http://juice-shop:3000/") == []

    def test_redirect_to_internal_not_flagged(self):
        """A 302 to an in-scope juice-shop location is not an open redirect."""
        out = "HTTP/1.1 302 Found\nLocation: http://juice-shop:3000/#/\n"
        findings = detect("curl", out, 'curl "http://juice-shop:3000/redirect?to=/"')
        assert "Open Redirect" not in types(findings)

    def test_commix_no_injection(self):
        assert detect("commix", "No injection point found.", 'commix -u "http://x?x=1"') == []


# ── unhandled tools / empty output ──────────────────────────────────────────
class TestNoOp:
    def test_unregistered_tool_returns_empty(self):
        assert detect("whatweb", "WordPress 6.1 detected", "whatweb http://x") == []

    def test_empty_output_returns_empty(self):
        for tool in ("sqlmap", "nuclei", "curl", "dalfox", "jwt_tool", "hydra"):
            assert detect(tool, "", "") == []
