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

    def test_cors_bare_wildcard_is_not_a_finding(self):
        """A bare ACAO:* is how you correctly serve a public API — browsers refuse
        to send credentials to a wildcard, so nothing private can be read. This
        used to emit MEDIUM and produced 12 false findings across an 18-run sweep,
        because Juice Shop sets it on its public root."""
        out = "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *\n"
        findings = detect("curl", out, 'curl http://juice-shop:3000/ -H "Origin: x"')
        assert "CORS Misconfiguration" not in types(findings)

    def test_cors_wildcard_with_credentials_is_low(self):
        """Browsers block this pair, so it is not exploitable — but it shows the
        origin check was meant to be permissive."""
        out = ("HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *\n"
               "Access-Control-Allow-Credentials: true\n")
        findings = detect("curl", out, 'curl http://juice-shop:3000/ -H "Origin: x"')
        f = next(f for f in findings if f["vuln_type"] == "CORS Misconfiguration")
        assert f["severity"] == "low"

    def test_cors_reflected_origin_with_credentials_is_high(self):
        """Reflection PLUS credentials is the exploitable case: any site can read
        authenticated responses."""
        out = ("Access-Control-Allow-Origin: https://evil.test\n"
               "Access-Control-Allow-Credentials: true\n")
        findings = detect("curl", out,
                          'curl http://juice-shop:3000/ -H "Origin: https://evil.test"')
        f = next(f for f in findings if f["vuln_type"] == "CORS Misconfiguration")
        assert f["severity"] == "high"

    def test_cors_reflected_origin_without_credentials_is_low(self):
        """Without credentials the attacker reads only what any anonymous client
        could already fetch, so this is not high severity."""
        out = "Access-Control-Allow-Origin: https://evil.test\n"
        findings = detect("curl", out,
                          'curl http://juice-shop:3000/ -H "Origin: https://evil.test"')
        f = next(f for f in findings if f["vuln_type"] == "CORS Misconfiguration")
        assert f["severity"] == "low"

    def test_cors_null_origin_with_credentials_is_high(self):
        """A sandboxed iframe or redirect chain can obtain a null origin."""
        out = ("Access-Control-Allow-Origin: null\n"
               "Access-Control-Allow-Credentials: true\n")
        findings = detect("curl", out, 'curl http://juice-shop:3000/ -H "Origin: null"')
        f = next(f for f in findings if f["vuln_type"] == "CORS Misconfiguration")
        assert f["severity"] == "high"

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

    def test_hydra_failed_run_no_false_finding(self):
        """A hydra run that couldn't even connect must not emit a finding — its
        progress/error lines contain 'login:'/'host:' but no cracked credential
        (regression from a real run log that falsely reported Broken Auth)."""
        out = ("[DATA] attacking http-post-form://[localhost:3000]:80/login:user=^USER^&pass=^PASS^:Invalid\n"
               "0 of 1 target completed, 0 valid password found\n"
               "[ERROR] could not resolve address: localhost:3000")
        assert detect("hydra", out) == []

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
        # Versioned on purpose: a BARE product name is the hardened config
        # and no longer reported. See TestBannerNeedsAVersion.
        out = "HTTP/1.1 200 OK\nX-Powered-By: Express 4.17.1\n"
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


# ── content discovery (gobuster / ffuf / dirb / wfuzz) ──────────────────────
class TestContentDiscovery:
    def test_gobuster_sensitive_paths(self):
        out = (
            "===============================================================\n"
            "/ftp                  (Status: 200) [Size: 1234]\n"
            "/api-docs             (Status: 200) [Size: 5678]\n"
            "/metrics              (Status: 200) [Size: 900]\n"
            "/about                (Status: 200) [Size: 100]\n"
            "/admin                (Status: 403) [Size: 50]\n"
        )
        findings = detect("gobuster", out, "gobuster dir -u http://juice-shop:3000 -w /w.txt")
        by_type = {f["vuln_type"]: f for f in findings}
        assert set(by_type) == {"Sensitive Data Exposure", "Security Misconfiguration"}
        # /ftp + /api-docs + /metrics = 3 findings; /about not sensitive, /admin 403 skipped
        assert len(findings) == 3
        assert by_type["Sensitive Data Exposure"]["url"] == "http://juice-shop:3000/ftp"
        metrics = next(f for f in findings if "/metrics" in f["url"])
        assert metrics["severity"] == "low"

    def test_ffuf_format(self):
        out = "ftp                     [Status: 200, Size: 1234, Words: 10, Lines: 5]"
        findings = detect("ffuf", out, "ffuf -u http://juice-shop:3000/FUZZ -w /w.txt")
        assert findings[0]["vuln_type"] == "Sensitive Data Exposure"
        assert findings[0]["url"] == "http://juice-shop:3000/ftp"

    def test_dirb_full_url_format(self):
        out = "+ http://juice-shop:3000/ftp (CODE:200|SIZE:1234)"
        findings = detect("dirb", out, "dirb http://juice-shop:3000 /w.txt")
        assert findings[0]["vuln_type"] == "Sensitive Data Exposure"
        assert findings[0]["url"] == "http://juice-shop:3000/ftp"

    def test_robots_txt_is_info_misconfig(self):
        out = "/robots.txt           (Status: 200) [Size: 200]"
        findings = detect("gobuster", out, "gobuster dir -u http://juice-shop:3000 -w /w.txt")
        assert findings[0]["vuln_type"] == "Security Misconfiguration"
        assert findings[0]["severity"] == "info"

    def test_source_map_exposed(self):
        out = "/main-es2015.abc.js.map   (Status: 200) [Size: 99999]"
        findings = detect("gobuster", out, "gobuster dir -u http://juice-shop:3000 -w /w.txt")
        assert findings[0]["vuln_type"] == "Sensitive Data Exposure"
        assert ".map" in findings[0]["evidence"]

    def test_protected_and_nonsensitive_paths_ignored(self):
        out = (
            "/ftp        (Status: 403) [Size: 50]\n"     # protected -> not an exposure
            "/login      (Status: 200) [Size: 100]\n"    # not sensitive
            "/ftpfiles   (Status: 200) [Size: 100]\n"    # segment guard: not '/ftp'
        )
        assert detect("gobuster", out, "gobuster dir -u http://juice-shop:3000 -w /w.txt") == []

    def test_decoration_line_with_status_is_skipped(self):
        # Defensive: a banner token that happens to be followed by a status
        # must not become a finding, but a real hit on the same run still does.
        out = "=== (Status: 200) ===\n/ftp        (Status: 200) [Size: 1]"
        findings = detect("gobuster", out, "gobuster dir -u http://x -w /w.txt")
        assert len(findings) == 1
        assert findings[0]["vuln_type"] == "Sensitive Data Exposure"

    def test_duplicate_paths_deduped(self):
        out = (
            "/ftp    (Status: 200) [Size: 1]\n"
            "/ftp    (Status: 200) [Size: 1]\n"
        )
        assert len(detect("gobuster", out, "gobuster dir -u http://x -w /w.txt")) == 1

    def test_findings_match_ground_truth(self):
        """The point of the detector: its findings score as true positives
        against the seeded ground truth (previously a silent miss). robots.txt
        here is GT #23 — one of the never-caught vulns."""
        out = ("/ftp        (Status: 200) [Size: 1]\n"
               "/robots.txt (Status: 200) [Size: 1]\n")
        findings = detect("gobuster", out, "gobuster dir -u http://localhost:3000 -w /w.txt")
        assert len(findings) == 2
        for f in findings:
            r = m._match_finding_to_ground_truth_scored(f, m.JUICE_SHOP_GROUND_TRUTH)
            assert r["match"], f"{f['vuln_type']} {f['url']} did not match GT"


# ── unhandled tools / empty output ──────────────────────────────────────────
class TestNoOp:
    def test_unregistered_tool_returns_empty(self):
        assert detect("whatweb", "WordPress 6.1 detected", "whatweb http://x") == []

    def test_empty_output_returns_empty(self):
        for tool in ("sqlmap", "nuclei", "curl", "dalfox", "jwt_tool", "hydra"):
            assert detect(tool, "", "") == []


class TestHeaderFlagIsAnchored:
    """`_curl_missing_headers` gates on whether the operator ASKED for headers.

    That gate was `"-i" in ctx.command` — an unanchored substring — so it
    matched inside ordinary URL text: `sign-in`, `--insecure`,
    `portal-internal`. A body-only fetch was then judged on headers nobody
    requested and reported at MEDIUM, in the largest finding class in the
    recorded corpus. The false-positive cleanroom found three of these on its
    first run.

    Third instance of this defect class in this codebase, after the OAST scope
    markers and the cookie flags — hence an explicit test rather than relying
    on the corpus alone.
    """

    NO_HEADERS = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"

    def _fires(self, command):
        return any(f["vuln_type"] == "Security Misconfiguration"
                   for f in detect("curl", self.NO_HEADERS, command))

    def test_real_header_requests_still_fire(self):
        for cmd in ("curl -s -i https://x.test/",
                    "curl -s -I https://x.test/",
                    "curl -sI https://x.test/",
                    "curl -si https://x.test/",
                    "curl -s --head https://x.test/",
                    "curl -s -I -H 'A: b' https://x.test/"):
            assert self._fires(cmd), f"should fire: {cmd}"

    def test_substring_matches_in_urls_do_not_fire(self):
        for cmd in ("curl -s https://www.acme.example.com/account/sign-in",
                    "curl -s https://inventory.corp.internal/api/v1/inventory --insecure",
                    'curl -s "https://portal-internal.acme-cleanroom.test/healthz"',
                    "curl -s https://x.test/plain",
                    "curl -s https://x.test/e-invoice",
                    "curl -s -H 'X-Test: -i' https://x.test/"):
            assert not self._fires(cmd), f"should NOT fire: {cmd}"

    def test_body_only_fetch_reports_nothing_about_headers(self):
        """The core of it: no header flag means no header evidence exists."""
        assert detect("curl", self.NO_HEADERS,
                      "curl -s https://x.test/account/sign-in") == []


class TestEvidenceGatesHold:
    """Two rules that claimed a finding without evidencing it.

    Both were found by the false-positive cleanroom on benign traffic, and both
    are the module's stated philosophy failing in its own code: this file is
    "evidence-gated vulnerability detection", and each rule reported a
    vulnerability its own evidence did not support.
    """

    def test_user_data_needs_an_actual_record(self):
        """It reported `API exposes user data: 0 user records found` — a claim
        of exposure whose evidence string says nothing was found.

        It fired on any ordinary HTML login form, because `name="email"` and
        `name="password"` put the quoted tokens in the body.
        """
        form = ('<form method="post" action="/account/sign-in">'
                '<input type="email" name="email">'
                '<input type="password" name="password"></form>')
        assert detect("curl", form, "curl -s https://x.test/account/sign-in") == []

    def test_user_data_still_fires_on_a_real_dump(self):
        out = '{"users":[{"email":"a@b.c","password":"x","role":"admin"}]}'
        f = detect("curl", out, "curl -s https://x.test/api/users")
        assert any(x["vuln_type"] == "Sensitive Data Exposure" for x in f)
        assert "1 user records found" in next(
            x["evidence"] for x in f if x["vuln_type"] == "Sensitive Data Exposure")

    def test_asset_path_is_not_a_filesystem_leak(self):
        """`/app/main.js` in a script tag is a URL path. Every SPA serving
        bundles from `/app/` was reported as disclosing server internals."""
        spa = ('HTTP/1.1 200 OK\r\nContent-Security-Policy: default-src \'self\'\r\n'
               'X-Frame-Options: DENY\r\nStrict-Transport-Security: max-age=1\r\n'
               'X-Content-Type-Options: nosniff\r\n\r\n'
               '<script src="/app/main.9c1e.js" defer></script>')
        assert detect("curl", spa, "curl -s -i https://x.test/") == []

    @pytest.mark.parametrize("out", [
        "Error: boom\n    at /juice-shop/routes/order.js:42:13\n",
        "<b>Fatal error</b>: Uncaught Error: x in /var/www/html/index.php on line 12",
        "{'stacktrace': 'at foo'}",
    ])
    def test_real_leaks_still_fire(self, out):
        """A stack marker or a real frame stands alone; a filesystem path
        counts when the response is actually showing an error."""
        f = detect("curl", out, "curl -s https://x.test/boom")
        assert any(x["vuln_type"] == "Information Disclosure" for x in f), out[:40]


class TestDeadDiscoveryPathsNowFire:
    """Two content-discovery branches that could not produce a finding.

    Both were found by the cleanroom's rule-reachability check, which is the
    control that separates "0 false positives" from "0 rules could run".
    """

    def test_wfuzz_native_table_is_parsed(self):
        """wfuzz was in _DETECTORS and routed to _detect_content_discovery, but
        that parser had only gobuster/ffuf/dirb patterns — so the detector was
        registered and structurally incapable of firing."""
        out = '000000123:   200        3 L      12 W       412 Ch      "ftp"\n'
        f = detect("wfuzz", out, "wfuzz -w /w.txt http://t/FUZZ")
        assert f, "wfuzz still cannot fire"
        assert f[0]["detector"] == "wfuzz:_detect_content_discovery"

    def test_wfuzz_colourised_output_is_parsed(self):
        """-c is wfuzz's colourise flag, so real output carries ANSI escapes.
        Adding the table pattern alone would not have been enough."""
        out = '\x1b[0m000000123:\x1b[0m   200   3 L   12 W   412 Ch   "robots.txt"\n'
        assert detect("wfuzz", out, "wfuzz -c -w /w.txt http://t/FUZZ")

    def test_dirb_directory_lines_are_parsed(self):
        """dirb announces DIRECTORIES only on these lines, so a live /ftp/ found
        by dirb was dropped while the same directory found by gobuster was
        reported — a recall gap, not a false positive."""
        f = detect("dirb", "==> DIRECTORY: http://t/ftp/\n", "dirb http://t/ /w.txt")
        assert f and f[0]["vuln_type"] == "Sensitive Data Exposure"

    def test_existing_shapes_are_unaffected(self):
        for tool, out in (("gobuster", "/ftp    (Status: 200) [Size: 1]\n"),
                          ("ffuf", "/ftp   [Status: 200, Size: 1]\n"),
                          ("dirb", "+ http://t/ftp (CODE:200|SIZE:412)\n")):
            assert detect(tool, out, f"{tool} http://t/ -w /w.txt"), tool


class TestOpenRedirectIsOriginBased:
    """The rule's only anti-false-positive guard was the literal string
    `"juice" not in location`, so on any target that is not Juice Shop every
    same-origin redirect under a /redirect path fired — a target-specific check
    in a tool used on real client engagements."""

    @staticmethod
    def _redirect(loc, url="http://clean.test/redirect?url=/dash"):
        out = (f"HTTP/1.1 302 Found\r\nLocation: {loc}\r\n"
               "Content-Security-Policy: x\r\nX-Frame-Options: DENY\r\n"
               "Strict-Transport-Security: m\r\nX-Content-Type-Options: nosniff\r\n\r\n")
        return [f for f in detect("curl", out, f"curl -s -i '{url}'")
                if f["vuln_type"] == "Open Redirect"]

    @pytest.mark.parametrize("loc", [
        "/dashboard",                       # relative: same origin by definition
        "http://clean.test/dashboard",
        "https://clean.test/x",             # scheme change, same host
        "http://app.clean.test/x",          # subdomain
    ])
    def test_same_origin_does_not_fire(self, loc):
        assert self._redirect(loc) == []

    @pytest.mark.parametrize("loc", ["http://evil.example/",
                                     "https://attacker.test/steal"])
    def test_off_origin_fires(self, loc):
        assert self._redirect(loc)

    def test_juice_shop_is_no_longer_special_cased(self):
        j = "http://juice-shop:3000/redirect?to=x"
        assert self._redirect("http://juice-shop:3000/x", j) == []
        assert self._redirect("http://evil.example/", j)


class TestRefusedAttacksAreNotFindings:
    """The single largest false-positive source: no rule checked the HTTP status.

    A 401, 403 or 429 was treated exactly like a 200, so a CORRECTLY REFUSED
    attack was reported as a successful one — including "SQL injection on login:
    server returned JWT token" printed against a 401 whose body was
    `"token": null`. The cleanroom found 9 CRITICAL and 11 HIGH findings on a
    clean target this way.
    """

    OK = "HTTP/1.1 200 OK\r\n\r\n"

    @pytest.mark.parametrize("status", ["401 Unauthorized", "403 Forbidden",
                                        "429 Too Many Requests"])
    def test_refused_login_is_not_sql_injection(self, status):
        out = (f"HTTP/1.1 {status}\r\n\r\n"
               '{"authentication":{"token":null},"error":"Invalid credentials"}')
        cmd = "curl -s -i -X POST -d \"email=a' or 1=1--\" http://t/rest/user/login"
        assert [f for f in detect("curl", out, cmd)
                if f["vuln_type"] == "SQL Injection"] == []

    def test_successful_bypass_still_fires(self):
        out = (self.OK + '{"authentication":{"token":'
               '"eyJhbGciOiJIUzI1NiJ9.abcdefghijklmnopqrst"}}')
        cmd = "curl -s -i -X POST -d \"email=a' or 1=1--\" http://t/rest/user/login"
        assert [f for f in detect("curl", out, cmd)
                if f["vuln_type"] == "SQL Injection"]

    def test_legitimate_login_is_not_sql_injection(self):
        """No payload in the command at all — an ordinary successful login."""
        out = self.OK + '{"authentication":{"token":"eyJhbGciOiJIUzI1NiJ9.abcdefghij"}}'
        cmd = 'curl -s -i -X POST -d "email=user@corp.test&password=hunter2" http://t/rest/user/login'
        assert [f for f in detect("curl", out, cmd)
                if f["vuln_type"] == "SQL Injection"] == []

    def test_refused_basket_read_is_not_idor(self):
        """The access check WORKING was reported as CRITICAL broken access
        control — the most expensive false positive in the corpus."""
        out = 'HTTP/1.1 403 Forbidden\r\n\r\n{"error":"not yours","products":[]}'
        assert [f for f in detect("curl", out, "curl -s -i http://t/rest/basket/12")
                if f["vuln_type"] == "Broken Access Control"] == []

    def test_granted_basket_read_still_fires(self):
        out = self.OK + '{"products":[{"id":1}]}'
        assert [f for f in detect("curl", out, "curl -s -i http://t/rest/basket/12")
                if f["vuln_type"] == "Broken Access Control"]

    def test_401_challenge_is_not_user_enumeration(self):
        out = ('HTTP/1.1 401 Unauthorized\r\n\r\n'
               '{"detail":"auth required","contact":{"email":"support@t"}}')
        assert [f for f in detect("curl", out, "curl -s -i http://t/api/users")
                if f["vuln_type"] == "Broken Access Control"] == []

    def test_self_service_endpoint_is_not_enumeration(self):
        """/api/users/me with the caller's OWN token returns one record — theirs."""
        out = self.OK + '{"email":"me@corp.test","id":8841}'
        assert [f for f in detect("curl", out, "curl -s -i http://t/api/users/me")
                if f["vuln_type"] == "Broken Access Control"] == []

    def test_sort_param_is_not_a_post(self):
        """`"POST" in command.upper()` matched `?sort=postedAt` — a plain GET
        read as a forged write."""
        out = self.OK + '{"data":[{"UserId":1}]}'
        assert [f for f in detect("curl", out,
                                  "curl -s -i http://t/api/feedbacks?sort=postedAt")
                if f["vuln_type"] == "Broken Access Control"] == []

    def test_commix_negative_result_is_not_command_injection(self):
        """"does not seem to be injectable" contains "injectable"."""
        out = "[!] Warning: The (GET) parameter 'host' does not seem to be injectable."
        assert detect("commix", out, "commix -u http://t/p?host=1") == []

    def test_commix_positive_still_fires(self):
        out = "[+] The (GET) parameter 'host' is injectable."
        assert detect("commix", out, "commix -u http://t/p?host=1")

    def test_rejected_null_byte_is_not_a_bypass(self):
        out = ('HTTP/1.1 400 Bad Request\r\n\r\n'
               '{"detail":"The supplied filename is invalid and was rejected."}')
        assert [f for f in detect("curl", out, "curl -s -i http://t/d?name=r%00.pdf")
                if f["detector"] == "curl:_curl_null_byte"] == []

    def test_served_file_after_null_byte_still_fires(self):
        out = "HTTP/1.1 200 OK\r\n\r\n" + "A" * 400
        assert [f for f in detect("curl", out, "curl -s -i http://t/d?name=r%00.pdf")
                if f["detector"] == "curl:_curl_null_byte"]

    def test_unknown_status_preserves_old_behaviour(self):
        """A curl without -i captures no status line. Those rules must behave
        exactly as before rather than going silent."""
        out = '{"products":[{"id":1}]}'
        assert [f for f in detect("curl", out, "curl -s http://t/rest/basket/12")
                if f["vuln_type"] == "Broken Access Control"]


class TestBannerNeedsAVersion:
    """A product name alone tells an attacker nothing they could not guess; a
    VERSION is what maps to a CVE list. The rule reported bare `Server: nginx`
    — the hardened configuration, with the version deliberately suppressed — as
    Information Disclosure."""

    def _fire(self, hdr):
        out = f"HTTP/1.1 200 OK\r\n{hdr}\r\n\r\n{{}}"
        return [f for f in detect("curl", out, "curl -s -i https://t/")
                if f["detector"] == "curl:_curl_server_header"]

    @pytest.mark.parametrize("hdr", ["Server: nginx", "X-Powered-By: Express"])
    def test_bare_product_name_is_silent(self, hdr):
        assert self._fire(hdr) == []

    @pytest.mark.parametrize("hdr", ["Server: nginx/1.18.0",
                                     "X-Powered-By: Express 4.17.1",
                                     "X-Powered-By: PHP/8.1.2"])
    def test_versioned_banner_fires(self, hdr):
        assert self._fire(hdr)


class TestHeadersJudgedAgainstTheResponse:
    """A header is only "missing" if it would have done something here. The rule
    judged every response against all four regardless of what it was."""

    def _missing(self, out, url="https://t/"):
        return [f for f in detect("curl", out, f"curl -s -i {url}")
                if f["detector"] == "curl:_curl_missing_headers"]

    def test_json_api_is_not_missing_csp_or_xfo(self):
        """CSP and X-Frame-Options defend a rendered document. They do nothing
        for an application/json body."""
        out = ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
               "X-Content-Type-Options: nosniff\r\n"
               "Strict-Transport-Security: max-age=1\r\n\r\n{}")
        assert self._missing(out) == []

    def test_json_api_still_needs_nosniff(self):
        out = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
        assert self._missing(out)

    def test_html_document_still_needs_csp(self):
        out = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>"
        assert self._missing(out)

    def test_hsts_is_not_expected_over_plain_http(self):
        """HSTS on an http:// origin is inert — browsers ignore it."""
        out = ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
               "X-Content-Type-Options: nosniff\r\n\r\n{}")
        assert self._missing(out, "http://intranet/") == []

    def test_empty_redirect_is_not_judged(self):
        """The canonical scheme upgrade has no body to protect."""
        out = "HTTP/1.1 301 Moved Permanently\r\nLocation: https://t/\r\n\r\n"
        assert self._missing(out, "http://t/") == []


class TestProfileIsNotADump:
    """A self-service endpoint returns the CALLER'S OWN record — the feature,
    not a leak. It fired on /api/users/me and on a legitimate login response."""

    def _fire(self, out, url):
        return [f for f in detect("curl", out, f"curl -s -i {url}")
                if f["detector"] == "curl:_curl_exposed_user_data"]

    @pytest.mark.parametrize("path", ["/api/users/me", "/api/profile",
                                      "/rest/user/login", "/api/session"])
    def test_self_service_paths_are_silent(self, path):
        out = 'HTTP/1.1 200 OK\r\n\r\n{"email":"a@b.c","role":"eng"}'
        assert self._fire(out, f"https://t{path}") == []

    def test_single_record_without_a_credential_is_not_exposure(self):
        out = 'HTTP/1.1 200 OK\r\n\r\n{"email":"a@b.c","role":"eng"}'
        assert self._fire(out, "https://t/api/users/1") == []

    def test_single_record_WITH_a_password_still_fires(self):
        out = 'HTTP/1.1 200 OK\r\n\r\n{"email":"a@b.c","password":"x"}'
        assert self._fire(out, "https://t/api/users/1")

    def test_multi_record_dump_still_fires(self):
        out = ('HTTP/1.1 200 OK\r\n\r\n[{"email":"a@b.c","role":"x"},'
               '{"email":"d@e.f","role":"y"}]')
        assert self._fire(out, "https://t/api/users")


class TestToolHedgesAreAuthoritative:
    """Four rules ignored the tool's OWN statement that it had not found
    anything. Each is the same shape as the commix "does not seem to be
    injectable" bug: erlik heard yes where the tool said no."""

    def test_sqlmap_false_positive_warning_is_honoured(self):
        out = ("sqlmap identified the following injection point:\nParameter: q\n"
               "[!] the back-end DBMS is not confirmed, this might be a false positive")
        assert detect("sqlmap", out, "sqlmap -u http://t/?q=1") == []

    def test_sqlmap_confirmed_injection_still_fires(self):
        out = ("sqlmap identified the following injection point:\nParameter: q (GET)\n"
               "    Type: boolean-based blind\nback-end DBMS: SQLite\n")
        assert detect("sqlmap", out, "sqlmap -u http://t/?q=1")

    def test_dalfox_encoded_reflection_is_not_xss(self):
        """The defence WORKING, reported as XSS: the line says the payload is
        inert, but it contains both 'reflected' and 'xss'."""
        out = ("[I] Reflected parameter q is HTML-entity encoded in the response, "
               "so the injected payload is inert and no XSS is possible here")
        assert detect("dalfox", out, "dalfox url http://t/") == []

    def test_marker_inside_the_target_url_is_not_a_result(self):
        """`/orders/confirmed` supplied the word 'confirmed' from _XSS_MARKERS."""
        out = ("[~] Testing parameter ref of https://shop.test/orders/confirmed?ref=A1\n"
               "[!] Reflections found: 0\n[-] No vectors found.")
        assert detect("xsstrike", out,
                      "xsstrike -u https://shop.test/orders/confirmed?ref=A1") == []

    def test_advisory_page_prose_is_not_xss(self):
        """A trust page saying 'not vulnerable to CVE-...' is not a finding."""
        out = ("[D] response snippet: <p>Our checkout service is not vulnerable to "
               "CVE-2024-1086; see the advisory below.</p>")
        assert detect("dalfox", out, "dalfox url http://t/") == []

    def test_real_xss_poc_still_fires(self):
        assert detect("dalfox", "[POC][R] http://t/?q=<script>alert(1)</script> triggered",
                      "dalfox url http://t/")

    def test_jwt_rejected_variants_are_not_a_bypass(self):
        """Two UNCORRELATED substring checks over the whole output: 'alg:none'
        supplied the 'none' and an unrelated line supplied the 'success', so a
        correct RS256 verifier was reported as CRITICAL broken authentication."""
        out = ("[*] Running 'alg:none' variant checks...\n"
               "[-] alg:none    - server returned 401, token rejected\n"
               "[*] Scan complete - success")
        assert detect("jwt_tool", out, "jwt_tool -t http://t/") == []

    def test_jwt_accepted_none_still_fires(self):
        out = "[+] alg:none  - server ACCEPTED the unsigned token (200 OK)"
        assert detect("jwt_tool", out, "jwt_tool -t http://t/")

    def test_zap_low_confidence_alert_is_skipped(self):
        """ZAP publishes its own confidence and erlik ignored it, promoting a
        heuristic ZAP itself distrusts to a HIGH finding."""
        import json as _j
        out = _j.dumps({"alerts": [{"risk": "High", "confidence": "Low",
                                    "name": "SQL Injection", "url": "http://t/",
                                    "alert": "SQL Injection"}]})
        assert detect("zap-cli", out, "zap-cli alerts http://t/") == []

    def test_zap_high_confidence_alert_still_fires(self):
        import json as _j
        out = _j.dumps({"alerts": [{"risk": "High", "confidence": "High",
                                    "name": "SQL Injection", "url": "http://t/",
                                    "alert": "SQL Injection"}]})
        assert detect("zap-cli", out, "zap-cli alerts http://t/")
