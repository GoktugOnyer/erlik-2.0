"""The false-positive cleanroom harness.

Against a clean target, any finding is BY DEFINITION a false positive — no
matcher, no threshold, no judgement. That is worth having because erlik's
recorded precision is partly matcher leniency:
`_match_finding_to_ground_truth_scored` awards type +1, url:generic +0.5 and
param:generic +0.5, totalling exactly the 2.0 threshold, so a finding whose only
correct attribute is its class name already scores as a true positive.

The single most important failure mode of this instrument is reporting
"0 false positives" when the truth is "0 rules could run". Every test here
exists to keep those two distinguishable.
"""

import pytest

from orchestrator.bench import cleanroom as C


def fx(route, zone, tool, command, response, expected=()):
    return C.Fixture(route=route, zone=zone, tool=tool, command=command,
                     response=response,
                     expected=tuple(tuple(sorted(e.items())) for e in expected))


CORS_RESPONSE = ("HTTP/1.1 200 OK\r\n"
                 "Access-Control-Allow-Origin: *\r\n"
                 "Access-Control-Allow-Credentials: true\r\n\r\n")


class TestZeroIsNeverReportedAlone:
    def test_empty_corpus_reports_zero_rules_exercised(self):
        """An empty corpus emits 0 false positives. It must simultaneously
        report 0/28 rules exercised, or that 0 reads as a clean bill of health
        when it is an empty test."""
        rep = C.measure([])
        assert rep.false_positives == 0
        assert rep.exercised == []
        assert len(rep.unreachable) == len(C.all_rule_names())

    def test_report_text_shows_both_numbers(self):
        out = C.format_report(C.measure([]))
        assert "false positives     0" in out
        assert "rules exercised     0/" in out

    def test_rule_inventory_is_derived_not_hardcoded(self):
        """A hardcoded list silently stops covering a rule added later."""
        from orchestrator import detection as D
        names = C.all_rule_names()
        assert len(names) == len(set(names))
        for r in D._CURL_RULES:
            assert f"curl:{r.__name__}" in names
        assert "gobuster:_detect_content_discovery" in names
        # _detect_curl is a dispatcher, not a leaf detector
        assert not any(n.endswith(":_detect_curl") for n in names)


class TestExpectedSetEquality:
    """Zone A fixtures are EXPECTED to fire — their emissions ARE the measured
    false positives. `assert findings == []` over them either fails on day one
    or gets neutered into a test that passes with detection.py deleted."""

    def test_matching_expectation_is_not_a_mismatch(self):
        got = C._emit(fx("/public/api", "A", "curl",
                         "curl -s -i http://clean:8080/public/api", CORS_RESPONSE))
        assert got, "fixture must actually fire for this test to mean anything"
        f = fx("/public/api", "A", "curl",
               "curl -s -i http://clean:8080/public/api", CORS_RESPONSE,
               expected=[{"vuln_type": g["vuln_type"], "severity": g["severity"],
                          "detector": g["detector"]} for g in got])
        rep = C.measure([f])
        assert rep.mismatches == []
        assert rep.false_positives == len(got)

    def test_drift_from_recorded_expectation_is_caught(self):
        """If a detector changes behaviour, the corpus must fail loudly rather
        than silently re-baselining."""
        f = fx("/public/api", "A", "curl",
               "curl -s -i http://clean:8080/public/api", CORS_RESPONSE,
               expected=[{"vuln_type": "Nonexistent Class", "severity": "low",
                          "detector": "curl:_curl_nothing"}])
        rep = C.measure([f])
        assert len(rep.mismatches) == 1
        assert rep.mismatches[0]["route"] == "/public/api"

    def test_zone_b_findings_are_counted_separately(self):
        """A Zone B emission is an unambiguous false positive — no collision
        story explains it."""
        f = fx("/public/api", "B", "curl",
               "curl -s -i http://clean:8080/public/api", CORS_RESPONSE,
               expected=[])
        rep = C.measure([f])
        assert rep.zone_b_findings > 0
        assert rep.clean is False


class TestDedupMatchesPersistence:
    def test_repeated_vuln_type_and_url_counts_once(self):
        """main.py dedups on (vuln_type, url) before persisting. Without
        replicating it the headline scales with probe-list length rather than
        with erlik's actual behaviour."""
        cmd = "curl -s -i http://clean:8080/public/api"
        got = C._emit(fx("r", "A", "curl", cmd, CORS_RESPONSE))
        exp = [{"vuln_type": g["vuln_type"], "severity": g["severity"],
                "detector": g["detector"]} for g in got]
        two = [fx("r1", "A", "curl", cmd, CORS_RESPONSE, exp),
               fx("r2", "A", "curl", cmd, CORS_RESPONSE, exp)]
        rep = C.measure(two)
        assert rep.mismatches == []
        assert rep.false_positives == len(got), "same (vuln_type, url) double-counted"

    def test_different_urls_count_separately(self):
        a = "curl -s -i http://clean:8080/a"
        b = "curl -s -i http://clean:8080/b"
        ga, gb = C._emit(fx("a", "A", "curl", a, CORS_RESPONSE)), C._emit(fx("b", "A", "curl", b, CORS_RESPONSE))
        mk = lambda g: [{"vuln_type": x["vuln_type"], "severity": x["severity"],
                         "detector": x["detector"]} for x in g]
        rep = C.measure([fx("a", "A", "curl", a, CORS_RESPONSE, mk(ga)),
                         fx("b", "A", "curl", b, CORS_RESPONSE, mk(gb))])
        assert rep.false_positives == len(ga) + len(gb)


class TestFixtureShape:
    def test_command_carries_the_url(self):
        """DetectContext parses the URL FROM THE COMMAND. With an empty command
        11 of 15 curl rules are structurally dead while a CORS canary still
        fires — green controls over a silent corpus."""
        with_cmd = C._emit(fx("r", "A", "curl",
                              "curl -s -i http://clean:8080/redirect?url=/dash",
                              "HTTP/1.1 302 Found\r\nLocation: http://evil.test/\r\n\r\n"))
        without = C._emit(fx("r", "A", "curl", "",
                             "HTTP/1.1 302 Found\r\nLocation: http://evil.test/\r\n\r\n"))
        assert with_cmd != without, (
            "url-dependent rules behave identically with and without a command — "
            "the fixture shape is no longer load-bearing")

    def test_missing_headers_needs_the_curl_dash_s_form(self):
        """_curl_missing_headers gates on the command starting with 'curl -s',
        so a corpus built only from `curl -i` cannot measure the largest
        finding class at all."""
        body = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        good = C._emit(fx("r", "A", "curl", "curl -s -i http://clean:8080/", body))
        bad = C._emit(fx("r", "A", "curl", "curl -i http://clean:8080/", body))
        assert any(f["detector"] == "curl:_curl_missing_headers" for f in good)
        assert not any(f["detector"] == "curl:_curl_missing_headers" for f in bad)


class TestEnvironmentGuard:
    def test_refuses_when_target_host_rewriting_is_on(self, monkeypatch):
        """ERLIK_DOCKER_TARGET_HOST makes _sanitize_command rewrite URLs, so the
        detectors would see a different corpus than the committed one."""
        monkeypatch.setenv("ERLIK_DOCKER_TARGET_HOST", "juice-shop")
        with pytest.raises(C.CleanroomError):
            C.measure([])

    def test_runs_with_a_clean_env(self, monkeypatch):
        monkeypatch.delenv("ERLIK_DOCKER_TARGET_HOST", raising=False)
        C.measure([])


class TestCommittedCorpus:
    def test_corpus_loads_if_present(self):
        corpus = C.load_corpus()
        if not corpus:
            pytest.skip("no committed cleanroom corpus yet")
        assert all(f.zone in ("A", "B") for f in corpus)
        assert all(f.command for f in corpus), "every fixture must carry a command"

    def test_corpus_matches_recorded_behaviour(self):
        corpus = C.load_corpus()
        if not corpus:
            pytest.skip("no committed cleanroom corpus yet")
        rep = C.measure(corpus)
        assert rep.mismatches == [], C.format_report(rep)

    # Zone B SHOULD be silent. Asserting 0 would leave the suite red while one
    # known case stands; asserting nothing would let the number grow unnoticed.
    # The measured baseline is pinned and the test fails BOTH ways — an
    # increase is a regression, a decrease says "lower this and lock the win".
    #
    # Trajectory, each step a measured drop rather than a claim:
    #   6 -> 3  anchored _curl_missing_headers' header-flag gate (`-i` had been
    #           an unanchored substring, matching inside `sign-in`,
    #           `--insecure`, `portal-internal`)
    #   3 -> 1  _curl_exposed_user_data no longer reports "0 user records
    #           found" as a finding; _curl_stack_trace no longer treats a bare
    #           `/app/` URL prefix as a filesystem leak
    #
    # The 1 that remains is NOT a code defect: _curl_missing_headers on
    # /v2/regions is a real `curl -s -i` where CSP and X-Frame-Options genuinely
    # are absent. Whether they matter on a JSON API is a triage question, and
    # C4's submission policy already demotes it to informational.
    ZONE_B_BASELINE = 0

    def test_zone_b_findings_do_not_grow(self):
        corpus = C.load_corpus()
        if not corpus:
            pytest.skip("no committed cleanroom corpus yet")
        rep = C.measure(corpus)
        assert rep.zone_b_findings <= self.ZONE_B_BASELINE, (
            "new false positives on benign traffic:\n" + C.format_report(rep))
        if rep.zone_b_findings < self.ZONE_B_BASELINE:
            pytest.fail(
                f"Zone B improved to {rep.zone_b_findings} (was "
                f"{self.ZONE_B_BASELINE}) — lower ZONE_B_BASELINE to lock it in.\n"
                + C.format_report(rep))

    def test_rule_coverage_does_not_regress(self):
        """A shrinking corpus is how "0 false positives" becomes meaningless."""
        corpus = C.load_corpus()
        if not corpus:
            pytest.skip("no committed cleanroom corpus yet")
        rep = C.measure(corpus)
        # NOT 28/28 any more, and that is the correct direction.
        #
        # On a CLEAN corpus a rule that fires is producing a false positive, so
        # full coverage here was measuring OVER-FIRING, not capability. Three
        # rules went quiet when their false positives were fixed —
        # _curl_api_users_bac, _curl_sqli_login and _detect_commix each had
        # every one of their cleanroom emissions removed, because each was
        # firing on a 401/403/429 or on the tool's own negative result.
        #
        # Capability is proven by positive controls in test_auto_detect.py,
        # which feed each rule a REAL vulnerability. This asserts the opposite
        # property: that the clean corpus still exercises enough of the detector
        # surface to be a meaningful test, and that the set of quiet rules is
        # the one we decided on rather than one that drifted.
        QUIET_ON_CLEAN = {
            "curl:_curl_api_users_bac",     # only fires on unauth enumeration
            "curl:_curl_sqli_login",        # only fires on a successful bypass
            "commix:_detect_commix",        # only fires on a real injection
            "curl:_curl_null_byte",         # only fires when the file is served
            "curl:_curl_missing_headers",   # clean app sends what its type needs
            "curl:_curl_server_header",     # clean app suppresses the version
            # These four now honour the TOOL'S OWN verdict, and on a clean
            # target every tool correctly reports nothing.
            "sqlmap:_detect_sqlmap",        # sqlmap flags its own false positives
            "jwt_tool:_detect_jwt_tool",    # every variant rejected
            "dalfox:_detect_xss_tools",     # reflection encoded, dalfox says inert
            "xsstrike:_detect_xss_tools",   # "No vectors found"
        }
        assert set(rep.unreachable) <= QUIET_ON_CLEAN, (
            "a rule went quiet that we did not expect to:\n" + C.format_report(rep))
        assert len(rep.exercised) >= 16, C.format_report(rep)
