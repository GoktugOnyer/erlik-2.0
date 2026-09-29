"""Run the real cases against applications with planted flaws.

Every case defect found on 2026-09-05 came from doing this, and none from
reading the YAML:

  * ATHN-01 reported every http->https redirect, and every dead host, as a
    HIGH finding -- it never followed the redirect and never looked at a form.
  * BUSL-04 fired ZERO requests when `parallel_n` was omitted and called that
    a clean race-condition test; its verdict regex also could not match two
    successes on separate lines.
  * CONF-07 scanned TLS on one port and checked HSTS on another.
  * SESS-02's only evaluator was an LLM, so the case was inert offline.
  * Three steps had never executed at all -- the admission guard read their
    bare shell as a program name.

The harness that found all of that lived in a scratchpad and died with the
container. It is committed now, so a case that regresses fails here.

WHAT MAKES THIS WORTH RUNNING: every assertion comes in a PAIR. A case must
fire on the planted flaw AND stay silent on a control with the same routes and
the flaw fixed. Half the defects above were false positives -- a case that
fires on both is worse than one that fires on neither, because it teaches an
operator to ignore it.
"""

import pytest

from tests.targets.fixtures import (curl_available, run_case,  # noqa: F401
                                    targets, tls_cert, vuln_types)

pytestmark = pytest.mark.skipif(
    not curl_available(), reason="curl is not installed; the cases shell out to it")


class TestReflectedXSS:
    def test_it_fires_on_an_unencoded_reflection(self, targets):
        r = run_case("WSTG-INPV-01", url=targets["web"] + "/search", parameter="q")
        assert "Reflected XSS" in vuln_types(r)

    def test_it_is_silent_when_the_reflection_is_encoded(self, targets):
        r = run_case("WSTG-INPV-01", url=targets["web_control"] + "/search",
                     parameter="q")
        assert not vuln_types(r), vuln_types(r)


class TestSQLInjection:
    def test_it_fires_on_a_raw_driver_error(self, targets):
        r = run_case("WSTG-INPV-05", url=targets["web"] + "/search", parameter="q")
        assert vuln_types(r)

    def test_it_is_silent_when_the_input_is_rejected(self, targets):
        r = run_case("WSTG-INPV-05", url=targets["web_control"] + "/search",
                     parameter="q")
        assert not vuln_types(r), vuln_types(r)


class TestCookieAttributes:
    def test_it_fires_on_a_flagless_session_cookie(self, targets):
        r = run_case("WSTG-SESS-02", url=targets["web"] + "/")
        assert "Insecure Cookie Attributes" in vuln_types(r)

    def test_it_is_silent_when_the_cookie_is_flagged(self, targets):
        r = run_case("WSTG-SESS-02", url=targets["web_control"] + "/")
        assert not vuln_types(r), vuln_types(r)

    def test_it_harvests_the_jwt_for_sess10(self, targets):
        """The producer added in #35. SESS-10 requires a jwt and nothing else
        in the catalogue makes one."""
        r = run_case("WSTG-SESS-02", url=targets["web"] + "/")
        assert (r.produced or {}).get("jwt"), r.produced


class TestClickjacking:
    def test_it_fires_when_no_framing_policy_is_set(self, targets):
        r = run_case("WSTG-CLNT-09", url=targets["web"] + "/")
        assert vuln_types(r)

    def test_it_is_silent_when_x_frame_options_is_set(self, targets):
        r = run_case("WSTG-CLNT-09", url=targets["web_control"] + "/")
        assert not vuln_types(r), vuln_types(r)


class TestCORS:
    def test_it_fires_on_a_reflected_origin_with_credentials(self, targets):
        r = run_case("WSTG-CLNT-07", url=targets["web"] + "/")
        assert vuln_types(r)

    def test_it_is_silent_on_an_allowlisted_origin(self, targets):
        r = run_case("WSTG-CLNT-07", url=targets["web_control"] + "/")
        assert not vuln_types(r), vuln_types(r)

    def test_the_null_origin_variant_fires_too(self, targets):
        r = run_case("WSTG-CLNT-07b", url=targets["web"] + "/")
        assert vuln_types(r)

    def test_the_null_origin_variant_is_silent_on_the_control(self, targets):
        r = run_case("WSTG-CLNT-07b", url=targets["web_control"] + "/")
        assert not vuln_types(r), vuln_types(r)


class TestErrorHandling:
    def test_it_fires_on_a_stack_trace(self, targets):
        r = run_case("WSTG-ERRH-01", url=targets["web"] + "/error")
        assert vuln_types(r)

    def test_it_is_silent_on_a_generic_error_page(self, targets):
        r = run_case("WSTG-ERRH-01", url=targets["web_control"] + "/error")
        assert not vuln_types(r), vuln_types(r)


class TestMetafiles:
    def test_it_reports_the_disclosed_paths(self, targets):
        r = run_case("WSTG-INFO-03", url=targets["web"])
        assert vuln_types(r)

    def test_it_harvests_paths_and_parameters(self, targets):
        """Both producers. The parameter one was added in #35 and only reaches
        a consumer because `_retarget` now prefers the field a child lacks."""
        r = run_case("WSTG-INFO-03", url=targets["web"])
        assert (r.produced or {}).get("url"), r.produced
        assert set((r.produced or {}).get("parameter") or []) >= {"q", "user_id"}, \
            r.produced


class TestCredentialsOverTheChannel:
    """ATHN-01's two false positives are the regression this file exists for."""

    def test_it_fires_on_a_login_form_served_over_http(self, targets):
        r = run_case("WSTG-ATHN-01", login_url=targets["web"] + "/login")
        assert "Login Form Served Over HTTP" in vuln_types(r)

    def test_it_is_silent_when_http_redirects_to_tls(self, targets):
        """The false positive: this is the CORRECT configuration and the most
        common one on the web, and it was reported HIGH."""
        r = run_case("WSTG-ATHN-01", login_url=targets["redirect_to_tls"] + "/login")
        assert not vuln_types(r), vuln_types(r)

    def test_it_is_silent_when_nothing_is_listening(self, targets):
        """The other false positive: %{http_code} is 000 when curl never
        connected, and `^\\d+ http://` matched it."""
        r = run_case("WSTG-ATHN-01", login_url="http://127.0.0.1:9/login")
        assert not vuln_types(r), vuln_types(r)

    def test_it_fires_on_a_tls_page_posting_to_a_cleartext_action(self, targets):
        """The canonical form of this defect, which the old case could not
        see at all."""
        r = run_case("WSTG-ATHN-01", login_url=targets["tls_cleartext_action"] + "/login")
        assert vuln_types(r), "a TLS page posting credentials in the clear"

    def test_it_is_silent_on_a_clean_tls_login(self, targets):
        r = run_case("WSTG-ATHN-01", login_url=targets["tls_no_hsts"] + "/login")
        assert not vuln_types(r), vuln_types(r)


class TestHSTS:
    def test_it_fires_when_tls_sets_no_hsts(self, targets):
        from urllib.parse import urlparse
        port = urlparse(targets["tls_no_hsts"]).port
        r = run_case("WSTG-CONF-07", host="127.0.0.1", port=str(port))
        assert "Missing HSTS" in vuln_types(r)

    def test_it_is_silent_when_hsts_is_set(self, targets):
        from urllib.parse import urlparse
        port = urlparse(targets["tls_hsts"]).port
        r = run_case("WSTG-CONF-07", host="127.0.0.1", port=str(port))
        assert "Missing HSTS" not in vuln_types(r), vuln_types(r)

    def test_it_does_not_report_a_dead_port_as_missing_hsts(self, targets):
        r = run_case("WSTG-CONF-07", host="127.0.0.1", port="9")
        assert "Missing HSTS" not in vuln_types(r), vuln_types(r)


class TestLdapDifferentials:
    """Both steps had never executed -- the admission guard read their bare
    shell as a program name. They also decide on RESPONSE SIZE, which is why
    the fixtures differ in size the way a directory would."""

    def test_the_wildcard_differential_fires(self, targets):
        r = run_case("WSTG-INPV-06", url=targets["ldap"] + "/s", parameter="q")
        assert vuln_types(r)

    def test_the_boolean_differential_fires_on_its_own(self, targets):
        """On the plain target the wildcard step fires first and this one is
        skipped by `no_finding_yet`, so without this fixture it would still
        never have been seen to work."""
        r = run_case("WSTG-INPV-06",
                     url=targets["ldap_wildcard_escaped"] + "/s", parameter="q")
        assert vuln_types(r)

    def test_both_are_silent_when_the_input_is_escaped(self, targets):
        r = run_case("WSTG-INPV-06", url=targets["ldap_control"] + "/s",
                     parameter="q")
        assert not vuln_types(r), vuln_types(r)

    def test_no_step_was_refused_before_running(self, targets):
        """The actual regression: a refused step reads like a missing tool and
        the case above it reads as clean."""
        r = run_case("WSTG-INPV-06", url=targets["ldap"] + "/s", parameter="q")
        refused = [s.step for s in r.steps
                   if not s.success and "TOOLSET" in str(s.error)]
        assert not refused, refused


class TestHttpMethods:
    def test_trace_is_reported_when_it_is_answered(self, targets):
        r = run_case("WSTG-CONF-06", url=targets["web"] + "/")
        assert vuln_types(r)

    def test_it_is_silent_when_trace_is_refused(self, targets):
        r = run_case("WSTG-CONF-06", url=targets["web_control"] + "/")
        assert not vuln_types(r), vuln_types(r)


class TestTheControlsAreRealControls:
    """Guard on the guards. If a control target stopped serving the route, its
    case would find nothing for the wrong reason and every silence above would
    be vacuous."""

    # /error answers 500 BY DESIGN -- it is an error page, and the control's
    # version simply does not leak a stack trace. Asserting 200 there was my
    # own sloppiness, and this guard caught it on the first run.
    @pytest.mark.parametrize("path,want", [
        ("/", 200), ("/search", 200), ("/login", 200), ("/robots.txt", 200),
        ("/error", 500),
    ])
    def test_the_control_still_serves_every_route(self, targets, path, want):
        import urllib.error
        import urllib.request
        try:
            with urllib.request.urlopen(targets["web_control"] + path,
                                        timeout=5) as r:
                got = r.status
        except urllib.error.HTTPError as e:
            got = e.code
        assert got == want

    def test_the_control_still_sets_a_session_cookie(self, targets):
        import urllib.request
        with urllib.request.urlopen(targets["web_control"] + "/", timeout=5) as r:
            assert "session=" in (r.headers.get("Set-Cookie") or "")


class TestTheHarnessDoesNotLeak:
    """A harness that changes global state for other people's tests is not a
    harness, it is a second bug.

    The first version set ERLIK_NATIVE in an autouse SESSION fixture. That
    broke test_skills_authoring, which requires it UNSET because native mode
    removes the container boundary -- and the symptom was the worst kind: the
    test passed alone and failed in the suite.
    """

    ENV = ("ERLIK_NATIVE", "CURL_CA_BUNDLE")

    def test_running_a_case_restores_the_environment(self, targets):
        import os
        before = {k: os.environ.get(k) for k in self.ENV}
        run_case("WSTG-CLNT-09", url=targets["web"] + "/")
        after = {k: os.environ.get(k) for k in self.ENV}
        assert before == after, (before, after)

    def test_it_restores_the_executors_native_flag_too(self, targets):
        """The env var and the module flag are read in different places; the
        first version of this fix restored one and not the other."""
        import orchestrator.tool_executor as TE
        before = TE.ERLIK_NATIVE
        run_case("WSTG-CLNT-09", url=targets["web"] + "/")
        assert TE.ERLIK_NATIVE is before

    def test_native_mode_is_actually_on_during_a_run(self, targets):
        """Negative control. If it were never set, every case would be refused
        for want of a container and every assertion in this file would pass
        against nothing."""
        r = run_case("WSTG-CLNT-09", url=targets["web"] + "/")
        refused = [s.step for s in r.steps
                   if not s.success and "container" in str(s.error).lower()]
        assert not refused, refused
        assert r.steps, "no step ran at all"

    def test_no_autouse_fixture_mutates_global_state(self):
        """Structural: the scoping is the fix, so an autouse fixture appearing
        here again should fail rather than be noticed by someone else's test."""
        import inspect

        from tests.targets import fixtures as F
        src = inspect.getsource(F)
        code = "\n".join(l for l in src.splitlines()
                          if not l.strip().startswith("#"))
        assert "autouse=True" not in code, (
            "an autouse fixture is back in the harness; scope environment "
            "changes to the case run instead"
        )
