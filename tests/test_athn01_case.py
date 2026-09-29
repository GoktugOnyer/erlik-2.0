"""WSTG-ATHN-01 reported on a channel it never looked at.

The case was:

    curl -s -o /dev/null -w "%{http_code} %{url_effective}" "{{login_url}}"
    regex: '^\\d+ http://'   ->  "Login Form Served Over HTTP", HIGH

Without `-L`, `%{url_effective}` is the URL you passed in, echoed back. So the
check reduced to "does the target string start with http://" and the response
was never consulted at all. Measured 2026-09-05:

    http://github.com/login   -> "301 http://github.com/login"  -> HIGH FINDING
    http://127.0.0.1:9099/    -> "000 http://127.0.0.1:9099/"   -> HIGH FINDING

The first is a site that redirects http to https, which is the correct
configuration and the most common one on the web. The second is a host that
answered nothing -- `%{http_code}` is 000 when curl never connected, `\\d+`
matches "000", and the step exits 7, so the case emitted a high-severity
finding from a step that failed.

It also could not see the canonical form of this defect: a login page served
over TLS whose form posts to an http:// action sends the password in cleartext,
and nothing in the case looked at the form.

These tests parse the shipped YAML. The five branch verdicts were also checked
against live local servers -- plain http with a password field, http without
one, TLS with a cleartext form action, TLS with a relative action, and an http
endpoint that 301s to TLS -- which is how the two false positives were
measured in the first place.
"""

import re
from pathlib import Path

import pytest
import yaml

CASE = (Path(__file__).resolve().parents[1] / "tests_catalog" / "wstg"
        / "ATHN-01_creds_over_channel.yaml")


@pytest.fixture(scope="module")
def case():
    return yaml.safe_load(CASE.read_text())


@pytest.fixture(scope="module")
def command(case):
    steps = case["steps"]
    assert len(steps) == 1, "the case is one deterministic step; update this test"
    return steps[0]["command"]


class TestTheProbeActuallyLooksAtTheTarget:
    def test_every_curl_follows_redirects(self, command):
        """The whole false positive. Without -L the effective URL is the input
        URL, so a site that redirects http to https reads as serving a login
        form in cleartext.

        Asserted over EVERY curl in the step, not the presence of the flag
        somewhere in it: the step issues two requests -- one for the status and
        effective URL, one for the body -- and either of them losing -L
        reintroduces the bug for the half it measures. Checking `" -L " in
        command` passed against exactly that mutation."""
        # `curl -` so the word inside the human-readable verdict text is not
        # mistaken for an invocation.
        curls = re.findall(r'curl\s+-[^;|)]*', command)
        assert len(curls) >= 2, curls
        missing = [c[:70] for c in curls if " -L " not in c]
        assert not missing, (
            f"these curl invocations do not follow redirects: {missing}"
        )

    def test_it_fetches_the_body(self, command):
        """A status code cannot tell a login page from a 404. The verdict now
        depends on whether a password field is actually there."""
        assert "password" in command

    def test_it_inspects_the_form_action(self, command):
        """The canonical WSTG-ATHN-01 defect, which the old case could not see
        at all: TLS page, cleartext form action."""
        assert "action=" in command


class TestNoResponseIsNotAFinding:
    def test_the_no_response_branch_exists(self, command):
        assert "ERLIK_ATHN_NO_RESPONSE" in command
        assert '"$CODE" = "000"' in command, (
            "000 is what %{http_code} reports when curl never connected; the "
            "old pattern '^\\\\d+ http://' matched it and emitted HIGH"
        )

    def test_no_evaluator_matches_it(self, case):
        """The regression, asserted where it lives: the not-assessed canary
        must not be reachable by any finding pattern."""
        for ev in case["steps"][0]["evaluators"]:
            assert not re.search(ev["pattern"], "ERLIK_ATHN_NO_RESPONSE: nothing came back"), (
                f"pattern {ev['pattern']!r} fires on a host that answered nothing"
            )

    def test_the_dashboard_will_render_it_as_not_assessed(self):
        """The canary has to match the dashboard's marker regex, or a run that
        declined to assess renders as a clean result -- which is the one thing
        this codebase treats as equal to a crash."""
        ui = (Path(__file__).resolve().parents[1] / "dashboard" / "templates"
              / "index.html").read_text()
        m = re.search(r"const TL_NOT_ASSESSED = /([^/]+)/", ui)
        assert m, "the dashboard's not-assessed marker regex moved"
        assert re.search(m.group(1), "ERLIK_ATHN_NO_RESPONSE"), (
            f"{m.group(1)} does not match ERLIK_ATHN_NO_RESPONSE"
        )


class TestTheVerdictsAreDistinct:
    VERDICTS = ["ERLIK_ATHN_NO_RESPONSE", "ERLIK_ATHN_FORM_OVER_HTTP",
                "ERLIK_ATHN_NO_FORM", "ERLIK_ATHN_ACTION_OVER_HTTP",
                "ERLIK_ATHN_OK"]

    def test_all_five_are_emitted(self, command):
        missing = [v for v in self.VERDICTS if v not in command]
        assert not missing, missing

    @pytest.mark.parametrize("verdict,expected", [
        ("ERLIK_ATHN_FORM_OVER_HTTP", 1),
        ("ERLIK_ATHN_ACTION_OVER_HTTP", 1),
        ("ERLIK_ATHN_NO_RESPONSE", 0),
        ("ERLIK_ATHN_NO_FORM", 0),
        ("ERLIK_ATHN_OK", 0),
    ])
    def test_each_verdict_fires_the_right_number_of_evaluators(
            self, case, verdict, expected):
        """Runs the shipped patterns against the shipped canaries. A verdict
        that matched two patterns would double-report; one that matched the
        wrong pattern is the old bug in a new place."""
        hits = [ev for ev in case["steps"][0]["evaluators"]
                if re.search(ev["pattern"], f"{verdict}: explanation text here")]
        assert len(hits) == expected, [ev["pattern"] for ev in hits]

    def test_a_clean_verdict_is_not_a_prefix_of_a_dirty_one(self):
        """Guard on the guard: if someone renames ERLIK_ATHN_OK to a string
        that ERLIK_ATHN_FORM_OVER_HTTP contains, the parametrisation above
        starts passing vacuously."""
        for a in self.VERDICTS:
            others = [b for b in self.VERDICTS if b != a]
            assert not any(a in b for b in others), a


class TestItSurvivesTheScopeGuard:
    def test_no_bare_scheme_reaches_the_extractor(self, command):
        """scope.check_command extracts every `http://…` substring of a
        rendered command and checks it as a target. A scheme written into the
        step's own shell -- in a bracket expression, or in `${EFF#http://}` --
        arrives there as a URL whose host is `[^` or `}`. That is why the
        scheme is compared by splitting the URL instead."""
        from orchestrator.testcase.scope import Scope, check_command
        rendered = command.replace("{{login_url}}", "http://127.0.0.1:9020/login")
        check_command(rendered, Scope(allow_hosts=["127.0.0.1"]))

    def test_the_guard_would_still_refuse_a_foreign_host(self, command):
        """Negative control: the test above must not pass because the guard
        stopped looking."""
        from orchestrator.testcase.scope import Scope, ScopeViolation, check_command
        rendered = command.replace("{{login_url}}", "http://evil.example/login")
        with pytest.raises(ScopeViolation):
            check_command(rendered, Scope(allow_hosts=["127.0.0.1"]))
