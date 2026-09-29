"""WSTG-CONF-06 must PROBE TRACE, not just read an Allow header.

The case originally had one TRACE check: a regex for `Allow:.*TRACE` on the
OPTIONS response. That only catches a server that ADVERTISES the method.
Servers routinely answer TRACE while advertising nothing, which is why the
guide says to test the method rather than believe a header — and Cross-Site
Tracing is a named part of this WSTG case.

Found live: a target returning no Allow header at all, answering
`TRACE / HTTP/1.1` with 200, `Content-Type: message/http`, and the request
echoed back. The case reported no finding.

The probe's precision matters as much as its reach. A 200 alone is not
evidence — a server that answers everything 200 would false-positive, and a
false "your server allows Cross-Site Tracing" in a client report is expensive.
So the pattern requires the ECHO signature, and the fixtures below include the
two controls that must stay silent.
"""

import re

import pytest

from orchestrator.testcase.loader import find_by_id

CASE = "WSTG-CONF-06"

VULNERABLE = (
    "HTTP/1.0 200 OK\r\n"
    "Server: VulnLab/0.1\r\n"
    "Content-Type: message/http\r\n"
    "Content-Length: 65\r\n"
    "\r\n"
    "TRACE / HTTP/1.1\r\nHost: t\r\n"
)
REFUSES = (
    "HTTP/1.0 405 Method Not Allowed\r\n"
    "Allow: GET, POST\r\n"
    "Content-Length: 0\r\n\r\n"
)
ALWAYS_OK_NO_ECHO = (
    "HTTP/1.0 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Content-Length: 20\r\n"
    "\r\n"
    "<html>welcome</html>"
)


def _trace_step():
    tc = find_by_id(CASE)
    assert tc is not None, f"{CASE} is not in the catalogue"
    for s in tc.steps:
        if "trace" in s.name.lower():
            return s
    pytest.fail(f"{CASE} has no TRACE probe step: {[s.name for s in tc.steps]}")


def _trace_pattern():
    step = _trace_step()
    pats = [e.pattern for e in step.evaluators if e.type == "regex" and e.pattern]
    assert pats, "the TRACE step asserts nothing"
    return pats[0]


class TestTheCaseActivelyProbesTrace:
    def test_a_trace_step_exists(self):
        step = _trace_step()
        cmd = step.command.upper()
        assert "-X TRACE" in cmd, f"the step does not issue a TRACE: {step.command}"

    def test_it_also_probes_track(self):
        """The IIS variant the guide names alongside TRACE."""
        assert "-X TRACK" in _trace_step().command.upper()

    def test_it_is_not_gated_behind_an_earlier_finding(self):
        """'The server advertises TRACE' and 'the server performs TRACE' are
        different claims. The second must be reachable even when the first
        already fired, or the active probe is skipped exactly when a header
        hinted the problem is real."""
        step = _trace_step()
        assert getattr(step, "when", None) in (None, ""), (
            f"the TRACE probe is conditional on {step.when!r}"
        )


class TestThePatternIsPrecise:
    def test_it_matches_a_real_trace_echo(self):
        assert re.search(_trace_pattern(), VULNERABLE, re.MULTILINE | re.IGNORECASE)

    def test_it_ignores_a_server_that_refuses_trace(self):
        assert not re.search(_trace_pattern(), REFUSES, re.MULTILINE | re.IGNORECASE)

    def test_it_ignores_a_server_that_answers_everything_200(self):
        """The control that a status-only check fails. Without the echo
        requirement this reports Cross-Site Tracing on a healthy server."""
        assert not re.search(_trace_pattern(), ALWAYS_OK_NO_ECHO,
                             re.MULTILINE | re.IGNORECASE)


class TestTheOriginalChecksSurvive:
    """The advertise-based check and the PUT probe were not replaced."""

    def test_options_still_reads_allow(self):
        tc = find_by_id(CASE)
        opt = [s for s in tc.steps if s.name == "options"]
        assert opt, [s.name for s in tc.steps]
        assert any("Allow" in (e.pattern or "") for e in opt[0].evaluators)

    def test_put_probe_still_exists_and_stays_gated(self):
        tc = find_by_id(CASE)
        put = [s for s in tc.steps if s.name == "put_probe"]
        assert put, [s.name for s in tc.steps]
        assert put[0].when == "no_finding_yet", (
            "the PUT probe writes a file to the target; it must stay "
            "conditional"
        )
