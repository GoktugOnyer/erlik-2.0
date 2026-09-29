"""The scope guard must refuse what it cannot parse, not crash on it.

`check_url` called `urlparse` and used the result. `urlparse` RAISES on some
malformed inputs rather than returning an empty host: anything with an
unbalanced `[` after the scheme gives `ValueError: Invalid IPv6 URL`, and an
out-of-range port raises when `.port` is read.

`_URL_RX` over-extracts on purpose -- that is the right call for a safety
boundary -- so a bracket expression inside a step's own grep pattern arrives
here as a "URL":

    grep -Eio "action=[\\"']?http://[^\\" >]*"     ->  http://[^\\"

That killed the entire run with a traceback out of `run_test_case`: not a
refusal, not a result, no finding either way, and a caller that catches
`ScopeViolation` would not have caught it. A guard that exists to fail closed
has to fail closed on its own error paths too.
"""

import pytest

from orchestrator.testcase.scope import Scope, ScopeViolation, check_command, check_url

SCOPE = Scope(allow_hosts=["127.0.0.1", "*.example.test"])


class TestUnparseableIsRefused:
    @pytest.mark.parametrize("url", [
        "http://[^a-z]*",
        "http://[unclosed",
        "http://127.0.0.1:99999/",
        "http://127.0.0.1:notaport/",
    ])
    def test_it_raises_scope_violation_and_not_something_else(self, url):
        # The message is pinned to the PARSE failure. Asserting only that some
        # ScopeViolation is raised cannot tell this apart from a handler that
        # swallows the error and substitutes a host which then happens to be
        # out of scope -- and the dangerous version of that substitutes one
        # that is IN scope, which allows the command through.
        with pytest.raises(ScopeViolation, match="could not parse"):
            check_url(url, SCOPE)

    @pytest.mark.parametrize("command", [
        'curl "http://[^a-z]*"',
        'bash -c \'grep -Eio "action=.?http://[^ >]*"\'',
        'curl http://127.0.0.1:99999/',
    ])
    def test_a_command_carrying_one_is_refused(self, command):
        with pytest.raises(ScopeViolation, match="could not parse"):
            check_command(command, SCOPE)

    def test_it_is_not_merely_that_everything_now_raises(self):
        """The negative control. If the try/except were too broad, or the guard
        started refusing outright, these tests would pass against a guard that
        blocks every command."""
        check_command('curl -s "http://127.0.0.1:9020/login"', SCOPE)
        check_command('curl -s "https://api.example.test/v1"', SCOPE)
        check_url("http://127.0.0.1:8080/x", SCOPE)


class TestTheOrdinaryRefusalsStillWork:
    def test_a_foreign_host_is_still_refused(self):
        with pytest.raises(ScopeViolation, match="not in allow_hosts"):
            check_url("http://evil.example/x", SCOPE)

    def test_a_bracketed_ipv6_literal_is_still_parsed_properly(self):
        """`[::1]` is a VALID URL host, not a parse failure. It must be judged
        on scope, not swept into the new error path."""
        with pytest.raises(ScopeViolation, match="not in allow_hosts"):
            check_url("http://[::1]:8080/", SCOPE)

    def test_an_empty_url_is_still_refused(self):
        with pytest.raises(ScopeViolation, match="empty URL"):
            check_url("", SCOPE)
