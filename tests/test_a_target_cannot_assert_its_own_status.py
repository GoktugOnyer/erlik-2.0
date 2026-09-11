"""The target writes the body. It must not be able to write the STATUS.

Every authorization check in the product rests on one primitive — "did this arm's
request succeed?" — and two lanes had each grown their own forgeable version of it:

    orchestrator/testcase/runner.py   re.search(r"^HTTP/\\S+\\s+2\\d\\d", out, MULTILINE)
    orchestrator/detection.py         _STATUS_RX.findall(out)[-1]

Both searched the WHOLE capture, and the body is part of the capture. So a refusal
whose body contained a line `HTTP/1.1 200 OK` read as a success — and the target types
its own body. That inverts the safety asymmetry the whole design rests on: a target is
supposed to be able to cost itself a finding and never to manufacture one.

The rule now: a status comes only from the first line of a HEADER BLOCK, walking
forward from the front and advancing only across 3xx blocks. `curl -i -L` prints every
header block and only the FINAL body, so redirect chains keep working and the body
stays unreachable.
"""
import pytest

from orchestrator import http_capture
from orchestrator.detection import _http_status
from orchestrator.testcase.runner import _http_status_ok, _response_body


DENIAL_TYPING_A_SUCCESS = (
    "HTTP/1.1 403 Forbidden\r\n"
    "Content-Type: application/json\r\n"
    "\r\n"
    "upstream said:\n"
    "HTTP/1.1 200 OK\n"
    '{"status":"error","data":{"id":1,"UserId":1,"email":"admin@juice-sh.op"}}'
)

DENIAL_FAKING_A_HEADER_BLOCK = (
    "HTTP/1.1 403 Forbidden\r\n"
    "\r\n"
    "\r\n"
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: application/json\r\n"
    "\r\n"
    '{"UserId":1,"email":"admin@juice-sh.op"}'
)


@pytest.mark.parametrize("capture,name", [
    (DENIAL_TYPING_A_SUCCESS, "a 200 line inside the body"),
    (DENIAL_FAKING_A_HEADER_BLOCK, "a whole fake header block inside the body"),
])
def test_a_refusal_cannot_claim_to_have_succeeded(capture, name):
    assert http_capture.status(capture) == 403, name
    assert http_capture.ok(capture) is False, name
    # Both lanes' entry points, because both were forgeable and both are shipped.
    assert _http_status_ok(capture) is False, name
    assert _http_status(capture) == 403, name


def test_the_forged_text_stays_in_the_body_where_it_belongs():
    """It is not scrubbed — it is evidence of what the target sent. It simply is not
    allowed to be read as a status."""
    assert "HTTP/1.1 200 OK" in _response_body(DENIAL_TYPING_A_SUCCESS)


def test_a_redirect_chain_still_reports_the_final_status():
    """`curl -i -L` is used by CONF-02 and CONF-04, so this must not regress: curl
    prints every header block and only the final body."""
    chain = ("HTTP/1.1 302 Found\r\nLocation: /app\r\n\r\n"
             "HTTP/1.1 301 Moved\r\nLocation: /app/\r\n\r\n"
             "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>done</html>")
    assert http_capture.status(chain) == 200
    assert http_capture.ok(chain) is True
    assert _response_body(chain) == "<html>done</html>"


def test_a_redirect_chain_ending_in_a_refusal_is_a_refusal():
    chain = ("HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n"
             "HTTP/1.1 401 Unauthorized\r\n\r\nplease sign in")
    assert http_capture.ok(chain) is False
    assert http_capture.status(chain) == 401


def test_a_capture_with_no_response_line_is_not_a_success():
    """A probe that recorded no response line did not succeed. Treating an unparseable
    capture as a 2xx is how a check reports on something that never happened."""
    for capture in ("", "curl: (28) Operation timed out", "HTTP/1.1\r\n\r\nbody"):
        assert http_capture.ok(capture) is False, capture
        assert _http_status_ok(capture) is False, capture
    assert http_capture.status("curl: (7) Failed to connect") is None


def test_a_header_only_capture_has_no_body():
    """Otherwise a marker reflected into a header satisfies a disclosure check."""
    assert _response_body("HTTP/1.1 200 OK\r\nX-Echo: admin@juice-sh.op") == ""


def test_the_status_is_not_read_from_a_header_value():
    """A header whose VALUE looks like a status line is still a header."""
    capture = ("HTTP/1.1 403 Forbidden\r\n"
               "X-Upstream-Status: HTTP/1.1 200 OK\r\n\r\ndenied")
    assert http_capture.status(capture) == 403
    assert http_capture.ok(capture) is False
