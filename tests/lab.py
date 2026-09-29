"""Is the local DVWA lab actually listening?

Two files measure real cases against DVWA on localhost:8081 — the IDOR verdicts and
the SQL-injection reach. Neither STARTS it; it is a long-lived container an operator
brings up with `docker compose up -d`, and both were gated on `ERLIK_DOCKER_TESTS=1`
alone.

CI sets that variable and has no DVWA, so on 2026-09-29 those twelve tests did not
skip — they FAILED, with `httpx.ConnectError: All connection attempts failed` and an
`AssertionError: 000` from curl's no-response code. Twelve red tests that mean "the
lab is not here", in a job that runs on every pull request.

A test that cannot run says so. That is the same rule the catalogue follows when a
case has no target, and the distinction matters in both directions: a skip names a
measurement nobody took, while a failure claims one was taken and came out wrong.

Deliberately NOT `pytest.fail`, and deliberately not the idiom used by the fixtures
that spin up their own target on an ephemeral port — those fail correctly, because
something they started did not come up, which is a defect. Nothing here started DVWA.
"""
import socket

import pytest

DVWA_HOST, DVWA_PORT = "localhost", 8081
DVWA = f"http://{DVWA_HOST}:{DVWA_PORT}"


def dvwa_is_listening(timeout: float = 0.5) -> bool:
    """A TCP connect, not an HTTP request: the question is whether anything is there.

    An HTTP probe would also have to decide what counts as DVWA answering, and a
    lab mid-restart would then read as absent rather than as a lab mid-restart.
    """
    try:
        with socket.create_connection((DVWA_HOST, DVWA_PORT), timeout=timeout):
            return True
    except OSError:
        return False


requires_dvwa = pytest.mark.skipif(
    not dvwa_is_listening(),
    reason=(f"nothing is listening on {DVWA}; these measure real cases against the "
            "local DVWA lab and do not start it — bring it up with "
            "`docker compose up -d` to run them"))
