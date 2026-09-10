"""E-028: the control arm ran at a different application configuration.

A differential is only about identity if identity is the only thing that varies.
WSTG-AUTHZ-04's anonymous arm was `curl -s "$U"` carrying nothing at all — and on
DVWA the application's SECURITY LEVEL travels in a cookie, with `dvwaSecurityLevelGet`
falling back to `impossible` when it is absent. So "anonymous" was not the
authenticated arms' application with nobody logged in; it was a DIFFERENT, hardened
application with nobody logged in.

Measured on `/vulnerabilities/authbypass/get_user_data.php`:

    admin (high), security=low       273 bytes — the full user table
    gordonb (low), security=low      273 bytes — the full user table
    anonymous WITH security=low      273 bytes — the full user table
    anonymous, NO cookie at all       41 bytes — {"result":"fail","error":"Access denied"}

The endpoint has no access control at that level, so the honest verdict is "public,
not an identity boundary". With the anonymous arm carrying no cookie the marker is
absent from it, every clause passes, and the case reports a HIGH finding — on data
the application hands to anyone who asks.

`config_cookie` is the fix: a non-secret, operator-declared cookie string carried by
EVERY arm, the anonymous one included. curl merges multiple `-b` options
(`-b "a=1" -b "b=2"` sends `a=1;b=2`), so it rides alongside an identity cookie
rather than replacing it.
"""
import pytest

from orchestrator.testcase import declared as D
from orchestrator.testcase.loader import find_by_id


@pytest.fixture
def case():
    return find_by_id("WSTG-AUTHZ-04")


def test_the_configuration_cookie_is_declarable():
    assert D.validate("config_cookie", "security=low") == ""
    assert D.validate("config_cookie", "security=low; locale=en") == ""


def test_it_is_not_an_evaluator_only_field():
    """It IS rendered into a command, so it keeps the shell metacharacter rule."""
    assert "config_cookie" not in D.EVALUATOR_ONLY
    assert D.validate("config_cookie", 'security="low"'), "a quote was accepted"
    assert D.validate("config_cookie", "security=$(id)"), "a subshell was accepted"


def test_every_arm_carries_the_configuration(case):
    """Including the anonymous one. That is the entire point."""
    for step in case.steps:
        assert "{{config_cookie}}" in step.command, (
            f"{step.name} does not carry the configuration cookie, so it runs at a "
            "different application configuration from the other arms")


def test_the_anonymous_arm_carries_configuration_and_no_identity(case):
    anonymous = next(s for s in case.steps if s.name == "fetch_anonymously")
    assert "{{config_cookie}}" in anonymous.command
    for secret in ("high_priv_token", "high_priv_cookie",
                   "low_priv_token", "low_priv_cookie"):
        assert secret not in anonymous.command, (
            f"the anonymous arm interpolates {secret}, so it is not anonymous")


def test_the_configuration_is_optional(case):
    """An application whose behaviour does not live in a cookie needs none, and
    the case must still run for it — Juice Shop is the measured example."""
    assert "config_cookie" in (case.target_schema.optional or [])
    assert "config_cookie" not in case.target_schema.required


def test_an_absent_configuration_adds_no_cookie_flag():
    """`${CC:+-b "$CC"}` expands to nothing when the field was not supplied, so a
    target that needs no configuration sees exactly the request it saw before."""
    import subprocess
    script = 'CC=""; printf "%s" "${CC:+-b \\"$CC\\"}"'
    assert subprocess.run(["bash", "-c", script], capture_output=True,
                          text=True).stdout == ""
    script = 'CC="security=low"; printf "%s" "${CC:+-b \\"$CC\\"}"'
    assert "security=low" in subprocess.run(["bash", "-c", script], capture_output=True,
                                            text=True).stdout
