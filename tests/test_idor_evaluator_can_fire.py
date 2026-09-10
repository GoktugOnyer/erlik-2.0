"""The typed `idor` evaluator could never fire on a cookie-authenticated app.

    low, high = target.get("low_priv_token"), target.get("high_priv_token")
    matched = bool(... and low != high)

On DVWA — and on most PHP, Rails and Django applications — neither token exists,
because the session is a cookie. Both are None, `None != None` is False, and the
clause the finding depends on can never hold. The evaluator is dead code on the
one lab target the project measures against.

This is the SAME defect AUTHZ-04's YAML case was already fixed for. Its comment
says so: "It required low_priv_token / high_priv_token and sent
`-H "Authorization: Bearer ..."`, so it was BEARER-ONLY by construction ... It now
accepts either material, per role, via `required_any`." The typed evaluator kept
the assumption, so the fix reached the case and not the code beside it.

The clause itself is right and must stay: an "IDOR" where both arms used the same
credential is one request reported twice. What has to change is what counts as an
identity — `credentials.auth_inputs` offers `{role}_priv_token` OR
`{role}_priv_cookie` depending on what the session actually is, and a cookie
authenticates exactly as much as a bearer token does.
"""
import pytest

from orchestrator.testcase.runner import _run_evaluator, StepResult
from orchestrator.testcase.schema import Evaluator, TestCase as Case, TestStep as Step


MARKER = "secret-account-balance-99"
CASE = Case(id="WSTG-AUTHZ-04", name="IDOR", category="Authorization",
            steps=[Step(name="fetch_as_low_priv", tool="curl", command="curl x")])
EVALUATOR = Evaluator(type="idor", emit_finding={"vuln_type": "Broken Access Control",
                                                 "severity": "high"})


def step(name, body):
    return StepResult(step=name, command="curl x", success=True, duration_ms=9, exit_code=0,
                      output=f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n{body}")


async def verdict(target):
    baseline = step("fetch_as_high_priv", f"<p>{MARKER}</p>")
    finding, _, _, _ = await _run_evaluator(
        EVALUATOR, step("fetch_as_low_priv", f"<p>{MARKER}</p>"), CASE,
        {"url": "http://app.test/account", "private_object_marker": MARKER, **target},
        None, None, [baseline])
    return finding


async def test_two_cookie_sessions_can_produce_a_finding():
    """The defect. Two distinct cookie sessions are two identities."""
    finding = await verdict({"low_priv_cookie": "PHPSESSID=aaaa1111",
                             "high_priv_cookie": "PHPSESSID=bbbb2222"})
    assert finding is not None, (
        "two different cookie sessions were not recognised as two identities, so "
        "this evaluator cannot fire on any cookie-authenticated application")


async def test_two_bearer_tokens_still_produce_a_finding():
    """The path that already worked must keep working."""
    assert await verdict({"low_priv_token": "aaa", "high_priv_token": "bbb"}) is not None


async def test_mixed_material_counts_as_two_identities():
    """One role on a bearer token and one on a cookie is still two principals."""
    assert await verdict({"low_priv_cookie": "PHPSESSID=aaaa", "high_priv_token": "bbb"}) is not None


# --------------------------------------------------------- what must stay

async def test_one_credential_used_twice_is_not_a_finding():
    """The clause exists for this, and it is the reason not to simply delete it:
    an IDOR whose two arms carried the SAME credential is one request reported
    twice."""
    assert await verdict({"low_priv_cookie": "PHPSESSID=same",
                          "high_priv_cookie": "PHPSESSID=same"}) is None
    assert await verdict({"low_priv_token": "same", "high_priv_token": "same"}) is None


async def test_no_credentials_at_all_is_not_a_finding():
    """Two unauthenticated fetches agreeing proves the page is public.

    This is what the old `None != None` accidentally enforced, and it is the one
    case it got right — so the fix must not turn "no credentials" into "two
    identities".
    """
    assert await verdict({}) is None


async def test_one_role_missing_is_not_a_finding():
    """A differential needs both arms. One identity is not a comparison."""
    assert await verdict({"low_priv_cookie": "PHPSESSID=aaaa"}) is None
    assert await verdict({"high_priv_token": "bbb"}) is None
