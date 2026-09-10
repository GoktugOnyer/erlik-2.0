"""E-029: an identity with plain cookies got no form discovery at all.

`KatanaAdapter.run` gated the entire browser pass — the only producer of
`source="form"` and `source="playwright"` endpoints — on

    ctx.config.headless or (ctx.identity or {}).get("storage_state")

while the egress proxy injects `identity.headers`, `identity.cookies` AND
`storage_state.cookies` on every in-scope request. So an identity authenticated by
plain cookies was fully authenticated and discovered nothing.

MEASURED against real DVWA, real worker image, real proxy, with the browser context
created as `storage_state=None` in both arms and only the identity differing:

    anonymous             1342 bytes (the login page)   1 link    1 form
    cookie-only identity  6436 bytes                   31 links  13 forms

and the 13 are DVWA's real module forms — brute, exec, csrf, upload, captcha. So
proxy-injected cookies do authenticate the rendered pass; the pass simply was not
being run. All 8 of the (url, parameter) pairs the lane finds on DVWA come from it.

WHY THE DECISION IS ASSESSMENT-LEVEL AND NOT PER-ARM. The obvious repair — "run it
when THIS identity carries material" — is itself a fork generator, and forks are
what §3's R0 gate exists to stop. E-008's matrix starts at "anonymous, two ordinary
users in different tenants, and one privileged lab identity"; under a per-arm test
the anonymous arm alone would have no rendered surface, so the arms could never
agree and `compare_arms` would refuse every differential on that assessment. The
question has to be asked of the assessment, so every arm answers it the same way.
"""
import pytest

from orchestrator.integrations.adapters import wants_rendered_pass
from orchestrator.integrations.contracts import AssessmentConfig


def config(**kwargs):
    return AssessmentConfig(scope={"allow_hosts": ["app.test"], "allow_ports": [80]}, **kwargs)


COOKIE_ONLY = {"target_origin": "http://app.test", "cookies": [{"name": "s", "value": "v"}]}
HEADER_ONLY = {"target_origin": "http://app.test", "headers": {"Authorization": "Bearer x"}}
WITH_STATE = {"target_origin": "http://app.test", "storage_state": {"cookies": []}}


def test_an_authenticated_assessment_gets_a_rendered_pass():
    """The defect. Any selected identity means the assessment is authenticated."""
    assert wants_rendered_pass(config(identity_ids=["handle-a"]))
    assert wants_rendered_pass(config(identity_ids=["handle-a", "handle-b"]))


def test_the_operator_opt_in_still_works_on_its_own():
    assert wants_rendered_pass(config(headless=True))
    assert wants_rendered_pass(config(headless=True, identity_ids=[]))


def test_an_anonymous_assessment_that_did_not_ask_gets_no_rendered_pass():
    """Unchanged, and deliberately: the pass launches Chromium, and an operator who
    asked for neither authentication nor a rendered crawl should not pay for it."""
    assert not wants_rendered_pass(config())
    assert not wants_rendered_pass(config(headless=False, identity_ids=[]))


@pytest.mark.parametrize("identity", [None, COOKIE_ONLY, HEADER_ONLY, WITH_STATE],
                         ids=["anonymous", "cookie-only", "header-only", "storage-state"])
def test_the_decision_does_not_depend_on_which_arm_is_asking(identity):
    """The property that keeps the R0 gate satisfiable.

    Every arm of one assessment must get the same answer, or the arms discover
    different surfaces and no differential between them is about the application.
    `wants_rendered_pass` therefore takes the CONFIG and nothing else — it cannot
    see the identity, so it cannot branch on it.
    """
    import inspect
    parameters = inspect.signature(wants_rendered_pass).parameters
    assert list(parameters) == ["config"], (
        f"wants_rendered_pass takes {list(parameters)}; anything beyond the "
        "assessment config lets one arm answer differently from another")

    authenticated = config(identity_ids=["handle-a", "anonymous"])
    assert wants_rendered_pass(authenticated) is True
    plain = config()
    assert wants_rendered_pass(plain) is False


def test_an_anonymous_arm_of_an_authenticated_assessment_is_included():
    """The case that would fork.

    An operator may name `anonymous` alongside real identities — E-008 asks for
    exactly that matrix, and `service.register` creates a stage per entry. That arm
    carries no material, so a per-arm test would exclude it while including the
    others.
    """
    assert wants_rendered_pass(config(identity_ids=["anonymous"]))
    assert wants_rendered_pass(config(identity_ids=["anonymous", "handle-a"]))
