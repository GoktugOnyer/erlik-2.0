"""Every arm must be testing the SAME application — the anonymous one included.

E-028 established this for the sweep lane with `config_cookie`. The LANE's anonymous arm is
the path that fix structurally cannot reach: `service.register` builds a stage's identity as
`SecretStore().get(...) if identity_id != "anonymous" else None`, the proxy injects nothing
when that is `None`, and `inventory.LANE_TARGET_FIELDS` is `{"url", "parameter"}` so no lane
case can be handed a `config_cookie` either.

DVWA's security level is a value the CALLER chooses — `dvwaPage.inc.php:200` returns
`$_COOKIE['security']` when set and "impossible" otherwise. Measured through the REAL proxy
against `/vulnerabilities/authbypass/get_user_data.php`:

    identity arm carrying security=low     200, 273 bytes, the full user table
    anonymous arm as the lane builds it    200,  41 bytes, {"result":"fail",...}

The anonymous arm is the load-bearing clause of both cross-arm authorization checks, so that
gap MANUFACTURED a finding. Measured end to end through the proxy with real DVWA sessions
for admin and gordonb: **1 false positive** without shared configuration and **0** with it,
on data DVWA hands to anybody who sets a cookie.

WHY THIS IS SAFE TO ADD: it is applied to every arm, so it cannot distinguish one arm from
another. What it can do is change the application under test, which is the point, and the
guarantee is exactly that — UNIFORMITY, not a promise that the values are not credentials.
`StageResult.metadata["application_configuration"]` records what each arm carried for that
reason.
"""
import pytest

from orchestrator.integrations.contracts import AssessmentConfig, Identity
from orchestrator.integrations.egress_policy import merged_cookies

DVWA = "http://dvwa"
JUICE = "http://juice-shop:3000"
SECURITY = {"name": "security", "value": "low", "target_origin": DVWA}


def merge(existing=None, application=(), identity=(), url=f"{DVWA}/vulnerabilities/x",
          path="/vulnerabilities/x", scheme="http", now=0):
    return merged_cookies(existing, list(application), list(identity), url, path, scheme, now)


# --------------------------------------------------- it reaches every arm

def test_the_anonymous_arm_carries_the_application_configuration():
    """The defect, stated as the fix: an arm with no identity still gets the cookie."""
    jar, _ = merge(application=[SECURITY], identity=[])
    assert jar == {"security": "low"}


def test_an_identity_arm_carries_both_its_own_material_and_the_configuration():
    jar, _ = merge(application=[SECURITY],
                   identity=[{"name": "PHPSESSID", "value": "abc"}])
    assert jar == {"PHPSESSID": "abc", "security": "low"}


# ------------------------------------------------- the merge, and its authority

def test_a_cookie_the_request_already_carried_is_not_discarded():
    """The proxy used to end with `headers["cookie"] = "; ".join(accepted)`, discarding
    whatever the request held. DVWA answers EVERY request with
    `Set-Cookie: security=impossible`, so a scanner arm that keeps a jar carries the
    application's own configuration back on later requests."""
    jar, _ = merge(existing="locale=en", application=[SECURITY],
                   identity=[{"name": "PHPSESSID", "value": "abc"}])
    assert jar == {"locale": "en", "PHPSESSID": "abc", "security": "low"}


def test_the_declared_configuration_outranks_a_cookie_the_TARGET_set():
    """Measured: DVWA sets `security=impossible` on every response and `login.py`'s jar is a
    flat name->value dict that absorbs it, so an identity captured by erlik's OWN credential
    flow carries `security=impossible` — a cookie the operator never declared and has no
    reason to know is there. If the identity won, declaring `security=low` would silently do
    nothing."""
    jar, overridden = merge(application=[SECURITY],
                            identity=[{"name": "PHPSESSID", "value": "abc"},
                                      {"name": "security", "value": "impossible"}])
    assert jar["security"] == "low"
    assert overridden == ["security"], "and the override must be reported, never silent"


def test_the_override_is_reported_only_when_it_changes_something():
    _, overridden = merge(application=[SECURITY],
                          identity=[{"name": "security", "value": "low"}])
    assert overridden == []


def test_duplicate_names_cannot_survive_the_merge():
    """A dict, not a join. Ablating it to the old `"; ".join(...)` was measured to flip the
    SAME declared configuration between 5070 bytes with five usernames and 389 bytes with
    nothing, purely on join order, because PHP takes the FIRST of duplicate cookie names."""
    jar, _ = merge(existing="security=impossible; security=high", application=[SECURITY])
    assert jar == {"security": "low"}
    assert list(jar).count("security") == 1


# ------------------------------------------------------ it cannot cross origins

def test_a_cookie_declared_for_one_application_is_not_sent_to_another():
    """`Identity.target_origin` exists so per-arm material cannot cross origins, and the
    first draft of this reused the cookie plumbing with that fence removed. Juice Shop treats
    a bare `token` cookie as a full identity, so on a two-host scope that handed a credential
    to a second application."""
    token = {"name": "token", "value": "SECRET-JWT", "target_origin": DVWA}
    jar, _ = merge(application=[token], url=f"{JUICE}/rest/user/whoami",
                   path="/rest/user/whoami")
    assert jar == {}


def test_the_port_is_part_of_the_origin():
    """No cookie `domain` can express a port — `domain: "localhost:8081"` silently matches
    nothing — which is why this is an origin and not a domain."""
    other = {"name": "s", "value": "1", "target_origin": "http://dvwa:8081"}
    jar, _ = merge(application=[other], url=f"{DVWA}/x", path="/x")
    assert jar == {}


def test_the_scheme_is_part_of_the_origin():
    https = {"name": "s", "value": "1", "target_origin": "https://dvwa"}
    jar, _ = merge(application=[https], url=f"{DVWA}/x", path="/x")
    assert jar == {}


@pytest.mark.parametrize("cookie,why", [
    ({"name": "s", "value": "1", "target_origin": DVWA, "path": "/admin"},
     "declared for a path this request is not under"),
])
def test_path_scoping_is_honoured(cookie, why):
    jar, _ = merge(application=[cookie], path="/public")
    assert jar == {}, why


# --------------------------------------------------------------- the declaration

def test_the_origin_is_required_and_held_to_the_scope():
    """An application cookie names the origin it configures, and that origin passes the same
    scope check an identity's does — otherwise a declaration could put a value on a host the
    engagement never authorised."""
    import asyncio

    from orchestrator.integrations.service import preflight
    from orchestrator.testcase.scope import ScopeViolation

    config = AssessmentConfig(
        scope={"allow_hosts": ["dvwa"], "allow_ports": [80]},
        application_cookies=[{"name": "s", "value": "1",
                              "target_origin": "http://elsewhere.test"}])
    with pytest.raises((ScopeViolation, ValueError)):
        asyncio.run(preflight(f"{DVWA}/", config, check_images=False))


@pytest.mark.parametrize("origin,why", [
    ("http://dvwa/path", "an origin carrying a path"),
    ("http://dvwa/?q=1", "an origin carrying a query"),
    ("http://dvwa/#f", "an origin carrying a fragment"),
    ("ftp://dvwa", "a non-HTTP scheme"),
    ("http://user@dvwa", "an origin carrying credentials"),
    ("", "no origin at all"),
])
def test_the_declared_origin_must_be_a_bare_HTTP_origin(origin, why):
    """It is compared against the request's origin, so anything but scheme+host+port is a
    declaration that can never match — silently, which is the worse failure."""
    import pydantic
    with pytest.raises(pydantic.ValidationError):
        AssessmentConfig(scope={"allow_hosts": ["dvwa"], "allow_ports": [80]},
                         application_cookies=[{"name": "s", "value": "1",
                                               "target_origin": origin}]), why


@pytest.mark.parametrize("bad,why", [
    ({"name": "a;b", "value": "x"}, "a ';' would make one declared cookie into two"),
    ({"name": "a", "value": "x;y"}, "same, in the value"),
    ({"name": "a b", "value": "x"}, "whitespace in a cookie name"),
    ({"name": "a=b", "value": "x"}, "'=' in a cookie name"),
    ({"name": "a", "value": "x\r\nX-Evil: 1"}, "a header smuggled through the value"),
    ({"name": "a", "value": "x", "path": "relative"}, "a path that is not a path"),
])
def test_a_declaration_that_could_forge_a_header_is_refused(bad, why):
    import pydantic
    with pytest.raises(pydantic.ValidationError):
        AssessmentConfig(scope={"allow_hosts": ["dvwa"], "allow_ports": [80]},
                         application_cookies=[{**bad, "target_origin": DVWA}]), why


def test_two_values_for_one_name_at_one_origin_are_refused():
    """Not configuration, a coin toss: the proxy would send one and the arms would agree
    only by luck."""
    import pydantic
    with pytest.raises(pydantic.ValidationError):
        AssessmentConfig(scope={"allow_hosts": ["dvwa"], "allow_ports": [80]},
                         application_cookies=[SECURITY, {**SECURITY, "value": "high"}])


def test_the_same_name_at_DIFFERENT_origins_is_fine():
    config = AssessmentConfig(
        scope={"allow_hosts": ["dvwa", "juice-shop"], "allow_ports": [80, 3000]},
        application_cookies=[SECURITY, {"name": "security", "value": "high",
                                        "target_origin": JUICE}])
    assert len(config.application_cookies) == 2


# ------------------------------------------------------- what the record must say

async def test_the_published_configuration_keeps_the_names_and_drops_the_values(tmp_path, monkeypatch):
    """`redact` blanks any key matching /cookie/ WHOLESALE, which turned this list into the
    string "[REDACTED]" — and the DefectDojo export path re-validates the published copy as
    an AssessmentConfig, so it raised a list_type error. `security=low` is not a secret; it
    is the single fact that makes a finding reproducible, and a report that cannot say which
    application the evidence describes is not a report."""
    import json

    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    from orchestrator.integrations.service import register
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()

    config = AssessmentConfig(scope={"allow_hosts": ["dvwa"], "allow_ports": [80]},
                              application_cookies=[SECURITY])
    await register("s", DVWA, config)
    rows = await db.rows("SELECT config FROM integration_assessments WHERE session_id='s'")
    published = json.loads(rows[0]["config"])
    assert published["application_cookies"][0]["name"] == "security"
    assert published["application_cookies"][0]["target_origin"] == DVWA
    assert published["application_cookies"][0]["value"] == "[REDACTED]"
    # And it must still be a valid AssessmentConfig, because other code re-validates it.
    assert AssessmentConfig.model_validate(published).application_cookies[0].name == "security"
