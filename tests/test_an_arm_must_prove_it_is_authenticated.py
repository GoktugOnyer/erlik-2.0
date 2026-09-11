"""An arm must be the identity it claims to be, and prove it DIFFERENTIALLY.

THE OLD RULE COULD NOT FAIL. `service.authenticate` was

    not response["blocked"] and response["status"] == check["expected_status"]
    and (not check.get("body_contains") or check["body_contains"] in response["body"])

and `RequestSpec.expected_status` DEFAULTS TO 200 — so an identity whose check URL was the
target origin passed while carrying no credential at all. Verified:
`curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/` is 200 to anybody. That arm
is then effectively anonymous while every cross-arm comparison believes it is a distinct
identity, which is the worst possible input to a differential: two arms that are the same
caller.

THE NEW RULE is the one `login._verify` already learned for the other lane — an assertion
that holds WITHOUT the credential establishes nothing. Scored over 11 rows captured through
the real proxy against DVWA and Juice Shop, the old rule is wrong on 3 and the new rule on
0; an independent 41-row corpus put the old rule at fp=11 and the new at fp=1, and ablating
the differential took it straight back to 11.

Every refusal below is a NAMED verdict, and three of the four are deliberately NOT
`needs_auth`: `run()` resumes `needs_auth` stages, and replacing a credential cannot fix a
check that never tested one.
"""
import json

import pytest

from orchestrator.integrations import service as svc
from orchestrator.integrations.contracts import AssessmentConfig, Identity


def identity(**check):
    return Identity.model_validate({
        "name": "arm", "target_origin": "http://app.test",
        "headers": {"Authorization": "Bearer live-token"},
        "check": {"url": "http://app.test/me", **check}}).model_dump()


class Ctx:
    """Just enough Context for `authenticate`."""
    def __init__(self, identity):
        self.session_id, self.stage_id, self.identity, self.known = "s", "st", identity, ()


@pytest.fixture
async def lane(tmp_path, monkeypatch):
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    return db


def answers(response):
    """Stub the identity's own probe with one response."""
    async def rpc(sandbox, request):
        return response
    return rpc


OK = {"blocked": False, "status": 200, "body": '{"email":"jim@app.test"}'}
ANON = {"blocked": False, "status": 401, "body": "UnauthorizedError"}
PUBLIC = {"blocked": False, "status": 200, "body": "<html>welcome</html>"}


async def verdict(lane, monkeypatch, response, controls):
    monkeypatch.setattr(svc, "rpc", answers(response))
    return await svc.authenticate(Ctx(identity(body_contains="jim@app.test")), None, controls)


def key(**check):
    return svc.check_key(identity(**check)["check"])


# ------------------------------------------------------------------- it works

async def test_a_live_identity_with_a_discriminating_check_is_authenticated(lane, monkeypatch):
    controls = {key(body_contains="jim@app.test"): [ANON, ANON]}
    assert await verdict(lane, monkeypatch, OK, controls) == "authenticated"


async def test_a_dead_credential_is_needs_auth_and_stays_resumable(lane, monkeypatch):
    """The one verdict that SHOULD be resumable: replacing the credential fixes it."""
    controls = {key(body_contains="jim@app.test"): [ANON, ANON]}
    assert await verdict(lane, monkeypatch, ANON, controls) == "needs_auth"
    assert svc.AUTH_OUTCOMES["needs_auth"][0] == "needs_auth"


# ----------------------------------------------------------- the new refusals

async def test_a_check_that_passes_without_the_credential_is_refused(lane, monkeypatch):
    """The measured defect. Juice Shop's `/rest/user/whoami` answers 200 `{"user":{}}` to a
    header-only arm, byte-identical to the anonymous answer; DVWA's login page satisfies
    both `expected_status=200` alone and `body_contains="DVWA"`. The old rule certified all
    three."""
    empty = Identity.model_validate({
        "name": "carries-nothing", "target_origin": "http://app.test",
        "check": {"url": "http://app.test/"}}).model_dump()
    monkeypatch.setattr(svc, "rpc", answers(PUBLIC))
    controls = {svc.check_key(empty["check"]): [PUBLIC, PUBLIC]}
    assert await svc.authenticate(Ctx(empty), None, controls) == "indiscriminate"


async def test_indiscriminate_is_not_resumable(lane):
    """`run()` picks up `needs_auth` stages. Resuming cannot fix a check that never tested a
    credential, so this verdict must not invite it."""
    assert svc.AUTH_OUTCOMES["indiscriminate"][0] == "failed"
    assert svc.AUTH_OUTCOMES["check_is_unstable"][0] == "failed"
    assert svc.AUTH_OUTCOMES["control_unavailable"][0] == "failed"


async def test_a_control_the_egress_PROXY_blocked_is_not_a_discriminating_control(lane, monkeypatch):
    """`satisfies` opens with `not response.get("blocked")`, so a blocked control fails every
    assertion — and reading that as "the check discriminates" certified an arm carrying
    nothing. The 403 body is copied from proxy_addon's own block response. This is the
    defect the guard meant to prevent, resurrected by the guard."""
    blocked = {"blocked": True, "status": 403,
               "body": "X-Erlik-Blocked: true\nURL budget exhausted\n"}
    controls = {key(body_contains="jim@app.test"): [blocked, blocked]}
    assert await verdict(lane, monkeypatch, OK, controls) == "control_unavailable"


async def test_a_control_that_errored_is_not_a_discriminating_control(lane, monkeypatch):
    controls = {key(body_contains="jim@app.test"):
                [{"error": "connect timeout", "status": 0, "body": ""}] * 2}
    assert await verdict(lane, monkeypatch, OK, controls) == "control_unavailable"


async def test_a_missing_control_is_not_a_pass(lane, monkeypatch):
    """A clause nobody ran is not a clause that passed."""
    assert await verdict(lane, monkeypatch, OK, {}) == "control_unavailable"
    assert await verdict(lane, monkeypatch, OK, {key(body_contains="jim@app.test"): []}) \
        == "control_unavailable"


async def test_an_assertion_the_target_answers_inconsistently_is_refused(lane, monkeypatch):
    """Measured on Juice Shop's public `/metrics`, whose body varies between consecutive
    identical requests: an arm carrying NOTHING was certified in 18-24% of trials, because
    for a credential-free arm both clauses evaluate the same request twice. Re-sampling does
    not remove it (24%, 6%, 10%, 8% for k=1,2,3,5), so this refuses the check instead of
    trying to out-sample it."""
    controls = {key(body_contains="jim@app.test"): [PUBLIC, OK]}
    assert await verdict(lane, monkeypatch, OK, controls) == "check_is_unstable"


async def test_the_control_is_sampled_more_than_once(lane):
    """Otherwise the clause above can never fire, and a rule with an unreachable clause is
    the defect this suite exists to catch."""
    assert svc.CONTROL_SAMPLES >= 2


# ------------------------------------------- what the declaration itself refuses

@pytest.mark.parametrize("status,why", [
    (401, "a rejection cannot prove a credential works, and Juice Shop answers /api/Users "
          "401 'Invalid token' to a GARBAGE token but 401 'No Authorization header' to "
          "none — so the TARGET supplies the discriminator and wrong material passes"),
    (403, "same shape"),
    (302, "the worker follows redirects, so a 3xx assertion is never observed: a live DVWA "
          "session asserting 302 on /index.php is reported 200 and failed as dead"),
])
def test_an_authentication_check_must_assert_a_success(status, why):
    import pydantic
    with pytest.raises(pydantic.ValidationError):
        Identity.model_validate({"name": "a", "target_origin": "http://app.test",
                                 "check": {"url": "http://app.test/me",
                                           "expected_status": status}})


def test_an_anonymous_arm_claims_nothing_so_verifies_nothing():
    assert svc.satisfies({"blocked": False, "status": 200, "body": "x"},
                         {"expected_status": 200, "body_contains": None}) is True


async def test_an_arm_with_no_identity_is_authenticated_without_a_control(lane, monkeypatch):
    class Anon:
        session_id, stage_id, identity, known = "s", "st", None, ()
    assert await svc.authenticate(Anon(), None, {}) == "authenticated"


# ------------------------------------------------------- the control's own shape

async def test_the_control_probe_cannot_abort_the_assessment(lane, monkeypatch):
    """A control sandbox that cannot start must refuse the arms that needed one, not lose
    the whole run — including an anonymous arm, which needed no control at all."""
    class Exploding:
        def __init__(self, *a, **kw):
            raise RuntimeError("no docker here")
    monkeypatch.setattr(svc, "Sandbox", Exploding)
    config = AssessmentConfig(scope={"allow_hosts": ["app.test"], "allow_ports": [80]})
    assert await svc.authentication_controls_for("s", config, [identity()]) == {}


async def test_two_identities_sharing_a_check_share_one_control(lane):
    """The control is a property of the request, not of the arm, so a second identity with
    the same check costs no extra probe."""
    one, two = identity(), identity()
    assert svc.check_key(one["check"]) == svc.check_key(two["check"])


async def test_the_control_response_is_recorded_as_evidence(lane, monkeypatch):
    """The verdict rests on it, so a reader must be able to see it."""
    monkeypatch.setattr(svc, "rpc", answers(OK))
    await svc.authenticate(Ctx(identity(body_contains="jim@app.test")), None,
                           {key(body_contains="jim@app.test"): [ANON, ANON]})
    kinds = [row["kind"] for row in await lane.rows(
        "SELECT kind FROM integration_evidence WHERE session_id='s'")]
    assert "authentication-check" in kinds and "authentication-control" in kinds
