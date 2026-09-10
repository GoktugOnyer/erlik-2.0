"""E-011: object-level authorization, and the two forgeries it must refuse.

The existing `idor` evaluator asks whether two identities received the SAME
BYTES. On an API that cannot work — every JSON response carries ids and
timestamps, so two identities never produce identical bytes and a hash
differential is noise. This evaluator asks a sharper question: does the
application ITSELF say the object belongs to somebody other than the caller?

Measured against the real lab (Juice Shop v17.1.1, http://localhost:3000):

    admin@juice-sh.op  is user 1 and owns basket 1
    jim@juice-sh.op    is user 2 and owns basket 2

    GET /rest/basket/1 as jim      -> 200 {"data":{"id":1,"UserId":1,...}}
    GET /rest/basket/2 as jim      -> 200 {"data":{"id":2,"UserId":2,...}}
    GET /rest/basket/99999 as jim  -> 200 {"status":"success","data":null}
    GET /rest/basket/1 anonymous   -> 401
    GET /api/Products  as anyone   -> 200, a list, no ownership field

The third line is why E-011 says "not merely HTTP 200": a nonexistent object
answers 200, and a status-code check reports a critical authorization flaw on an
object that does not exist.
"""
import json

import pytest

from orchestrator.testcase.runner import _run_evaluator, StepResult
from orchestrator.testcase.schema import Evaluator, TestCase as Case, TestStep as Step


CASE = Case(id="WSTG-AUTHZ-04.2", name="Object-level authorization",
                category="Authorization", steps=[Step(name="read_as_caller", tool="curl", command="curl x")])


def response(status, body):
    return (f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n"
            + (body if isinstance(body, str) else json.dumps(body)))


def owned_by(owner):
    return response(200, {"status": "success", "data": {"id": 1, "UserId": owner}})


def step(name, output):
    return StepResult(step=name, command="curl x", output=output,
                      exit_code=0, success=True, duration_ms=12)


EVALUATOR = Evaluator(type="ownership", owner_field="data.UserId",
                      owner_step="read_as_owner", anonymous_step="read_anonymously",
                      emit_finding={"vuln_type": "Broken Object Level Authorization",
                                    "severity": "high"})


async def verdict(caller_output, *, subject, owner_output=None, anon_output=None,
                  evaluator=EVALUATOR):
    prior = []
    if owner_output is not None:
        prior.append(step("read_as_owner", owner_output))
    if anon_output is not None:
        prior.append(step("read_anonymously", anon_output))
    finding, _, _, _ = await _run_evaluator(
        evaluator, step("read_as_caller", caller_output), CASE,
        {"url": "http://app.test/rest/basket/1", "subject_id": subject},
        None, None, prior)
    return finding


# ------------------------------------------------------------- the finding

async def test_the_measured_juice_shop_violation_is_reported():
    """jim (user 2) reads basket 1, which the application attributes to user 1."""
    finding = await verdict(owned_by(1), subject=2,
                            owner_output=owned_by(1), anon_output=response(401, {"error": "unauthorised"}))
    assert finding is not None
    assert finding.severity == "high"
    assert "'2'" in finding.evidence or "2" in finding.evidence
    assert "data.UserId" in finding.evidence
    assert "anonymous was refused" in finding.evidence


async def test_a_string_identifier_works_as_well_as_a_numeric_one():
    """Not every application numbers its users."""
    finding = await verdict(owned_by("alice@lab.invalid"), subject="bob@lab.invalid",
                            owner_output=owned_by("alice@lab.invalid"),
                            anon_output=response(403, {"error": "forbidden"}))
    assert finding is not None


# ------------------------------------------------------- the negative controls

async def test_the_caller_reading_their_own_object_is_not_a_finding():
    """jim reads basket 2. Expected access, and the commonest response of all."""
    assert await verdict(owned_by(2), subject=2, owner_output=owned_by(2),
                         anon_output=response(401, {})) is None


async def test_a_numeric_owner_matching_a_string_subject_is_not_a_finding():
    """`2` and `"2"` are the same principal.

    An application returns JSON numbers; an operator types a string into a form.
    Comparing them by type would report every identity as reading every one of
    its OWN objects — a critical finding on every request the tool makes.
    """
    assert await verdict(owned_by(2), subject="2", owner_output=owned_by(2),
                         anon_output=response(401, {})) is None


async def test_a_nonexistent_object_answering_200_is_not_a_finding():
    """The measured trap: GET /rest/basket/99999 -> 200 {"data":null}."""
    absent = response(200, {"status": "success", "data": None})
    assert await verdict(absent, subject=2, owner_output=absent,
                         anon_output=response(401, {})) is None


async def test_public_content_with_no_ownership_field_is_not_a_finding():
    """GET /api/Products -> 200 and a list. Nothing is being attributed."""
    catalogue = response(200, {"status": "success", "data": [{"id": 1, "name": "Apple Juice"}]})
    assert await verdict(catalogue, subject=2, owner_output=catalogue,
                         anon_output=response(401, {})) is None


async def test_a_caller_who_was_refused_is_not_a_finding():
    """Access control working is the outcome we hope for, not a finding."""
    assert await verdict(response(403, {"error": "forbidden"}), subject=2,
                         owner_output=owned_by(1), anon_output=response(401, {})) is None


# ------------------------------------------------------------- the forgeries

async def test_a_target_that_forges_ownership_is_refused():
    """The clause that stops a target choosing its own finding.

    A fixture that asserts one owner to EVERY caller, anonymous included, is
    publishing that content — however it attributes it. Without the anonymous
    clause the lane reports a critical authorization leak on a page the
    application serves to the world, and the target decides when that happens.

    Verified against a real fixture as well as here: a local server answering
    /forged with {"data":{"UserId":1}} to everyone was refused, while the same
    body behind a 401 for anonymous was reported.
    """
    assert await verdict(owned_by(1), subject=2, owner_output=owned_by(1),
                         anon_output=owned_by(1)) is None, (
        "content served to anonymous callers was reported as a leak")


async def test_an_uncorroborated_owner_is_refused():
    """The other forgery: naming an owner who cannot read the object.

    A target that answers every request with "UserId: 1" but denies user 1 has
    not leaked anything to anyone — it has printed a number at us.
    """
    assert await verdict(owned_by(1), subject=2,
                         owner_output=response(403, {"error": "forbidden"}),
                         anon_output=response(401, {})) is None


async def test_an_owner_who_returns_a_different_owner_is_refused():
    assert await verdict(owned_by(1), subject=2, owner_output=owned_by(7),
                         anon_output=response(401, {})) is None


# --------------------------------------------------- the clauses are required

@pytest.mark.parametrize("missing", ["owner_step", "anonymous_step", "owner_field"])
async def test_every_clause_is_required_for_a_finding(missing):
    """A partly-configured evaluator must stay silent, not fall back to a weaker
    check. Degrading to "200 and a different number" is precisely what E-011
    forbids."""
    fields = dict(type="ownership", owner_field="data.UserId",
                  owner_step="read_as_owner", anonymous_step="read_anonymously")
    fields[missing] = None
    assert await verdict(owned_by(1), subject=2, owner_output=owned_by(1),
                         anon_output=response(401, {}),
                         evaluator=Evaluator(**fields)) is None


async def test_a_missing_subject_id_is_not_a_finding():
    """`subject_id` is what the operator declares. Without it there is nothing to
    compare the target's claim against, and guessing would mean trusting the
    target on both sides of the comparison."""
    assert await verdict(owned_by(1), subject=None, owner_output=owned_by(1),
                         anon_output=response(401, {})) is None
    assert await verdict(owned_by(1), subject="", owner_output=owned_by(1),
                         anon_output=response(401, {})) is None


async def test_an_anonymous_step_that_never_ran_is_not_a_finding():
    """Absent is not refused. A clause nobody executed proves nothing."""
    assert await verdict(owned_by(1), subject=2, owner_output=owned_by(1),
                         anon_output=None) is None
