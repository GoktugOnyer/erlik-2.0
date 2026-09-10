"""E-027: the marker the authorization check needs could not be supplied.

The typed `idor` evaluator compares a `private_object_marker` — a fragment that
identifies the privileged object — across three arms. Nothing could set it:

  - `private_object_marker` was not in `declared.DECLARABLE`, so an operator
    declaring it got "is not a declarable field";
  - and `looks_injectable` refuses `"`, so the markers that actually identify an
    object in a JSON API — `"UserId":1`, `"email":"admin@juice-sh.op"` — would have
    been refused even once listed.

The second rule is right where it applies and does not apply here. It exists because
a declared value is RENDERED INTO A COMMAND, and `"` closes a quoted argument. A
marker is never rendered into anything: the evaluator reads it in Python and uses it
as a substring. So it gets a rule appropriate to that — bounded, no control
characters, no NUL — and a test below asserts the premise, that no catalogue command
interpolates it.

The marker is also the safety property of the whole check. It is OPERATOR-authored;
the responses are the target's. A target can therefore fail to contain the marker
and cost itself a finding, and cannot invent one.
"""
import pytest

from orchestrator.testcase import declared as D


REALISTIC = [
    '"UserId":1',
    '"email":"admin@juice-sh.op"',
    '"author":"admin@juice-sh.op"',
    "secret-account-balance-99",
    '"role":"admin"',
    "Administrator",
]


@pytest.mark.parametrize("marker", REALISTIC)
def test_the_markers_a_json_api_actually_needs_are_accepted(marker):
    assert D.validate("private_object_marker", marker) == "", (
        f"{marker!r}: {D.validate('private_object_marker', marker)}")


@pytest.mark.parametrize("bad,because", [
    ("", "is empty"),
    ("   ", "is empty"),
    ("x" * 513, "longer"),
    ("a\nb", "control"),
    ("a\rb", "control"),
    ("a\x00b", "control"),
])
def test_a_marker_that_cannot_be_compared_safely_is_refused(bad, because):
    reason = D.validate("private_object_marker", bad)
    assert reason, f"{bad!r} was accepted"
    assert because in reason.lower(), f"{bad!r} -> {reason!r}"


def test_a_marker_is_not_a_path_and_is_not_prefixed_with_the_base_url():
    """`render` prepends the target's base URL to PATH_FIELDS. A marker is a body
    fragment, so doing that to it would compare the application's response against
    a string beginning `http://app.test`, and the check would never fire."""
    assert "private_object_marker" not in D.PATH_FIELDS
    assert D.render("private_object_marker", '"UserId":1', "http://app.test") == '"UserId":1'


def test_no_catalogue_command_interpolates_the_marker():
    """The premise of relaxing the shell rule for this field.

    If any step rendered `{{private_object_marker}}` into a command, the marker would
    be shell-adjacent text after all and would need `looks_injectable`. This asserts
    the premise rather than assuming it, so adding such a step fails here rather than
    quietly widening what reaches a command line.
    """
    from orchestrator.testcase.loader import load_catalog

    offenders = [(case_id, step.name)
                 for case_id, tc in load_catalog().items()
                 for step in tc.steps
                 if "private_object_marker" in step.command]
    assert not offenders, (
        "these steps render the marker into a command, so it must keep the shell "
        f"metacharacter rule: {offenders}")


def test_the_shell_rule_still_applies_to_fields_that_are_rendered():
    """The relaxation is for one field, not a general loosening."""
    for field in ("url", "parameter", "submit", "object_ids"):
        assert D.validate(field, 'a"b'), f"{field} accepted a double quote"
        assert D.validate(field, "a$b"), f"{field} accepted a dollar sign"


# ------------------------------------- the other two gates on the same field

def test_the_sweep_gate_accepts_an_evaluator_only_field():
    """There are three places a target field is checked for injectability, and they
    exist for different reasons. This one's own comment says why it exists: the
    values "are substituted into `bash -c '...'` command templates". For a marker
    that is false — `test_no_catalogue_command_interpolates_the_marker` above holds
    the premise — so this gate consults the same `EVALUATOR_ONLY` list rather than
    keeping a second opinion that can drift from the first.
    """
    from orchestrator.testcase import sweep as S
    from orchestrator.testcase.loader import load_catalog

    cases = [tc.model_dump() for tc in load_catalog().values()]
    plan = S.plan_sweep(cases, "http://app.test", "juiceshop",
                        extra={"low_priv_token": "a", "high_priv_token": "b",
                               "private_object_marker": '"UserId":1'})
    skipped = {s["id"]: s.get("reason", "") for s in plan["skipped"]}
    assert "WSTG-AUTHZ-04" not in skipped, (
        f"the case is still skipped: {skipped.get('WSTG-AUTHZ-04')}")


def test_the_sweep_gate_still_refuses_a_marker_it_cannot_compare():
    from orchestrator.testcase import sweep as S
    from orchestrator.testcase.loader import load_catalog

    cases = [tc.model_dump() for tc in load_catalog().values()]
    plan = S.plan_sweep(cases, "http://app.test", "juiceshop",
                        extra={"low_priv_token": "a", "high_priv_token": "b",
                               "private_object_marker": "has a\nnewline"})
    skipped = {s["id"]: s.get("reason", "") for s in plan["skipped"]}
    assert "WSTG-AUTHZ-04" in skipped
    assert "control character" in skipped["WSTG-AUTHZ-04"]


def test_a_marker_can_never_be_harvested_from_a_response():
    """The forgery this field would otherwise open.

    `Evaluator.produces` lets a case lift a value out of the TARGET'S OWN OUTPUT
    and carry it forward as a target field. The whole safety property of the
    authorization check is that the marker is OURS and the responses are the
    target's — a target that could choose the marker could choose the finding, by
    naming something it returns to everybody.

    So an evaluator-only field is refused in `produces` structurally, and not left
    to whoever writes the next case.
    """
    import pytest
    from pydantic import ValidationError
    from orchestrator.testcase.schema import Evaluator

    with pytest.raises(ValidationError) as exc:
        Evaluator(type="regex", pattern="(.*)", produces={"private_object_marker": 1})
    assert "private_object_marker" in str(exc.value)

    # An ordinary produced field is unaffected.
    Evaluator(type="regex", pattern="(.*)", produces={"url": 1})


def test_no_catalogue_case_harvests_an_evaluator_only_field():
    from orchestrator.testcase.loader import load_catalog
    from orchestrator.testcase.declared import EVALUATOR_ONLY

    offenders = [(case_id, step.name, field)
                 for case_id, tc in load_catalog().items()
                 for step in tc.steps
                 for ev in step.evaluators
                 for field in (ev.produces or {})
                 if field in EVALUATOR_ONLY]
    assert not offenders, offenders
