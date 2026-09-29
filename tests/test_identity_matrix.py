"""Increment 6: the identity matrix — E-008's other half.

The plan's slice sentence opens with "an operator selects two lab identities", and every
later clause is now built: a hidden API operation is discovered (Increment 4), its
coverage is visible (Increment 5), a seeded authorization flaw reproduces (the
`ownership` evaluator), and its evidence opens. What was missing is the declaration that
makes the rest mean something — E-008 asks for "roles, tenant labels, object ownership,
authentication-check status, and expected permissions" on the existing named identities,
starting from "anonymous, two ordinary users in different tenants, and one privileged lab
identity", with operators declaring "which objects each identity may access".

WHY THESE FIELDS AND NOT OTHERS. The `ownership` evaluator rests on one asymmetry: who
the caller IS comes from the OPERATOR and the asserted owner comes from the TARGET, so a
target can cost itself a finding and cannot manufacture one. `subject_id` was being passed
per-run in the target dict, which works for a hand-driven check and cannot work in the
lane — there, authentication happens at the PROXY and a case carries no credentials at
all, so nothing told a case who it was running as. Putting it on the identity is what
makes the evaluator reachable from a real assessment, and it travels with the arm rather
than with the run, so two arms cannot share one by accident.
"""
import pytest
from pydantic import ValidationError

from orchestrator.integrations.contracts import Identity


def identity(**kw):
    base = {"name": "reader", "target_origin": "http://app.test",
            "check": {"url": "http://app.test/me", "method": "GET"}}
    base.update(kw)
    return Identity.model_validate(base)


# ------------------------------------------------------------ the declarations

def test_an_identity_can_declare_its_role_tenant_and_subject():
    who = identity(role="customer", tenant="acme", subject_id="2")
    assert who.role == "customer"
    assert who.tenant == "acme"
    assert who.subject_id == "2"


def test_the_fields_are_optional_so_existing_identities_still_validate():
    """Every identity stored before this existed has none of them, and an assessment
    that does not need a matrix should not have to invent one."""
    who = identity()
    assert who.role == "" and who.tenant == "" and who.subject_id == ""
    assert who.may_access == []


def test_an_operator_declares_which_objects_an_identity_may_reach():
    """E-008: "Operators declare which objects each identity may access." That is the
    only non-target-derived statement of expected access there is, and without it
    `expected access` and `unexpected access` cannot be distinguished."""
    who = identity(subject_id="2", may_access=["/rest/basket/2", "/api/Cards/5"])
    assert who.may_access == ["/rest/basket/2", "/api/Cards/5"]


# ---------------------------------------------------------------- validation

@pytest.mark.parametrize("field,value", [
    ("role", "a" * 81),
    ("tenant", "a" * 81),
    ("subject_id", "a" * 201),
    ("role", "cust\nomer"),
    ("tenant", "ac;me`id`"),
    ("subject_id", 'x"y'),
    ("subject_id", "$(id)"),
])
def test_a_declaration_that_could_not_be_rendered_safely_is_refused(field, value):
    """These are operator text that reaches a command template and an evidence quote, so
    they are held to the same rule as every other declared field. `subject_id` especially:
    it is compared against the application's own response and printed into the finding."""
    with pytest.raises(ValidationError):
        identity(**{field: value})


def test_an_absurd_number_of_declared_objects_is_refused():
    with pytest.raises(ValidationError):
        identity(may_access=[f"/o/{n}" for n in range(201)])


def test_a_declared_object_must_be_a_path_not_a_url():
    """Same reasoning as `declared.PATH_FIELDS`: a declaration that can name a host lets
    an identity claim access to a different machine, and nothing downstream would catch
    it."""
    with pytest.raises(ValidationError):
        identity(may_access=["http://evil.test/o/1"])
    with pytest.raises(ValidationError):
        identity(may_access=["//evil.test/o/1"])
    identity(may_access=["/o/1"])


# --------------------------------------------------- they are not secrets

def test_the_matrix_fields_are_never_scrubbed_from_evidence():
    """`secret_values` is an explicit allow-list of the secret-bearing fields, and it
    must stay one.

    If it swept every string on the identity instead, `subject_id` would be redacted out
    of the very evidence that quotes it — the ownership finding says "the caller is
    declared to be '2'", and a finding whose own comparison is replaced by a redaction
    marker cannot be checked by the person reading it.
    """
    from orchestrator.integrations.security import secret_values

    who = identity(role="customer", tenant="acme", subject_id="2",
                   may_access=["/rest/basket/2"],
                   headers={"Authorization": "Bearer s3cret"},
                   cookies=[{"name": "sid", "value": "c00kie"}])
    values = secret_values(who.model_dump())
    assert "s3cret" in values and "c00kie" in values
    for declared in ("customer", "acme", "2", "/rest/basket/2", "reader"):
        assert declared not in values, f"{declared!r} was treated as a secret"


def test_the_redacted_view_keeps_the_matrix_and_drops_the_material():
    """An operator reading a saved assessment should see WHO the arms were, and never
    what authenticated them."""
    from orchestrator.integrations.security import redact

    who = identity(role="customer", tenant="acme", subject_id="2",
                   headers={"Authorization": "Bearer s3cret"})
    view = redact(who.model_dump())
    assert "s3cret" not in str(view)
    assert view["role"] == "customer" and view["tenant"] == "acme"
    assert view["subject_id"] == "2"


# ------------------------------------------------ reaching a case in the lane

def test_the_lane_hands_a_case_the_identity_it_is_running_as():
    """Without this the `ownership` evaluator is unreachable from an assessment.

    In the lane a case carries no credentials — the proxy injects them — so nothing told
    a case who it was running as, and the evaluator's `subject_id` could only be supplied
    by hand. These are the non-secret declarations, so they travel in the target dict
    while the material stays at the proxy.
    """
    from orchestrator.integrations.contracts import identity_target_fields

    who = identity(role="customer", tenant="acme", subject_id="2",
                   headers={"Authorization": "Bearer s3cret"},
                   cookies=[{"name": "sid", "value": "c00kie"}])
    fields = identity_target_fields(who.model_dump())
    assert fields == {"subject_id": "2", "identity_role": "customer",
                      "identity_tenant": "acme"}
    # Nothing that authenticates is in there. A case that needs credentials is meant to
    # be refused by the lane, not quietly handed them in a target field.
    assert "s3cret" not in str(fields) and "c00kie" not in str(fields)
    assert "cookie" not in fields and "auth_header" not in fields


def test_an_identity_with_no_declarations_adds_no_fields():
    """An empty string is not a declaration. Passing `subject_id: ""` would make the
    ownership evaluator's "is an owner asserted for this caller" question unanswerable
    while looking answered."""
    from orchestrator.integrations.contracts import identity_target_fields

    assert identity_target_fields(identity().model_dump()) == {}
    assert identity_target_fields(None) == {}
    assert identity_target_fields({}) == {}


def test_the_catalogue_adapter_passes_them_through():
    from pathlib import Path
    source = Path("orchestrator/integrations/deterministic.py").read_text()
    assert "identity_target_fields" in source, (
        "the adapter does not hand a case its identity, so the ownership evaluator "
        "cannot run in the lane")


async def test_the_arm_comparison_reports_role_and_tenant(tmp_path, monkeypatch):
    """E-011's acceptance names cross-user, cross-tenant and privileged-function
    violations. `tenant` is what makes the middle one something a reader can see rather
    than infer from two opaque identity handles."""
    import json
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    from orchestrator.integrations.inventory import compare_arms
    from orchestrator.integrations.security import SecretStore

    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()

    store = SecretStore()
    first = store.put(identity(name="alice", role="customer", tenant="acme",
                               subject_id="2").model_dump())
    second = store.put(identity(name="bob", role="customer", tenant="globex",
                                subject_id="3").model_dump())
    for handle in (first, second):
        await db.execute("INSERT INTO integration_identities VALUES(?,?,?)",
                         (handle, "x", "http://app.test"))
        await db.execute(
            "INSERT OR REPLACE INTO integration_endpoints"
            "(session_id,url,method,identity_id,sources,parameters) VALUES(?,?,?,?,?,?)",
            ("s", "http://app.test/basket", "GET", handle, json.dumps(["katana"]),
             json.dumps(["id"])))

    result = await compare_arms("s", first, second)
    assert result["comparable"], result["refused_because"]
    assert result["roles"] == {first: "customer", second: "customer"}
    assert result["tenants"] == {first: "acme", second: "globex"}
    assert result["cross_tenant"] is True


# ---------------------------- the boundary the matrix does NOT cross, pinned

def test_a_lane_stage_carries_exactly_one_identity():
    """Why the matrix does not make the ownership evaluator lane-runnable.

    Each stage resolves ONE identity from its own row, and the proxy authenticates every
    request in that stage as that identity. The `ownership` evaluator needs three arms in
    ONE case execution — the caller, the declared owner, and anonymous — so no single
    lane stage can satisfy it however the identity is declared.

    This is pinned rather than explained away: a future reader seeing `subject_id` travel
    into a case's target dict would reasonably expect the evaluator to work there, and it
    does not. The lane-native shape is a comparison ACROSS stages, which `compare_arms`
    already does for surfaces and does not yet do for responses — recorded in
    docs/future-plan.md rather than half-built here.
    """
    from pathlib import Path
    source = Path("orchestrator/integrations/service.py").read_text()
    assert 'identity = SecretStore().get(stage["identity_id"])' in source, (
        "if a stage can now carry more than one identity, this limit has moved")

    from orchestrator.integrations.inventory import executable_test_cases
    assert "WSTG-AUTHZ-04" not in executable_test_cases(), (
        "AUTHZ-04 became lane-runnable; its three-arm shape needs per-role credentials "
        "the lane has nothing to choose between")


def test_the_declarations_do_not_widen_what_the_lane_supplies():
    """`subject_id` reaches a case through the identity, not through discovery.

    It is deliberately NOT in `LANE_TARGET_FIELDS`: that set answers "what can DISCOVERY
    produce", and adding a field no lane-runnable case requires would change the measured
    9-of-35 figure for nothing. The bridge is how it travels; the set is unchanged.
    """
    from orchestrator.integrations.inventory import LANE_TARGET_FIELDS, executable_test_cases
    from orchestrator.testcase.loader import load_catalog

    assert LANE_TARGET_FIELDS == frozenset({"url", "parameter"})
    # 9, not the 12 this once asserted, and the three that left are named with their
    # causes in test_curl_dialect.TestWhatTheLaneCannotRunIsDeclared rather than
    # absorbed into a smaller number here. Nothing about `subject_id` caused it.
    assert len(executable_test_cases()) == 9
    # 35 since the business-logic and stale-access cases joined: BUSL-05 (usage
    # limits), BUSL-06 (workflow circumvention) and AUTHZ-02 (access surviving an
    # ownership transfer). None is lane-runnable and none may become so —
    # both need operator-supplied fields (`request_template`, `final_request`) that
    # the lane has no way to invent, so the 9 above is the figure that matters here.
    assert len(load_catalog()) == 35
