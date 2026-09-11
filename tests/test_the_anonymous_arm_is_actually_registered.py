"""The cross-arm authorization checks could not run on any assessment the product accepts.

`service.register` built its arm list as `config.identity_ids or ["anonymous"]`, so an
anonymous arm existed ONLY when no identity was configured — and `preflight` rejects
"anonymous" as an identity_id, because it is looked up in the SecretStore. So no session the
product would accept could hold the three arms both cross-arm checks require. Measured on a
real two-identity registration: 4 stages, 2 arms, no anonymous one, and

    cross_arm_privileged_function(...) -> refused_because ['anonymous_arm_did_not_run']

Increments 7 and 8 built those checks and their tests INSERTED the anonymous stage row into
the database by hand, so the suite was green on a feature that was unreachable in
production. That is this project's recurring defect at the top level: confident output from
a path nothing could take.

These tests go through the real `register`, which is the only thing that would have caught
it.
"""
import pytest

from orchestrator.integrations.contracts import AssessmentConfig, Identity


@pytest.fixture
async def lane(tmp_path, monkeypatch):
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    from orchestrator.integrations.security import SecretStore
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    store = SecretStore()
    handles = [store.put(Identity.model_validate({
        "name": name, "target_origin": "http://app.test", "role": role,
        "subject_id": subject,
        "check": {"url": "http://app.test/me", "body_contains": name}}).model_dump())
        for name, role, subject in (("admin", "admin", "1"), ("jim", "customer", "2"))]
    return {"db": db, "handles": handles}


def config(handles, **overrides):
    return AssessmentConfig(scope={"allow_hosts": ["app.test"], "allow_ports": [80]},
                            identity_ids=handles, stages=["katana"], active=True,
                            test_cases=["WSTG-INPV-05.2"], **overrides)


async def arms_of(lane, session_id):
    rows = await lane["db"].rows(
        "SELECT identity_id FROM integration_stages WHERE session_id=?", (session_id,))
    return sorted({row["identity_id"] for row in rows})


async def test_an_anonymous_arm_is_registered_alongside_the_identities(lane):
    from orchestrator.integrations.service import register

    await register("s", "http://app.test", config(lane["handles"]))
    arms = await arms_of(lane, "s")
    assert "anonymous" in arms, (
        "without it both cross-arm checks refuse, which is what made the authorization "
        "work unreachable on every real assessment")
    assert len(arms) == 3


async def test_each_arm_gets_every_selected_stage(lane):
    from orchestrator.integrations.service import register

    await register("s", "http://app.test", config(lane["handles"]))
    rows = await lane["db"].rows(
        "SELECT adapter, identity_id FROM integration_stages WHERE session_id='s'")
    per_arm = {}
    for row in rows:
        per_arm.setdefault(row["identity_id"], set()).add(row["adapter"])
    assert len(per_arm) == 3
    assert all(stages == {"katana", "testcases"} for stages in per_arm.values()), per_arm


async def test_the_operator_can_opt_out(lane):
    """It costs one more pass of each stage, so it is a declaration and not a surprise."""
    from orchestrator.integrations.service import register

    await register("s", "http://app.test", config(lane["handles"], anonymous_arm=False))
    assert "anonymous" not in await arms_of(lane, "s")


async def test_an_assessment_with_no_identities_still_has_exactly_one_arm(lane):
    """The previous behaviour, unchanged: the anonymous arm is the only arm."""
    from orchestrator.integrations.service import register

    await register("s", "http://app.test",
                   AssessmentConfig(scope={"allow_hosts": ["app.test"],
                                           "allow_ports": [80]}, stages=["katana"]))
    assert await arms_of(lane, "s") == ["anonymous"]


async def test_the_registered_arms_are_enough_for_the_cross_arm_checks_to_run(lane):
    """The point of the whole test file: the checks must get past `anonymous_arm_did_not_run`
    on a session the product itself created. They still refuse for want of shared
    OPERATIONS — nothing has run yet — and that refusal is about data, not about wiring."""
    from orchestrator.integrations.inventory import cross_arm_privileged_function
    from orchestrator.integrations.service import register

    await register("s", "http://app.test", config(lane["handles"]))
    # A stage must have produced something for the arm to count as having run; registration
    # alone only proves the arm EXISTS, which is what was missing.
    assert "anonymous" in await arms_of(lane, "s")
    result = await cross_arm_privileged_function(
        "s", lane["handles"][0], lane["handles"][1], '"x":1', anonymous="anonymous")
    assert "no_anonymous_arm" not in result["refused_because"]
