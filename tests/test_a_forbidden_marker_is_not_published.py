"""An operator declaration naming data that must not be disclosed was served by an API route.

`AssessmentConfig.security_assertions[].forbidden_marker` is, by its own definition, a
string naming data the operator says must not appear — "this identity must not be able to
see this string here". For most engagements that is a real customer's address, an internal
identifier, a card number.

`service.register` publishes `redact(config.model_dump())` into
`integration_assessments.config`, and `GET /api/integrations/sessions/{id}` returns that row
in full. `redact` blanks by KEY NAME against /authorization|cookie|password|secret|token|
api.?key|session/ — and nothing called `marker` matches any of those. Measured before this
fix, end to end through the real route: a marker of "14 Rue de la Paix, 75002 Paris" came
back verbatim from that route and sat verbatim in the persisted row.

This was not a hypothetical about some future declaration. The field has existed, been
validated, and been published, for as long as `security_assertions` has.

The EXECUTABLE copy keeps it, because the run cannot make the assertion without it — that
copy lives in the SecretStore, which is the whole reason `register` keeps two. And the
`description` survives, because it is what tells a reader which assertion was made and it is
not the secret: the same split `application_cookies` already gets, where names and origins
stay and values go.
"""
import json

import pytest

SECRET = "14 Rue de la Paix, 75002 Paris"


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


async def registered(lane, marker=SECRET):
    from orchestrator.integrations import service
    from orchestrator.integrations.contracts import AssessmentConfig
    from orchestrator.integrations.security import SecretStore
    identity = SecretStore().put({"name": "jim", "target_origin": "http://app.test",
                                  "role": "customer"})
    config = AssessmentConfig(
        scope={"allow_hosts": ["app.test"], "allow_ports": [80]}, identity_ids=[identity],
        active=True, security_assertions=[{
            "request": {"url": "http://app.test/rest/profile", "method": "GET"},
            "identity_id": identity,
            "description": "a customer must not see another customer's address",
            "forbidden_marker": marker}])
    await service.register("s", "http://app.test/", config)
    return config


async def test_the_route_does_not_serve_it(lane):
    from orchestrator.integrations.api import assessment_status
    await registered(lane)
    assert SECRET not in json.dumps(await assessment_status("s"))


async def test_the_persisted_row_does_not_hold_it(lane):
    await registered(lane)
    row = (await lane.rows("SELECT config FROM integration_assessments "
                           "WHERE session_id='s'"))[0]
    assert SECRET not in row["config"]
    assert "[REDACTED]" in row["config"], "blanked, not dropped — the shape stays"


async def test_the_assertion_stays_legible(lane):
    """A record that cannot say which assertion was made is not a record. The value is the
    part that does not belong in it."""
    from orchestrator.integrations.api import assessment_status
    await registered(lane)
    served = json.dumps(await assessment_status("s"))
    assert "a customer must not see another customer's address" in served
    assert "http://app.test/rest/profile" in served


async def test_the_run_can_still_make_the_assertion(lane):
    """The executable copy keeps the marker. Redacting THAT would have turned a leak into a
    check that silently tests for the string "[REDACTED]"."""
    from orchestrator.integrations.security import SecretStore
    await registered(lane)
    row = (await lane.rows("SELECT config_secret_id FROM integration_assessments "
                           "WHERE session_id='s'"))[0]
    executable = SecretStore().get(row["config_secret_id"])
    assert SECRET in json.dumps(executable)


async def test_the_published_copy_still_revalidates(lane):
    """The DefectDojo export path re-validates this row as an AssessmentConfig when there is
    no secret to read, and a previous redaction of this kind broke exactly that."""
    from orchestrator.integrations.contracts import AssessmentConfig
    await registered(lane)
    row = (await lane.rows("SELECT config FROM integration_assessments "
                           "WHERE session_id='s'"))[0]
    again = AssessmentConfig.model_validate_json(row["config"])
    assert len(again.security_assertions) == 1
    assert again.security_assertions[0].forbidden_marker == "[REDACTED]"


async def test_an_assessment_with_no_assertions_is_unchanged(lane):
    """The negative control: the new line must not invent a key on every config."""
    from orchestrator.integrations import service
    from orchestrator.integrations.contracts import AssessmentConfig
    await service.register("s", "http://app.test/", AssessmentConfig(
        scope={"allow_hosts": ["app.test"], "allow_ports": [80]}))
    row = (await lane.rows("SELECT config FROM integration_assessments "
                           "WHERE session_id='s'"))[0]
    assert json.loads(row["config"])["security_assertions"] == []
