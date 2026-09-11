"""E-030: a schema fetched by URL is identity-dependent.

`SchemaInput` accepts a URL as well as inline content, and `schema_file` fetches that
document through the egress proxy — which injects the identity's headers and cookies
on every request to the target origin. So a target that serves a different OpenAPI
document per role forks the schema-derived operations exactly as a rendered form
does, and the arms are no longer one variable.

The information to catch it already existed and nothing compared it: both the ZAP and
Schemathesis adapters record `schema_sha256` in their stage metadata. Two arms whose
digests differ did not assess the same API.

This is detection, not prevention. Refusing a per-identity schema fetch would break
the legitimate case — a schema that is itself behind authentication — and fetching it
once anonymously would break it differently. Saying so is what lets an operator
decide; saying nothing is what made it invisible.
"""
import json

import pytest


@pytest.fixture
async def store(tmp_path, monkeypatch):
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    return db


async def stage(db, identity, digest, adapter="zap"):
    import uuid
    result = {"status": "completed", "metadata": {"schema_sha256": digest} if digest else {}}
    await db.execute(
        "INSERT INTO integration_stages(id,session_id,adapter,identity_id,status,result) "
        "VALUES(?,?,?,?,?,?)",
        (uuid.uuid4().hex, "s", adapter, identity, "completed", json.dumps(result)))


async def endpoint(db, identity, url="http://app.test/a"):
    await db.execute(
        "INSERT OR REPLACE INTO integration_endpoints"
        "(session_id,url,method,identity_id,sources,parameters) VALUES(?,?,?,?,?,?)",
        ("s", url, "GET", identity, json.dumps(["katana"]), json.dumps(["id"])))


async def test_two_arms_given_different_schemas_are_refused(store):
    from orchestrator.integrations.inventory import compare_arms

    await endpoint(store, "reader")
    await endpoint(store, "admin")
    await stage(store, "reader", "a" * 64)
    await stage(store, "admin", "b" * 64)

    result = await compare_arms("s", "reader", "admin")
    assert not result["comparable"], "the arms assessed different APIs and were comparable"
    assert "different_schema" in result["refused_because"]
    assert result["schema"]["reader"] == "a" * 64
    assert result["schema"]["admin"] == "b" * 64


async def test_the_same_schema_is_not_a_refusal(store):
    from orchestrator.integrations.inventory import compare_arms

    await endpoint(store, "reader")
    await endpoint(store, "admin")
    await stage(store, "reader", "a" * 64)
    await stage(store, "admin", "a" * 64)

    result = await compare_arms("s", "reader", "admin")
    assert result["comparable"], result["refused_because"]


async def test_no_schema_at_all_is_not_a_refusal(store):
    """Most assessments supply none, and an absent schema is not a disagreement."""
    from orchestrator.integrations.inventory import compare_arms

    await endpoint(store, "reader")
    await endpoint(store, "admin")
    await stage(store, "reader", None)
    await stage(store, "admin", None)

    result = await compare_arms("s", "reader", "admin")
    assert result["comparable"], result["refused_because"]
    assert result["schema"] == {}


async def test_one_arm_with_a_schema_and_one_without_is_refused(store):
    """The sharper version: a target that serves the document to one identity and
    refuses it to another has given the two arms different surfaces, and an absent
    digest on one side is not agreement."""
    from orchestrator.integrations.inventory import compare_arms

    await endpoint(store, "reader")
    await endpoint(store, "admin")
    await stage(store, "reader", None)
    await stage(store, "admin", "b" * 64)

    result = await compare_arms("s", "reader", "admin")
    assert not result["comparable"]
    assert "different_schema" in result["refused_because"]
