"""E-016: a finding packaged so someone else can check it.

The supporting material was spread across `integration_evidence`, the stage that produced it,
the assessment's configuration and three tables. Everything needed to hand a developer one
finding existed; nothing assembled it.

THE RULE THIS IS BUILT AROUND, and the acceptance names it: "an exported archive contains no
credential values". A bundle carries DECLARATIONS and EVIDENCE. The identity's `headers`,
`cookies`, `storage_state` and `check` are what makes an arm that arm, and none of them is in
it — only the labels the operator chose and the lane already reports. The configuration comes
from the PUBLISHED row rather than the secret store's private copy, the same distinction
`service.register` draws for the same reason.

The other two clauses of the acceptance: "a reviewer can trace a finding to its supporting
evidence", which is why every cited artifact's content travels with its digest; and "a changed
or missing artifact is detectable", which is why each is read through `evidence_bytes` and a
failure is REPORTED rather than quietly leaving the bundle smaller.
"""
import json
import uuid
import zipfile

import pytest

from orchestrator.integrations.bundle import (
    DECLARED_IDENTITY_FIELDS, finding_bundle, write_bundle_archive)
from orchestrator.integrations.contracts import Identity
from orchestrator.integrations.security import SecretStore

TOKEN = "Bearer erlik-lab-token-9f3c2a-do-not-leak"
COOKIE_VALUE = "session=8a1f-secret-cookie-value"
URL = "http://app.test/api/Users/1"


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


async def seeded(db):
    """One session, one identity carrying real-shaped credentials, one cited artifact."""
    identity_id = SecretStore().put(Identity.model_validate({
        "name": "jim", "target_origin": "http://app.test", "role": "customer",
        "tenant": "acme", "subject_id": "2", "may_access": ["/api/Users/2"],
        "headers": {"Authorization": TOKEN},
        "cookies": [{"name": "session", "value": COOKIE_VALUE}],
        "check": {"url": "http://app.test/me", "method": "GET"}}).model_dump())
    await db.execute(
        "INSERT INTO integration_assessments(session_id,target,status,config) VALUES(?,?,?,?)",
        ("s", "http://app.test/", "completed",
         json.dumps({"scope": {"allow_hosts": ["app.test"]},
                     "test_cases": ["WSTG-AUTHZ-04"],
                     # Named, because a bundle that resolved these against the secret store
                     # is exactly the leak the test below looks for — and a fixture without
                     # them cannot catch it.
                     "identity_ids": [identity_id]})))
    stage = uuid.uuid4().hex
    await db.execute(
        "INSERT INTO integration_stages(id,session_id,adapter,identity_id,status,result) "
        "VALUES(?,?,?,?,?,?)",
        (stage, "s", "schemathesis", identity_id, "completed",
         json.dumps({"metadata": {"seed": 1, "schema_sha256": "abc123", "version": "4.0.14"}})))
    proof = await db.evidence("s", stage, "testcase:WSTG-AUTHZ-04", json.dumps(
        {"steps": [{"command": 'curl -s -i -H "Authorization: $LOW_PRIV_TOKEN" ' + URL,
                    "output": "HTTP/1.1 200 OK\r\n\r\n{\"data\":{\"UserId\":1}}"}]}))
    noise = await db.evidence("s", stage, "stdout", "katana crawled 41 urls")
    finding = {"fingerprint": "fp-1", "title": "One identity read another's object",
               "url": URL, "rule": "erlik:authorization:object", "source": "cross-arm",
               "identity": identity_id, "compared_with": "anonymous", "severity": "high",
               "confidence": "confirmed", "basis": "Three-arm differential",
               "produced_by": "erlik cross-arm evaluation over stored evidence",
               "evidence_ids": [proof], "methodology": ["WSTG-AUTHZ-04"],
               "triage_state": "open"}
    await db.execute("INSERT INTO integration_findings VALUES(?,?,?)",
                     ("s", "fp-1", json.dumps(finding)))
    return identity_id, proof, noise


# ------------------------------------------------------- no credential values, asserted


async def test_no_credential_value_reaches_the_bundle(lane):
    """The acceptance clause, checked over the whole serialised bundle rather than a field
    at a time — a field-by-field check tests the fields someone thought of."""
    await seeded(lane)
    rendered = json.dumps(await finding_bundle("s", "fp-1"))
    for secret in (TOKEN, COOKIE_VALUE, "erlik-lab-token", "8a1f-secret"):
        assert secret not in rendered, f"{secret!r} reached the bundle"


async def test_no_credential_value_reaches_the_archive(lane, tmp_path):
    """The bytes that actually leave, not the structure they came from."""
    await seeded(lane)
    path = tmp_path / "out" / "bundle.zip"
    await write_bundle_archive("s", path)
    raw = path.read_bytes()
    with zipfile.ZipFile(path) as archive:
        members = b"".join(archive.read(name) for name in archive.namelist())
    for secret in (TOKEN.encode(), COOKIE_VALUE.encode(), b"erlik-lab-token"):
        assert secret not in members and secret not in raw, secret


async def test_the_declarations_do_travel(lane):
    """The other half. A bundle that carried nothing about the identity would be safe and
    useless: "this identity should not have read it" needs to say which identity."""
    await seeded(lane)
    context = (await finding_bundle("s", "fp-1"))["authorization_context"]
    assert context["identity"]["name"] == "jim"
    assert context["identity"]["role"] == "customer"
    assert context["identity"]["subject_id"] == "2"
    assert context["identity"]["tenant"] == "acme"
    assert context["compared_with"]["name"] == "anonymous"


def test_the_carried_fields_are_a_named_set_that_excludes_the_credential():
    """`headers`, `cookies`, `storage_state` and `check` are how an arm authenticates."""
    assert set(DECLARED_IDENTITY_FIELDS).isdisjoint(
        {"headers", "cookies", "storage_state", "check"})
    assert "subject_id" in DECLARED_IDENTITY_FIELDS


# ------------------------------------------------- traceable, and tampering is detectable


async def test_every_cited_artifact_travels_with_its_content_and_digest(lane):
    await seeded(lane)
    evidence = (await finding_bundle("s", "fp-1"))["evidence"]
    assert len(evidence) == 1
    assert "UserId" in evidence[0]["content"], "the proof did not travel"
    assert len(evidence[0]["sha256"]) == 64
    assert evidence[0]["kind"] == "testcase:WSTG-AUTHZ-04"


async def test_a_changed_artifact_is_reported_rather_than_quietly_dropped(lane, tmp_path):
    """"A changed or missing artifact is detectable." A bundle that omitted it would read as
    a finding resting on less evidence, rather than as evidence that moved underneath it."""
    from orchestrator.integrations.security import runtime_root

    _, proof, _ = await seeded(lane)
    (runtime_root() / "evidence" / proof).write_text("tampered")
    bundle = await finding_bundle("s", "fp-1")
    assert bundle["evidence"] == []
    assert bundle["evidence_not_readable"][0]["evidence_id"] == proof
    assert "digest" in bundle["evidence_not_readable"][0]["reason"].lower()
    assert "rests on less than it says" in bundle["establishes"]


async def test_a_missing_artifact_is_reported_too(lane):
    from orchestrator.integrations.security import runtime_root

    _, proof, _ = await seeded(lane)
    (runtime_root() / "evidence" / proof).unlink()
    bundle = await finding_bundle("s", "fp-1")
    assert bundle["evidence_not_readable"][0]["evidence_id"] == proof


# --------------------------------------------- diagnostics are separate from the proof


async def test_several_cited_artifacts_are_all_excluded_from_diagnostics(lane):
    """TWO cited artifacts, because one is the case a broken exclusion still passes.

    A first version filtered with an `id NOT IN (...)` subquery built from
    `"|".join(evidence_ids)` — correct for a single id, matching nothing for several. Every
    real finding cites more than one.
    """
    _, proof, noise = await seeded(lane)
    second = await lane.evidence("s", "stage-2", "testcase:WSTG-AUTHZ-04", "a second proof")
    await lane.execute(
        "UPDATE integration_findings SET payload=? WHERE fingerprint='fp-1'",
        (json.dumps({**json.loads((await lane.rows(
            "SELECT payload FROM integration_findings WHERE fingerprint='fp-1'"))[0]["payload"]),
            "evidence_ids": [proof, second]}),))
    bundle = await finding_bundle("s", "fp-1")
    assert {a["id"] for a in bundle["evidence"]} == {proof, second}
    assert not ({proof, second} & {d["id"] for d in bundle["diagnostics"]}), (
        "a cited artifact is listed again as a diagnostic")
    assert noise in [d["id"] for d in bundle["diagnostics"]]


async def test_an_artifact_that_failed_its_check_is_not_offered_as_a_diagnostic(lane):
    """It is reported in `evidence_not_readable`. Listing it again as context would offer
    the bytes that just failed their digest as something a reader may rely on."""
    from orchestrator.integrations.security import runtime_root

    _, proof, _ = await seeded(lane)
    (runtime_root() / "evidence" / proof).write_text("tampered")
    bundle = await finding_bundle("s", "fp-1")
    assert proof in [e["evidence_id"] for e in bundle["evidence_not_readable"]]
    assert proof not in [d["id"] for d in bundle["diagnostics"]]


async def test_diagnostics_are_not_mixed_with_the_evidence(lane):
    """"Keep optional diagnostics separate from substantive evidence." A reader who cannot
    tell them apart is being asked to weigh a stage's stdout against the response that
    proves the finding."""
    _, proof, noise = await seeded(lane)
    bundle = await finding_bundle("s", "fp-1")
    assert [a["id"] for a in bundle["evidence"]] == [proof]
    assert noise in [d["id"] for d in bundle["diagnostics"]]
    assert proof not in [d["id"] for d in bundle["diagnostics"]], (
        "the cited proof is listed again as diagnostics")
    assert all("content" not in d for d in bundle["diagnostics"]), (
        "diagnostics carry their content, which makes the split cosmetic")


# ---------------------------------------------------------- reproduction and the archive


async def test_the_bundle_says_what_would_have_to_be_run_again(lane):
    await seeded(lane)
    provenance = (await finding_bundle("s", "fp-1"))["provenance"]
    assert provenance["produced_by"], "the finding does not say what made it"
    assert provenance["stages"]["schemathesis"]["seed"] == 1
    assert provenance["stages"]["schemathesis"]["schema_sha256"] == "abc123"
    assert provenance["methodology"] == ["WSTG-AUTHZ-04"]


async def test_the_reproduction_command_still_says_what_it_requested(lane):
    """"Sanitized reproduction instructions." Building this bundle found that they were not.

    `redact`'s sensitive-header rule ate to end of line, which is right in a response capture
    and wrong in a shell command: the stored command was

        curl -s -i -H "Authorization: [REDACTED]

    with no closing quote and no URL. A reproduction instruction that does not say what it
    requested is not one. Fixed in `redact` — see `_redact_header` — and asserted from here,
    because this is the consumer that made the loss visible.
    """
    await seeded(lane)
    content = (await finding_bundle("s", "fp-1"))["evidence"][0]["content"]
    assert URL in content, content[:200]
    assert "[REDACTED]" in content, "the credential slot is no longer redacted"
    assert "$LOW_PRIV_TOKEN" not in content, (
        "erring the other way: the placeholder survived, and redaction cannot tell a "
        "placeholder from a real token")


async def test_the_archive_manifest_lets_a_reader_check_what_they_received(lane, tmp_path):
    import hashlib

    await seeded(lane)
    path = tmp_path / "bundle.zip"
    manifest = await write_bundle_archive("s", path)
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
        assert "MANIFEST.json" in names and "findings/fp-1.json" in names
        for name, entry in manifest["members"].items():
            body = archive.read(name)
            assert hashlib.sha256(body).hexdigest() == entry["sha256"], name
            assert len(body) == entry["size"], name


async def test_the_manifest_does_not_overclaim(lane, tmp_path):
    """It attests the archive was not altered in transit. It does NOT attest the evidence
    was untouched before the bundle was built — `finding_bundle` checks that, and saying
    otherwise would be the kind of confident wrong claim this project keeps removing."""
    await seeded(lane)
    manifest = await write_bundle_archive("s", tmp_path / "b.zip")
    assert "does not attest" in manifest["establishes"]


async def test_an_unknown_finding_is_an_error_not_an_empty_bundle(lane):
    await seeded(lane)
    with pytest.raises(KeyError):
        await finding_bundle("s", "no-such-fingerprint")


async def test_an_archive_of_every_finding_is_the_default(lane, tmp_path):
    await seeded(lane)
    manifest = await write_bundle_archive("s", tmp_path / "b.zip")
    assert manifest["findings"] == ["fp-1"]


async def test_the_route_serves_the_bundle(lane):
    from orchestrator.integrations.api import finding_bundle_report

    await seeded(lane)
    body = await finding_bundle_report("s", "fp-1")
    assert body["finding"]["fingerprint"] == "fp-1"
    assert TOKEN not in json.dumps(body)


async def test_the_route_404s_on_a_finding_that_is_not_there(lane):
    from fastapi import HTTPException

    from orchestrator.integrations.api import finding_bundle_report

    await seeded(lane)
    with pytest.raises(HTTPException) as raised:
        await finding_bundle_report("s", "nope")
    assert raised.value.status_code == 404
