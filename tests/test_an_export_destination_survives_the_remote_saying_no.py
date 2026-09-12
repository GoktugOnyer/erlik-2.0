"""E-032: two ways the client's tracker stopped receiving findings.

Both are about delivery rather than detection. A finding erlik got right and never
delivered is worth nothing to whoever has to fix it.

    DEDUPLICATION      A stock DefectDojo with
                       `System_Settings.enable_deduplication=True` — the steady-state
                       client configuration — imports every finding and marks the ones
                       its algorithm considers duplicates `duplicate=True,
                       active=False`. A PATCH setting `active: true` on one is refused
                       HTTP 400 "Duplicate findings cannot be verified or active".
                       Measured against a live 2.58.4 with 6 of 9 catalogue findings
                       coming back duplicate, and reproduced here:

                           export 1   uncertain, "DefectDojo PATCH returned HTTP 400"
                           export 2   returns export 1's row; a triage to
                                      false_positive cannot propagate
                           export 3   zero requests issued

                       Two defects in one: `raise` abandoned the findings after the
                       first refusal, so the cross-arm findings were stranded behind a
                       catalogue triplet; and `uncertain` blocked the destination for
                       the session, while nothing was in fact uncertain — the server
                       answered, declining, with a reason.

    ROTATION           The identity handle is in every fingerprint. Registering a
                       rotated credential with `POST /identities` mints a new handle, so
                       the same violation arrives as a NEW remote finding at
                       `triage_state` open while the old row stays active forever.
                       `PUT /identities/{id}` already does the right thing; nothing said
                       so and nothing flagged the collision.
"""
import copy
import json

import pytest

from orchestrator.integrations import defectdojo, persistence as db, service
from orchestrator.integrations.contracts import AssessmentConfig, Identity, fingerprint
from orchestrator.integrations.security import SecretStore


@pytest.fixture
async def deduplicating(tmp_path, monkeypatch):
    """The API double, configured as DefectDojo is out of the box."""
    import orchestrator.database as original
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    await service.register("s", "https://app.test", AssessmentConfig(
        scope={"allow_hosts": ["app.test"], "allow_ports": [443]}))

    class FakeSandbox:
        def __init__(self, *a, **kw):
            assert len(kw["services"]) == 1 and kw["services"][0].startswith("https://")

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

    monkeypatch.setattr(defectdojo, "Sandbox", FakeSandbox)

    class Remote:
        calls = []
        findings = {}
        originals = 1           # the first import is original; everything later duplicates
        refusal_status = 400

        async def rpc(self, sandbox, request):
            self.calls.append(copy.deepcopy(request))
            method = request.get("method", "POST")
            if method == "GET":
                return {"status": 200, "body": json.dumps(
                    {"results": list(self.findings.values()), "next": None})}
            if method == "PATCH":
                key = int(request["url"].rstrip("/").rsplit("/", 1)[1])
                item, body = self.findings[key], request["body"]
                if item.get("duplicate") and (body.get("active") or body.get("verified")):
                    return {"status": self.refusal_status, "body": json.dumps(
                        {"detail": "Duplicate findings cannot be verified or active"})}
                item.update(body)
                return {"status": 200, "body": json.dumps(item)}
            for finding in request["report"]["findings"]:
                key = len(self.findings) + 1
                duplicate = key > self.originals
                self.findings[key] = dict(
                    finding, id=key, test=42, duplicate=duplicate,
                    active=False if duplicate else finding.get("active"),
                    verified=False if duplicate else finding.get("verified"))
            return {"status": 200, "body": json.dumps({"test": 42})}

    remote = Remote()
    remote.calls, remote.findings = [], {}
    monkeypatch.setattr(defectdojo, "rpc", remote.rpc)
    remote.secret = SecretStore().put({"token": "only-in-runtime"})
    remote.config = defectdojo.ExportConfig(server="https://dojo.test",
                                            secret_id=remote.secret, test_id=42)
    yield remote


async def put_finding(fingerprint_value, **overrides):
    data = dict(fingerprint=fingerprint_value, title=f"Finding {fingerprint_value}",
                basis="Deterministic evidence", severity="high", confidence="confirmed",
                url="https://app.test/private", triage_state="open")
    data.update(overrides)
    await db.execute("INSERT OR REPLACE INTO integration_findings VALUES(?,?,?)",
                     ("s", fingerprint_value, json.dumps(data)))


def patches(remote):
    return [c for c in remote.calls if c.get("method") == "PATCH"]


# ------------------------------------------------------------------- deduplication


async def test_a_refused_update_does_not_block_the_destination(deduplicating):
    """`uncertain` means "a write may have landed and we cannot tell". A 400 carrying a
    reason is the opposite of that, and an uncertain row makes every later export a
    no-op."""
    for n in range(3):
        await put_finding(f"fp-{n}")
    first = await defectdojo.export("s", deduplicating.config)
    assert first["status"] == "partial", dict(first)
    assert "2 of 3" in first["detail"] and "deduplication" in first["detail"], first["detail"]

    before = len(deduplicating.calls)
    again = await defectdojo.export("s", deduplicating.config)
    assert again["id"] != first["id"], (
        "the second export returned the first export's row, so it did nothing")
    assert len(deduplicating.calls) > before, "no request was issued at all"


async def test_one_refused_finding_does_not_strand_the_others(deduplicating):
    """The measured consequence: all three were in the remote test and only the first was
    mapped locally, so the cross-arm findings sat behind a catalogue triplet."""
    for n in range(3):
        await put_finding(f"fp-{n}")
    await defectdojo.export("s", deduplicating.config)
    attempted = {int(c["url"].rstrip("/").rsplit("/", 1)[1]) for c in patches(deduplicating)}
    assert attempted == {2, 3}, (
        f"only {sorted(attempted)} was attempted; a refusal stopped the loop")


async def test_a_later_triage_reaches_the_remote_row_it_can_reach(deduplicating):
    """The plan's sharpest consequence: "a later triage to false_positive can never
    propagate". It propagates for every finding the remote will accept."""
    for n in range(3):
        await put_finding(f"fp-{n}")
    await defectdojo.export("s", deduplicating.config)
    await put_finding("fp-0", triage_state="false_positive")
    await defectdojo.export("s", deduplicating.config)
    assert deduplicating.findings[1]["false_p"] is True, deduplicating.findings[1]
    assert deduplicating.findings[1]["active"] is False


async def test_a_refused_finding_is_not_recorded_as_synchronized(deduplicating):
    """`integration_remote_findings` is what the remote is believed to hold. Recording a
    refused PATCH's digest would make the next export read the stale remote row as current
    and stop trying."""
    for n in range(3):
        await put_finding(f"fp-{n}")
    await defectdojo.export("s", deduplicating.config)
    mapped = [r["fingerprint"] for r in await db.rows(
        "SELECT fingerprint FROM integration_remote_findings")]
    assert mapped == ["fp-0"], mapped


async def test_the_refusals_are_named_in_the_export_evidence(deduplicating):
    """A count in `detail` cannot be acted on. Which findings, and what the remote said."""
    for n in range(3):
        await put_finding(f"fp-{n}")
    row = await defectdojo.export("s", deduplicating.config)
    artifact = await db.rows("SELECT id FROM integration_evidence WHERE id=?",
                             (row["evidence_id"],))
    assert artifact, "the export recorded no evidence artifact"
    audit = json.loads((await db.evidence_bytes(row["evidence_id"])).decode())
    refused = next((entry["refused_updates"] for entry in audit if "refused_updates" in entry),
                   None)
    assert refused and {r["fingerprint"] for r in refused} == {"fp-1", "fp-2"}, audit[-1]
    assert all(r["status"] == 400 for r in refused), refused
    assert all("Duplicate findings cannot be verified" in r["remote_said"] for r in refused), (
        "the refusal does not carry what the remote actually said")


async def test_a_server_error_on_an_update_is_still_uncertain(deduplicating):
    """The distinction the fix rests on. A 5xx or a dropped connection leaves the write
    genuinely unknown, and THAT is what `uncertain` and the destination block are for."""
    deduplicating.refusal_status = 503
    for n in range(3):
        await put_finding(f"fp-{n}")
    row = await defectdojo.export("s", deduplicating.config)
    assert row["status"] == "uncertain", dict(row)
    before = len(deduplicating.calls)
    again = await defectdojo.export("s", deduplicating.config)
    assert again["id"] == row["id"] and len(deduplicating.calls) == before, (
        "an uncertain write no longer blocks its destination, which it must")


async def test_an_export_the_remote_fully_accepts_is_still_completed(deduplicating):
    """The positive control. Every assertion above is only meaningful because a clean
    export does not report `partial`."""
    deduplicating.originals = 3
    for n in range(3):
        await put_finding(f"fp-{n}")
    row = await defectdojo.export("s", deduplicating.config)
    assert row["status"] == "completed", dict(row)
    assert row["detail"] == "Synchronized by stable fingerprint"


# ----------------------------------------------------------------------- rotation


@pytest.fixture
async def identities(tmp_path, monkeypatch):
    import orchestrator.database as original
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    return db


def declaration(token="token-v1", name="reader"):
    return Identity.model_validate(
        {"name": name, "target_origin": "https://app.test",
         "check": {"url": "https://app.test/me", "expected_status": 200,
                   "body_contains": "reader"},
         "headers": {"Authorization": f"Bearer {token}"}})


def finding_key(identity_id):
    return fingerprint("https://app.test", "erlik:authorization:x", "GET",
                       "https://app.test/private", identity=identity_id)


async def test_identity_rotation_keeps_its_findings(identities):
    """PUT is the rotation route, and it already was — it keeps the handle, so it keeps
    the fingerprint, so the export updates the remote row instead of adding one."""
    from orchestrator.integrations.api import create_identity, replace_identity

    first = await create_identity(declaration())
    before = finding_key(first["id"])
    await replace_identity(first["id"], declaration("token-v2"))
    assert finding_key(first["id"]) == before
    assert SecretStore().get(first["id"])["headers"]["Authorization"] == "Bearer token-v2", (
        "the credential was not actually replaced, so the handle now resolves to a dead one")


async def test_two_distinct_identities_never_share_a_fingerprint(identities):
    """THE GUARD ON THE FIX THAT FIRST SUGGESTS ITSELF. Keying the identity term on
    (name, origin) would make rotation free — and would merge two callers who share a name,
    so a finding about one arm would arrive as a finding about the other. The whole lane
    rests on telling arms apart."""
    from orchestrator.integrations.api import create_identity

    first = await create_identity(declaration())
    second = await create_identity(declaration("token-v2"))
    assert first["id"] != second["id"]
    assert finding_key(first["id"]) != finding_key(second["id"]), (
        "two separately registered identities share a fingerprint, so their findings "
        "would collapse into one remote row")


async def test_re_registering_the_same_identity_says_what_it_costs(identities):
    """It still registers — the operator is the authority on who the caller is — but a
    silent orphaning of every finding from the earlier handle is not acceptable."""
    from orchestrator.integrations.api import create_identity

    first = await create_identity(declaration())
    assert "already_registered" not in first, first
    second = await create_identity(declaration("token-v2"))
    assert second["already_registered"] == [first["id"]], second
    assert "PUT the replacement" in second["note"], second["note"]


async def test_a_different_identity_on_the_same_origin_is_not_a_collision(identities):
    """Two arms on one application is the ordinary case — an assessment needs at least two
    to compare. Flagging it would train an operator to ignore the flag."""
    from orchestrator.integrations.api import create_identity

    await create_identity(declaration(name="reader"))
    other = await create_identity(declaration(name="admin"))
    assert "already_registered" not in other, other
