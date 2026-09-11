"""Two markers against one operation overwrote each other's label, silently.

`contracts.fingerprint` has no marker term, so two route calls declaring different markers
against one URL build one key — and the label lived inside the `evidence` PROSE, so
`INSERT OR REPLACE` kept whichever arrived second. Measured on the real Juice Shop
assessment: marker A (the administrator's email) fires at `/api/Users` and `/api/Users/1`,
marker B fires at `/api/Users` and another URL, and after persisting both the row for the
shared operation carried only B's label. Arrival order decided which.

ONE FINDING IS RIGHT, and the split is the wrong fix. Two IntegrationFinding records built
from two true declarations about one operation differ in exactly one key — `evidence`, and
within it in twelve hex characters. Everything a reader acts on is identical: title, url,
rule, severity, confidence, cwe, basis, identity, compared_with, methodology. Two rows in a
client's tracker would be two indistinguishable verified-high rows for one missing
authorization check, two triage decisions and two retests; and measured against the export
path, the split posts twice and leaves the first remote row active forever while local
triage reaches only the second. The merge path posts once and patches.

So the label is a FIELD, merged the way `evidence_ids` already is. It had to leave the prose
to make that possible: prose is built before the merge happens, so a label written into it
could never reflect what the merge produced.
"""
import json

import pytest

TARGET = "http://app.test/"
URL = "http://app.test/api/Users"


def result(label, url=URL):
    return {"refused_because": [], "findings": [{
        "url": url, "privileged": "H", "privileged_role": "admin",
        "unprivileged": "L", "unprivileged_role": "customer", "marker_digest": label}]}


@pytest.fixture
async def lane(tmp_path, monkeypatch):
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    await db.execute("INSERT INTO integration_assessments(session_id,target,status,config) "
                     "VALUES(?,?,?,?)", ("s", TARGET, "completed", "{}"))
    return db


def findings(label, url=URL):
    from orchestrator.integrations.inventory import authorization_findings
    return authorization_findings(TARGET, "function", result(label, url))


# ------------------------------------------------------------------ the premise

def test_two_declarations_on_one_operation_share_a_key():
    """Asserted, not assumed: everything below rests on this collision existing."""
    assert findings("aaaaaaaaaaaa")[0].fingerprint == findings("bbbbbbbbbbbb")[0].fingerprint


def test_the_label_is_a_field_and_not_prose():
    """The move is what makes the merge possible at all."""
    finding = findings("aaaaaaaaaaaa")[0]
    assert finding.marker_digests == ["aaaaaaaaaaaa"]
    assert "aaaaaaaaaaaa" not in finding.evidence


def test_a_finding_with_no_marker_carries_no_label():
    """Empty for the object-level check and for every catalogue finding — not a default
    that reads as a declaration nobody made."""
    from orchestrator.integrations.inventory import authorization_findings
    objects = authorization_findings(TARGET, "object", {"refused_because": [], "findings": [{
        "url": URL, "caller": "L", "caller_subject_id": "2", "owner": "H",
        "asserted_owner": "1", "owner_field": "data.UserId"}]})
    assert objects[0].marker_digests == []


# ------------------------------------------------------------------ and the merge

async def test_the_second_declaration_does_not_replace_the_first(lane):
    await lane.persist_findings("s", findings("aaaaaaaaaaaa"))
    await lane.persist_findings("s", findings("bbbbbbbbbbbb"))
    rows = await lane.rows("SELECT payload FROM integration_findings WHERE session_id='s'")
    assert len(rows) == 1, "one operation, one row"
    assert json.loads(rows[0]["payload"])["marker_digests"] == ["aaaaaaaaaaaa", "bbbbbbbbbbbb"]


async def test_arrival_order_does_not_decide(lane):
    await lane.persist_findings("s", findings("bbbbbbbbbbbb"))
    await lane.persist_findings("s", findings("aaaaaaaaaaaa"))
    row = (await lane.rows("SELECT payload FROM integration_findings WHERE session_id='s'"))[0]
    assert json.loads(row["payload"])["marker_digests"] == ["aaaaaaaaaaaa", "bbbbbbbbbbbb"]


async def test_re_running_one_declaration_does_not_grow_the_list(lane):
    for _ in range(3):
        await lane.persist_findings("s", findings("aaaaaaaaaaaa"))
    row = (await lane.rows("SELECT payload FROM integration_findings WHERE session_id='s'"))[0]
    assert json.loads(row["payload"])["marker_digests"] == ["aaaaaaaaaaaa"]


async def test_different_operations_keep_their_own_declarations(lane):
    """The merge must not leak a label sideways onto an operation it did not prove."""
    await lane.persist_findings("s", findings("aaaaaaaaaaaa", URL))
    await lane.persist_findings("s", findings("bbbbbbbbbbbb", URL + "/1"))
    got = {json.loads(r["payload"])["url"]: json.loads(r["payload"])["marker_digests"]
           for r in await lane.rows("SELECT payload FROM integration_findings "
                                    "WHERE session_id='s'")}
    assert got == {URL: ["aaaaaaaaaaaa"], URL + "/1": ["bbbbbbbbbbbb"]}


async def test_the_merged_labels_reach_the_export(lane):
    """A merge nothing renders is a merge nobody can read."""
    from orchestrator.integrations.defectdojo import finding_payload
    await lane.persist_findings("s", findings("aaaaaaaaaaaa"))
    await lane.persist_findings("s", findings("bbbbbbbbbbbb"))
    row = (await lane.rows("SELECT payload FROM integration_findings WHERE session_id='s'"))[0]
    description = finding_payload(json.loads(row["payload"]))["description"]
    assert "aaaaaaaaaaaa" in description and "bbbbbbbbbbbb" in description
    assert "cannot be recovered from the label" in description, (
        "a reader shown a label has to be told what it is and is not")


async def test_triage_still_survives_a_second_declaration(lane):
    """The merge must not cost what `persist_findings` already guarantees."""
    first = findings("aaaaaaaaaaaa")
    await lane.persist_findings("s", first)
    payload = json.loads((await lane.rows(
        "SELECT payload FROM integration_findings WHERE fingerprint=?",
        (first[0].fingerprint,)))[0]["payload"])
    payload.update(triage_state="false_positive", triage_note="mine")
    await lane.execute("UPDATE integration_findings SET payload=? WHERE fingerprint=?",
                       (json.dumps(payload), first[0].fingerprint))
    await lane.persist_findings("s", findings("bbbbbbbbbbbb"))
    after = json.loads((await lane.rows(
        "SELECT payload FROM integration_findings WHERE fingerprint=?",
        (first[0].fingerprint,)))[0]["payload"])
    assert after["triage_state"] == "false_positive" and after["triage_note"] == "mine"
    assert after["marker_digests"] == ["aaaaaaaaaaaa", "bbbbbbbbbbbb"]


async def test_the_product_own_report_names_the_declarations_too(lane, monkeypatch):
    """The DefectDojo export carried these and `service.report()` did not, so erlik's own
    report was the one place a reader could not tell which marker proved a finding."""
    from orchestrator.integrations import service
    await lane.persist_findings("s", findings("aaaaaaaaaaaa"))
    await lane.persist_findings("s", findings("bbbbbbbbbbbb"))
    report = await service.report("s")
    assert report is not None
    assert len(report["findings"]) == 1
    assert report["findings"][0]["marker_digests"] == ["aaaaaaaaaaaa", "bbbbbbbbbbbb"]


async def test_a_finding_with_no_declaration_reports_an_empty_list(lane):
    """Not a missing key, which a consumer would have to special-case."""
    from orchestrator.integrations import service
    from orchestrator.integrations.inventory import authorization_findings
    await lane.persist_findings("s", authorization_findings(TARGET, "object", {
        "refused_because": [], "findings": [{
            "url": URL, "caller": "L", "caller_subject_id": "2", "owner": "H",
            "asserted_owner": "1", "owner_field": "data.UserId"}]}))
    report = await service.report("s")
    assert report["findings"][0]["marker_digests"] == []
