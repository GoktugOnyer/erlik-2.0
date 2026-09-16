"""E-018: "reports separate local triage from external synchronization status."

They are different facts and the report conflated them by omission. It listed findings whose
`triage_state` is `open` and said nothing else — so:

  * a reader saw a count of N and could not tell that M more had been triaged away. That is
    the shape `coverage` exists to remove one layer down: a report listing only what remains
    reads as a clean bill of health for everything it omits.
  * a finding triaged `fixed` looked dealt with, when nothing said whether the client's
    tracker had ever heard of it. An export that went `partial` — the steady-state DefectDojo
    deduplication case, E-032 — leaves findings in the tracker in a state erlik could not set,
    and an `uncertain` one leaves it unknown whether a write landed at all.

`synchronization` answers the second from `integration_remote_findings`, which records the
payload digest at the moment of a successful write. Recomputing it now says whether the tracker
holds what erlik currently says.

AND UNRESOLVED EXPORTS MAKE ALL OF IT PROVISIONAL, which is why they travel beside the
per-finding states rather than under them. A report showing `synchronized` next to an uncertain
export would be asserting the one thing nobody knows.
"""
import json

import pytest

from orchestrator.integrations.defectdojo import (
    SYNCHRONIZATION_STATES, digest, finding_payload, synchronization)

URL = "http://app.test/x"


@pytest.fixture
async def lane(tmp_path, monkeypatch):
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    await db.execute(
        "INSERT INTO integration_assessments(session_id,target,status,config) VALUES(?,?,?,?)",
        ("s", "http://app.test/", "completed", "{}"))
    return db


def finding(fingerprint="fp-1", **overrides):
    data = {"fingerprint": fingerprint, "title": "SQL injection", "url": URL,
            "rule": "WSTG-INPV-05:error_based", "source": "testcase", "severity": "high",
            "confidence": "confirmed", "basis": "b", "cwe": "89", "evidence_ids": [],
            "triage_state": "open"}
    data.update(overrides)
    return data


async def store(db, *findings):
    for item in findings:
        await db.execute("INSERT OR REPLACE INTO integration_findings VALUES(?,?,?)",
                         ("s", item["fingerprint"], json.dumps(item)))


async def exported(db, item, *, server="https://dojo.test", test_id=42, stale=False):
    await db.execute(
        "INSERT OR REPLACE INTO integration_remote_findings"
        "(server,remote_test_id,fingerprint,remote_finding_id,payload_hash) VALUES(?,?,?,?,?)",
        (server, test_id, item["fingerprint"], 7,
         "an-older-digest" if stale else digest(finding_payload(item))))
    await db.execute(
        "INSERT INTO integration_exports(id,session_id,destination,payload_hash,status) "
        "VALUES(?,?,?,?,?)",
        (f"e-{item['fingerprint']}", "s", f"{server}/{test_id}", "h", "completed"))


# ----------------------------------------------------------- the two facts, kept apart


async def test_a_finding_nobody_exported_says_so(lane):
    await store(lane, finding())
    result = await synchronization("s")
    assert result["findings"]["fp-1"]["state"] == "never_exported"
    assert result["summary"]["never_exported"] == 1


async def test_a_finding_the_tracker_holds_as_written_is_synchronized(lane):
    item = finding()
    await store(lane, item)
    await exported(lane, item)
    result = await synchronization("s")
    assert result["findings"]["fp-1"]["state"] == "synchronized"
    assert result["findings"]["fp-1"]["remote_test_ids"] == [42]


async def test_a_finding_that_moved_after_it_was_sent_says_the_tracker_is_behind(lane):
    """The one an operator most needs: the client is reading an older version. Recomputed
    from the payload, so a severity, triage or evidence change is enough to show it."""
    item = finding()
    await store(lane, item)
    await exported(lane, item, stale=True)
    entry = (await synchronization("s"))["findings"]["fp-1"]
    assert entry["state"] == "changed_since_export"
    assert "export again" in entry["detail"]


async def test_a_local_triage_change_alone_makes_the_tracker_stale(lane):
    """Triaging locally does not tell anybody. This is the gap the entry names: a finding
    marked `fixed` that the client's tracker still shows as active."""
    item = finding()
    await store(lane, item)
    await exported(lane, item)
    assert (await synchronization("s"))["findings"]["fp-1"]["state"] == "synchronized"
    await store(lane, finding(triage_state="fixed"))
    assert (await synchronization("s"))["findings"]["fp-1"]["state"] == "changed_since_export"


# --------------------------------------------- an unresolved export makes it provisional


@pytest.mark.parametrize("status", ["uncertain", "partial", "running"])
async def test_an_unresolved_export_is_reported_beside_the_states(lane, status):
    """`partial` is the steady-state DefectDojo deduplication case and `uncertain` means a
    write may or may not have landed. Showing `synchronized` beside either without saying so
    would assert the one thing nobody knows."""
    item = finding()
    await store(lane, item)
    await exported(lane, item)
    await lane.execute("UPDATE integration_exports SET status=?,detail=? WHERE session_id='s'",
                       (status, "2 of 3 findings were refused by the remote"))
    result = await synchronization("s")
    assert result["unresolved_exports"], result
    assert result["unresolved_exports"][0]["status"] == status
    assert "provisional" in result["establishes"]


async def test_a_resolved_export_does_not_cry_wolf(lane):
    """A caveat on every report is a caveat nobody reads."""
    item = finding()
    await store(lane, item)
    await exported(lane, item)
    result = await synchronization("s")
    assert result["unresolved_exports"] == []
    assert "provisional" not in result["establishes"]


# ------------------------------------------------------------------ and in the report


async def test_the_report_counts_what_it_does_not_list(lane):
    """It lists OUTSTANDING findings and used to drop the rest without a word."""
    from orchestrator.integrations.service import report

    await store(lane, finding("fp-1"), finding("fp-2", triage_state="fixed"),
                finding("fp-3", triage_state="false_positive"))
    body = await report("s")
    assert body["statistics"]["findings"] == 1
    assert [f["id"] for f in body["findings"]] == ["fp-1"]
    assert body["triage"]["excluded_from_this_report"] == 2
    assert body["triage"]["fixed"] == 1 and body["triage"]["false_positive"] == 1
    assert "not listed above" in body["triage"]["establishes"]


async def test_the_report_keeps_the_two_facts_in_separate_places(lane):
    """The entry's actual wording. A reader must not have to infer one from the other."""
    from orchestrator.integrations.service import report

    item = finding()
    await store(lane, item)
    await exported(lane, item)
    body = await report("s")
    assert set(body["triage"]) >= {"open", "excluded_from_this_report"}
    assert body["synchronization"]["findings"]["fp-1"]["state"] == "synchronized"
    assert set(body["synchronization"]["summary"]) == set(SYNCHRONIZATION_STATES)
    assert "separate facts" in body["synchronization"]["establishes"]


async def test_the_report_still_works_with_nothing_exported(lane):
    from orchestrator.integrations.service import report

    await store(lane, finding())
    body = await report("s")
    assert body["synchronization"]["summary"]["never_exported"] == 1
    assert body["synchronization"]["unresolved_exports"] == []
