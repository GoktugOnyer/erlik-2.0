"""The benchmark's own numbers were computed from bytes nothing checked.

`tests/test_integration_benchmark.py::metrics` is the function a release is judged on, and
it is Docker-gated — so its behaviour had no hermetic coverage at all, and two defects of
exactly the shape it was written to catch sat inside it.

    the audit loop    read `(runtime_root()/"evidence"/id).read_text()` straight off disk,
                      while `_intact()` — a digest check over the same artifacts — sat ten
                      lines below. `schema_operation_coverage` and `request_count` come out
                      of those bytes. Measured by an adversarial pass: appending two lines
                      to the stored artifact moved coverage 0.5 -> 1.0 and request_count
                      2 -> 4, past this file's own `assert schema_operation_coverage == 1`.

    `supported`       counted a finding as having non-empty resolvable evidence on
                      `bool(f["evidence_ids"])` — a property of the LIST, not of the bytes.
                      A finding whose only citation is a zero-byte file was counted as
                      supported.

The second needs care rather than a `size > 0`: an empty diagnostic FILE is a valid
retained attachment (R0 clause 3, and `adapters.keep` implements it), and a `size > 0`
conjunct in `existing` once contradicted that clause. "Is this artifact retained" and "is
this finding supported" are different questions, so they get different sets.

This loads `metrics` directly, with no Docker and no lane run.
"""
import hashlib
import importlib.util
import json

import pytest

from orchestrator.integrations.security import runtime_root


def _metrics_fn():
    spec = importlib.util.spec_from_file_location(
        "_bench", __import__("pathlib").Path(__file__).with_name("test_integration_benchmark.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.metrics


@pytest.fixture
async def store(tmp_path, monkeypatch):
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    await db.execute("INSERT INTO integration_assessments(session_id,target,status,config) "
                     "VALUES(?,?,?,?)", ("s", "http://app.test/", "completed", "{}"))
    return db


async def finding(store, rule, evidence_ids):
    payload = {"fingerprint": rule, "title": "t", "url": "http://app.test/x", "rule": rule,
               "source": "testcases", "basis": "b", "severity": "high",
               "confidence": "likely", "cwe": None, "evidence_ids": evidence_ids,
               "triage_state": "open"}
    await store.execute("INSERT INTO integration_findings VALUES(?,?,?)",
                        ("s", rule, json.dumps(payload)))


# ------------------------------------------------------- an empty citation is not proof

async def test_a_finding_citing_only_an_empty_artifact_is_not_supported(store):
    empty = await store.evidence("s", "stage", "scanner.log", "")
    await finding(store, "WSTG-X", [empty])
    counts = (await _metrics_fn()("s", 1.0, []))["evidence_completeness"]
    assert counts["total_findings"] == 1
    assert counts["findings_with_nonempty_resolvable_evidence"] == 0
    assert counts["findings_citing_only_empty_artifacts"] == ["WSTG-X"]
    # ...and the artifact is still a retained, resolvable row. The two questions differ.
    assert counts["resolvable_evidence_rows"] == 1
    assert counts["unresolvable_evidence_ids"] == []


async def test_a_finding_with_one_substantive_citation_is_supported(store):
    """The negative control: an empty artifact ALONGSIDE a real one must not disqualify."""
    empty = await store.evidence("s", "stage", "scanner.log", "")
    real = await store.evidence("s", "stage", "testcase:WSTG-X", '{"steps": []}')
    await finding(store, "WSTG-X", [empty, real])
    counts = (await _metrics_fn()("s", 1.0, []))["evidence_completeness"]
    assert counts["findings_with_nonempty_resolvable_evidence"] == 1
    assert counts["findings_citing_only_empty_artifacts"] == []


async def test_a_finding_citing_nothing_is_still_reported_separately(store):
    """Three different defects, three different numbers."""
    await finding(store, "WSTG-Y", [])
    counts = (await _metrics_fn()("s", 1.0, []))["evidence_completeness"]
    assert counts["findings_citing_no_evidence"] == ["WSTG-Y"]
    assert counts["findings_citing_only_empty_artifacts"] == []


# ------------------------------------------------ and the request numbers are verified

async def test_tampering_with_the_audit_artifact_does_not_move_the_numbers(store):
    """The decisive one. The artifact is rewritten on disk AFTER its digest was recorded."""
    events = [{"url": "http://app.test/a", "allowed": True, "method": "GET"}]
    audit = await store.evidence("s", "stage", "requests",
                                 "\n".join(json.dumps(e) for e in events))
    before = await _metrics_fn()("s", 1.0, [])
    assert before["request_count"] == 1, before

    path = runtime_root() / "evidence" / audit
    path.write_text(path.read_text() + "\n" +
                    json.dumps({"url": "http://app.test/b", "allowed": True, "method": "GET"}))
    after = await _metrics_fn()("s", 1.0, [])
    # The whole artifact is excluded, so the count DROPS rather than holding: none of those
    # bytes can be trusted, including the line that was there before. What must never happen
    # is the tampered number — 2 — being reported as a measurement.
    assert after["request_count"] == 0, (
        "appended lines were counted; the audit loop is reading unverified bytes again")
    assert after["unverified_audit_artifacts"], "and the exclusion must be named, not silent"
    assert after["unverified_audit_artifacts"][0]["id"] == audit
    assert after["unverified_audit_artifacts"][0]["error"] == "EvidenceIntegrityError"


async def test_an_unreadable_audit_line_is_named_not_fatal(store):
    """A truncated last line is what a killed mitmproxy leaves. It must not abort the
    benchmark, and it must not pass unmentioned."""
    good = json.dumps({"url": "http://app.test/a", "allowed": True, "method": "GET"})
    await store.evidence("s", "stage", "requests", good + '\n{"url": "http://app.test/b')
    result = await _metrics_fn()("s", 1.0, [])
    assert result["request_count"] == 1
    assert any(u["error"] == "unreadable audit line"
               for u in result["unverified_audit_artifacts"])


async def test_a_clean_audit_artifact_counts_normally(store):
    """The negative control for both: nothing above may cost a healthy store its numbers."""
    events = [{"url": "http://app.test/a", "allowed": True, "method": "GET"},
              {"url": "http://app.test/b", "allowed": True, "method": "GET"}]
    await store.evidence("s", "stage", "requests", "\n".join(json.dumps(e) for e in events))
    result = await _metrics_fn()("s", 1.0, [])
    assert result["request_count"] == 2
    assert result["unverified_audit_artifacts"] == []
