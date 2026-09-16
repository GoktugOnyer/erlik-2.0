"""Comparable bounded local assessments with declared operation/finding ground truth."""
import asyncio
import hashlib
import json
import os
import re
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit
import pytest
from orchestrator.integrations import persistence as db
from orchestrator.integrations.adapters import Context, ADAPTERS, rpc, record
from orchestrator.integrations.contracts import AssessmentConfig, Endpoint, StageResult, Identity
from orchestrator.integrations.deterministic import CatalogueAdapter
from orchestrator.integrations.runtime import Sandbox, IMAGES, docker, JobOutput
from orchestrator.integrations.security import SecretStore, runtime_root
from orchestrator.integrations.service import assertion_controls, register

pytestmark = [pytest.mark.docker, pytest.mark.skipif(os.environ.get("ERLIK_DOCKER_TESTS") != "1", reason="local Docker benchmark opt-in")]
ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = {"/visible", "/hidden", "/api/private", "/api/error"}
EXPECTED = {("cookie", "/hidden"), ("cors", "/hidden"), ("authorization", "/api/private")}


@pytest.fixture
async def benchmark_lab(tmp_path, monkeypatch):
    import orchestrator.database as original
    key = uuid.uuid4().hex[:10]
    network, name = "erlik-bench-" + key, "erlik-benchmark-" + key
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setenv("ERLIK_INTEGRATION_EGRESS_NETWORK", network)
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "benchmark.db")
    await original.init_db()
    await db.migrate()
    await docker("network", "create", "--internal", network)
    fixture = ROOT / "tests/fixtures/integration_benchmark.py"
    try:
        await docker("run", "-d", "--name", name, "--network", network, "--network-alias", "target",
                     "-v", f"{fixture}:/fixture.py:ro", "--entrypoint", "python", IMAGES["worker"], "/fixture.py")
        await asyncio.sleep(0.3)
        yield fixture
    finally:
        await docker("rm", "-f", name, check=False)
        await docker("network", "rm", network, check=False)


async def metrics(session_id, duration, stages):
    inventory = await db.rows("SELECT url,method FROM integration_endpoints WHERE session_id=?", (session_id,))
    evidence = await db.rows("SELECT * FROM integration_evidence WHERE session_id=?", (session_id,))
    findings = [json.loads(r["payload"]) for r in await db.rows("SELECT payload FROM integration_findings WHERE session_id=?", (session_id,))]
    predictions, unscored = set(), 0
    for f in findings:
        kind = ("cookie" if f["rule"].startswith("WSTG-SESS-02") else "cors" if f["rule"].startswith("WSTG-CLNT-07")
                else "authorization" if f["confidence"] == "confirmed" and f["source"] == "schemathesis" else None)
        if kind:
            predictions.add((kind, urlsplit(f["url"]).path))
        else:
            unscored += 1
    # THROUGH THE DIGEST CHECK, like the evidence count below, and not straight off disk.
    # These bytes produce `schema_operation_coverage` and `request_count`, and the loop read
    # them with a bare `read_text()` while `_intact` sat ten lines away — the same defect
    # one commit fixed for evidence completeness and left here. Measured: appending two
    # lines to the stored `requests` artifact moved coverage 0.5 -> 1.0 and request_count
    # 2 -> 4, straight past this file's own `assert schema_operation_coverage == 1`, and the
    # only trace was an unrelated count dropping.
    #
    # An artifact that fails its digest is NAMED and excluded rather than raising: a
    # benchmark that aborts tells you nothing, and one that quietly includes unverified
    # bytes tells you something false.
    audit, unverified = [], []
    for e in evidence:
        if e["kind"] != "requests":
            continue
        try:
            raw = await db.evidence_bytes(e["id"])
        except Exception as exc:
            unverified.append({"id": e["id"], "error": type(exc).__name__})
            continue
        for line in raw.decode("utf-8", "replace").splitlines():
            if not line.strip():
                continue
            try:
                audit.append(json.loads(line))
            except ValueError:
                unverified.append({"id": e["id"], "error": "unreadable audit line"})
    requested = {urlsplit(e["url"]).path for e in audit if "allowed" in e and e["allowed"] and e.get("method") == "GET"}
    # INTACT, not merely present. This read `size` from the DATABASE ROW and
    # called that a resolvable reference — the row compared against itself, so a
    # truncated or substituted artifact scored as evidence-complete. And the
    # `size > 0` conjunct contradicted the clause about empty diagnostic files:
    # once record() retains a zero-byte scanner log, that conjunct would score it
    # dangling and drive the metric straight back to "0 of 17".
    def _intact(row):
        path = runtime_root() / "evidence" / row["id"]
        return path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == row["sha256"]

    existing = {e["id"] for e in evidence if _intact(e)}
    # AND AN EMPTY ARTIFACT IS NOT PROOF. `existing` is deliberately size-blind — an empty
    # scanner log is a valid retained attachment, which is the clause a `size > 0` conjunct
    # here once contradicted — but "this finding has substantive evidence" is a different
    # question, and `bool(f["evidence_ids"])` answered it about the LIST rather than the
    # bytes. A finding whose only citation is a zero-byte file was counted as supported.
    #
    # The size comes from the FILE, never from the database row: the row compared against
    # itself is exactly what the digest lesson above is about.
    substantive = {key for key in existing
                   if (runtime_root() / "evidence" / key).stat().st_size > 0}
    supported = sum(bool(f["evidence_ids"])
                    and all(key in existing for key in f["evidence_ids"])
                    and any(key in substantive for key in f["evidence_ids"])
                    for f in findings)
    empty_only = [f["rule"] for f in findings
                  if f["evidence_ids"] and all(key in existing for key in f["evidence_ids"])
                  and not any(key in substantive for key in f["evidence_ids"])]
    # "0 of 17" is not a finding anyone can act on. A finding that cited NO
    # evidence and one that cited an id which does not resolve are different
    # defects with different fixes, so the metric distinguishes them.
    uncited = [f["rule"] for f in findings if not f["evidence_ids"]]
    dangling = {key for f in findings for key in f["evidence_ids"] if key not in existing}
    by_id = {e["id"]: e for e in evidence}
    why = {}
    for key in dangling:
        row = by_id.get(key)
        if row is None:
            why[key] = "no evidence row for this id"
        elif not (runtime_root() / "evidence" / key).is_file():
            why[key] = f"row present but artifact missing (kind={row['kind']})"
        elif not _intact(row):
            why[key] = f"artifact failed its digest check (kind={row['kind']}, stage={row['stage_id']})"
        else:
            why[key] = "unknown"
    return {"duration_seconds": duration,
        # Audit artifacts excluded from the coverage and request counts below because they
        # could not be verified, and lines inside them that could not be read. Non-empty
        # here means every request and coverage number in this payload is a FLOOR — which
        # is the difference between a benchmark that is silent about unverified bytes and
        # one that is honest about them.
        "unverified_audit_artifacts": unverified,
        "endpoints": sorted({i["url"] for i in inventory}),
        "endpoint_count": len({i["url"] for i in inventory}), "schema_operations_reached": sorted(requested & OPERATIONS),
        "schema_operation_coverage": len(requested & OPERATIONS) / len(OPERATIONS),
        "expected_findings": sorted(EXPECTED), "expected_findings_recovered": sorted(predictions & EXPECTED),
        "false_positives_in_scored_rules": sorted(predictions - EXPECTED), "unscored_scanner_findings": unscored,
        "recall_in_scored_rules": len(predictions & EXPECTED) / len(EXPECTED),
        "evidence_completeness": {"findings_with_nonempty_resolvable_evidence": supported, "total_findings": len(findings),
            "findings_without_substantive_evidence": sorted(
                f["rule"] for f in findings if not (f.get("evidence") or "").strip()),
            "findings_citing_no_evidence": sorted(set(uncited)), "unresolvable_evidence_ids": sorted(dangling),
            # Named separately, in the house style of the two above: a finding citing
            # nothing, one citing an id that does not resolve, and one whose every citation
            # is an empty file are three different defects with three different fixes.
            "findings_citing_only_empty_artifacts": sorted(set(empty_only)),
            "unresolvable_reasons": sorted(set(why.values())),
            "stored_evidence_rows": len(evidence), "resolvable_evidence_rows": len(existing)},
        "request_count": sum(e.get("allowed", False) for e in audit), "blocked_request_count": sum(e.get("allowed") is False for e in audit),
        "stages": stages}


@pytest.mark.asyncio
async def test_integrated_coverage_and_finding_benchmark(benchmark_lab):
    identity = Identity(name="reader", target_origin="http://target:8080", headers={"Authorization": "Bearer reader-token"},
                        check={"url": "http://target:8080/me", "body_contains": "reader"})
    identity_id = SecretStore().put(identity.model_dump())
    cfg = AssessmentConfig(scope={"allow_hosts": ["target"], "allow_ports": [8080]}, identity_ids=[identity_id],
        stages=["katana", "zap", "schemathesis"], active=True,
        test_cases=["WSTG-SESS-02", "WSTG-CLNT-07"], schema_input={"url": "http://target:8080/openapi.json"},
        security_assertions=[{"identity_id": identity_id, "description": "Reader can access the admin object",
                              "request": {"url": "http://target:8080/api/private"}, "forbidden_marker": "admin-object-canary"}],
        budget={"stage_seconds": 120, "assessment_seconds": 600, "requests_per_second": 20})
    arms = {}
    for arm in ("baseline", "integrated"):
        session_id = "coverage-" + arm
        await register(session_id, "http://target:8080", cfg)
        started, stages = time.monotonic(), []
        async with asyncio.timeout(cfg.budget.assessment_seconds):
            names = ["baseline"] if arm == "baseline" else ["katana", "zap", "schemathesis"]
            for name in [*names, "testcases"]:
                # Only Schemathesis and explicitly selected catalogue probes are active.
                effective = cfg.model_copy(update={"active": name in ("schemathesis", "testcases")})
                # The control sweep the real lane runs once per assessment. Without it the
                # assertion path grades `likely` for want of a differential, and the
                # benchmark measures a product that does not exist — measured: recall in
                # scored rules 0.667 instead of 1, because the authorization rule was scored
                # only on `confirmed`.
                ctx = Context(session_id, name, "http://target:8080", effective, identity_id,
                              identity.model_dump(),
                              assertion_controls=await assertion_controls(session_id, effective))
                async with Sandbox(effective, identity.model_dump()) as sandbox:
                    if name == "baseline":
                        script = sandbox.write("baseline.js", (ROOT / "scripts/pw-crawl.js").read_text())
                        raw = await rpc(sandbox, {"action": "baseline_browser", "script": script, "url": ctx.target})
                        assert raw["exit_code"] == 0 and "Page Title" in raw["stdout"], raw
                        urls = set(re.findall(r"http://target:8080[^\s]+", raw["stdout"]))
                        result = await record(ctx, sandbox, JobOutput(0, json.dumps(raw), ""), StageResult(endpoints=[
                            Endpoint(url=url, source="baseline", identity=identity_id) for url in urls]))
                    elif name == "testcases":
                        result = await CatalogueAdapter().run(ctx, sandbox)
                    else:
                        result = await ADAPTERS[name].run(ctx, sandbox)
                    await db.persist_result(session_id, name, result)
                    stages.append({"name": name, "status": result.status, "reason": result.reason, "metadata": result.metadata,
                                   "active": effective.active})
                    assert result.status == "completed", result.model_dump()
        arms[arm] = await metrics(session_id, time.monotonic() - started, stages)
    report = {"fixture_version": "1.0", "fixture_sha256": hashlib.sha256(benchmark_lab.read_bytes()).hexdigest(),
        "baseline_crawler_sha256": hashlib.sha256((ROOT / "scripts/pw-crawl.js").read_bytes()).hexdigest(),
        "protocol": "Same local target, identity and budgets. Baseline: original crawler plus selected catalogue checks. Integrated: Katana, passive ZAP, active Schemathesis and the same catalogue checks.",
        "limitations": "Scored rules are cookie attributes, credentialed CORS reflection and explicit authorization assertion only. Other scanner alerts remain unadjudicated. Evidence metric verifies stored evidence references, not manual evidentiary sufficiency. No client-target generalization.",
        "arms": arms}
    # Written BEFORE the assertions. A benchmark that only produces its report
    # when it passes cannot tell you what regressed when it fails, which is the
    # one time you need the numbers.
    if os.environ.get("ERLIK_COVERAGE_REPORT"):
        Path(os.environ["ERLIK_COVERAGE_REPORT"]).write_text(json.dumps(report, indent=2))
    assert arms["integrated"]["schema_operation_coverage"] == 1
    assert arms["integrated"]["recall_in_scored_rules"] == 1
    assert not arms["integrated"]["false_positives_in_scored_rules"]
    assert arms["integrated"]["recall_in_scored_rules"] > arms["baseline"]["recall_in_scored_rules"]
    counts = arms["integrated"]["evidence_completeness"]
    assert counts["total_findings"] > 0 and counts["findings_with_nonempty_resolvable_evidence"] == counts["total_findings"], counts
    # SUBSTANTIVE, not merely cited. The clause is "each finding has substantive
    # supporting evidence", and this metric only ever asked whether the ids
    # resolved. A real run from before findings carried their proof —
    # lane10-final-low, 2026-09-10 — had 9 of 9 findings with an EMPTY evidence
    # field and every id resolvable, so it would have scored 100% complete.
    assert counts["findings_without_substantive_evidence"] == [], counts
