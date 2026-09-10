"""What `record()` attaches to a finding.

A finding is only as useful as the response a reader can check it against.
"""


async def test_a_finding_that_cites_its_own_evidence_keeps_only_that(tmp_path, monkeypatch):
    """The catalogue attaches exactly one evidence id per finding — the run that
    produced it. `record()` used to union the whole stage's evidence onto every
    finding, so all nine findings of the 2026-09-10 DVWA run came out citing the
    same 772 ids and a client could not tell which response proved which
    HIGH-severity SQL injection.

    Scanner findings still inherit, because they arrive citing nothing: ZAP's
    alerts have only the stage report to point at."""
    from orchestrator.integrations.adapters import record
    from orchestrator.integrations.contracts import IntegrationFinding, StageResult
    from orchestrator.integrations.runtime import JobOutput

    precise = IntegrationFinding(fingerprint="a", title="t", url="u", rule="r",
                                 source="testcase", basis="b", evidence_ids=["mine"])
    inherits = IntegrationFinding(fingerprint="b", title="t", url="u", rule="r",
                                  source="zap", basis="b")
    result = StageResult(findings=[precise, inherits])
    result.evidence_ids = ["stage-1", "stage-2"]

    class _Sandbox:
        images = {}
        output = tmp_path / "out"
        directory = tmp_path

    _Sandbox.output.mkdir()

    class _Ctx:
        session_id = "s"
        stage_id = "stage"
        known = []

    await record(_Ctx, _Sandbox, JobOutput(0, "", ""), result)
    assert precise.evidence_ids == ["mine"], "precise attribution was averaged away"
    assert inherits.evidence_ids == ["stage-1", "stage-2"], "a scanner finding lost its only evidence"
