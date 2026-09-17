"""What the proxy refused, and why — E-020's "policy decisions are visible in the action log".

The proxy records a decision for EVERY request, refusals included, with the reason it used:
`{"url", "method", "allowed", "reason", "timestamp"}`. `record()` read two things out of that
file and neither was the one an operator needs.

    request_count     every DECISION, allowed or refused
    blocked_requests  a bare count, no reasons

`request_count` is the number the BUDGET is accounted against — `budget_refusal` counts a
refused request too — so it is right for that and reads like activity for everything else. A
stage where all 47 requests were refused reported the same `request_count` as a stage where
all 47 succeeded. The number that means COVERAGE had to be derived by subtraction, and the
reasons the proxy had already written were read by nothing.

A BARE COUNT INVITES THE WRONG CONCLUSION IN BOTH DIRECTIONS. Forty-seven refusals is
unremarkable when they are out-of-scope links a crawler followed, and is a misconfiguration
when they are "operation not selected" — the workflow selected nothing the scanner tried.
Those are different repairs and the count alone cannot tell them apart.

AND A STAGE THAT REACHED NOTHING IS NOT A CLEAN STAGE. A scanner whose every request was
refused can still exit 0 and be recorded `completed` with no findings, which is exactly what a
target with nothing wrong with it looks like.
"""
import json

import pytest

from orchestrator.integrations.adapters import audit_events


class _Ctx:
    session_id, stage_id, known = "s", "stage", ()


class _Sandbox:
    """The three attributes `record()` reaches for. Same stub as the audit-log tests."""
    def __init__(self, directory):
        self.directory = directory
        self.images = {}
        self.output = directory / "output"
        self.output.mkdir(exist_ok=True)


async def _async(value):
    return value


async def _record(tmp_path, monkeypatch, events):
    """Drive the real `record()` over an audit log of exactly these decisions."""
    from orchestrator.integrations.adapters import record
    from orchestrator.integrations.contracts import StageResult
    from orchestrator.integrations.runtime import JobOutput

    audit(tmp_path, events)
    monkeypatch.setattr("orchestrator.integrations.adapters.db.evidence",
                        lambda *a, **kw: _async("eid"))
    return await record(_Ctx(), _Sandbox(tmp_path), JobOutput(0, "", ""), StageResult())


def audit(tmp_path, events):
    """An audit log in the shape the proxy addon writes."""
    directory = tmp_path / "audit"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "requests.jsonl"
    path.write_text("".join(json.dumps(event) + "\n" for event in events))
    return path


ALLOWED = {"url": "http://app.test/a", "method": "GET", "allowed": True,
           "reason": "target destination"}


def refused(reason, url="http://app.test/x"):
    return {"url": url, "method": "POST", "allowed": False, "reason": reason}


# --------------------------------------------------------------- the counts it now keeps


async def test_the_number_that_means_coverage_is_recorded_not_derived(tmp_path, monkeypatch):
    result = await _record(tmp_path, monkeypatch, [ALLOWED, ALLOWED, refused("host outside scope")])
    assert result.metadata["request_count"] == 3, "the budget number counts every decision"
    assert result.metadata["blocked_requests"] == 1
    assert result.metadata["requests_allowed"] == 2, (
        "the count that means coverage must not have to be worked out by subtraction")


async def test_the_reasons_are_broken_out_not_totalled(tmp_path, monkeypatch):
    result = await _record(tmp_path, monkeypatch, [
        ALLOWED,
        refused("host outside scope"), refused("host outside scope"),
        refused("operation not selected")])
    assert result.metadata["blocked_by_reason"] == {
        "host outside scope": 2, "operation not selected": 1}


async def test_a_stage_with_no_refusals_carries_no_reason_map(tmp_path, monkeypatch):
    """An empty map is noise on the common path, and an absent one is not the same claim as
    a map full of zeroes."""
    result = await _record(tmp_path, monkeypatch, [ALLOWED, ALLOWED])
    assert "blocked_by_reason" not in result.metadata
    assert result.metadata["requests_allowed"] == 2


async def test_a_refusal_with_no_stated_reason_is_counted_as_unstated(tmp_path, monkeypatch):
    """Not dropped. A decision the proxy could not explain is still a decision, and losing it
    would make the reasons add up to less than the count beside them."""
    result = await _record(tmp_path, monkeypatch, [{"url": "http://app.test/x", "allowed": False}])
    assert result.metadata["blocked_by_reason"] == {"unstated": 1}
    assert sum(result.metadata["blocked_by_reason"].values()) == result.metadata["blocked_requests"]


# ------------------------------------------------------- reaching nothing is not clean


async def test_every_request_refused_is_a_failed_stage(tmp_path, monkeypatch):
    """The defect this file is named for. The scanner exits 0, finds nothing, and `completed`
    with no findings is what a target with nothing wrong with it looks like."""
    result = await _record(tmp_path, monkeypatch, [
        refused("host outside scope"), refused("host outside scope"),
        refused("operation not selected")])
    assert result.status == "failed", "no coverage must not be reported as a clean scan"
    assert "NO coverage" in result.reason
    assert "2x host outside scope" in result.reason, "the operator is not told what to repair"
    assert "1x operation not selected" in result.reason


async def test_one_request_getting_through_is_not_nothing(tmp_path, monkeypatch):
    """The boundary. Partial coverage is a different claim from none, and this clause must
    not swallow a stage that did reach the target."""
    result = await _record(tmp_path, monkeypatch, [ALLOWED, refused("host outside scope")])
    assert result.status == "completed"
    assert result.metadata["requests_allowed"] == 1


async def test_a_stage_that_made_no_requests_at_all_is_left_alone(tmp_path, monkeypatch):
    """No decisions is not the same as every decision refused — a stage that never got as far
    as issuing a request has its own reasons, and this clause has nothing to say about it."""
    result = await _record(tmp_path, monkeypatch, [])
    assert result.status == "completed"
    assert result.metadata["request_count"] == 0


async def test_the_reasons_are_ordered_by_how_many(tmp_path, monkeypatch):
    """Forty of one and one of another: the operator should read the dominant cause first."""
    result = await _record(tmp_path, monkeypatch,
                           [refused("operation not selected")]
                           + [refused("host outside scope")] * 40)
    assert result.reason.index("40x host outside scope") < result.reason.index(
        "1x operation not selected")


# ------------------------------------------------------------- the log is read tolerantly


async def test_a_truncated_last_line_still_yields_its_reasons(tmp_path, monkeypatch):
    """`audit_events` already tolerates the half-written line a killed mitmproxy leaves. The
    reason breakdown is built from the same events, so it inherits that and the count of what
    could not be read stays beside it."""
    path = audit(tmp_path, [ALLOWED, refused("host outside scope")])
    path.write_text(path.read_text() + '{"url": "http://app.test/z", "allo')
    events, unreadable = audit_events(path)
    assert unreadable == 1
    assert [e.get("reason") for e in events if e.get("allowed") is False] == [
        "host outside scope"]
