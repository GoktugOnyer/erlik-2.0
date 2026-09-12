"""One half-written line in a log took the whole assessment with it.

`Collector.finish()` and `adapters.record()` both read the proxy audit log,
`audit/requests.jsonl`, and both parsed it with a bare `json_lines(audit.read_text())` —
which raises on the first line it cannot parse. That file is written by mitmproxy, a process
that can be killed, so a truncated last line is an ordinary outcome rather than an attack:

    a clean log                     1 event
    a truncated last line           json.JSONDecodeError: Unterminated string
    invalid utf-8 bytes             UnicodeDecodeError, out of read_text() itself

Out of `finish()` that reached nothing until `service.run`'s `finally`, which wrote the
assessment `completed` — see
`tests/test_an_assessment_that_did_not_finish_does_not_say_completed.py`. `finish()` already
counted malformed CALLBACK lines and degraded the stage to `partial` for them; the audit log
is held to the same rule now, because a request history with holes is a history whose counts
are floors and the caller has to be able to say so.
"""
import asyncio
import json

import pytest

from orchestrator.integrations.adapters import audit_events

CLEAN = json.dumps({"url": "http://t/poll?id=1", "status": 200, "allowed": True})


def write(tmp_path, body: bytes):
    path = tmp_path / "requests.jsonl"
    path.write_bytes(body)
    return path


# ---------------------------------------------------------------- the tolerant reader

def test_a_clean_log_reads_every_line(tmp_path):
    """The control, first: a reader that returns nothing proves nothing below."""
    path = write(tmp_path, (CLEAN + "\n" + CLEAN + "\n").encode())
    events, unreadable = audit_events(path)
    assert len(events) == 2 and unreadable == 0


@pytest.mark.parametrize("damage,why", [
    (b'{"url": "http://t/po', "a truncated last line, which is what a killed proxy leaves"),
    (b"\xff\xfe", "bytes that are not utf-8 at all"),
    (b"[1, 2, 3]", "valid JSON that is not an object"),
    (b"not json", "a line that is not JSON"),
])
def test_a_damaged_line_is_counted_not_raised(tmp_path, damage, why):
    path = write(tmp_path, CLEAN.encode() + b"\n" + damage + b"\n")
    events, unreadable = audit_events(path)
    assert [e["status"] for e in events] == [200], why
    assert unreadable == 1, why


def test_a_missing_file_is_not_an_error(tmp_path):
    assert audit_events(tmp_path / "absent.jsonl") == ([], 0)


# ------------------------------------------------------ and what the callers do with it

class _Sandbox:
    def __init__(self, directory):
        self.directory = directory
        self.images = {}
        self.output = directory / "output"
        self.output.mkdir(exist_ok=True)


async def test_finish_degrades_the_stage_instead_of_raising(tmp_path, monkeypatch):
    """The decisive one: the method that used to take the assessment down."""
    from orchestrator.integrations.contracts import StageResult
    from orchestrator.integrations.interactsh import Collector

    audit = tmp_path / "audit"
    audit.mkdir()
    (audit / "requests.jsonl").write_bytes(CLEAN.encode() + b'\n{"url": "http://t/po')

    async def still_polling():
        await asyncio.sleep(3600)

    collector = Collector.__new__(Collector)
    collector.sandbox = _Sandbox(tmp_path)
    collector.ctx = None
    collector.payloads, collector.issued_payloads, collector.probe_evidence = {}, [], []
    # PENDING, so `early_exit` is False and the status would otherwise have been
    # `completed` — which is the case this clause exists for. A task that had already
    # exited degrades the stage for its own reason and would have hidden the point.
    collector.task = asyncio.ensure_future(still_polling())
    recorded = {}

    async def fake_record(ctx, sandbox, output, result):
        recorded["result"] = result
        return result

    monkeypatch.setattr("orchestrator.integrations.interactsh.record", fake_record)
    monkeypatch.setattr("orchestrator.integrations.interactsh.correlate",
                        lambda *a, **kw: StageResult())
    result = await collector.finish(wait=False)
    assert result.status == "partial", "a hole in the poll history is not a clean one"
    assert "unreadable lines" in (result.reason or ""), result.reason
    assert result.metadata["unreadable_audit_lines"] == 1


async def test_a_clean_audit_log_leaves_the_stage_alone(tmp_path, monkeypatch):
    """The negative control: the clause must not degrade a healthy stage."""
    from orchestrator.integrations.contracts import StageResult
    from orchestrator.integrations.interactsh import Collector

    audit = tmp_path / "audit"
    audit.mkdir()
    (audit / "requests.jsonl").write_bytes(CLEAN.encode() + b"\n")

    async def still_polling():
        await asyncio.sleep(3600)

    collector = Collector.__new__(Collector)
    collector.sandbox = _Sandbox(tmp_path)
    collector.ctx = None
    collector.payloads, collector.issued_payloads, collector.probe_evidence = {}, [], []
    collector.task = asyncio.ensure_future(still_polling())

    async def fake_record(ctx, sandbox, output, result):
        return result

    monkeypatch.setattr("orchestrator.integrations.interactsh.record", fake_record)
    monkeypatch.setattr("orchestrator.integrations.interactsh.correlate",
                        lambda *a, **kw: StageResult())
    result = await collector.finish(wait=False)
    assert result.status == "completed"
    assert "unreadable_audit_lines" not in result.metadata


async def test_record_counts_the_requests_it_could_read(tmp_path, monkeypatch):
    """`record()` had the identical unguarded parse over the same file."""
    from orchestrator.integrations.adapters import record
    from orchestrator.integrations.contracts import StageResult
    from orchestrator.integrations.runtime import JobOutput

    audit = tmp_path / "audit"
    audit.mkdir()
    (audit / "requests.jsonl").write_bytes(
        (CLEAN + "\n").encode() * 2 + b'{"url": "http://t/po')

    class _Ctx:
        session_id, stage_id, known = "s", "stage", ()

    monkeypatch.setattr("orchestrator.integrations.adapters.db.evidence",
                        lambda *a, **kw: _async("eid"))
    # And it must not reach for the strict parser again: `json_lines` raising here would
    # be the defect returning, so this makes that loud rather than silent.
    monkeypatch.setattr("orchestrator.integrations.adapters.json_lines",
                        lambda text: (_ for _ in ()).throw(AssertionError(
                            "record() must not parse the audit log with json_lines")))
    out = await record(_Ctx(), _Sandbox(tmp_path), JobOutput(0, "", ""), StageResult())
    assert out.metadata["request_count"] == 2, "the readable lines still count"
    assert out.metadata["unreadable_audit_lines"] == 1


async def _async(value):
    return value
