"""A finding has to carry the bytes it rests on.

Measured on 2026-09-10: the lane reported nine findings on DVWA, two of them
graded `confirmed` and exported to DefectDojo with `verified: true`, and the
description of each was one sentence — "regex evaluator matched captured tool
output". The blind evaluators build a byte-level proof (control sizes, then the
first differing window quoting `User ID is MISSING` against `User ID exists`), it
reached the evidence blob, and it stopped there. A client could not check a
HIGH-severity claim against anything.

Two properties, and the second is why `evidence` is not merely appended to
`basis`: the proof is TARGET-CONTROLLED text. It has to arrive redacted, bounded,
and unable to act as markup wherever it is rendered.
"""
import json

import pytest

from orchestrator.integrations.adapters import MAX_EVIDENCE_CHARS, _marker_window
from orchestrator.integrations.contracts import IntegrationFinding
from orchestrator.integrations.defectdojo import _quoted, finding_payload
from orchestrator.integrations.security import redact


def _finding(**kw):
    base = dict(fingerprint="f", title="t", url="http://app.test/x", rule="r",
                source="testcase", basis="b")
    return IntegrationFinding(**{**base, **kw})


def test_the_field_exists_and_defaults_to_nothing():
    assert _finding().evidence == ""
    assert _finding(evidence="proof").evidence == "proof"


def test_basis_and_evidence_stay_separate():
    """One is lane-authored and safe to render; the other is the application's.
    ZAP's evidence used to be concatenated onto its basis, which is how the two
    got conflated and why basis was the only thing anyone exported."""
    import inspect
    from orchestrator.integrations import adapters
    source = inspect.getsource(adapters.parse_zap)
    assert 'basis="ZAP alert; "' not in source, "the target's bytes are back in basis"
    assert 'evidence=redact(str(item.get("evidence", ""))' in source


# ------------------------------------------------- it arrives safe

def test_a_credential_echoed_by_the_target_never_reaches_the_finding():
    """A response body is exactly where an identity's own session cookie comes
    back at us. The evidence is redacted on the way in, with the same known
    values the evidence blob uses."""
    secret = "1da920c8055f4e1b7a2c9d8e3f4a5b6c"
    body = f"Set-Cookie: PHPSESSID={secret}\nYou have an error in your SQL syntax"
    cleaned = redact(body, (secret,))
    assert secret not in cleaned
    assert "You have an error in your SQL syntax" in cleaned, "redaction ate the proof"
    assert secret not in _finding(evidence=cleaned).evidence


def test_evidence_is_bounded_on_both_sides_of_the_seam():
    """The runner caps it at 1500 and the integration layer caps it again,
    because the two are separated by a seam and the field is target-controlled."""
    import inspect
    from orchestrator.testcase import runner
    assert runner.MAX_EVIDENCE == 1500
    assert "[:MAX_EVIDENCE]" in inspect.getsource(runner._run_evaluator)
    from orchestrator.integrations import deterministic
    assert MAX_EVIDENCE_CHARS == 1500
    assert "[:MAX_EVIDENCE_CHARS]" in inspect.getsource(deterministic.CatalogueAdapter.run)


def test_the_marker_window_shows_the_forbidden_content_not_the_whole_response():
    body = "x" * 500 + "TOP-SECRET-SALARY-TABLE" + "y" * 500
    window = _marker_window(body, "TOP-SECRET-SALARY-TABLE")
    assert "TOP-SECRET-SALARY-TABLE" in window
    assert len(window) <= 200
    assert _marker_window("nothing here", "absent") == ""


# ------------------------------------------- it cannot act as markup

def test_target_bytes_cannot_break_out_of_the_exported_description():
    """DefectDojo renders a description as markdown, and the content is chosen by
    the application under test. A fence can be closed from inside it; four
    leading spaces cannot."""
    hostile = ("```\n"
               "<script>alert(document.cookie)</script>\n"
               "# Injected heading\n"
               "[click](http://evil.test)\n"
               "````\nstill inside?")
    body = finding_payload({"basis": "b", "title": "t", "severity": "high",
                            "fingerprint": "f", "url": "u", "confidence": "suspected",
                            "evidence": hostile})["description"]
    quoted = body.split("redacted:\n\n", 1)[1]
    for line in quoted.splitlines():
        assert line == "" or line.startswith("    "), f"escaped the block: {line!r}"
    # ...and every hostile construct is still READABLE, just inert.
    assert "<script>alert(document.cookie)</script>" in quoted
    assert "# Injected heading" in quoted


def test_a_lone_carriage_return_cannot_hide_what_the_evidence_says():
    """A bare CR rewinds the line in some renderers, so quoted evidence can be
    made to display something other than what it contains."""
    assert "\r" not in _quoted("User ID exists\rUser ID is MISSING")
    assert "User ID exists" in _quoted("User ID exists\rUser ID is MISSING")


# ------------------------------------------------- it reaches consumers

def test_the_export_carries_the_proof():
    payload = finding_payload({
        "basis": "blind boolean: 2 controls agreed, true_string differs from false_string",
        "title": "SQL Injection (blind)", "severity": "high", "fingerprint": "f",
        "url": "http://app.test/x", "confidence": "confirmed",
        "evidence": "first difference:\n    false: User ID is MISSING\n    true : User ID exists"})
    description = payload["description"]
    assert "blind boolean: 2 controls agreed" in description
    assert "User ID is MISSING" in description and "User ID exists" in description
    assert payload["verified"] is True, "a confirmed finding must still export as verified"


def test_a_finding_with_no_evidence_exports_exactly_as_before():
    """Most scanner findings have none, and the description must not grow an
    empty section for them."""
    payload = finding_payload({"basis": "ZAP alert zap:10010", "title": "t", "severity": "low",
                               "fingerprint": "f", "url": "u", "confidence": "suspected"})
    assert payload["description"] == "ZAP alert zap:10010"
    assert "Evidence" not in payload["description"]


def test_a_finding_persisted_before_the_field_existed_still_works():
    """The payload is stored as JSON and read back; rows written by an earlier
    version have no `evidence` key at all."""
    legacy = {"basis": "b", "title": "t", "severity": "high", "fingerprint": "f",
              "url": "u", "confidence": "suspected", "triage_state": "open"}
    assert "Evidence" not in finding_payload(legacy)["description"]
    # and the engagement projection reads it with .get
    import inspect
    from orchestrator.integrations import service
    assert 'f.get("evidence", "")' in inspect.getsource(service)


def test_the_engagement_projection_keeps_it_separate_from_the_description():
    """A consumer that renders `description` as trusted text and `evidence` as
    untrusted text can only do that if they arrive as different fields."""
    import inspect
    from orchestrator.integrations import service
    projection = inspect.getsource(service).split('"findings": [{', 1)[1].split("for f in findings", 1)[0]
    assert '"description": f["basis"]' in projection
    assert '"evidence": f.get("evidence", "")' in projection


# ------------------------- the cookie case, where the proof IS the header

def test_a_cookie_header_keeps_the_attributes_and_loses_the_values():
    """WSTG-SESS-02's whole claim is "this session cookie lacks HttpOnly /
    SameSite / Secure", and the Set-Cookie line is the proof. Redaction used to
    replace that line wholesale, so the finding said the attributes were missing
    and the evidence said `Set-Cookie: [REDACTED]` — unverifiable, and
    indistinguishable from a cookie that had every attribute set.

    The value is what is secret. An attribute name is not."""
    raw = ("HTTP/1.1 200 OK\r\n"
           "Set-Cookie: SESSIONID=abc123def456; Path=/\r\n"
           "Set-Cookie: csrf=x9; Path=/; HttpOnly; SameSite=Strict; Secure\r\n"
           "Cookie: PHPSESSID=deadbeefdeadbeef; security=low\r\n"
           "Authorization: Bearer eyJhbGciOiJI.payload.sig\r\n"
           "X-Api-Key: k-123456789\r\n")
    out = redact(raw, ("abc123def456", "deadbeefdeadbeef"))
    for secret in ("abc123def456", "deadbeefdeadbeef", "eyJhbGciOiJI", "k-123456789"):
        assert secret not in out, f"{secret} survived redaction"
    for attribute in ("HttpOnly", "SameSite=Strict", "Secure", "Path=/"):
        assert attribute in out, f"{attribute} was erased with the secret"
    # the cookie NAMES survive too, or the evidence cannot say which cookie
    assert "SESSIONID=[REDACTED]" in out and "csrf=[REDACTED]" in out
    # ...and a request Cookie header loses every value, having no attributes
    assert "PHPSESSID=[REDACTED]" in out and "security=[REDACTED]" in out
    # Authorization and X-Api-Key keep the blanket rule: no structure to keep
    assert "Authorization: [REDACTED]" in out and "X-Api-Key: [REDACTED]" in out


async def test_the_cookie_attributes_finding_can_now_be_checked_against_its_evidence():
    """End to end on the one case whose evidence is a header block: the evaluator
    decides from the Set-Cookie line, and what survives redaction still shows a
    reader the same thing the evaluator saw."""
    from orchestrator.testcase.loader import find_by_id
    from orchestrator.testcase.runner import run_test_case

    weak = ("HTTP/1.1 200 OK\r\n"
            "Set-Cookie: SESSIONID=abc123def456; Path=/\r\n"
            "\r\n<html></html>")

    async def executor(command, **kwargs):
        return {"success": True, "exit_code": 0, "output": weak, "error": None}

    run = await run_test_case(
        find_by_id("WSTG-SESS-02"),
        {"url": "http://app.test/", "scope": {"allow_hosts": ["app.test"]}},
        executor=executor, allow_llm=False)
    assert run.findings, "the evaluator no longer fires on a cookie with no attributes"
    exported = redact(run.findings[0].evidence, ("abc123def456",))
    assert "abc123def456" not in exported
    assert "SESSIONID=[REDACTED]" in exported, "a reader cannot tell which cookie"
    # The evidence now NAMES the absent attributes rather than leaving a reader
    # to notice they are not in the header — and the header is still quoted, so
    # the claim can be checked against it rather than taken on trust.
    assert "missing: HttpOnly, SameSite" in exported
    assert "Set-Cookie: SESSIONID=[REDACTED]; Path=/" in exported


# ----------------------- the evidence has to contain its own match

def test_the_window_is_centred_on_the_match_not_the_head_of_the_response():
    """Evidence used to be `output[:1500]`, which is the proof only when the
    match happens to be near the top. DVWA prints PHP's fatal error BEFORE the
    page, so it was. A 2957-character body with the same error rendered at offset
    2788 — what an ordinary framework does — gave 1500 characters of page
    furniture proving nothing.

    A finding is worse for carrying evidence that does not contain its own match:
    it looks checkable and is not."""
    from orchestrator.testcase.runner import MAX_EVIDENCE, _around
    proof = "You have an error in your SQL syntax; check the manual"
    body = "<html><head>" + ("<!-- nav -->" * 250) + "</head><body><p>" + proof + "</p></body>"
    window = _around(body, body.index(proof))
    assert proof in window
    assert len(window) <= MAX_EVIDENCE + 64, "the header must not blow the bound"
    assert "from offset" in window, "a reader needs to know where the excerpt came from"
    assert _around("a short body", 3) == "a short body", "a body that fits is not excerpted"


async def test_a_regex_finding_carries_the_matched_text_wherever_it_sits():
    """End to end through the real runner: the same match at the top of the
    response and buried past the old 1500-character cut."""
    from orchestrator.testcase.loader import find_by_id
    from orchestrator.testcase.runner import run_test_case
    proof = ("You have an error in your SQL syntax; check the manual that corresponds to "
             "your MySQL server version for the right syntax to use near 'probe' at line 1")

    for label, body in (("at the top", proof + "<html>" + "x" * 4000),
                        ("buried at 4000", "<html>" + "x" * 4000 + proof)):
        async def executor(command, **kwargs):
            return {"success": True, "exit_code": 0,
                    "output": body if "erlik'probe" in command else "<p>no rows</p>",
                    "error": None}

        run = await run_test_case(
            find_by_id("WSTG-INPV-05.2"),
            {"url": "http://app.test/x", "parameter": "id", "scope": {"allow_hosts": ["app.test"]}},
            executor=executor, allow_llm=False)
        assert run.findings, label
        assert proof in run.findings[0].evidence, f"{label}: the evidence lacks its own match"


async def test_a_cookie_finding_quotes_the_line_it_judged_and_names_what_is_missing():
    from orchestrator.testcase.loader import find_by_id
    from orchestrator.testcase.runner import run_test_case

    async def executor(command, **kwargs):
        return {"success": True, "exit_code": 0, "error": None,
                "output": "HTTP/1.1 200 OK\r\nSet-Cookie: SESSIONID=abc123def456; Path=/\r\n\r\n<html>"}

    run = await run_test_case(
        find_by_id("WSTG-SESS-02"),
        {"url": "http://app.test/", "scope": {"allow_hosts": ["app.test"]}},
        executor=executor, allow_llm=False)
    evidence = run.findings[0].evidence
    assert "Set-Cookie: SESSIONID=abc123def456; Path=/" in evidence
    assert "HttpOnly" in evidence and "SameSite" in evidence, "it must name what is absent"
    assert "Secure" not in evidence, "the endpoint is http, so Secure does not apply"


# ------------------------------------------------- it survives the plumbing

async def test_a_rerun_with_no_proof_does_not_strip_the_proof_already_stored():
    """A fingerprint covers (case, step, url, parameter, identity), so two writes
    are two runs of the same probe and the later proof is as good as the earlier
    — except when it is empty. An empty artifact is not evidence."""
    import orchestrator.database as database
    from orchestrator.integrations import persistence as db
    from orchestrator.integrations.contracts import StageResult

    await database.init_db()
    await db.migrate()
    session = "evidence-merge-test"

    def result(evidence):
        return StageResult(findings=[_finding(fingerprint="same", evidence=evidence)])

    await db.persist_result(session, "one", result("the proof: User ID exists"))
    await db.persist_result(session, "two", result(""))
    rows = await db.rows("SELECT payload FROM integration_findings WHERE session_id=? AND fingerprint=?",
                         (session, "same"))
    assert json.loads(rows[0]["payload"])["evidence"] == "the proof: User ID exists"

    await db.persist_result(session, "three", result("a better proof"))
    rows = await db.rows("SELECT payload FROM integration_findings WHERE session_id=? AND fingerprint=?",
                         (session, "same"))
    assert json.loads(rows[0]["payload"])["evidence"] == "a better proof", (
        "a later run with real proof must be able to replace the earlier one")


async def test_a_user_cannot_write_the_evidence_field_through_triage():
    """The field is the application's bytes. If a reviewer could set it, it stops
    being that and becomes free text, which defeats the point of having it."""
    import orchestrator.database as database
    from orchestrator.integrations import api, persistence as db
    from orchestrator.integrations.contracts import StageResult

    assert set(api.TriageInput.model_fields) == {"state", "note"}, (
        "the triage body accepts a new field; check it cannot be `evidence`")

    await database.init_db()
    await db.migrate()
    session = "evidence-triage-test"
    await db.persist_result(session, "one", StageResult(
        findings=[_finding(fingerprint="t1", evidence="the application's own bytes")]))
    updated = await api.triage(session, "t1",
                               api.TriageInput(state="false_positive", note="reviewed by hand"))
    assert updated["triage_state"] == "false_positive"
    assert updated["evidence"] == "the application's own bytes", "triage rewrote the proof"
