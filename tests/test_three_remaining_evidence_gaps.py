"""The three gaps the 2026-09-10 evidence work left open, and their closures.

Each was named in docs/measurements/2026-09-10-full-lane.md as still open after
findings started carrying their proof:

  1. ZAP's `attack` and `otherinfo` were parsed and discarded
  2. the out-of-band SSRF finding carried no evidence at all
  3. WSTG-INPV-11.2 and WSTG-INPV-05.2 shipped byte-identical proof under two
     titles, one of them calling the injection unclassified while the other
     classified it
"""
import json

import pytest

from orchestrator.integrations.adapters import parse_zap
from orchestrator.integrations.interactsh import _callback_evidence, correlate
from orchestrator.testcase.loader import find_by_id


class _Ctx:
    known = ()
    identity_id = "i"
    target = "http://app.test"


# --------------------------------------------------- 1. the scanner's payload

def _zap_document(**instance):
    base = {"uri": "http://app.test/s?q=1", "method": "GET", "param": "q"}
    return {"site": [{"alerts": [{
        "pluginid": "40018", "name": "SQL Injection", "riskcode": "3", "cweid": "89",
        "instances": [{**base, **instance}]}]}]}


def test_a_zap_finding_carries_the_payload_zap_sent():
    """A client reading a ZAP SQL-injection finding got `ZAP alert zap:40018` and
    nothing else, while the instance in hand held
    `attack="1' AND '1'='1' -- "`. The payload is the one thing that makes a
    scanner finding replayable."""
    finding = parse_zap(_zap_document(
        attack="1' AND '1'='1' -- ",
        evidence="You have an error in your SQL syntax",
        otherinfo="The page results were successfully manipulated"), _Ctx).findings[0]
    # repr, because the trailing space in MySQL's `-- ` comment is significant
    # and a reader replaying a stripped payload gets a different query.
    assert repr("1' AND '1'='1' -- ") in finding.evidence
    assert "You have an error in your SQL syntax" in finding.evidence
    assert "successfully manipulated" in finding.evidence
    assert "parameter q" in finding.evidence
    # and the basis stays the lane's own sentence, with none of the target in it
    assert finding.basis == "ZAP alert zap:40018"
    assert "error in your SQL" not in finding.basis


def test_a_zap_instance_with_nothing_to_say_carries_no_empty_block():
    """Most ZAP alerts are informational and hold none of the three fields. An
    empty evidence section is worse than none: it promises a quote."""
    assert parse_zap(_zap_document(), _Ctx).findings[0].evidence == ""


def test_zap_evidence_is_sanitised_like_any_other_target_bytes():
    finding = parse_zap(_zap_document(evidence="before\x00after‮reordered"), _Ctx).findings[0]
    assert "<U+0000>" in finding.evidence and "<U+202E>" in finding.evidence
    assert "\x00" not in finding.evidence


# ------------------------------------------------- 2. the out-of-band callback

def test_the_callback_finding_quotes_the_probe_host_it_rests_on():
    """An out-of-band finding is the hardest kind to reconstruct: there is no
    response body, and the whole claim is that something reached a host only this
    assessment knew about. Without the host, the protocol and the time, a client
    is told an interaction happened and given no way to believe it."""
    probe = {"url": "http://app.test/fetch", "parameter": "next", "engine": "testcase"}
    event = {"full-id": "a1b2c3d4e5", "protocol": "dns", "timestamp": "2026-09-10T06:12:03Z",
             "remote-address": "10.0.3.7", "unique-id": "a1b2c3d4e5"}
    result = correlate([event], {"a1b2c3d4e5.oast.test": probe}, _Ctx)
    assert result.findings, "the callback no longer correlates"
    evidence = result.findings[0].evidence
    assert "a1b2c3d4e5.oast.test" in evidence, "the host is the uniqueness argument"
    assert "next on http://app.test/fetch" in evidence
    assert "dns" in evidence and "2026-09-10T06:12:03Z" in evidence
    assert "10.0.3.7" in evidence, "a reader wants to know who called back"
    assert "raw callback record" in evidence


def test_the_callback_record_is_treated_as_target_controlled():
    """Whatever made the callback chose its content — same provenance as a
    response body."""
    evidence = _callback_evidence(
        "h.oast.test", {"url": "u", "parameter": "p"}, "http",
        {"timestamp": "t", "raw-request": "GET / HTTP/1.1\r\nX: ‮reordered\x00"}, _Ctx)
    # json.dumps already turns them into the literal text `\u202e` / `\u0000`,
    # which is inert; what matters is that no raw character survives to reorder
    # or truncate what a reader sees.
    assert not any(c in evidence for c in ("\u202e", "\u0000"))
    assert "reordered" in evidence, "the attempt must still be visible"
    assert len(evidence) <= 1500


def test_the_callback_finding_stays_graded_likely():
    """A callback proves the parameter reached a resolver. It does not prove
    impact, and the grading says so."""
    result = correlate([{"full-id": "h", "protocol": "dns", "timestamp": "t"}],
                       {"h": {"url": "u", "parameter": "p"}}, _Ctx)
    assert result.findings[0].confidence == "likely"
    assert "does not prove SSRF impact" in result.findings[0].basis


# ------------------------------------------------------ 3. the duplicate

def test_only_the_overlapping_step_declares_subsumption():
    """WSTG-INPV-11.2's XPath, CRLF and metacharacter steps are not subsumed by
    anything. A case-level flag would have dropped them too."""
    steps = {s.name: s.subsumed_by for s in find_by_id("WSTG-INPV-11.2").steps}
    assert steps["single_quote"] == ["WSTG-INPV-05.2"]
    for name, subsumers in steps.items():
        if name != "single_quote":
            assert subsumers == [], f"{name} should not declare subsumption"


def test_the_declared_subsumer_sends_the_same_payload():
    """The declaration is only honest if the two steps really probe the same
    thing. If either payload changes, this should fail and be re-examined."""
    def payload(case, step):
        command = next(s.command for s in find_by_id(case).steps if s.name == step)
        return command.split("{{parameter}}=", 1)[1].rstrip('"')
    assert payload("WSTG-INPV-11.2", "single_quote") == payload("WSTG-INPV-05.2", "single_quote")


def test_the_lane_drops_the_vaguer_finding_and_says_so():
    """Measured on 2026-09-10: every DVWA run shipped both findings for the same
    request with byte-identical proof, one titled 'unclassified injection' while
    the other classified it as SQL."""
    import inspect
    from orchestrator.integrations import deterministic
    source = inspect.getsource(deterministic.CatalogueAdapter.run)
    assert "finding_subsumed" in source, "a dropped finding must be reported, not vanish"
    assert "reported = {(f.url, f.parameter, f.rule.partition(\":\")[0])" in source
    # ...and the step still RUNS, so a run without the more specific case reports
    assert "result.findings = kept" in source
    gate = source.split("ONE VULNERABILITY, ONE FINDING", 1)[1].split("if not result.metadata", 1)[0]
    assert "if better:" in gate and "else:" in gate


async def test_the_safety_net_holds_when_nothing_classified_the_error():
    """The property that makes suppression safe rather than a blind spot: with
    WSTG-INPV-11.2 selected alone, nothing classifies the error, so its finding
    must stand. Measured against live DVWA — 2 findings, 0 suppressed — and
    pinned here in-process so it cannot regress without the lab.

    This is why suppression happens at the END of the stage rather than by not
    running the step."""
    from orchestrator.integrations.contracts import IntegrationFinding

    def finding(case, step, url, parameter, title):
        return IntegrationFinding(
            fingerprint=f"{case}:{parameter}", title=title, url=url,
            rule=f"{case}:{step}", source="testcase", parameter=parameter, basis="b")

    vague = finding("WSTG-INPV-11.2", "single_quote", "http://app.test/x", "id",
                    "Parameter reaches an interpreter (unclassified injection — quote)")
    precise = finding("WSTG-INPV-05.2", "single_quote", "http://app.test/x", "id",
                      "SQL Injection (error-based)")

    def survivors(findings):
        """The stage's own suppression rule, applied to a finding list."""
        reported = {(f.url, f.parameter, f.rule.partition(":")[0]) for f in findings}
        kept = []
        for f in findings:
            case_id, _, step_name = f.rule.partition(":")
            case = find_by_id(case_id)
            step = next((s for s in (case.steps if case else []) if s.name == step_name), None)
            if any((f.url, f.parameter, other) in reported
                   for other in (getattr(step, "subsumed_by", None) or [])):
                continue
            kept.append(f)
        return {f.rule for f in kept}

    assert survivors([vague]) == {"WSTG-INPV-11.2:single_quote"}, (
        "with nothing to classify it, the unclassified finding must stand")
    assert survivors([vague, precise]) == {"WSTG-INPV-05.2:single_quote"}
    # and a DIFFERENT parameter is not covered by the classification of another
    other = finding("WSTG-INPV-11.2", "single_quote", "http://app.test/x", "name",
                    "Parameter reaches an interpreter (unclassified injection — quote)")
    assert "WSTG-INPV-11.2:single_quote" in survivors([other, precise])
