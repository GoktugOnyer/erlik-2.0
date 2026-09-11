"""`confirmed` meant DefectDojo `verified=True` on a claim nothing could corroborate.

`finding_payload` maps `confidence == "confirmed"` to `verified=True`, which tells a client
that a human need not check this finding. The function-level check's decisive input is the
operator's marker — what privileged data looks like — and that is both unverifiable from any
evidence the lane holds AND deliberately absent from the report, because the marker is not
quoted. So the one thing most needing a check was the one thing a reader could not perform.

Measured over sixteen markers on the real Juice Shop assessment: 12 of 26 findings true
(0.46); 12 of 16 over the ten realistic markers (0.75); and on the negative-control target
one plausible marker gives 0 of 1. Those two rows were also the ONLY `confirmed` findings in
that whole assessment — so the single producer of `verified=True` was the one resting on an
operator string.

THE OBJECT-LEVEL CHECK KEEPS `confirmed`. Its load-bearing value, who the application says
owns the record, comes from the TARGET — a target can cost itself a finding and cannot
manufacture one — and the own-data case is excluded in code by `derived_urls` rather than
left to a declaration.

SEVERITY IS UNCHANGED. The grade is about certainty, not impact: a customer reading the
administrator's record is high severity whether or not a human still has to confirm it.

AND A MARKER MUST BE ABLE TO IDENTIFY SOMETHING. The marker `2` validated, and the check then
reported ten high findings of which none was true, plus thirty-six operations skipped for
reflecting it. An evaluator-only declaration is judged by whether it APPEARS in a response,
so one that appears by chance is not evidence of anything.
"""
import pytest

from orchestrator.integrations.defectdojo import finding_payload, remote_mismatches
from orchestrator.integrations.inventory import authorization_findings
from orchestrator.testcase import declared
from orchestrator.testcase.declared import MIN_EVALUATOR_VALUE

TARGET = "http://app.test/"

FUNCTION = {"refused_because": [], "findings": [{
    "url": "http://app.test/api/Users", "privileged": "H", "privileged_role": "admin",
    "unprivileged": "L", "unprivileged_role": "customer", "marker_digest": "aaaaaaaaaaaa"}]}
OBJECT = {"refused_because": [], "findings": [{
    "url": "http://app.test/rest/basket/1", "caller": "L", "caller_subject_id": "2",
    "owner": "H", "asserted_owner": "1", "owner_field": "data.UserId"}]}


# ---------------------------------------------------------------------------- the grade

def test_the_function_level_check_is_not_confirmed():
    finding = authorization_findings(TARGET, "function", FUNCTION)[0]
    assert finding.confidence == "likely"
    assert finding.severity == "high", "the grade is certainty; severity is impact"
    assert finding_payload(finding.model_dump())["verified"] is False


def test_the_object_level_check_still_is():
    """Its decisive value comes from the target, which cannot manufacture a finding."""
    finding = authorization_findings(TARGET, "object", OBJECT)[0]
    assert finding.confidence == "confirmed"
    assert finding_payload(finding.model_dump())["verified"] is True


def test_a_false_positive_triage_still_clears_verified():
    """The existing rule the regrade must not disturb."""
    finding = authorization_findings(TARGET, "object", OBJECT)[0].model_dump()
    finding["triage_state"] = "false_positive"
    assert finding_payload(finding)["verified"] is False


# ------------------------------------------------------------ and the marker must identify

@pytest.mark.parametrize("marker", ["2", "1", "a", "id", '"id":2', "abc"])
def test_a_marker_too_small_to_identify_anything_is_refused(marker):
    assert len(marker) < MIN_EVALUATOR_VALUE
    assert "too short" in declared.validate("private_object_marker", marker)


@pytest.mark.parametrize("marker", ['"email":"admin@juice-sh.op"', '"role":"admin"',
                                    "4242424242424242", '"deluxeToken"'])
def test_a_marker_that_can_identify_a_datum_is_accepted(marker):
    """Including an all-digit one. "must contain a letter" was the other candidate rule and
    it would have refused a card number, which is exactly the kind of datum an operator
    should be able to name — so the rule is length, the honest proxy for "unlikely by
    chance"."""
    assert declared.validate("private_object_marker", marker) == ""


async def test_the_check_refuses_an_unidentifying_marker(tmp_path, monkeypatch):
    """End to end: the refusal reaches `refused_because`, where the plumbing already was."""
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    from orchestrator.integrations.inventory import cross_arm_privileged_function
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    await db.execute("INSERT INTO integration_assessments(session_id,target,status,config) "
                     "VALUES(?,?,?,?)", ("s", TARGET, "completed", "{}"))
    result = await cross_arm_privileged_function("s", "H", "L", "2", anonymous="anonymous")
    assert "marker_unusable" in result["refused_because"]
    assert authorization_findings(TARGET, "function", result) == []


# ------------------------------------------------- and the methodology is checkable, not sent blind

def test_the_methodology_reaches_a_field_the_read_back_compares():
    payload = finding_payload(authorization_findings(TARGET, "function",
                                                     FUNCTION)[0].model_dump())
    assert "methodology WSTG-AUTHZ-04" in payload["description"]
    assert payload["tags"] == ["WSTG-AUTHZ-04"]


@pytest.mark.parametrize("remote", [["wstg-authz-04"], [], ["WSTG-AUTHZ-04", "imported"]])
def test_a_remote_that_normalises_tags_does_not_block_the_destination(remote):
    """`tags` is exempt from the read-back the way `endpoints` is. DefectDojo stores tags
    through a tagging model that lowercases and re-orders, and a parser may drop them — and
    a mismatch writes the export row `uncertain`, which blocks EVERY later export to that
    destination for that session. A convenience label must not be able to do that, which is
    why the methodology is asserted in `description` too.
    """
    expected = finding_payload(authorization_findings(TARGET, "function",
                                                      FUNCTION)[0].model_dump())
    assert remote_mismatches({**expected, "tags": remote}, expected) == []


def test_a_real_mismatch_still_fires():
    """The negative control for the exemption: it must not have disabled the comparison."""
    expected = finding_payload(authorization_findings(TARGET, "function",
                                                      FUNCTION)[0].model_dump())
    assert remote_mismatches({**expected, "severity": "Low"}, expected)
    assert remote_mismatches({**expected, "verified": True}, expected)
