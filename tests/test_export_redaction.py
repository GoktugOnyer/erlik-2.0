"""The export-boundary redaction shared by the PDF and HackerOne exports.

Default-deny, the same posture `_mask_export_rows` takes for the thesis export:
free text is masked, controlled vocabulary is left readable, and the input
object is never mutated — the five older exports still read the shared
`_build_report_json` result raw and must keep seeing it unchanged.
"""

import copy

from orchestrator.export_redaction import redact_finding, redact_report

SECRET = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjF9.deadbeefdeadbeefcafe9999"


def _report():
    return {
        "engagement": {"name": "e", "target": "http://a/x?jwt=" + SECRET, "status": "complete"},
        "statistics": {"total": 1, "critical": 1},
        "findings": [{
            "id": "F-001",
            "title": "SQL Injection",
            "severity": "CRITICAL",
            "confidence": "likely",
            "cwe": "CWE-89",
            "affected_url": "http://a/x?jwt=" + SECRET,
            "description": "Authorization: Bearer " + SECRET + "\nerror in your SQL syntax",
            "impact": "data disclosure",
            "remediation": "use parameterised queries",
            "references": ["https://ref/" + "token=" + SECRET, "https://ok/cwe-89"],
        }],
    }


class TestFreeTextIsMasked:
    def test_description_credential_is_gone_proof_remains(self):
        f = redact_finding(_report()["findings"][0])
        assert SECRET not in f["description"]
        assert "error in your SQL syntax" in f["description"]

    def test_references_are_masked(self):
        f = redact_finding(_report()["findings"][0])
        assert all(SECRET not in r for r in f["references"])


class TestControlledVocabularyIsLeftReadable:
    def test_the_structural_fields_survive(self):
        f = redact_finding(_report()["findings"][0])
        # A legitimate class name / enum / id must not be hashed into noise.
        assert f["title"] == "SQL Injection"
        assert f["severity"] == "CRITICAL"
        assert f["confidence"] == "likely"
        assert f["cwe"] == "CWE-89"


class TestTheUrlStaysParseable:
    def test_scheme_host_path_survive_and_a_secret_param_is_masked(self):
        f = redact_finding(_report()["findings"][0])
        assert f["affected_url"].startswith("http://a/x?")
        assert SECRET not in f["affected_url"]


class TestItNeverMutatesItsInput:
    def test_the_shared_report_object_is_untouched(self):
        """The five older exports read the same _build_report_json object raw;
        redacting for the new ones must not reach back and change it."""
        r = _report()
        before = copy.deepcopy(r)
        out = redact_report(r)
        assert r == before, "redact_report mutated its input"
        # and it really did redact the copy
        assert SECRET not in str(out)
        assert SECRET in str(r), "nothing was left to redact — fixture is vacuous"

    def test_engagement_target_is_masked_on_the_copy(self):
        out = redact_report(_report())
        assert SECRET not in out["engagement"]["target"]
        assert out["engagement"]["status"] == "complete"


class TestEmptyAndMissing:
    def test_a_report_with_no_findings_is_fine(self):
        out = redact_report({"engagement": {}, "statistics": {}, "findings": []})
        assert out["findings"] == []

    def test_missing_keys_do_not_crash(self):
        out = redact_report({})
        assert out["findings"] == []
        assert out["engagement"] == {}
