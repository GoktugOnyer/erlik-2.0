"""The two new client-facing exports: a PDF of the HTML report, and HackerOne
report-submission JSON.

Both derive from the same `_build_report_json` object the five existing exports
do, so they inherit the submission-policy gate. Unlike those five, they also
redact at the export boundary (`export_redaction.redact_report`) — a credential
that reached a finding row is masked on the way out even though report.json,
SARIF and the rest would ship it. These tests pin the output shape AND that the
boundary redaction actually fires.

The redaction fixtures seed a RAW secret into a `findings` row — the exact thing
report.json leaks today — and assert it is gone from the export. A fixture that
seeded already-scrubbed evidence would prove nothing, the mistake
test_deliverable warns about twice.
"""

import asyncio
import warnings

import pytest

import orchestrator.database as db_mod
import orchestrator.main as M


@pytest.fixture(autouse=True)
def _restore_db_globals():
    """`_client` repoints the database globals at a tmp DB; conftest fails the
    run if they are not put back. Restore them after every test."""
    before = (db_mod.DB_DIR, db_mod.DB_PATH)
    yield
    db_mod.DB_DIR, db_mod.DB_PATH = before


# A credential in the shape report.json carries verbatim: it is written into the
# `evidence` column, which becomes a finding's `description`.
LEAKED_SECRET = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjF9.deadbeefdeadbeefcafe9999"
EVIDENCE_WITH_SECRET = (
    "Authorization: Bearer " + LEAKED_SECRET + "\n"
    "You have an error in your SQL syntax")
# A legitimate proof string that is NOT a credential — it must survive redaction,
# or the export drops the evidence a client needs to act.
PROOF = "You have an error in your SQL syntax"


def _client(tmp_path, rows):
    """A TestClient over a DB seeded with `rows` of (vuln_type, severity, evidence)."""
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    from fastapi.testclient import TestClient

    db_mod.DB_DIR = tmp_path
    db_mod.DB_PATH = tmp_path / "exp.db"

    async def seed():
        await db_mod.init_db()
        db = await db_mod.get_db()
        await db.execute(
            "INSERT INTO sessions (id,target_url,scope_mode,model,enabled_tools,"
            "status) VALUES ('s1','http://a','full','m','curl','completed')")
        for vt, sev, ev in rows:
            await db.execute(
                "INSERT INTO findings (session_id,vuln_type,severity,url,evidence) "
                "VALUES ('s1',?,?,?,?)", (vt, sev, "http://a/x", ev))
        await db.commit()
        await db.close()

    asyncio.run(seed())
    return TestClient(M.app)


# A finding the submission policy demotes, and a control it does not. Same pair
# the existing export tests use, because the policy is evidence-based.
BLOCKED = ("CORS Misconfiguration", "medium", "Access-Control-Allow-Origin: *")
ALLOWED = ("SQL Injection", "critical", PROOF)


# ===================================================================== HackerOne

class TestHackerOneShape:
    def test_one_report_object_per_finding(self, tmp_path):
        j = _client(tmp_path, [BLOCKED, ALLOWED]).get(
            "/api/sessions/s1/report.hackerone.json").json()
        assert j["schema"] == "hackerone-report-submission"
        assert j["session_id"] == "s1"
        assert len(j["reports"]) == 2
        for r in j["reports"]:
            assert r["data"]["type"] == "report"
            attrs = r["data"]["attributes"]
            # The four attributes a HackerOne submission always carries.
            for k in ("title", "vulnerability_information", "impact",
                      "severity_rating"):
                assert k in attrs, k

    def test_severity_maps_to_the_hackerone_rating_enum(self, tmp_path):
        j = _client(tmp_path, [ALLOWED]).get(
            "/api/sessions/s1/report.hackerone.json").json()
        attrs = j["reports"][0]["data"]["attributes"]
        assert attrs["severity_rating"] == "critical"

    def test_informational_maps_to_none_not_an_invalid_rating(self):
        """HackerOne rejects a rating outside none|low|medium|high|critical."""
        from orchestrator.hackerone import report_to_hackerone
        j = report_to_hackerone(
            {"findings": [{"title": "t", "severity": "INFORMATIONAL"}]})
        assert j["reports"][0]["data"]["attributes"]["severity_rating"] == "none"

    def test_the_submission_policy_rides_along(self, tmp_path):
        """Annotate, never remove: a withheld finding is still emitted, flagged
        in meta and bannered in the body."""
        j = _client(tmp_path, [BLOCKED, ALLOWED]).get(
            "/api/sessions/s1/report.hackerone.json").json()
        by = {r["data"]["attributes"]["title"]: r for r in j["reports"]}
        cors = by["CORS Misconfiguration"]
        assert cors["meta"]["submittable"] is False
        assert cors["meta"]["policy_rule"]
        assert "NOT SUBMITTABLE" in cors["data"]["attributes"]["vulnerability_information"]
        assert by["SQL Injection"]["meta"]["submittable"] is True

    def test_nothing_is_removed(self, tmp_path):
        j = _client(tmp_path, [BLOCKED, ALLOWED]).get(
            "/api/sessions/s1/report.hackerone.json").json()
        assert len(j["reports"]) == 2

    def test_it_does_not_invent_a_team_handle_or_weakness_id(self, tmp_path):
        """Fields that cannot be filled honestly offline stay absent, not faked
        with a placeholder that would post to the wrong programme."""
        j = _client(tmp_path, [ALLOWED]).get(
            "/api/sessions/s1/report.hackerone.json").json()
        attrs = j["reports"][0]["data"]["attributes"]
        assert "team_handle" not in attrs
        assert "weakness_id" not in attrs
        assert "structured_scope_id" not in attrs


class TestHackerOneRedactsAtTheBoundary:
    def test_a_credential_in_a_finding_row_is_masked_in_the_export(self, tmp_path):
        """The exact leak report.json has: a raw secret in `evidence`. It reaches
        the export as a finding's description and must be masked here even though
        report.json ships it in the clear."""
        j = _client(tmp_path, [("XSS", "high", EVIDENCE_WITH_SECRET)]).get(
            "/api/sessions/s1/report.hackerone.json").json()
        blob = str(j)
        assert LEAKED_SECRET not in blob, "the credential survived the export"
        assert PROOF in blob, "redaction ate the legitimate proof"
        assert "redacted" in blob, "the secret was dropped without a placeholder"

    def test_report_json_really_does_leak_it_so_the_test_is_not_vacuous(self, tmp_path):
        """Control: the same row, read through the UNredacted report.json, DOES
        carry the secret. If this ever stops being true the boundary test above
        is proving nothing."""
        raw = _client(tmp_path, [("XSS", "high", EVIDENCE_WITH_SECRET)]).get(
            "/api/sessions/s1/report.json").json()
        assert LEAKED_SECRET in str(raw)


class TestHackerOneEvidenceCannotBreakOutOfMarkdown:
    def test_hostile_evidence_is_quoted_inert(self):
        """HackerOne renders `vulnerability_information` as markdown and the
        evidence inside it is the target's own bytes. A fence can be closed from
        inside; a four-space block cannot."""
        from orchestrator.hackerone import report_to_hackerone
        hostile = ("```\n</pre><script>alert(1)</script>\n# Injected\n```\nescaped?")
        j = report_to_hackerone({"findings": [{
            "title": "t", "severity": "high",
            "description": "summary line",
            "evidence": hostile}]})
        body = j["reports"][0]["data"]["attributes"]["vulnerability_information"]
        block = body.split("credentials redacted):", 1)[1]
        for line in block.splitlines():
            if line.strip() == "" or line.startswith("##"):
                continue
            assert line.startswith("    "), f"escaped the block: {line!r}"
        # ...and the hostile content is still readable, just inert.
        assert "<script>alert(1)</script>" in body


# =========================================================================== PDF

class TestPdfRouteDegradesGracefully:
    def test_a_missing_browser_answers_503_not_an_empty_file(self, tmp_path, monkeypatch):
        """Declared and disabled, never a silent empty PDF. The route looks the
        function up on the module at call time, so this stands in for a runtime
        with no Playwright or no browser."""
        import orchestrator.report_pdf as RP

        async def boom(_report):
            raise RP.PdfUnavailable("no browser here")
        monkeypatch.setattr(RP, "report_to_pdf", boom)

        resp = _client(tmp_path, [ALLOWED]).get("/api/sessions/s1/report.pdf")
        assert resp.status_code == 503
        assert "unavailable" in resp.json()["detail"].lower()


class TestPdfIsDrivenByTheHtmlReport:
    def test_the_pdf_renders_the_one_html_template(self):
        """One template, so the PDF and the HTML report cannot drift. If the PDF
        ever grows its own rendering this guard fails."""
        import inspect
        import orchestrator.report_pdf as RP
        src = inspect.getsource(RP)
        assert "report_to_html(report)" in src

    def test_the_route_redacts_before_rendering(self):
        """The PDF must render the redacted report, not the raw one."""
        import inspect
        src = inspect.getsource(M.get_report_pdf)
        assert "redact_report(await _build_report_json" in src
        assert "report_to_pdf(report)" in src


# The real browser render. Playwright is an OPTIONAL dependency (it lives in
# requirements-browser-login.txt, not the lean runtime), so these skip cleanly
# where it or the browser is absent — the same structural-skip posture as the
# container suites.
#
# The guard uses importlib.util.find_spec rather than a module-level
# pytest.importorskip: these tests must stay COLLECTED whether or not Playwright
# is installed, because test_release_tooling pins the README fresh-clone figure
# to the suite's collected count, and a module-level importorskip would make
# that count depend on whether this particular machine has Playwright.
def _render_available() -> bool:
    import importlib.util
    import os
    if importlib.util.find_spec("playwright") is None:
        return False
    from orchestrator.report_pdf import _CHROMIUM
    # Either the pinned container path exists, or Playwright can find its own.
    return os.path.exists(_CHROMIUM) or bool(os.environ.get("PLAYWRIGHT_BROWSERS_PATH"))


@pytest.mark.skipif(not _render_available(),
                    reason="needs Playwright + Chromium for PDF rendering")
class TestPdfRealRender:
    def test_the_route_returns_a_real_pdf(self, tmp_path):
        resp = _client(tmp_path, [BLOCKED, ALLOWED]).get("/api/sessions/s1/report.pdf")
        assert resp.status_code == 200, resp.text[:300]
        assert resp.headers["content-type"] == "application/pdf"
        assert "attachment" in resp.headers["content-disposition"]
        body = resp.content
        assert body[:5] == b"%PDF-", "not a PDF"
        assert len(body) > 1000, "implausibly small PDF"

    def test_a_report_with_no_findings_still_renders(self, tmp_path):
        resp = _client(tmp_path, []).get("/api/sessions/s1/report.pdf")
        assert resp.status_code == 200
        assert resp.content[:5] == b"%PDF-"

    def test_the_builder_returns_bytes_from_a_report_dict(self):
        from orchestrator.report_pdf import report_to_pdf
        report = {"engagement": {"name": "e", "target": "http://a"},
                  "statistics": {"total": 0},
                  "findings": [{"id": "F-001", "title": "SQLi", "severity": "HIGH",
                                "description": "proof"}]}
        pdf = asyncio.run(report_to_pdf(report))
        assert pdf[:5] == b"%PDF-"
        assert len(pdf) > 1000
