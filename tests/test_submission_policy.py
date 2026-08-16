"""The submission policy: which finding classes are informational, not submittable.

Of 216 findings in the recorded corpus, 153 (71%) sit in the four classes this
policy governs, all written at `medium` or above, so they sort over real
findings in a severity-ordered client table.

Two things every control here is built to prevent:

* A rule table that cannot fire. Fixtures are real `(tool, output, command)`
  triples pushed through `detection.auto_detect_findings()` — never
  hand-written evidence strings. A rule whose key does not match what the code
  actually emits would pass a hand-authored fixture and do nothing in
  production, which is this project's signature defect.

* Negative controls that pass vacuously. `classify()` reports WHY each rule
  declined, so a control asserts the specific `(rule_id, condition)` that
  refused it. Deleting the whole rule table would make those assertions fail,
  which is the point.
"""

import pytest
import yaml

from orchestrator.detection import auto_detect_findings
from orchestrator import submission_policy as SP


@pytest.fixture
def rules():
    SP.reset_cache()
    rs, version = SP.load_rules()
    assert version == "1", "catalogue version changed — review the rules"
    return rs


def detect(tool, output, command):
    found = auto_detect_findings(tool, output, command)
    assert found, "fixture produced no finding — the control would be vacuous"
    return found


# Every rule paired with a real detector invocation that produces it.
LIVE_FIXTURES = {
    "missing_security_headers": (
        "curl", "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n",
        "curl -s -i http://juice-shop:3000/"),
    "server_version_banner": (
        "curl", "HTTP/1.1 200 OK\r\nX-Powered-By: Express\r\n"
                "Content-Security-Policy: default-src 'self'\r\n"
                "X-Frame-Options: DENY\r\nStrict-Transport-Security: max-age=1\r\n"
                "X-Content-Type-Options: nosniff\r\n\r\n",
        "curl -s -i http://juice-shop:3000/"),
    "robots_txt_disclosure": (
        "gobuster", "/robots.txt (Status: 200) [Size: 1]\n",
        "gobuster dir -u http://juice-shop:3000 -w /w.txt"),
    "metrics_endpoint": (
        "gobuster", "/metrics (Status: 200) [Size: 1]\n",
        "gobuster dir -u http://juice-shop:3000 -w /w.txt"),
    "security_txt_disclosure": (
        "gobuster", "/security.txt (Status: 200) [Size: 1]\n",
        "gobuster dir -u http://juice-shop:3000 -w /w.txt"),
    "source_map_exposed": (
        "gobuster", "/main.js.map (Status: 200) [Size: 1]\n",
        "gobuster dir -u http://juice-shop:3000 -w /w.txt"),
}


class TestCatalogueIntegrity:
    def test_every_rule_has_a_live_fixture(self, rules):
        """Meta-test: a rule with no real detector output behind it is a rule
        nobody can prove works."""
        assert {r.id for r in rules} == set(LIVE_FIXTURES), (
            "every rule needs an entry in LIVE_FIXTURES driven by real "
            "detection output")

    @pytest.mark.parametrize("rule_id", sorted(LIVE_FIXTURES))
    def test_rule_fires_on_real_detector_output(self, rule_id, rules):
        """Positive control, one per rule."""
        tool, out, cmd = LIVE_FIXTURES[rule_id]
        matched = [SP.classify(f, rules).rule for f in detect(tool, out, cmd)]
        assert rule_id in matched, f"{rule_id} never fired on its own fixture"

    def test_all_rules_are_demote_only(self, rules):
        """Suppression was deliberately dropped: it created a contradiction
        where the thesis reported a ground-truth item found while the client
        deliverable said nothing was found."""
        assert all(r.action == SP.INFORMATIONAL for r in rules)

    def test_every_rule_keys_on_a_code_controlled_string(self, rules):
        """A rule matching on vuln_type alone would sweep up model-reported
        findings whose text erlik does not control."""
        import pathlib
        src = (pathlib.Path(__file__).resolve().parents[1]
               / "orchestrator" / "detection.py").read_text()
        for r in rules:
            keys = ([r.evidence_prefix] if r.evidence_prefix else []) + list(r.evidence_contains)
            assert keys, f"{r.id} matches on vuln_type alone"
            for k in keys:
                assert k in src, (
                    f"{r.id}: {k!r} is not a literal detection.py emits — the "
                    f"rule keys on text erlik does not control")


class TestLoaderFailsLoud:
    def test_absent_file_is_unloaded_not_empty(self, tmp_path):
        rs, version = SP.load_rules(tmp_path / "nope.yaml")
        assert rs == [] and version == "unloaded"

    def test_broken_yaml_raises(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text("rules: [\n  - id: x\n")
        with pytest.raises(SP.PolicyError):
            SP.load_rules(p)

    @pytest.mark.parametrize("body,frag", [
        ({"version": 1, "rules": [{"id": "a", "vuln_types": ["X"],
                                   "max_severity": "medium", "action": "suppress",
                                   "evidence_prefix": "p"}]}, "suppress"),
        ({"version": 1, "rules": [{"id": "a", "vuln_types": ["X"],
                                   "max_severity": "nonsense", "action": "informational",
                                   "evidence_prefix": "p"}]}, "max_severity"),
        ({"version": 1, "rules": [{"id": "a", "vuln_types": ["X"],
                                   "max_severity": "medium",
                                   "action": "informational"}]}, "code-controlled"),
        ({"version": 1, "rules": [{"id": "d", "vuln_types": ["X"], "max_severity": "low",
                                   "action": "informational", "evidence_prefix": "p"},
                                  {"id": "d", "vuln_types": ["Y"], "max_severity": "low",
                                   "action": "informational", "evidence_prefix": "q"}]},
         "duplicate"),
    ])
    def test_malformed_rule_raises(self, tmp_path, body, frag):
        p = tmp_path / "r.yaml"
        p.write_text(yaml.safe_dump(body))
        with pytest.raises(SP.PolicyError) as e:
            SP.load_rules(p)
        assert frag in str(e.value)


class TestRealFindingsAreNotTouched:
    """Negative controls. Each asserts the SPECIFIC condition that refused it,
    so an empty rule table fails them instead of passing silently."""

    @pytest.mark.parametrize("tool,out,cmd", [
        ("sqlmap", "sqlmap identified the following injection point:\n"
                   "Parameter: q (GET)\n    Type: boolean-based blind\n"
                   "back-end DBMS: SQLite\n",
         "sqlmap -u http://juice-shop:3000/rest/products/search?q=1 --batch"),
        ("dalfox", "[POC] http://juice-shop:3000/#/search?q=<script>alert(1)</script>",
         "dalfox url http://juice-shop:3000/#/search"),
    ])
    def test_real_vulnerabilities_stay_submittable(self, tool, out, cmd, rules):
        for f in detect(tool, out, cmd):
            d = SP.classify(f, rules)
            assert d.action == SP.SUBMIT
            assert d.rule is None
            assert d.effective_severity == f["severity"]

    def test_ftp_directory_is_not_demoted(self, rules):
        """/ftp is a real exposed directory and 26 rows of the corpus. It shares
        the `Content discovery: ` prefix with demoted classes, so this proves
        the rules discriminate on the note, not the prefix."""
        f = detect("gobuster", "/ftp (Status: 200) [Size: 1]\n",
                   "gobuster dir -u http://juice-shop:3000 -w /w.txt")[0]
        d = SP.classify(f, rules)
        assert d.action == SP.SUBMIT
        assert ("source_map_exposed", "evidence_contains") in d.rejected_by

    def test_enriched_banner_requalifies(self, rules):
        """`unless_field: cve_id` is evaluated at REPORT time, because the CVE
        is written by enrichment hundreds of turns after the finding."""
        base = {"vuln_type": "Information Disclosure", "severity": "medium",
                "evidence": "Server header exposes: Express 4.16.0"}
        assert SP.classify(base, rules).rule == "server_version_banner"

        enriched = dict(base, cve_id="CVE-2024-29041")
        d = SP.classify(enriched, rules)
        assert d.action == SP.SUBMIT
        assert ("server_version_banner", "unless_field") in d.rejected_by

    def test_escalation_releases_the_brake(self, rules):
        """max_severity is a brake: something escalated above the band the rule
        was written for is no longer that rule's business."""
        f = {"vuln_type": "Security Misconfiguration", "severity": "critical",
             "evidence": "Missing security headers: CSP, HSTS"}
        d = SP.classify(f, rules)
        assert d.action == SP.SUBMIT
        assert ("missing_security_headers", "max_severity") in d.rejected_by

    def test_severity_override_wins_over_stored_severity(self, rules):
        """An operator's triage decision must not be undone by the policy."""
        f = {"vuln_type": "Security Misconfiguration", "severity": "medium",
             "severity_override": "high",
             "evidence": "Missing security headers: CSP, HSTS"}
        assert SP.classify(f, rules).action == SP.SUBMIT


class TestBrakeIsLoadBearing:
    def test_overbroad_rule_still_cannot_demote_a_high_finding(self):
        """Mutation test — the only control proving max_severity does work.

        Inject a deliberately over-broad rule that matches everything of its
        type; a high-severity finding must still escape it.
        """
        evil = SP.Rule(id="overbroad", vuln_types=("CORS Misconfiguration",),
                       max_severity="medium", action=SP.INFORMATIONAL,
                       evidence_contains=("",))
        low = {"vuln_type": "CORS Misconfiguration", "severity": "low",
               "evidence": "anything"}
        high = {"vuln_type": "CORS Misconfiguration", "severity": "high",
                "evidence": "anything"}
        assert SP.classify(low, [evil]).rule == "overbroad"
        d = SP.classify(high, [evil])
        assert d.action == SP.SUBMIT
        assert ("overbroad", "max_severity") in d.rejected_by


class TestPolicyReachesTheReport:
    """Anti-inert controls: a correct classifier nobody calls is worth nothing.

    This is the failure that shipped 100 BugHunter skills which were routable,
    listed in the UI, and selected by nothing.
    """

    @pytest.fixture
    def db(self, tmp_path, monkeypatch):
        import asyncio
        import orchestrator.database as db_mod
        import orchestrator.main as M
        monkeypatch.setattr(db_mod, "DB_DIR", tmp_path)
        monkeypatch.setattr(db_mod, "DB_PATH", tmp_path / "t.db")
        asyncio.run(db_mod.init_db())

        async def seed():
            d = await db_mod.get_db()
            try:
                await d.execute("INSERT INTO sessions (id, target_url, system_prompt) "
                                "VALUES (?, ?, ?)", ("s1", "http://juice-shop:3000", "t"))
                await d.commit()
            finally:
                await d.close()
        asyncio.run(seed())
        return M

    def test_demoted_finding_is_marked_in_the_rendered_table(self, db, monkeypatch):
        import asyncio
        M = db
        for f in detect("curl", "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
                        "curl -s -i http://juice-shop:3000/"):
            asyncio.run(M._record_finding("s1", f, source="auto_detect"))
        asyncio.run(M._record_finding("s1", {
            "vuln_type": "SQL Injection", "severity": "high",
            "url": "http://juice-shop:3000/l", "parameter": "q",
            "evidence": "confirmed"}, source="llm_reported"))

        async def fake_chat(*a, **k):
            return "stub"
        monkeypatch.setattr(M.llm_client, "chat", fake_chat)
        md, _s, _ms = asyncio.run(M._generate_report(
            "s1", "m", "http://juice-shop:3000", "cold", "general",
            total_steps=1, total_findings=2, total_duration_ms=1))

        assert "informational (was medium)" in md, "policy never reached the report"
        assert "marked informational by the submission policy" in md
        # ...and the real finding is untouched
        assert "SQL Injection" in md
        assert "informational (was high)" not in md

    def test_no_marker_when_nothing_is_demoted(self, db, monkeypatch):
        """Negative control: the note must not appear on a clean report."""
        import asyncio
        M = db
        asyncio.run(M._record_finding("s1", {
            "vuln_type": "SQL Injection", "severity": "high",
            "url": "http://juice-shop:3000/l", "parameter": "q",
            "evidence": "confirmed"}, source="llm_reported"))

        async def fake_chat(*a, **k):
            return "stub"
        monkeypatch.setattr(M.llm_client, "chat", fake_chat)
        md, _s, _ms = asyncio.run(M._generate_report(
            "s1", "m", "http://juice-shop:3000", "cold", "general",
            total_steps=1, total_findings=1, total_duration_ms=1))
        assert "submission policy" not in md
        assert "informational (was" not in md


class TestMeasurementNeutrality:
    def test_classify_never_mutates_the_finding(self, rules):
        f = {"vuln_type": "Security Misconfiguration", "severity": "medium",
             "evidence": "Missing security headers: CSP, HSTS"}
        before = dict(f)
        SP.classify(f, rules)
        assert f == before, "policy must not touch the stored severity"

    def test_ground_truth_matching_is_unaffected(self, rules):
        """Demotion changes severity only. The matcher builds its haystack from
        vuln_type/url/parameter/evidence, so every recorded recall figure holds.
        """
        import orchestrator.main as M
        f = detect("gobuster", "/robots.txt (Status: 200) [Size: 1]\n",
                   "gobuster dir -u http://localhost:3000 -w /w.txt")[0]
        before = M._match_finding_to_ground_truth_scored(f, M.JUICE_SHOP_GROUND_TRUTH)
        demoted = dict(f, severity=SP.classify(f, rules).effective_severity)
        after = M._match_finding_to_ground_truth_scored(demoted, M.JUICE_SHOP_GROUND_TRUTH)
        assert before == after
        assert before is not None, "robots.txt is GT #23 — fixture must match it"
