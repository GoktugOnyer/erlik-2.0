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
        "curl", "HTTP/1.1 200 OK\r\nX-Powered-By: Express 4.17.1\r\n"
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
    def test_every_detector_rule_has_a_live_fixture(self, rules):
        """Meta-test: a rule with no real detector output behind it is a rule
        nobody can prove works.

        Scoped to source == "detector". Model-authored rules have no detector
        output BY CONSTRUCTION — that is what makes them a separate class — and
        they carry their own proof-of-fire instead: TestModelReportedRules
        requires each one to match a real recorded finding. Both halves must
        stay non-empty, asserted below, so the scoping cannot quietly exempt
        the whole catalogue."""
        det = {r.id for r in rules if r.source == "detector"}
        assert det == set(LIVE_FIXTURES), (
            "every detector rule needs an entry in LIVE_FIXTURES driven by "
            "real detection output")

    def test_the_two_rule_classes_are_both_populated(self, rules):
        """Guard on the scoping: if every rule became model_reported, the
        fixture and evidence-literal tests above would pass vacuously."""
        assert [r for r in rules if r.source == "detector"]
        assert [r for r in rules if r.source == "model_reported"]

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

    def test_every_detector_rule_keys_on_a_code_controlled_string(self, rules):
        """A DETECTOR rule matching on vuln_type alone, or on text erlik does
        not control, passes a hand-authored fixture and dies in production.

        Model-authored rules are exempt because no such literal exists for
        them; their equivalent guarantee is the severity cap enforced by the
        loader plus the corpus fire-check in TestModelReportedRules."""
        import pathlib
        src = (pathlib.Path(__file__).resolve().parents[1]
               / "orchestrator" / "detection.py").read_text()
        for r in [x for x in rules if x.source == "detector"]:
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


class TestModelReportedRules:
    """Rules governing MODEL-AUTHORED findings, and the guard that replaces the
    evidence-literal check.

    Detector rules key on a string orchestrator/detection.py builds itself, and
    the loader enforces that. Model-authored findings have no such anchor: they
    carry detector = NULL and evidence written fresh each run, and the same CORS
    issue appears under SIX different vuln_type strings in the corpus. So the
    guarantee comes from two other places, both asserted here:

      * the loader caps `max_severity` at medium for these rules, so none can
        ever demote a high or critical finding; and
      * every such rule must fire on at least one REAL recorded finding — the
        corpus-backed equivalent of "this rule can actually fire".
    """

    CORPUS = (__import__("pathlib").Path(__file__).resolve().parents[1]
              / "data" / "pentest.db")

    def _corpus(self):
        import sqlite3
        if not self.CORPUS.exists():
            pytest.skip("no recorded corpus in this checkout")
        c = sqlite3.connect(f"file:{self.CORPUS}?mode=ro", uri=True)
        c.row_factory = sqlite3.Row
        try:
            rows = [dict(r) for r in c.execute(
                "SELECT vuln_type, severity, COALESCE(evidence,'') AS evidence, "
                "cve_id, detector FROM findings")]
        except sqlite3.OperationalError:
            # The file existing is not the corpus existing. Something in the
            # suite creates an EMPTY data/pentest.db, so the exists() guard
            # above passes on a fresh clone and the query then fails with
            # "no such table: findings" — a corpus-dependent test reported as a
            # product failure to anyone who has just cloned the repo.
            pytest.skip("no recorded corpus in this checkout (schema absent)")
        if not rows:
            pytest.skip("corpus present but empty")
        return rows

    def test_loader_rejects_a_model_rule_that_could_demote_high(self, tmp_path):
        """The cap IS the safeguard. Without it, a broad vuln_type would
        quietly demote real work."""
        bad = tmp_path / "p.yaml"
        bad.write_text(
            "version: 1\nrules:\n  - id: x\n    source: model_reported\n"
            "    vuln_types: ['SQL Injection']\n    max_severity: high\n"
            "    action: informational\n")
        with pytest.raises(SP.PolicyError, match="may not demote above"):
            SP.load_rules(bad)

    def test_detector_rules_still_require_an_evidence_literal(self, tmp_path):
        """The original guard must survive: relaxing it for everything is how
        a brittle rule gets in."""
        bad = tmp_path / "p.yaml"
        bad.write_text(
            "version: 1\nrules:\n  - id: x\n    vuln_types: ['Whatever']\n"
            "    max_severity: low\n    action: informational\n")
        with pytest.raises(SP.PolicyError, match="vuln_type alone"):
            SP.load_rules(bad)

    def test_every_model_rule_fires_on_a_real_finding(self, rules):
        """A rule that cannot fire is the defect this whole file guards."""
        corpus = self._corpus()
        model_rules = [r for r in rules if r.source == "model_reported"]
        assert model_rules, "no model_reported rules — test would be vacuous"
        for rule in model_rules:
            fired = [f for f in corpus
                     if SP.classify(f, [rule]).rule == rule.id]
            assert fired, f"rule {rule.id!r} matches nothing in the corpus"

    def test_no_high_or_critical_finding_is_ever_demoted(self, rules):
        corpus = self._corpus()
        for f in corpus:
            if SP._rank(SP.current_severity(f)) >= SP._rank("high"):
                d = SP.classify(f, rules)
                assert not d.is_informational, (
                    f"demoted a {f['severity']} finding: {f['vuln_type']!r} "
                    f"by rule {d.rule!r}")

    @pytest.mark.parametrize("vt", [
        "SQL Injection", "Command Injection", "XSS", "Stored XSS",
        "Reflected XSS", "Server-Side Request Forgery (SSRF)",
        "Authentication Bypass", "Arbitrary File Upload", "Broken Authentication",
        "Default Login Credentials", "Weak Credentials", "CRLF Injection",
    ])
    def test_real_vulnerability_classes_stay_submittable(self, rules, vt):
        """The list a client actually pays for. If any of these is demoted the
        policy has stopped being a noise filter and started hiding findings."""
        corpus = [f for f in self._corpus() if f["vuln_type"] == vt]
        if not corpus:
            pytest.skip(f"no {vt} in corpus")
        for f in corpus:
            assert not SP.classify(f, rules).is_informational, f

    def test_exploitable_cors_is_not_demoted(self, rules):
        """`Allow-Origin: *` cannot be read with credentials — browsers refuse
        the wildcard. The exploitable shape is a REFLECTED origin with
        Allow-Credentials: true, and it must survive the rule."""
        exploitable = {
            "vuln_type": "CORS Misconfiguration", "severity": "medium",
            "evidence": ("Access-Control-Allow-Origin: https://evil.example "
                         "reflected, Access-Control-Allow-Credentials: true"),
        }
        assert not SP.classify(exploitable, rules).is_informational

    def test_wildcard_cors_is_demoted(self, rules):
        wildcard = {
            "vuln_type": "CORS Misconfiguration", "severity": "medium",
            "evidence": "Access-Control-Allow-Origin: * — allows any domain",
        }
        d = SP.classify(wildcard, rules)
        assert d.is_informational and d.rule == "cors_wildcard_no_credentials"

    def test_measured_effect_on_the_corpus(self, rules):
        """Records what the policy actually does, so a future rule change that
        doubles the demotion rate is visible rather than silent."""
        corpus = self._corpus()
        demoted = [f for f in corpus if SP.classify(f, rules).is_informational]
        frac = len(demoted) / len(corpus)
        assert 0.10 < frac < 0.45, (
            f"policy demotes {frac:.0%} of the corpus ({len(demoted)}/{len(corpus)}) "
            f"— outside the reviewed band; re-check the rules")
