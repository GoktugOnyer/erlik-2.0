"""The ARSENAL attack-class index and its read API.

Two things this guards.

1. LICENCE PROVENANCE. `render_skills` stamped one blanket line above every
   selection: "Source: transilienceai/communitytools (MIT)." Since the
   BugHunter import that header sat above 100 CC BY 4.0 sheets, so the text fed
   to the model — and anything derived from it — misattributed the work and
   asserted a licence that does not apply.

2. JOIN INTEGRITY. Every edge in CLASSES is hand-declared, because auto-joining
   was measured unusable on the real catalogues: techniques-by-tag produced 30
   false edges out of 35, WSTG-by-router-regex 4 out of 5. `audit()` therefore
   fails in BOTH directions — a declared id that does not exist makes the guide
   lie, and an unclaimed catalogue entry is a capability it silently omits.
"""

import warnings

import pytest

warnings.filterwarnings("ignore", category=DeprecationWarning)

from fastapi.testclient import TestClient  # noqa: E402

import orchestrator.main as M  # noqa: E402
from orchestrator import capabilities as C  # noqa: E402
from orchestrator.skills import (SKILLS_ROOT, license_of, render_skills,  # noqa: E402
                                 UNKNOWN_LICENCE)


@pytest.fixture(scope="module")
def client():
    return TestClient(M.app)


class TestLicenceProvenance:
    def test_bughunter_is_cc_by_not_mit(self):
        lic = license_of(SKILLS_ROOT / "bughunter" / "hunt-xss.md")
        assert "CC BY 4.0" in lic
        assert "MIT" not in lic

    def test_communitytools_dirs_are_mit(self):
        assert "MIT" in license_of(SKILLS_ROOT / "injection" / "sql-injection.md")

    def test_unknown_directory_is_unknown_not_mit(self):
        """A new corpus dropped in without a licence entry must be visibly
        unattributed, never silently relabelled MIT."""
        assert license_of(SKILLS_ROOT / "experimental" / "x.md") == UNKNOWN_LICENCE
        assert license_of(SKILLS_ROOT / "data" / "skills_local" / "x.md") == UNKNOWN_LICENCE

    def test_rendered_block_no_longer_claims_mit_over_everything(self):
        out = render_skills("hunt for xss and idor")
        header = out.split("----- skill")[0]
        assert "transilienceai/communitytools (MIT)." not in header

    def test_each_sheet_carries_its_own_licence(self):
        out = render_skills("hunt for xss and idor")
        markers = [l for l in out.splitlines() if l.startswith("----- skill:")]
        assert markers, "fixture selected nothing — the control would be vacuous"
        for m in markers:
            assert "[" in m and "]" in m, m

    def test_a_cc_by_sheet_is_never_served_under_an_mit_marker(self):
        """The actual defect: CC BY 4.0 text served with an MIT claim."""
        out = render_skills("hunt for xss and idor")
        for line in out.splitlines():
            if line.startswith("----- skill:") and "bughunter /" in line:
                assert "CC BY 4.0" in line, line
                assert "transilienceai" not in line, line


class TestJoinIntegrity:
    def test_audit_is_clean_in_both_directions(self):
        a = C.audit()
        assert a == {k: [] for k in a}, a

    def test_every_declared_wstg_case_exists(self):
        declared = {w for c in C.CLASSES for w in c["wstg"]}
        assert declared <= C.wstg_ids()

    def test_every_declared_detector_exists(self):
        declared = {d for c in C.CLASSES for d in c["detectors"]}
        assert declared <= C.detector_names()

    def test_every_class_key_is_a_real_routing_class(self):
        assert {c["key"] for c in C.CLASSES} == C.routing_class_keys()

    def test_audit_would_catch_a_dangling_reference(self, monkeypatch):
        """Guard on the guard: a clean audit must not be clean vacuously."""
        monkeypatch.setattr(C, "CLASSES", C.CLASSES + [
            {"key": "sqli", "label": "x", "owasp": "x",
             "wstg": ["WSTG-DOES-NOT-EXIST"], "detectors": ["nope:_nope"]}])
        a = C.audit()
        assert a["wstg_declared_missing"] == ["WSTG-DOES-NOT-EXIST"]
        assert a["detectors_declared_missing"] == ["nope:_nope"]


class TestTwoVerdictsNeverOne:
    def test_detector_backed_class_is_confirmable(self):
        v = C.verdicts(next(c for c in C.CLASSES if c["key"] == "sqli"))
        assert v["agent_session"] == "confirmable"
        assert v["wstg_engine"] == "deterministic"

    def test_class_without_a_detector_is_model_only(self):
        """An agent run can report SSRF; nothing re-checks the claim."""
        v = C.verdicts(next(c for c in C.CLASSES if c["key"] == "ssrf"))
        assert v["agent_session"] == "model-only"

    def test_gaps_are_surfaced_not_hidden(self):
        gaps = C.overview()["model_only_classes"]
        assert "ssrf" in gaps and "xxe" in gaps
        assert "sqli" not in gaps


class TestReadApi:
    def test_overview_reports_listed_and_routable_separately(self, client):
        d = client.get("/api/library/overview").json()
        # /api/skills counts every .md and overstates by 15; showing the bigger
        # number tells an operator they have capabilities the router never picks.
        from orchestrator.skills import _catalog
        assert d["skills"]["listed"] > d["skills"]["routable"]
        assert d["skills"]["routable"] == len(_catalog())
        assert d["detectors"] == len(C.detector_names())
        assert d["wstg_cases"] == len(C.wstg_ids())

    def test_audit_route_wins_over_the_parameter_route(self, client):
        """/classes/audit must be declared before /classes/{key}."""
        r = client.get("/api/library/classes/audit")
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_unknown_class_is_404(self, client):
        assert client.get("/api/library/classes/nope").status_code == 404

    def test_detectors_report_coverage_not_just_a_count(self, client):
        d = client.get("/api/library/detectors").json()
        assert d["total"] == len(C.detector_names())
        assert any(x["exercised"] for x in d["detectors"])
        # NOT all 28 any more, and that is correct. On a CLEAN corpus a rule
        # that fires is producing a false positive, so full coverage was
        # measuring OVER-FIRING. Four rules went quiet when their false
        # positives were fixed — they only fire on a real vulnerability, which
        # a cleanroom by definition does not contain. Capability is proven by
        # positive controls in test_auto_detect.py instead.
        assert len(d["unreachable"]) <= 10, d["unreachable"]
        assert sum(1 for x in d["detectors"] if x["exercised"]) >= 16

    def test_testcases_surface_load_errors(self, client):
        d = client.get("/api/library/testcases").json()
        assert d["count"] == len(C.wstg_ids())
        assert d["load_errors"] == []

    def test_routing_explain_uses_the_real_selector(self, client):
        """The explainer must not reimplement ranking — a second implementation
        drifts, and then the UI confidently shows what runs do not do."""
        from orchestrator.skills import select_skill_files
        mission = "Assess for SQL injection and broken access control"
        d = client.post("/api/library/routing/explain",
                        json={"mission": mission}).json()
        expected = [p.stem for p in select_skill_files(mission)]
        assert [s["stem"] for s in d["selected"]] == expected
        assert d["injected_total"] == sum(s["injected_bytes"] for s in d["selected"])

    def test_routing_explain_reports_injected_not_file_size(self, client):
        """Injected bytes are capped per sheet; reporting raw file size would
        overstate what a run receives."""
        d = client.post("/api/library/routing/explain",
                        json={"mission": "sql injection"}).json()
        for s in d["selected"]:
            assert s["injected_bytes"] <= s["file_bytes"]
            if s["excerpted"]:
                assert s["injected_bytes"] < s["file_bytes"]

    def test_empty_mission_is_handled(self, client):
        d = client.post("/api/library/routing/explain", json={"mission": ""}).json()
        assert "injected_total" in d
