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


class TestProducedOutputIsActuallyRead:
    """A path that emits confident output nothing consumes is this codebase's
    recurring defect. These guard the producer/consumer join at the UI edge.

    The AI REVIEW toggle spends a SECOND LLM pass per run and writes
    session_reviews. The dashboard shipped the switch that turns it on and then
    never fetched the result — five critiques accumulated unread, holding
    exactly what an operator wants next ("SQL Injection testing was omitted
    despite mission requirements").
    """

    UI = (__import__("pathlib").Path(__file__).resolve().parents[1]
          / "dashboard" / "templates" / "index.html")

    def test_the_review_endpoint_is_fetched_by_the_dashboard(self):
        src = self.UI.read_text()
        assert "/review" in src, "AI REVIEW is billable and its result is never read"
        assert "renderRunReview" in src

    def test_the_review_renderer_is_actually_called(self):
        """Defining it is not wiring it."""
        src = self.UI.read_text()
        assert "renderRunReview(sid)" in src

    def test_toggle_and_consumer_both_exist(self):
        """If the toggle is ever removed, this test should be removed with it —
        it exists to keep the pair together, not the toggle alone."""
        src = self.UI.read_text()
        assert "rc-aireview" in src and "ai_review" in src

    def test_the_deterministic_lane_is_reachable_from_the_ui(self):
        """All six /api/v2/* endpoints had zero callers: the 22 committed WSTG
        cases could not be listed, run or reviewed from the dashboard."""
        src = self.UI.read_text()
        assert "/api/v2/testcases" in src
        assert "/api/v2/sweep/plan" in src
        assert "view-testlab" in src

    def test_not_assessed_is_distinguishable_from_clean(self):
        """WSTG-CLNT-09 against a host that 302s emits
        ERLIK_FRAMING_NOT_ASSESSED_REDIRECT — it declined to assess. Rendering
        that as "clean" tells an operator there is no clickjacking issue when
        the truth is that it was never tested."""
        src = self.UI.read_text()
        assert "NOT_ASSESSED" in src
        assert "not assessed" in src
        assert "tlVerdict" in src


class TestHostedProviderRateLimit:
    """A hosted provider has a request QUOTA; local Ollama has a GPU.

    Hetzner's Inference API allows 10 requests per 60s per key, and one agent
    run makes up to 30 LLM calls. `_openai_chat` previously surfaced every 4xx
    immediately — the comment said "surface 4xx (incl. 401/429)" — so on a
    rate-limited provider a run would die partway through rather than wait out
    a window that reopens in seconds.
    """

    import inspect as _i
    import orchestrator.llm_client as _L

    def test_429_is_retried_not_surfaced(self):
        import inspect
        import orchestrator.llm_client as L
        src = inspect.getsource(L._openai_chat)
        assert "code == 429" in src, "429 is not distinguished from other 4xx"
        assert "surface 4xx (incl. 401/429) immediately" not in src

    def test_the_server_backoff_header_is_honoured(self):
        """Guessing a delay when the server told us one is how a client keeps
        spending its budget on rejected requests."""
        import inspect
        import orchestrator.llm_client as L
        assert "_retry_after" in inspect.getsource(L._openai_chat)

    def test_401_is_still_surfaced_immediately(self):
        """The retry must not swallow a bad key into a slow loop."""
        import inspect
        import orchestrator.llm_client as L
        src = inspect.getsource(L._openai_chat)
        assert "code >= 500" in src, "5xx handling was lost"

    def test_pacing_is_client_side_and_process_wide(self):
        """Reacting to 429 alone converges on spending the whole allowance on
        rejected requests, because the retry lands in the same window. And a
        per-session limiter would multiply the rate by the session count, since
        every session shares one key."""
        import orchestrator.llm_client as L
        assert hasattr(L, "_pace") and hasattr(L, "_rate_lock")
        assert isinstance(L.LLM_RPM, int)

    def test_pacing_is_off_by_default(self):
        """Local Ollama must not be throttled: its constraint is the GPU, not a
        quota. Off unless ERLIK_LLM_RPM says otherwise."""
        import importlib
        import os
        import orchestrator.llm_client as L
        old = os.environ.pop("ERLIK_LLM_RPM", None)
        try:
            importlib.reload(L)
            assert L.LLM_RPM == 0
        finally:
            if old is not None:
                os.environ["ERLIK_LLM_RPM"] = old
            importlib.reload(L)

    def test_ollama_path_is_not_paced(self):
        import inspect
        import orchestrator.llm_client as L
        assert "await _pace()" not in inspect.getsource(L._ollama_chat)

    def test_pace_actually_waits(self):
        """Behavioural, not source-inspection: two paced calls must be spaced."""
        import asyncio
        import importlib
        import os
        import time
        import orchestrator.llm_client as L
        os.environ["ERLIK_LLM_RPM"] = "60"      # 1s spacing, keeps the test quick
        try:
            importlib.reload(L)

            async def two():
                await L._pace()
                t0 = time.monotonic()
                await L._pace()
                return time.monotonic() - t0

            assert asyncio.run(two()) >= 0.9
        finally:
            os.environ.pop("ERLIK_LLM_RPM", None)
            importlib.reload(L)

    def test_env_file_is_loaded_by_the_launcher(self):
        """Credentials live in a gitignored .env. Without the launcher sourcing
        it the server starts on whatever the shell happens to hold, which
        silently runs the wrong provider."""
        import pathlib
        run = (pathlib.Path(__file__).resolve().parents[1] / "run.sh").read_text()
        assert ". ./.env" in run and "set -a" in run

    def test_env_is_gitignored(self):
        """The one thing that must never become a tracked file."""
        import pathlib
        ig = (pathlib.Path(__file__).resolve().parents[1] / ".gitignore").read_text()
        assert ".env" in ig.split()
