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


class TestControlsSurviveTheRunTheyDescribe:
    """A control rendered into a cell that a run REPLACES is a control the
    operator loses precisely when they need it.

    `tlRunOne` sets `fd.innerHTML` on the `tlfd-` cell -- on both the success
    and the error path -- so anything placed there is gone the moment the case
    is run, and gone from every row after a sweep. VIEW opens the case
    DEFINITION, which does not change when the case runs; it must therefore
    live in a cell the run does not touch.
    """

    UI = (__import__("pathlib").Path(__file__).resolve().parents[1]
          / "dashboard" / "templates" / "index.html")

    @staticmethod
    def _findings_cell(src):
        """The `tlfd-` <td> of the row template, from its opening tag to the
        matching </td>."""
        start = src.index('id="tlfd-')
        start = src.rindex("<td", 0, start)
        return src[start:src.index("</td>", start)]

    def test_the_premise_still_holds(self):
        """If tlRunOne stops overwriting the cell, this whole class is vacuous
        and should be reconsidered rather than left as a green no-op."""
        src = self.UI.read_text()
        body = src[src.index("async function tlRunOne"):]
        body = body[:body.index("async function tlSweep")]
        assert "fd.innerHTML" in body

    def test_view_is_offered_at_all(self):
        assert "data-tlview" in self.UI.read_text()

    def test_view_is_not_in_the_cell_the_run_overwrites(self):
        cell = self._findings_cell(self.UI.read_text())
        assert "data-tlrun-case" in cell, "wrong cell located -- RUN lives here"
        assert "data-tlview" not in cell, (
            "VIEW is rendered into the cell tlRunOne replaces, so it vanishes "
            "from every case that has been run"
        )


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


class TestCasesAreFiledUnderTheRightAttackClass:
    """The Arsenal was wrong in BOTH directions at once.

    Three cases were filed under the wrong class:

        WSTG-INPV-19  "Server-Side Request Forgery"  -> claimed by `ssti`
        WSTG-INPV-06  "LDAP Injection"               -> claimed by `cmdi`
        WSTG-INPV-05.6 "NoSQL Operator Injection"    -> claimed by `sqli`

    So the operator was told SSRF, LDAP and NoSQL had no deterministic
    coverage — while SSTI and command injection were credited with coverage
    that tested something else entirely. Both halves of that are worse than a
    gap: a gap is visible.

    The existing integrity audit passed the whole time, because it asked only
    whether every declared id EXISTS and whether every case is claimed by
    SOMEONE. Both were true. Correct attribution needs the case itself to say
    what it proves.
    """

    EXPECTED = {
        "WSTG-INPV-05":   "sqli",
        "WSTG-INPV-05.6": "nosql",
        "WSTG-INPV-06":   "ldap",
        "WSTG-INPV-19":   "ssrf",
        "WSTG-INPV-01":   "xss",
        "WSTG-AUTHZ-04":  "authz",
        "WSTG-SESS-10":   "jwt",
    }

    def test_the_specific_cases_that_were_wrong(self):
        from orchestrator import capabilities as C
        claimed = {w: c["key"] for c in C.CLASSES for w in (c.get("wstg") or [])}
        for case, key in self.EXPECTED.items():
            assert claimed.get(case) == key, (
                f"{case} is claimed by {claimed.get(case)!r}, expected {key!r}")

    def test_every_case_declares_the_class_it_proves(self):
        from orchestrator import capabilities as C
        declared = C.case_declared_classes()
        ids = C.wstg_ids()
        missing = sorted(ids - set(declared))
        assert not missing, f"cases with no attack_class: {missing}"

    def test_declared_classes_are_real_class_keys(self):
        from orchestrator import capabilities as C
        keys = {c["key"] for c in C.CLASSES}
        for case, key in C.case_declared_classes().items():
            assert key in keys, f"{case} declares unknown class {key!r}"

    def test_the_audit_reports_misattribution(self):
        from orchestrator import capabilities as C
        assert "wstg_misattributed" in C.audit()

    def test_the_audit_would_have_caught_the_original_bug(self):
        """The control: re-file the SSRF case under `ssti` and the audit must
        object. Without this, the check is only asserted against a corpus that
        is already correct — which is exactly how the old audit passed."""
        from orchestrator import capabilities as C
        real = C.CLASSES
        broken = []
        for c in real:
            c = dict(c)
            if c["key"] == "ssrf":
                c["wstg"] = []
            elif c["key"] == "ssti":
                # ssti KEEPS its own case and additionally takes ssrf's. A
                # mutation that dropped WSTG-INPV-18 would make it genuinely
                # unclaimed, which the OLD audit does catch — and the point
                # here is a bug the old audit cannot see.
                c["wstg"] = ["WSTG-INPV-18", "WSTG-INPV-19"]
            broken.append(c)
        C.CLASSES = broken
        try:
            a = C.audit()
            assert {"case": "WSTG-INPV-19", "case_declares": "ssrf",
                    "claimed_by": "ssti"} in a["wstg_misattributed"]
            # ...and the checks that existed before stay silent, which is the
            # whole reason the bug survived.
            assert a["wstg_declared_missing"] == []
            assert a["wstg_unclaimed"] == []
        finally:
            C.CLASSES = real

    def test_a_class_with_no_case_says_so_rather_than_borrowing_one(self):
        """`cmdi` reports no engine coverage. That is the honest answer; the
        alternative was credit for WSTG-INPV-06, which tests LDAP.

        `ssti` was in this list until WSTG-INPV-18 was written for it — the
        gap the corrected attribution made visible."""
        from orchestrator import capabilities as C
        c = next(x for x in C.CLASSES if x["key"] == "cmdi")
        assert c["wstg"] == [], f"cmdi claims {c['wstg']}"
        assert C.verdicts(c)["wstg_engine"] == "not covered"
        # ...and it is still reachable on the other lane, via commix.
        assert C.verdicts(c)["agent_session"] == "confirmable"

    def test_the_classes_that_gained_correct_coverage(self):
        from orchestrator import capabilities as C
        for key in ("ssrf", "ldap", "nosql"):
            c = next(x for x in C.CLASSES if x["key"] == key)
            assert C.verdicts(c)["wstg_engine"] == "deterministic", key


class TestTheSixNewCases:
    """Six classes had no deterministic case: SSTI, XXE, OAuth, file upload,
    insecure deserialization, and unclassified injection.

    A case that never fires and a case that always fires both report zero
    useful information, and the second is worse because it looks like work. So
    every evaluator is checked in BOTH directions.
    """

    NEW = ["WSTG-INPV-18", "WSTG-INPV-07", "WSTG-AUTHZ-05",
           "WSTG-BUSL-09", "WSTG-INPV-11", "WSTG-INPV-11.2"]

    # What a genuinely vulnerable application returns, per step.
    VULNERABLE = {
        "WSTG-INPV-18": {
            "jinja_twig_braces": "search results for 219359",
            "dollar_braces": "Hello 219359",
            "erb_aspnet": "<td>219359</td>",
            "hash_braces": "value: 219359",
            "string_repetition": "<p>7777777</p>",
            "engine_error_signature": "jinja2.exceptions.TemplateSyntaxError: x",
        },
        "WSTG-INPV-07": {
            "classic_file_read": "root:x:0:0:root:/root:/bin/bash",
            "php_wrapper_read": "PD9waHAKZWNobyAiaGkiOwo/Pg==",
            "windows_file_read": "[fonts]\n[extensions]",
            "entity_parser_signature": "Warning: failed to load external entity",
        },
        "WSTG-AUTHZ-05": {
            "redirect_uri_not_validated": "302 https://erlik-not-registered.example/cb?code=a",
            "redirect_uri_suffix_bypass": "302 https://app.acme.com.erlik-not-registered.example/cb",
            "implicit_flow_supported":
                "HTTP/1.1 302 Found\r\nLocation: https://a/cb#access_token=eyJ&x=1\r\n",
            "state_parameter_not_required": "302 https://app.acme.com/cb?code=abc123",
        },
        "WSTG-BUSL-09": {
            "double_extension_upload": '{"stored":"/uploads/erlik-upload-canary.php.jpg"}',
            "content_type_spoof_upload": '{"file":"erlik-upload-canary.php"}',
            "uploaded_file_executes": "ERLIK-UPLOAD-EXECUTED-CANARY",
            "rejection_names_the_allowlist": "Only jpg, png, gif files are permitted",
        },
        "WSTG-INPV-11": {
            "php_object_probe": "Notice: unserialize(): Error at offset 0",
            "java_stream_probe": "java.io.StreamCorruptedException: bad header",
            "python_pickle_probe": "_pickle.UnpicklingError: invalid load key",
            "dotnet_ruby_probe": "System.Runtime.Serialization.SerializationException",
            "serialized_cookie_probe": "__PHP_Incomplete_Class Object",
        },
        "WSTG-INPV-11.2": {
            "single_quote": "javax.xml.xpath.XPathExpressionException: nope",
            "expression_metachars": 'Traceback (most recent call last):\n  File "a.py"',
            "xpath_probe": "Invalid XPath expression: token",
            "crlf_header_probe": "smtplib.SMTPRecipientsRefused",
        },
    }

    # Ordinary output from an application with none of these defects. The
    # `200` entry is not hypothetical: an earlier upload evaluator matched any
    # "200"/"success" in the body and fired on Juice Shop's index page, where
    # the 200 it matched was the HTTP status line of a POST the application
    # ignored.
    BENIGN = [
        "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><body>Welcome</body></html>",
        '{"status":"ok","results":[],"count":49,"page":201}',
        "<h1>Search</h1><p>No results for your query.</p>",
        "Error: invalid request. Please try again.",
        "HTTP/1.1 404 Not Found\n\nCannot POST /upload",
        "success: true, uploaded 0 files",
        '{"allowed":true,"type":"user","format":"json"}',
    ]

    @staticmethod
    def _cat():
        from orchestrator.testcase.loader import load_catalog
        return load_catalog()

    def test_all_six_load(self):
        cat = self._cat()
        for cid in self.NEW:
            assert cid in cat, f"{cid} did not load"

    def test_each_declares_its_attack_class_and_is_claimed_by_it(self):
        from orchestrator import capabilities as C
        cat = self._cat()
        claimed = {w: c["key"] for c in C.CLASSES for w in (c.get("wstg") or [])}
        for cid in self.NEW:
            says = cat[cid].attack_class
            assert says, f"{cid} declares no attack_class"
            assert claimed.get(cid) == says, (
                f"{cid} declares {says!r} but is claimed by {claimed.get(cid)!r}")

    def test_every_evaluator_fires_on_vulnerable_output(self):
        """Otherwise the case is decoration: it would report zero findings on
        a target that IS vulnerable, and look identical to a clean result."""
        import re
        cat = self._cat()
        dead = []
        for cid in self.NEW:
            for st in cat[cid].steps:
                sample = self.VULNERABLE[cid].get(st.name)
                if sample is None:
                    continue
                rx = [e for e in st.evaluators if e.type == "regex"]
                if not any(re.search(e.pattern, sample,
                                     re.I if e.case_insensitive else 0) for e in rx):
                    dead.append(f"{cid}::{st.name}")
        assert not dead, f"evaluators that never fire: {dead}"

    def test_no_evaluator_fires_on_ordinary_output(self):
        """THE precision test. A generic detector is exactly where recall eats
        precision, and a false positive in a client deliverable costs more
        than a miss."""
        import re
        cat = self._cat()
        bad = []
        for cid in self.NEW:
            for st in cat[cid].steps:
                for e in st.evaluators:
                    if e.type != "regex":
                        continue
                    for sample in self.BENIGN:
                        if re.search(e.pattern, sample,
                                     re.I if e.case_insensitive else 0):
                            bad.append(f"{cid}::{st.name} matched {sample[:40]!r}")
        assert not bad, "false positives on ordinary output:\n  " + "\n  ".join(bad)

    def test_the_payloads_survive_template_rendering(self):
        """The SSTI payloads use {{...}}, the same syntax as the engine's own
        placeholders. If _render consumed them the case would test nothing and
        still report clean."""
        from orchestrator.testcase.runner import _render
        cat = self._cat()
        ctx = {"url": "http://t.example/s", "parameter": "q", "client_id": "cid"}
        rendered = [_render(s.command, ctx) for s in cat["WSTG-INPV-18"].steps]
        assert any("31337*7" in r for r in rendered), "the arithmetic payload was eaten"
        assert any("7*'7'" in r for r in rendered)

    def test_no_case_uses_a_tool_the_runner_will_not_allow(self):
        from orchestrator.testcase.runner import _TOOLS_ALL
        cat = self._cat()
        for cid in self.NEW:
            for st in cat[cid].steps:
                assert st.tool in _TOOLS_ALL, f"{cid}::{st.name} uses {st.tool!r}"

    def test_no_case_trips_safe_mode(self):
        """A case blocked by safe mode reports nothing and looks like a clean
        result. DELETE/PUT/PATCH are refused; POST is not."""
        from orchestrator.testcase.runner import _render
        from orchestrator.tool_executor import _safe_mode_violation
        cat = self._cat()
        ctx = {"url": "http://t.example/s", "parameter": "q", "client_id": "cid"}
        for cid in self.NEW:
            for st in cat[cid].steps:
                cmd = _render(st.command, ctx)
                why = _safe_mode_violation(cmd, enabled=True)
                assert why is None, f"{cid}::{st.name} blocked by safe mode: {why}"

    def test_the_upload_case_is_the_only_one_that_writes(self):
        """It is unavoidable there — "does this endpoint accept a file it
        should refuse" cannot be answered without sending one — and it must
        stay the only one."""
        cat = self._cat()
        writers = []
        for cid in self.NEW:
            for st in cat[cid].steps:
                if "-F " in st.command or "--form" in st.command:
                    writers.append(cid)
        assert set(writers) == {"WSTG-BUSL-09"}, writers

    def test_the_upload_payload_is_inert_and_traceable(self):
        """It proves execution and gives whoever finds the file nothing to
        use, and the canary is in the filename so cleanup is one find."""
        from pathlib import Path
        y = Path("tests_catalog/wstg/BUSL-09_file_upload.yaml").read_text()
        assert "erlik-upload-canary" in y
        assert "ERLIK-UPLOAD-EXECUTED-CANARY" in y
        for shell in ("system(", "exec(", "shell_exec", "passthru", "popen",
                      "eval(", "base64_decode"):
            assert shell not in y, f"upload payload contains {shell!r}"


class TestOneFilenamePredicate:
    """Both scope guards had their own idea of what a filename is —
    tool_executor knew eight extensions, testcase/scope.py knew two — so the
    file-upload case was refused by the runner's copy before it ever sent a
    request, while the agent lane's copy would have allowed it.
    """

    def test_filenames_are_not_treated_as_hosts(self):
        from orchestrator.tool_executor import looks_like_filename
        for name in ("erlik-upload-canary.php.jpg", "report.tar.gz",
                     "wordlist.txt", "dump.sql", "cert.pem", "app.log",
                     "/usr/share/wordlists/common.txt"):
            assert looks_like_filename(name), name

    def test_real_TLDs_are_still_treated_as_hosts(self):
        """.zip, .mov, .md, .sh, .io, .app and .dev are delegated TLDs.
        Skipping any of them as a "file extension" would let `evil.zip` past
        the guard as a filename — the whole reason the list is not simply
        "common file extensions"."""
        from orchestrator.tool_executor import looks_like_filename, extract_hosts
        for host in ("evil.zip", "payload.mov", "notes.md", "run.sh",
                     "thing.io", "site.app", "x.dev"):
            assert not looks_like_filename(host), host
            assert extract_hosts(f"nmap {host}") == [host], host

    def test_the_upload_command_resolves_to_one_host(self):
        from orchestrator.tool_executor import extract_hosts
        cmd = ('curl -s -i -F "file=@/dev/null;'
               'filename=erlik-upload-canary.php.jpg;type=image/jpeg" '
               'http://localhost:3000/')
        assert extract_hosts(cmd) == ["localhost"]

    def test_both_guards_use_the_same_predicate(self):
        import inspect
        from orchestrator.testcase import scope as S
        assert "looks_like_filename" in inspect.getsource(S.check_command), \
            "the runner's guard has its own filename list again"

    def test_the_runner_guard_allows_the_upload_command(self):
        """The behavioural check. The source assertion above passes if the
        import is present but unused."""
        from orchestrator.testcase.scope import check_command, Scope
        cmd = ('curl -s -F "file=@-;filename=erlik-upload-canary.php;'
               'type=image/png" http://localhost:3000/')
        check_command(cmd, Scope(allow_hosts=["localhost"], allow_ports=[3000]))

    def test_the_runner_guard_still_refuses_a_real_off_scope_host(self):
        import pytest
        from orchestrator.testcase.scope import check_command, Scope, ScopeViolation
        with pytest.raises(ScopeViolation):
            check_command("curl http://evil.example/x",
                          Scope(allow_hosts=["localhost"], allow_ports=[3000]))


class TestDeclaredAuthIsActuallySent:
    """14 cases declared `cookie`/`auth_header` and only 2 used them.

    The other 12 accepted a session and then sent UNAUTHENTICATED requests —
    so on any target behind a login they tested the login page and reported it
    clean. The whole credential milestone (store, verified session, handle,
    resolution) reached those cases and was dropped on the floor, and nothing
    failed: a clean result from an unauthenticated request looks exactly like a
    clean result.

    Declaring an input a case cannot apply is a promise the engine keeps on its
    behalf and the case then breaks.
    """

    AUTH_FIELDS = ("cookie", "auth_header", "jwt", "low_priv_token", "high_priv_token")

    @staticmethod
    def _cases():
        import yaml
        from pathlib import Path
        for f in sorted(Path("tests_catalog/wstg").glob("*.yaml")):
            yield f.name, yaml.safe_load(f.read_text())

    def test_every_case_that_declares_auth_uses_it(self):
        offenders = []
        for name, doc in self._cases():
            ts = doc.get("target_schema") or {}
            declared = {f for f in self.AUTH_FIELDS
                        if f in set(ts.get("optional") or []) | set(ts.get("required") or [])}
            if not declared:
                continue
            cmds = " ".join(s.get("command", "") for s in (doc.get("steps") or []))
            used = {f for f in declared if "{{" + f + "}}" in cmds}
            if not used:
                offenders.append(f"{doc['id']} declares {sorted(declared)} and uses none")
        assert not offenders, (
            "cases that accept a session and send it nowhere:\n  " + "\n  ".join(offenders))

    def test_auth_renders_away_cleanly_when_absent(self):
        """`curl -b "" -H ""` is harmless — verified against a live server —
        so the arguments can be unconditional. If they rendered to `-b` with no
        value, curl would consume the next argument as the cookie."""
        from orchestrator.testcase.loader import load_catalog
        from orchestrator.testcase.runner import _render
        cat = load_catalog()
        bare = {"url": "http://t/x", "parameter": "q", "url_template": "http://t/x",
                "host": "t", "port": 80, "client_id": "c"}
        for tc in cat.values():
            for st in tc.steps:
                cmd = _render(st.command, bare)
                assert " -b -" not in cmd and " -H -" not in cmd, f"{tc.id}::{st.name}: {cmd}"
                assert not cmd.rstrip().endswith(("-b", "-H")), f"{tc.id}::{st.name}"

    def test_auth_reaches_the_command_when_supplied(self):
        from orchestrator.testcase.loader import load_catalog
        from orchestrator.testcase.runner import _render
        cat = load_catalog()
        ctx = {"url": "http://t/x", "parameter": "q", "cookie": "SID=abc",
               "auth_header": "Authorization: Bearer XYZ"}
        cmd = _render(cat["WSTG-INPV-05"].steps[0].command, ctx)
        assert "SID=abc" in cmd and "Bearer XYZ" in cmd

    def test_a_case_that_cannot_apply_auth_does_not_declare_it(self):
        """WSTG-BUSL-04 fires the operator's own request_template verbatim, so
        a session belongs inside that template. Declaring `auth_header` there
        promised something the case has no way to apply."""
        import yaml
        from pathlib import Path
        doc = yaml.safe_load(Path("tests_catalog/wstg/BUSL-04_race_condition.yaml").read_text())
        opt = set((doc.get("target_schema") or {}).get("optional") or [])
        assert not (opt & set(self.AUTH_FIELDS)), opt
