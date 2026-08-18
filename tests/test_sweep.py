"""Sweep planning: what would run, where, and what is skipped and why.

THE DEFECT THIS GUARDS

A test case pointed at the wrong endpoint does not miss — it produces a
confident wrong answer. WSTG-INPV-19 (SSRF) was run against
`/rest/products/search`, a search-term parameter that cannot exercise SSRF at
all, and recorded "SSRF (suspected — LLM judged)" there. Nothing in the output
marked the target as implausible, and that row then reached the agent handoff as
an established fact.

Two properties follow, and both are tested here:

  * planning is PURE — no network, no database, no execution — so the operator
    can inspect targeting before anything is sent;
  * a case that cannot run is a NAMED SKIP, never a silent omission. A missing
    case reads as "the lane found nothing here", which is indistinguishable from
    a clean result.
"""

import warnings

import pytest

warnings.filterwarnings("ignore", category=DeprecationWarning)

from fastapi.testclient import TestClient  # noqa: E402

import orchestrator.main as M  # noqa: E402
from orchestrator.testcase import sweep as S  # noqa: E402


@pytest.fixture(scope="module")
def client():
    return TestClient(M.app)


BASE = "http://target.test:8080"


def _cases(client):
    return client.get("/api/v2/testcases").json()["test_cases"]


class TestSkipsAreNamedNeverSilent:
    def test_every_skip_carries_a_reason(self, client):
        plan = S.plan_sweep(_cases(client), BASE, "juiceshop")
        assert plan["skipped"], "fixture selected nothing to skip — test is vacuous"
        for s in plan["skipped"]:
            assert s["reason"], s

    def test_skipped_plus_runnable_accounts_for_every_case(self, client):
        """The arithmetic is the guard: a case may not vanish between the
        catalogue and the plan."""
        cases = _cases(client)
        plan = S.plan_sweep(cases, BASE, "juiceshop")
        assert plan["counts"]["total"] == len(cases)
        ids = {c["id"] for c in plan["runnable"]} | {c["id"] for c in plan["skipped"]}
        assert ids == {c["id"] for c in cases}

    def test_auth_dependent_cases_say_so(self, client):
        plan = S.plan_sweep(_cases(client), BASE, "juiceshop")
        by = {s["id"]: s["reason"] for s in plan["skipped"]}
        assert "WSTG-AUTHZ-04" in by
        assert "two authenticated accounts" in by["WSTG-AUTHZ-04"]

    def test_supplying_the_missing_input_makes_a_case_runnable(self, client):
        """Guard on the guard: the skip must be caused by the missing input, not
        by the case being unconditionally excluded. This is also the milestone-D
        contract — authentication turns these on."""
        cases = _cases(client)
        before = {s["id"] for s in S.plan_sweep(cases, BASE, "juiceshop")["skipped"]}
        assert "WSTG-AUTHZ-04" in before
        after = S.plan_sweep(cases, BASE, "juiceshop",
                             extra={"low_priv_token": "a", "high_priv_token": "b"})
        assert "WSTG-AUTHZ-04" not in {s["id"] for s in after["skipped"]}


class TestTargeting:
    def test_profile_endpoints_beat_the_default(self, client):
        """The actual SSRF defect: without a profile the case gets the base URL
        and a default parameter, which cannot exercise it."""
        case = next(c for c in _cases(client) if c["id"] == "WSTG-INPV-19")
        with_p, _ = S.build_target(case, BASE, S.PROFILES["juiceshop"])
        without, _ = S.build_target(case, BASE, {})
        assert with_p["url"].endswith("/profile/image/url")
        assert with_p["parameter"] == "imageUrl"
        assert without["url"] != with_p["url"]

    def test_base_is_substituted_not_hardcoded(self, client):
        case = next(c for c in _cases(client) if c["id"] == "WSTG-INPV-19")
        tgt, _ = S.build_target(case, "https://client.example", S.PROFILES["juiceshop"])
        assert tgt["url"].startswith("https://client.example")
        assert "juice-shop" not in tgt["url"]

    def test_scope_travels_with_every_target(self, client):
        """The runner enforces scope from the target. A plan that omitted it
        would hand the executor a case with no boundary."""
        plan = S.plan_sweep(_cases(client), BASE, "juiceshop")
        for r in plan["runnable"]:
            sc = r["target"].get("scope") or {}
            assert sc.get("allow_hosts") == ["target.test"], r["id"]
            assert sc.get("allow_ports") == [8080], r["id"]

    def test_https_default_port(self, client):
        case = next(c for c in _cases(client) if c["id"] == "WSTG-CLNT-09")
        tgt, _ = S.build_target(case, "https://client.example", {})
        assert tgt["scope"]["allow_ports"] == [443]

    def test_explicit_extra_overrides_the_profile(self, client):
        case = next(c for c in _cases(client) if c["id"] == "WSTG-INPV-19")
        tgt, _ = S.build_target(case, BASE, S.PROFILES["juiceshop"],
                                extra={"parameter": "avatarUrl"})
        assert tgt["parameter"] == "avatarUrl"


class TestPlanningIsPure:
    def test_planning_touches_no_network_or_db(self, client, monkeypatch):
        """If planning could execute, an operator inspecting a plan against a
        client would be attacking them."""
        import socket

        def boom(*a, **k):
            raise AssertionError("plan_sweep opened a socket")

        cases = _cases(client)          # fetch BEFORE patching — TestClient
        monkeypatch.setattr(socket, "socket", boom)   # itself opens sockets
        plan = S.plan_sweep(cases, BASE, "juiceshop")
        assert plan["counts"]["runnable"] > 0

    def test_plan_is_deterministic(self, client):
        cases = _cases(client)
        a = S.plan_sweep(cases, BASE, "juiceshop")
        b = S.plan_sweep(cases, BASE, "juiceshop")
        assert a == b


class TestApi:
    def test_plan_endpoint_matches_the_module(self, client):
        """The endpoint must not reimplement planning — a second implementation
        drifts, and then the dashboard shows what runs do not do."""
        body = {"target": BASE, "profile": "juiceshop"}
        api = client.post("/api/v2/sweep/plan", json=body).json()
        direct = S.plan_sweep(_cases(client), BASE, "juiceshop")
        assert api["counts"] == direct["counts"]
        assert [r["id"] for r in api["runnable"]] == [r["id"] for r in direct["runnable"]]

    def test_target_is_required(self, client):
        assert client.post("/api/v2/sweep/plan", json={}).status_code == 400

    def test_only_filters(self, client):
        d = client.post("/api/v2/sweep/plan",
                        json={"target": BASE, "only": ["WSTG-INPV-05"]}).json()
        assert d["counts"]["total"] == 1

    def test_profiles_endpoint_lists_reasons(self, client):
        d = client.get("/api/v2/sweep/profiles").json()
        assert "juiceshop" in d["profiles"]
        assert d["unsuppliable"], "operator cannot see why cases skip"

    def test_no_profile_still_plans(self, client):
        """A brand-new customer has no profile yet; the sweep must still run the
        cases that need only a base URL."""
        d = client.post("/api/v2/sweep/plan", json={"target": BASE}).json()
        assert d["counts"]["runnable"] > 0


class TestCliAndApiShareOneImplementation:
    def test_script_imports_rather_than_copies(self):
        import pathlib
        src = (pathlib.Path(__file__).resolve().parents[1]
               / "scripts" / "deterministic_sweep.py").read_text()
        assert "from orchestrator.testcase.sweep import" in src
        assert "PROFILES: dict" not in src, "script re-declares the endpoint map"
