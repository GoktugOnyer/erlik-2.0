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
        """A profile supplies the real endpoint and parameter.

        This test used to assert the OPPOSITE and call it correct: it checked
        that without a profile the case still produced a target, built from the
        base URL and a parameter named "q". That is the defect, not the
        contract — see test_a_guess_can_never_satisfy_a_required_field.
        """
        case = next(c for c in _cases(client) if c["id"] == "WSTG-INPV-19")
        with_p, why = S.build_target(case, BASE, S.PROFILES["juiceshop"])
        assert with_p["url"].endswith("/profile/image/url")
        assert with_p["parameter"] == "imageUrl"
        assert why == ""

        without, why = S.build_target(case, BASE, {})
        assert without is None, "ran a parameter case against an invented parameter"
        assert "parameter" in why

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



class TestAGuessIsNotKnowledge:
    """`defaults` conflated two different things, and the difference is the
    whole point of this module.

    DERIVED values are facts about the target the operator gave us — the base
    URL is the base URL. GUESSED values were inventions: a parameter named "q",
    a login form at /login. Both sat in one dict, so a guess SATISFIED a
    required field and the "no value for required field" branch never fired for
    it.

    The consequence on any target without a profile: the SSRF, XSS, SQLi and
    open-redirect cases all ran against the bare base URL with ?q= and reported
    "no finding" — 22 confident negative verdicts, most of which assessed
    nothing. sweep.py's own docstring says the module exists to prevent exactly
    that, and precision is what a client deliverable is made of.

    A guess may still FILL a field nobody named; it can never SATISFY a
    REQUIRED one. Required means "this case cannot run without knowing this",
    and inventing the answer does not make it known.
    """

    @pytest.mark.parametrize("case_id,needle", [
        ("WSTG-INPV-19", "parameter"),   # SSRF
        ("WSTG-INPV-01", "parameter"),   # reflected XSS
        ("WSTG-INPV-05", "parameter"),   # SQLi
        ("WSTG-ATHN-01", "login url"),   # the reason is prose, not the field name
    ])
    def test_a_guess_can_never_satisfy_a_required_field(self, client, case_id, needle):
        case = next(c for c in _cases(client) if c["id"] == case_id)
        tgt, why = S.build_target(case, BASE, {})
        assert tgt is None, f"{case_id} ran on an invented value"
        assert needle in why.lower(), why

    def test_the_reason_says_how_to_fix_it(self, client):
        """A skip an operator cannot act on is only marginally better than a
        wrong answer."""
        case = next(c for c in _cases(client) if c["id"] == "WSTG-INPV-19")
        _, why = S.build_target(case, BASE, {})
        assert "profile" in why or "supply" in why

    def test_a_profile_still_satisfies_it(self, client):
        case = next(c for c in _cases(client) if c["id"] == "WSTG-INPV-19")
        tgt, why = S.build_target(case, BASE, S.PROFILES["juiceshop"])
        assert tgt and tgt["parameter"] == "imageUrl" and why == ""

    def test_an_explicit_value_still_satisfies_it(self, client):
        """Discovery feeding a real parameter in is the whole point of the
        next change; it must work today."""
        case = next(c for c in _cases(client) if c["id"] == "WSTG-INPV-19")
        tgt, why = S.build_target(case, BASE, {}, extra={"parameter": "imageUrl"})
        assert tgt and tgt["parameter"] == "imageUrl" and why == ""

    def test_derived_values_still_satisfy_required_fields(self, client):
        """Guard on the guard: the fix must not make everything skip. The base
        URL is a fact, not a guess."""
        case = next(c for c in _cases(client) if c["id"] == "WSTG-INFO-02")
        tgt, why = S.build_target(case, BASE, {})
        assert tgt and tgt["url"] == BASE and why == ""

    def test_the_profile_path_is_unchanged(self, client):
        """The juiceshop profile supplies real endpoints, so every recorded
        sweep against it must plan exactly as before: 19 runnable, 3 skipped."""
        plan = S.plan_sweep(_cases(client), BASE, "juiceshop")
        assert plan["counts"] == {"runnable": 19, "skipped": 3, "total": 22}

    def test_an_unknown_target_skips_more_and_says_why(self, client):
        """The honest number for a target nobody has described."""
        plan = S.plan_sweep(_cases(client), BASE, "")
        assert plan["counts"]["runnable"] == 13
        assert plan["counts"]["skipped"] == 9
        for sk in plan["skipped"]:
            assert sk["reason"], sk
        guessed = [sk for sk in plan["skipped"]
                   if "parameter" in sk["reason"] or "login URL" in sk["reason"]]
        assert len(guessed) == 6, "the guess-driven skips are missing"

    def test_guessed_and_derived_are_separate_sets_in_the_source(self):
        """The two must not drift back into one dict — that merge IS the bug.

        Scoped to build_target's own source. A whole-file check fails on
        PROFILES, where `"parameter": "q"` is Juice Shop's REAL search
        parameter — a profile value is knowledge about a specific application,
        which is exactly what a guess is not.
        """
        import inspect
        src = inspect.getsource(S.build_target)
        assert "derived = {" in src and "guessed = {" in src
        derived_block = src.split("derived = {")[1].split("}")[0]
        for invented in ("parameter", "login_url"):
            assert invented not in derived_block, (
                f"{invented!r} is back among the derived values")
