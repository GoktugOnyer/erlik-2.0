"""Cheap checks first, and don't plan a case that cannot complete.

A sweep that is interrupted, capped, or fanned out over many endpoints spent
its budget in whatever order the catalogue happened to load. Twenty-four of the
29 cases are curl-only; five pull in an external scanner (sqlmap 180s, dalfox
120s, testssl 90s, jwt_tool 60s, whatweb/wafw00f). Ordering by the ceiling a
case could consume means the cheap two-thirds all complete before the first
scanner starts -- and anything they DISCOVER is then available to what follows.

The precondition is the other half, and it came from a measurement. WSTG-CONF-07
was planned against every base including plain http, where `plan_sweep` builds a
scope of allow_ports=[80]:

    base http://app.example.test
    tls_scan     ALLOWED   -- 90s of testssl against a port not in scope
    hsts_header  REFUSED   -- port 443 not in allow_ports [80]

The expensive half ran against a service the operator never declared and the
cheap half could not run at all. A case that cannot complete belongs in
`skipped` with the reason, not in `runnable`.
"""

import pytest

from orchestrator.testcase import load_catalog
from orchestrator.testcase.sweep import (case_cost_s, plan_sweep,
                                         precondition_unmet)

CASES = [c.model_dump() for c in load_catalog().values()]


def _plan(base):
    return plan_sweep(CASES, base)


class TestCostIsDerivedFromTheRealTimeouts:
    def test_a_curl_only_case_is_the_cheap_tier(self):
        case = [c for c in CASES if c["id"] == "WSTG-CLNT-09"][0]
        assert case_cost_s(case) == 30

    def test_a_scanner_case_is_dearer(self):
        sqli = [c for c in CASES if c["id"] == "WSTG-INPV-05"][0]
        assert case_cost_s(sqli) > case_cost_s(
            [c for c in CASES if c["id"] == "WSTG-CLNT-09"][0])

    def test_it_reads_the_executors_own_timeouts(self):
        """Re-deriving the numbers here would let the two drift apart
        silently."""
        from orchestrator.tool_executor import TOOL_TIMEOUTS
        case = {"steps": [{"tool": "sqlmap"}, {"tool": "curl"}]}
        assert case_cost_s(case) == TOOL_TIMEOUTS["sqlmap"] + TOOL_TIMEOUTS["curl"]

    def test_an_unknown_tool_costs_the_default(self):
        assert case_cost_s({"steps": [{"tool": "nosuchtool"}]}) == 30

    def test_a_tool_used_twice_is_counted_once(self):
        assert case_cost_s({"steps": [{"tool": "curl"}, {"tool": "curl"}]}) == 30


class TestThePlanIsOrderedCheapFirst:
    def test_the_dearest_case_is_last(self):
        rows = _plan("https://app.example.test")["runnable"]
        assert rows[-1]["cost_s"] == max(r["cost_s"] for r in rows)

    def test_costs_are_non_decreasing(self):
        rows = _plan("https://app.example.test")["runnable"]
        costs = [r["cost_s"] for r in rows]
        assert costs == sorted(costs), costs

    def test_every_scanner_case_runs_after_every_curl_case(self):
        rows = _plan("https://app.example.test")["runnable"]
        cheap = [i for i, r in enumerate(rows) if r["cost_s"] == 30]
        dear = [i for i, r in enumerate(rows) if r["cost_s"] > 30]
        assert not dear or max(cheap) < min(dear)

    def test_the_order_is_stable_within_a_tier(self):
        """`sorted` is stable, so a plan for an all-curl target must be
        byte-identical to before this change -- otherwise every recorded sweep
        ordering moved for no reason."""
        cheap = [c for c in CASES if case_cost_s(c) == 30]
        rows = plan_sweep(cheap, "http://app.example.test")["runnable"]
        assert [r["id"] for r in rows] == [
            c["id"] for c in cheap
            if not any(s["id"] == c["id"]
                       for s in plan_sweep(cheap, "http://app.example.test")["skipped"])
        ]

    def test_the_cost_is_visible_on_every_row(self):
        """An operator seeing a rearranged plan must be able to see why."""
        for r in _plan("https://app.example.test")["runnable"]:
            assert isinstance(r["cost_s"], int)


class TestPreconditions:
    def test_a_tls_case_is_not_planned_against_http(self):
        plan = _plan("http://app.example.test")
        assert not [r for r in plan["runnable"] if r["id"] == "WSTG-CONF-07"]

    def test_it_is_skipped_with_a_reason_not_dropped(self):
        """The convention: an operator seeing one fewer row must be able to
        tell a precondition from a bug."""
        sk = [s for s in _plan("http://app.example.test")["skipped"]
              if s["id"] == "WSTG-CONF-07"]
        assert sk, "CONF-07 vanished from the plan entirely"
        assert "https" in sk[0]["reason"] and "http" in sk[0]["reason"]

    def test_the_same_case_IS_planned_against_https(self):
        """Negative control. Without this the test above passes on a case that
        simply never runs."""
        plan = _plan("https://app.example.test")
        assert [r for r in plan["runnable"] if r["id"] == "WSTG-CONF-07"]

    @pytest.mark.parametrize("base,unmet", [
        ("https://x.test", False),
        ("http://x.test", True),
        ("", False),          # unknown scheme: do not invent a refusal
    ])
    def test_the_predicate(self, base, unmet):
        case = {"preconditions": {"scheme": "https"}}
        assert bool(precondition_unmet(case, base)) is unmet

    def test_a_case_with_no_precondition_is_never_skipped_for_one(self):
        assert precondition_unmet({"preconditions": {}}, "http://x") is None
        assert precondition_unmet({}, "http://x") is None

    def test_only_conf07_declares_one(self):
        declared = {c["id"] for c in CASES if c.get("preconditions")}
        assert declared == {"WSTG-CONF-07"}, declared

    def test_an_unknown_precondition_key_is_refused_by_the_schema(self):
        """A precondition nothing evaluates would silently never hold, which
        is worse than not declaring one."""
        from pydantic import ValidationError

        from orchestrator.testcase.schema import TestCase as _Case
        with pytest.raises(ValidationError):
            _Case(id="X", name="n", category="c",
                  preconditions={"port": "443"},
                  steps=[{"name": "s", "tool": "curl", "command": "curl x"}])


class TestItIsPlanningOnlyNotAGuard:
    def test_the_scope_guard_is_untouched(self):
        """A precondition must never be mistaken for a security control: it
        decides what is worth planning, not what is allowed to run."""
        import inspect

        from orchestrator.testcase import sweep as S
        src = inspect.getsource(S.precondition_unmet)
        for word in ("check_command", "check_url", "Scope", "allow_hosts"):
            assert word not in src, (
                f"precondition_unmet references {word!r}; scope enforcement "
                "belongs in scope.py and must not be duplicated here"
            )


class TestThePlanStaysCheapToCompute:
    """`plan_sweep` is documented as pure and is called freely -- by the
    dashboard, the sweep scripts and 60-odd tests. The first version of the
    cost model called `find_by_id` per case, and `load_catalog` re-reads and
    re-parses all 29 YAML files on every call, so one plan became 29 full
    catalogue parses and the sweep tests went from seconds to timing out.

    `load_catalog` is deliberately NOT cached -- editing a case on disk and
    re-running has to take effect, which is how every guard in this repo is
    mutation-tested -- so the fix is one load per plan, not memoisation.
    """

    def test_the_catalogue_is_loaded_once_per_plan(self):
        calls = {"n": 0}
        import orchestrator.testcase.loader as L
        real = L.load_catalog

        def counting():
            calls["n"] += 1
            return real()

        L.load_catalog = counting
        try:
            plan_sweep(CASES, "https://app.example.test")
        finally:
            L.load_catalog = real
        assert calls["n"] <= 1, (
            f"the catalogue was parsed {calls['n']} times for one plan; the "
            "cost model is calling it per case"
        )

    def test_a_plan_is_still_fast(self):
        import time
        t0 = time.time()
        for _ in range(5):
            plan_sweep(CASES, "https://app.example.test")
        assert time.time() - t0 < 5.0, "planning got expensive"

    def test_the_cost_is_still_right_when_the_map_is_passed_in(self):
        """The optimisation must not change the answer."""
        from orchestrator.testcase.sweep import catalog_tools
        tools = catalog_tools()
        sqli = [c for c in CASES if c["id"] == "WSTG-INPV-05"][0]
        assert case_cost_s(sqli, tools) == case_cost_s(sqli)
