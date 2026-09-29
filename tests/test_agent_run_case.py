"""The agent can run a deterministic case instead of improvising one.

`orchestrator/handoff.py` already gives the agent the deterministic lane's
results at session start, so it does not rediscover ports and endpoints a scan
already found. Nothing went the other way: `run_test_case` was reachable only
from the v2 HTTP endpoints, so an agent that FOUND a parameter, a login form or
an upload field had to keep probing it with LLM turns -- when a reviewed,
mutation-tested case for exactly that already existed and costs a handful of
curl requests.

The `run_case` action closes that. The model spends a turn CHOOSING a probe
rather than improvising one, and the case runs through `run_test_case`, so it
passes the same scope guard, admission control and evaluators as the
deterministic lane. There is no second path to the network.

THE MEASUREMENT PROPERTY. A case result is NOT written to `findings`, for the
reason handoff.py already records: `findings` is what recall and precision are
computed from, so counting a deterministic result there would inflate every
agent-lane metric and make new runs incomparable with every recorded one. The
run is persisted to v2_runs exactly as the deterministic lane does, and the
agent is told the verdict. Evidence, not credit.
"""

import inspect
import re

import pytest

import orchestrator.main as M


class TestTheModelIsToldTheActionExists:
    def test_the_prompt_documents_run_case(self):
        out = M.render_system_prompt("http://127.0.0.1:9000/")
        assert '"action": "run_case"' in out

    def test_the_example_is_well_formed_json(self):
        """The model copies examples verbatim. A malformed one costs a turn."""
        import json
        out = M.render_system_prompt("http://127.0.0.1:9000/")
        line = [l for l in out.splitlines() if '"action": "run_case"' in l][0]
        parsed = json.loads(line)
        assert parsed["action"] == "run_case"
        assert parsed["case_id"]
        assert isinstance(parsed["target"], dict)

    def test_the_example_names_a_case_that_exists(self):
        """A model told about a case that does not exist wastes a turn finding
        out."""
        import json
        from orchestrator.testcase import find_by_id
        out = M.render_system_prompt("http://127.0.0.1:9000/")
        line = [l for l in out.splitlines() if '"action": "run_case"' in l][0]
        assert find_by_id(json.loads(line)["case_id"]) is not None

    def test_the_catalogue_is_generated_not_hand_listed(self):
        """A hand-written list goes stale the first time a case is added."""
        from orchestrator.testcase import load_catalog
        out = M.render_system_prompt("http://127.0.0.1:9000/")
        for tc_id in load_catalog():
            assert tc_id in out, f"{tc_id} is missing from the prompt catalogue"

    def test_each_entry_says_what_the_case_needs(self):
        """Without the required fields the model's first attempt is a guess."""
        out = M._case_catalogue_for_prompt()
        assert out.count("needs:") >= 25, out[:300]

    def test_no_placeholder_leaks_into_the_catalogue(self):
        out = M.render_system_prompt("http://acme.test:8080")
        leaked = [m for m in re.findall(r"\{[^}\n]*\}", out) if '"action"' not in m]
        assert leaked == [], leaked


class TestScopeIsNotWidened:
    def test_a_case_is_bound_to_the_session_target_host(self):
        assert M._agent_scope_hosts("http://app.example.test:8443/x") == \
            ["app.example.test"]

    def test_a_bare_host_still_resolves(self):
        assert M._agent_scope_hosts("app.example.test") == ["app.example.test"]

    def test_an_unparseable_target_yields_no_hosts(self):
        """Empty allow_hosts makes `check_url` refuse everything -- the guard
        fails closed rather than defaulting to something permissive."""
        assert M._agent_scope_hosts("") == []
        from orchestrator.testcase.scope import Scope, ScopeViolation, check_url
        with pytest.raises(ScopeViolation):
            check_url("http://anything.test/", Scope(allow_hosts=[]))

    def test_the_branch_uses_that_scope_and_not_the_agents(self):
        src = inspect.getsource(M.agent_loop)
        i = src.index('action_type == "run_case"')
        block = src[i:i + 3000]
        assert "_agent_scope_hosts(target_url)" in block, (
            "the case does not get the session's own scope"
        )


class TestTheResultIsEvidenceNotCredit:
    """The property that protects every recorded agent-lane metric."""

    def _block(self) -> str:
        src = inspect.getsource(M.agent_loop)
        i = src.index('action_type == "run_case"')
        j = src.index('action_type == "done"', i)
        return src[i:j]

    def test_it_does_not_write_to_findings(self):
        block = self._block()
        for bad in ("INSERT INTO findings", "full_findings_data.append"):
            assert bad not in block, (
                f"run_case writes {bad!r}; a deterministic result counted as an "
                "agent finding inflates recall and precision, and makes this "
                "run incomparable with every campaign already recorded"
            )

    def test_the_persisted_run_carries_the_session_owner(self):
        """Otherwise a run the agent invoked is the one row in v2_runs nobody
        can attribute to a customer or a person."""
        block = self._block()
        assert "engagement_id=session_engagement_id" in block
        assert "operator_id=session_operator_id" in block

    def test_the_model_is_told_not_to_re_report_it(self):
        assert "re-report" in self._block()

    def test_it_is_recorded_as_a_step(self):
        """A case is real work and belongs in the step record -- coverage and
        telemetry are computed from that table."""
        assert "INSERT INTO steps" in self._block()

    def test_it_does_not_double_count_the_step_counter(self):
        """`step_number` advances once per TURN at the top of the loop, for
        every action type; `run_tool` and `finding` both rely on that and do
        not touch it. An extra increment here double-counted every case --
        measured step_number=2 after a single case ran, which distorts the
        minimum-turns gate and every per-step figure derived from it."""
        assert "step_number += 1" not in self._block()

    def test_the_turn_loop_still_does_increment_it(self):
        """Guard on that guard: if the turn-level increment ever moved, the
        assertion above would be silently wrong rather than protective."""
        src = inspect.getsource(M.agent_loop)
        head = src[src.index("for turn in range(max_turns):"):]
        assert "step_number += 1" in head[:1200]


class TestAVerdictIsReportedHonestly:
    """A case that DECLINED to assess must never be rendered as clean -- the
    same rule the dashboard follows for the same canaries."""

    class _Result:
        def __init__(self, findings=(), not_assessed=(), steps=()):
            self.findings = list(findings)
            self.not_assessed = list(not_assessed)
            self.steps = list(steps)

    class _NA:
        def __init__(self, step, reason):
            self.step, self.reason = step, reason

    class _Step:
        def __init__(self, step, success, error=None):
            self.step, self.success, self.error = step, success, error

    class _F:
        def __init__(self, severity, vuln_type, parameter=None):
            self.severity, self.vuln_type, self.parameter = severity, vuln_type, parameter

    def _tc(self):
        from orchestrator.testcase import find_by_id
        return find_by_id("WSTG-CLNT-09")

    def test_a_finding_is_stated_with_its_severity(self):
        out = M._format_case_result_for_agent(
            "WSTG-INPV-05", self._tc(),
            self._Result(findings=[self._F("high", "SQL Injection", "q")]))
        assert "CONFIRMED" in out and "high" in out and "SQL Injection" in out
        assert "parameter: q" in out

    def test_a_clean_run_says_no_finding(self):
        out = M._format_case_result_for_agent("X", self._tc(), self._Result())
        assert "No finding." in out

    def test_a_declined_check_is_not_reported_as_clean(self):
        out = M._format_case_result_for_agent(
            "X", self._tc(),
            self._Result(not_assessed=[self._NA("probe", "backend unreachable")]))
        assert "NOT ASSESSED" in out
        assert "not a clean result" in out

    def test_a_refused_step_is_surfaced_too(self):
        out = M._format_case_result_for_agent(
            "X", self._tc(),
            self._Result(steps=[self._Step("probe", False, "scope violation")]))
        assert "STEP FAILED" in out
        assert "not a clean result" in out

    def test_a_clean_run_is_not_hedged(self):
        """The negative control. If every result carried the caveat, the model
        would learn to ignore it."""
        out = M._format_case_result_for_agent("X", self._tc(), self._Result())
        assert "not a clean result" not in out

    def test_the_brief_does_not_instruct(self):
        """handoff.format_for_agent is terse because a measured 12-run
        experiment found injected guidance costs recall dose-dependently. The
        same applies here: state the verdict, do not coach."""
        out = M._format_case_result_for_agent(
            "X", self._tc(), self._Result(findings=[self._F("high", "XSS")]))
        for word in ("you should", "next you", "try ", "recommend"):
            assert word not in out.lower(), out


class TestUnknownInputIsHandled:
    def _block(self):
        src = inspect.getsource(M.agent_loop)
        i = src.index('action_type == "run_case"')
        return src[i:src.index('action_type == "done"', i)]

    def test_an_unknown_case_id_lists_the_real_ones(self):
        block = self._block()
        assert "_runnable_case_ids()" in block

    def test_a_missing_required_field_tells_the_model_what_is_needed(self):
        """`run_test_case` raises ValueError for an incomplete target. Failing
        the turn with a bare error teaches the model nothing."""
        block = self._block()
        assert "except ValueError" in block
        assert "tc.target_schema.required" in block

    def test_the_catalogue_ids_are_real(self):
        from orchestrator.testcase import load_catalog
        assert set(M._runnable_case_ids()) == set(load_catalog())


class TestEndToEndThroughTheRealLoop:
    """Source greps cannot tell "calls it" from "mentions it".

    A mutation that kept the literal `save_v2_run(` in the file while never
    reaching it left the grep-based persistence test green. So this drives the
    actual agent loop with a scripted model and reads the database afterwards.
    The target port is dead on purpose: the case's steps fail to connect, which
    is irrelevant -- what is under test is that the run is recorded, attributed,
    and kept out of `findings`.
    """

    def _run(self, tmp_path, script, monkeypatch):
        import asyncio
        import json
        import sqlite3

        # Without native mode the loop finds no kali container and ends before
        # the turn loop, silently -- every assertion below then fails on an
        # empty database with nothing explaining why. The case runs `curl`
        # locally anyway, so this is also what the scenario needs.
        monkeypatch.setenv("ERLIK_NATIVE", "1")
        import orchestrator.tool_executor as TE
        monkeypatch.setattr(TE, "ERLIK_NATIVE", True)

        import orchestrator.database as db_mod
        import orchestrator.llm_client as LC

        old = db_mod.DB_DIR, db_mod.DB_PATH
        old_chat = LC.chat
        old_health = LC.health_check
        old_ok = LC.provider_is_healthy
        old_ensure = LC.ensure_model_available
        db_mod.DB_DIR, db_mod.DB_PATH = tmp_path, tmp_path / "p.db"
        calls = {"n": 0}

        async def fake_chat(messages, **kw):
            i = calls["n"]; calls["n"] += 1
            return script[i] if i < len(script) else json.dumps(
                {"action": "done", "summary": "done"})

        async def fake_health(**kw):
            return {"ok": True}

        try:
            async def fake_ensure(*a, **k):
                return True

            LC.chat = fake_chat
            LC.health_check = fake_health
            LC.provider_is_healthy = lambda h: (True, "")
            # Gates the loop BEFORE any logging: without this the whole run
            # returns silently and every assertion below fails on an empty
            # database with nothing to explain why.
            LC.ensure_model_available = fake_ensure
            target = "http://127.0.0.1:9/"          # discard port: never listening

            async def go():
                await db_mod.init_db()
                db = await db_mod.get_db()
                await db.execute(
                    "INSERT INTO sessions (id, target_url, scope_mode, system_prompt, "
                    "model, enabled_tools, operator_id) VALUES "
                    "('s1', ?, 'full', '', 'm', 'curl', 'opr_shared_token')",
                    (target,))
                await db.commit()
                await db.close()
                await M.agent_loop("s1", target, "full",
                                   M.render_system_prompt(target),
                                   ["curl"], "m", max_turns=4)

            asyncio.run(go())
            con = sqlite3.connect(tmp_path / "p.db")
            return {
                "v2_runs": con.execute(
                    "SELECT test_case_id, operator_id FROM v2_runs").fetchall(),
                "findings": con.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
                "steps": con.execute(
                    "SELECT tool_called FROM steps").fetchall(),
            }
        finally:
            db_mod.DB_DIR, db_mod.DB_PATH = old
            LC.chat, LC.health_check, LC.provider_is_healthy = \
                old_chat, old_health, old_ok
            LC.ensure_model_available = old_ensure

    @pytest.fixture
    def out(self, tmp_path, monkeypatch):
        import json
        return self._run(tmp_path, [
            json.dumps({"action": "run_case", "case_id": "WSTG-CLNT-09",
                        "target": {"url": "http://127.0.0.1:9/"},
                        "reason": "framing headers"}),
            json.dumps({"action": "done", "summary": "done"}),
        ], monkeypatch)

    def test_the_run_is_actually_persisted(self, out):
        assert out["v2_runs"], "no v2_runs row: the case ran and vanished"
        assert out["v2_runs"][0][0] == "WSTG-CLNT-09"

    def test_it_carries_the_session_operator(self, out):
        assert out["v2_runs"][0][1] == "opr_shared_token"

    def test_nothing_reached_findings(self, out):
        assert out["findings"] == 0, (
            "a deterministic result was counted as an agent finding, which "
            "inflates recall and precision for every run from here on"
        )

    def test_the_step_is_recorded_under_the_case_id(self, out):
        assert ("case:WSTG-CLNT-09",) in out["steps"], out["steps"]
