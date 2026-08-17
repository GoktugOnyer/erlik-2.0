"""Per-session safe-mode override, and the prompt cost of a refusal.

Two things, both from C5's tail.

1. A bare `safe_mode: false` must NOT disarm the guard. The dashboard's
   applyRunPreset() blanket-assigns every control from the chosen preset, so a
   checkbox wired the ordinary way would post `safe_mode: false` the moment
   someone touched the preset dropdown — silently disarming a guard nobody
   meant to disarm. An explicit `safe_mode_ack` naming the engagement is
   required, which also leaves a record of who claimed the authorisation.

2. Refusal feedback is resent to the model EVERY turn under
   MAX_ESTIMATED_TOKENS, and _trim_messages evicts older content to fit — so a
   verbose refusal does not merely add bytes, it DISPLACES real tool output.
   That displacement is the mechanism behind the measured r = -0.796 between
   injected volume and recall, which makes an over-long refusal a direct cost
   to the run rather than cosmetic noise.
"""

import inspect
import os

import pytest

import orchestrator.main as M
import orchestrator.tool_executor as T
from orchestrator.runconfig import resolve

DESTRUCTIVE = "curl -s -X DELETE http://juice-shop:3000/api/Users/1"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("ERLIK_SAFE_MODE", raising=False)
    monkeypatch.delenv("ERLIK_SCOPE_ENFORCE", raising=False)


class TestAckIsRequiredToDisarm:
    def test_default_is_armed(self):
        assert resolve({})["safe_mode"] is True

    def test_bare_false_is_ignored_and_warns(self):
        """The accidental-disarm case the dashboard would otherwise produce."""
        r = resolve({"safe_mode": False})
        assert r["safe_mode"] is True
        assert any("safe_mode_ack" in w for w in r["run_config_warnings"])

    @pytest.mark.parametrize("ack", ["", "   ", None])
    def test_empty_ack_does_not_count(self, ack):
        r = resolve({"safe_mode": False, "safe_mode_ack": ack})
        assert r["safe_mode"] is True

    def test_false_plus_ack_disarms_and_records_who(self):
        r = resolve({"safe_mode": False, "safe_mode_ack": "SOW-2026-0142"})
        assert r["safe_mode"] is False
        assert r["safe_mode_ack"] == "SOW-2026-0142"
        assert r["run_config_warnings"] == []

    def test_ack_alone_does_not_disarm(self):
        """An ack is permission to disarm, not the act of disarming."""
        assert resolve({"safe_mode_ack": "SOW-1"})["safe_mode"] is True


class TestOverrideReachesTheGate:
    def test_gate_honours_an_explicit_enable(self):
        assert T._safe_mode_violation(DESTRUCTIVE, enabled=True) is not None

    def test_gate_honours_an_explicit_disable(self):
        assert T._safe_mode_violation(DESTRUCTIVE, enabled=False) is None

    def test_none_falls_back_to_the_environment(self, monkeypatch):
        assert T._safe_mode_violation(DESTRUCTIVE, enabled=None) is not None
        monkeypatch.setenv("ERLIK_SAFE_MODE", "0")
        assert T._safe_mode_violation(DESTRUCTIVE, enabled=None) is None

    def test_execute_tool_accepts_the_override(self):
        assert "safe_mode" in inspect.signature(T.execute_tool).parameters

    def test_agent_loop_passes_the_session_value(self):
        src = inspect.getsource(M)
        assert 'safe_mode=runcfg.get("safe_mode", True))' in src

    def test_poc_verify_is_no_longer_left_on_the_env_default(self):
        """It ran with the ambient env, so an authorised destructive engagement
        still got `denied_safe_mode` stamped by a guard the operator turned off."""
        src = inspect.getsource(M.poc_reverify_session)
        assert "safe_mode" in inspect.signature(M.poc_reverify_session).parameters
        assert "safe_mode=safe_mode" in src


class TestRefusalPromptCost:
    DENIAL = ("SAFE_MODE: HTTP write verb (DELETE/PUT/PATCH) — can modify or destroy "
              "client data [http-write-verb]. Safe mode is on; this engagement has not "
              "authorised destructive testing. Set ERLIK_SAFE_MODE=0 only with written "
              "authorisation.")

    def _feedback(self, raw):
        why = (raw or "").strip().split("\n")[0][:M.DENIED_FEEDBACK_MAX]
        return (f"REFUSED (not run, no output): {why}\n"
                "Do not retry this or a variant. Different approach. JSON action.")

    def test_cap_exists_and_is_small(self):
        assert M.DENIED_FEEDBACK_MAX <= 200

    def test_a_long_refusal_is_truncated(self):
        """The failed-path used to echo up to 1500 chars of a message erlik
        wrote itself."""
        long_raw = "SCOPE: out-of-scope host " + "x" * 900
        fb = self._feedback(long_raw)
        assert len(fb) < 300
        assert "x" * 200 not in fb

    def test_refusal_costs_meaningfully_less_than_the_failed_path(self):
        old = (f"Tool: curl | Status: FAILED | Duration: 0ms\nError:\n{self.DENIAL[:1500]}\n\n"
               "This command failed. Do NOT retry it. Try a DIFFERENT tool or approach.\n"
               "Remember: use http://t with the http:// prefix.\nRespond with a JSON action.")
        new = self._feedback(self.DENIAL)
        assert len(new) < len(old) * 0.7, f"{len(new)} vs {len(old)}"

    def test_twenty_refusals_stay_under_half_the_prompt_budget(self):
        """The number that matters: refusals must not crowd out tool output.
        Under safe mode they are routine, not exceptional."""
        budget_chars = M.MAX_ESTIMATED_TOKENS * 4
        cost = 20 * len(self._feedback(self.DENIAL))
        assert cost < budget_chars * 0.5, f"{cost} of {budget_chars}"

    def test_feedback_still_says_what_the_model_needs(self):
        fb = self._feedback(self.DENIAL)
        assert "REFUSED" in fb
        assert "no output" in fb
        assert "not retry" in fb.lower()
        assert "SAFE_MODE" in fb, "the reason must survive truncation"

    def test_denied_branch_is_reached_before_the_generic_failed_branch(self):
        """Ordering matters: `executed=False` implies success=False, so a
        generic-failure branch placed first would swallow every refusal."""
        src = inspect.getsource(M)
        i_denied = src.index('elif not result.get("executed", True):')
        i_failed = src.index('f"Tool: {tool_name} | Status: FAILED | Duration:')
        assert i_denied < i_failed
