"""The stagnation guard: stop a LOOPING agent, not a working one.

Measured on 33 recorded sessions, 32 stopped before the 30-turn cap — and in
the server log 5 of 6 ended on a `run_tool` action, meaning the agent was
mid-work asking for its next command when the loop terminated it.

The cause: the counter reset only on a new FINDING. An agent doing exactly what
it should — enumerating endpoints, fingerprinting, working through a phase —
looked identical to one stuck in a loop, because neither produces findings.

Progress now means a new finding OR a tool not used before OR a newly
discovered endpoint. Repeating a command that taught you nothing is not
progress, which is the behaviour the guard exists to catch.
"""

import inspect
import re

import orchestrator.main as M

SRC = inspect.getsource(M)


class TestProgressIsMoreThanFindings:
    def test_progress_tuple_includes_tools_and_discoveries(self):
        assert "progress = (findings_count, len(tools_executed), len(sticky_discoveries))" in SRC

    def test_guard_reads_the_progress_counter_not_the_finding_counter(self):
        i = SRC.index("turns_since_progress >= stagnation_threshold")
        window = SRC[i - 400:i + 200]
        assert "turns_since_last_finding >= stagnation_threshold" not in window

    def test_finding_counter_survives_for_telemetry(self):
        """It still drives the UI line; it just no longer decides the stop."""
        assert "turns_since_last_finding += 1" in SRC


class TestThresholdsAreConfigurable:
    def test_env_overridable(self, monkeypatch):
        import importlib
        monkeypatch.setenv("ERLIK_STAGNATION_START", "0.9")
        monkeypatch.setenv("ERLIK_STAGNATION_DRY", "0.8")
        importlib.reload(M)
        assert M.STAGNATION_START_FRAC == 0.9
        assert M.STAGNATION_DRY_FRAC == 0.8
        monkeypatch.delenv("ERLIK_STAGNATION_START")
        monkeypatch.delenv("ERLIK_STAGNATION_DRY")
        importlib.reload(M)

    def test_defaults_give_more_room_than_before(self):
        """The old 0.40/0.35 fired at turn 12 of 30 after 10 dry turns, which is
        why almost no session reached its cap."""
        assert M.STAGNATION_START_FRAC > 0.40
        assert M.STAGNATION_DRY_FRAC > 0.35
        mt = 30
        assert max(5, int(mt * M.STAGNATION_START_FRAC)) > 12
        assert max(5, int(mt * M.STAGNATION_DRY_FRAC)) > 10

    def test_floor_still_applies_for_short_runs(self):
        """max(5, ...) keeps a 5-turn run from being killed on turn 1."""
        assert max(5, int(4 * M.STAGNATION_START_FRAC)) == 5


class TestGuardStillExists:
    def test_it_can_still_fire(self):
        """This is a runaway guard, not decoration — removing it entirely would
        let a looping agent burn its whole budget."""
        assert "turns_since_progress >= stagnation_threshold" in SRC
        assert "Auto-stopping" in SRC

    def test_disable_flag_is_honoured(self):
        """Benchmark runs opt out so a measured comparison is not truncated."""
        i = SRC.index("turns_since_progress >= stagnation_threshold")
        assert "if not disable_stagnation:" in SRC[i - 600:i]

    def test_stop_reason_is_printed_not_only_broadcast(self):
        """A broadcast goes to a websocket nobody is recording during a sweep;
        the reason a run ended has to be in the log too."""
        assert "STOP: stagnation at turn" in SRC


class TestSimulatedLoop:
    """The state machine, exercised directly rather than asserted about."""

    @staticmethod
    def _run(turn_events, max_turns=30):
        """turn_events: list of (findings, tools, discoveries) per turn."""
        start = max(5, int(max_turns * M.STAGNATION_START_FRAC))
        dry = max(5, int(max_turns * M.STAGNATION_DRY_FRAC))
        last, since = (0, 0, 0), 0
        for turn, ev in enumerate(turn_events):
            if turn >= start and since >= dry:
                return turn          # stopped here
            if ev != last:
                since, last = 0, ev
            else:
                since += 1
        return None                  # ran to completion

    def test_a_working_agent_is_not_stopped(self):
        """Finds nothing for 20 turns but keeps reaching new tools and
        endpoints — the recon pattern that was being killed."""
        events = [(0, i // 2 + 1, i) for i in range(30)]
        assert self._run(events) is None

    def test_a_genuinely_looping_agent_is_stopped(self):
        """Same tools, same endpoints, no findings — nothing new at all."""
        events = [(1, 3, 4)] * 30
        assert self._run(events) is not None

    def test_findings_alone_still_count_as_progress(self):
        events = [(i // 3, 3, 4) for i in range(30)]
        assert self._run(events) is None

    def test_the_old_rule_would_have_killed_the_working_agent(self):
        """Guard on the fix: under a findings-only counter the recon pattern
        above stops early, which is the regression being removed."""
        events = [(0, i // 2 + 1, i) for i in range(30)]
        start, dry = max(5, int(30 * 0.4)), max(5, int(30 * 0.35))
        since = 0
        for turn, (f, _, _) in enumerate(events):
            if turn >= start and since >= dry:
                assert turn < 30
                return
            since = 0 if f > 0 else since + 1
        raise AssertionError("old rule did not stop it — premise is wrong")
