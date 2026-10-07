"""Structured error feedback (Reflexion-lite), the ERLIK_ERROR_FEEDBACK lever.

Two things are under test:

1. The run-config switch is a tri-state boolean like every other help lever —
   off by default, env-proof inside the measured arms so no recorded run drifts.
2. The feedback builder turns erlik's own category-prefixed refusal/failure
   strings into a short "what was wrong + minimal valid retry" correction that a
   small local model can act on, WITHOUT growing long enough to displace real
   tool output from the context window.

These assert the real functions and the real loop source — not a local
re-implementation — so the suite fails if the wiring or the shape regresses.
"""

import inspect
import pathlib

import orchestrator.main as M
import orchestrator.runconfig as rc

_SRC = (pathlib.Path(__file__).resolve().parents[1]
        / "orchestrator" / "main.py").read_text()


# ----------------------------------------------------------------------------
# The run-config lever: off by default, tri-state, env-proof in measured arms.
# ----------------------------------------------------------------------------

def test_error_feedback_defaults_off_and_is_tri_state(monkeypatch):
    assert rc.resolve({"preset": "custom"})["error_feedback"] is False   # absent: off
    r = rc.resolve({"preset": "custom", "error_feedback": True})          # explicit on
    assert r["error_feedback"] is True
    assert not any("error_feedback" in w for w in r["run_config_warnings"]), (
        "error_feedback is a recognised key and must not warn")
    monkeypatch.setenv("ERLIK_ERROR_FEEDBACK", "true")                   # env fallback
    assert rc.resolve({"preset": "custom"})["error_feedback"] is True


def test_error_feedback_is_env_proof_in_the_measured_arms(monkeypatch):
    """A help lever that rewrites the agent's error-path prompts must not flip
    on inside a measured arm from a stray env var, or two runs labelled the same
    arm would feed the model different corrections."""
    monkeypatch.setenv("ERLIK_ERROR_FEEDBACK", "true")
    for preset in ("ai_only", "guided_ai"):
        assert rc.resolve({"preset": preset})["error_feedback"] is False, preset


# ----------------------------------------------------------------------------
# The feedback builder: category-aware corrections.
# ----------------------------------------------------------------------------

def test_scope_refusal_names_the_only_allowed_host():
    fb = M._structured_error_feedback(
        "SCOPE: out-of-scope host 'evil.com' (target 'juice.local'); set "
        "ERLIK_SCOPE_EXTRA_HOSTS to allow, or ERLIK_SCOPE_ENFORCE=0 to disable",
        executed=False, target_url="http://juice.local:3000/")
    assert fb.startswith("FIX:")
    assert "scope" in fb.lower()
    assert "juice.local" in fb, "the retry must name the host that IS allowed"
    assert "evil.com" not in fb, "do not echo the out-of-scope host back"


def test_toolset_refusal_lists_enabled_tools():
    fb = M._structured_error_feedback(
        "TOOLSET: segment runs 'metasploit' which is not permitted here",
        executed=False, target_url="http://t/",
        enabled_tools=["nmap", "curl", "nuclei"])
    assert "enabled" in fb.lower()
    assert "nmap" in fb and "curl" in fb


def test_safe_mode_refusal_asks_for_a_read_only_retry():
    fb = M._structured_error_feedback(
        "SAFE_MODE: HTTP write verb (DELETE/PUT/PATCH) [http-write-verb]. Safe "
        "mode is on; this engagement has not authorised destructive testing.",
        executed=False)
    assert "read-only" in fb.lower() or "non-destructive" in fb.lower()


def test_write_confinement_points_at_tmp():
    fb = M._structured_error_feedback(
        "WRITE_CONFINEMENT: writes to /etc/passwd outside permitted roots",
        executed=False)
    assert "/tmp" in fb


def test_container_down_tells_the_model_to_wait_or_finish():
    fb = M._structured_error_feedback(
        "kali-tools container is not running. Start it with: docker compose up -d kali-tools",
        executed=False)
    assert "container" in fb.lower()
    assert "done" in fb.lower() or "reissue" in fb.lower()


def test_run_failure_fallback_says_fix_args_or_switch():
    fb = M._structured_error_feedback(
        "Exit code 1", executed=True, target_url="http://t/")
    assert fb.startswith("FIX:")
    assert "fail" in fb.lower()
    assert "RETRY:" in fb


def test_a_bare_refusal_fallback_forbids_a_retry_variant():
    fb = M._structured_error_feedback(
        "command was blocked for safety", executed=False)
    assert "different approach" in fb.lower() or "do not repeat" in fb.lower()


def test_json_retry_names_the_action_field_and_a_minimal_object():
    fb = M._structured_json_retry("http://target/")
    assert "action" in fb
    assert '{"action": "run_tool"' in fb
    assert "http://target/" in fb


# ----------------------------------------------------------------------------
# Budget discipline: the correction must not crowd out tool output. This is the
# same constraint the terse-refusal path was built for (measured r = -0.796
# between injected prompt volume and recall).
# ----------------------------------------------------------------------------

def test_every_correction_stays_short():
    samples = [
        M._structured_error_feedback("SCOPE: out-of-scope host 'x'", executed=False,
                                     target_url="http://t/"),
        M._structured_error_feedback("TOOLSET: nope", executed=False,
                                     enabled_tools=["a", "b", "c", "d", "e"]),
        M._structured_error_feedback("SAFE_MODE: x", executed=False),
        M._structured_error_feedback("Exit code 2", executed=True),
        M._structured_json_retry("http://target/"),
    ]
    for fb in samples:
        assert len(fb) < 300, f"{len(fb)}: {fb!r}"


def test_a_long_refusal_does_not_leak_into_the_correction():
    """The builder keys off the category, so a 900-char refusal body cannot
    bloat the message the way echoing the raw string would."""
    fb = M._structured_error_feedback(
        "SCOPE: out-of-scope host " + "x" * 900, executed=False,
        target_url="http://t/")
    assert len(fb) < 300
    assert "x" * 100 not in fb


def test_twenty_corrections_stay_under_half_the_prompt_budget():
    budget_chars = M.MAX_ESTIMATED_TOKENS * 4
    cost = 20 * len(M._structured_error_feedback(
        "SAFE_MODE: HTTP write verb (DELETE/PUT/PATCH) [http-write-verb]",
        executed=False))
    assert cost < budget_chars * 0.5, f"{cost} of {budget_chars}"


# ----------------------------------------------------------------------------
# Wiring guards: a run_config key that nothing reads is this codebase's
# signature defect, and an override that does not sit behind the flag would
# change the frozen arms. Both are asserted against the real loop source.
# ----------------------------------------------------------------------------

def test_the_loop_reads_the_lever_from_run_config():
    assert 'runcfg.get("error_feedback")' in _SRC


def test_the_loop_actually_calls_the_builders():
    assert "_structured_error_feedback(" in _SRC
    assert "_structured_json_retry(" in _SRC


def test_every_override_sits_behind_the_flag():
    """Each structured override must be guarded by `if error_feedback_on:`, or
    the OFF path (every recorded arm) would feed structured text instead of the
    existing refusal/failure/JSON strings it fed before."""
    # The three existing default strings must still be built unconditionally.
    assert "REFUSED (not run, no output):" in _SRC
    assert "Tool: {tool_name} | Status: FAILED | Duration:" in _SRC
    assert "Please respond with a valid JSON object. Example:" in _SRC
    # Each builder call is immediately preceded by the gate.
    for call in ("tool_feedback = _structured_error_feedback(",
                 "_json_nudge = _structured_json_retry("):
        idx = _SRC.index(call)
        preceding = _SRC[:idx]
        assert preceding.rstrip().endswith("if error_feedback_on:"), (
            f"override {call!r} is not guarded by the flag")


def test_refused_branch_still_precedes_the_failed_branch():
    """Ordering the gate must not disturb: executed=False implies success=False,
    so the refusal branch has to stay ahead of the generic-failure branch."""
    i_denied = _SRC.index('elif not result.get("executed", True):')
    i_failed = _SRC.index('f"Tool: {tool_name} | Status: FAILED | Duration:')
    assert i_denied < i_failed
