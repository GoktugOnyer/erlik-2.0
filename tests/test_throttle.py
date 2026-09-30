"""Per-session pacing (roadmap R1).

The one property that protects every recorded thesis arm is this: with the
knobs off (the default), the throttle must be an EXACT no-op — not a
`sleep(0)`, but no await at all. These tests assert against the real
`SessionThrottle` the agent loop constructs, and drive time by monkeypatching
`asyncio.sleep` (capturing its argument) rather than sleeping the wall clock,
so a configured delay is proven to pace without the suite paying for it.

Each guard is mutation-checked in its own docstring: break the thing, and the
named test is the one that goes red.
"""

import asyncio
import pathlib

import pytest

from orchestrator.throttle import SessionThrottle


@pytest.fixture
def captured_sleeps(monkeypatch):
    """Record every `asyncio.sleep` the code under test awaits, without waiting.

    Returns the list of durations passed to sleep. A real sleep here would make
    the pacing tests cost wall-clock time — the exact anti-pattern the task
    calls out — so we replace it with an instant coroutine.
    """
    calls: list[float] = []

    async def fake_sleep(seconds):
        calls.append(seconds)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    return calls


# --------------------------------------------------------------- off = no-op

async def test_off_by_default_never_sleeps(captured_sleeps):
    """The thesis-protecting invariant. Default construction is fully off, and
    off means NO await — mutate `before_tool`/`before_llm` to `sleep(0)` on the
    off path and this fails, which is the whole point."""
    t = SessionThrottle()
    assert t.enabled is False
    assert await t.before_tool() == 0.0
    assert await t.before_llm() == 0.0
    assert captured_sleeps == [], "off must not sleep at all, not even sleep(0)"


async def test_explicit_zeroes_are_also_off(captured_sleeps):
    """0 is a real 'off', not a knob whose label lies: passing 0/0 explicitly is
    identical to the default."""
    t = SessionThrottle(tool_delay_seconds=0, llm_rpm=0)
    assert t.enabled is False
    await t.before_tool()
    await t.before_llm()
    assert captured_sleeps == []


# ------------------------------------------------------------- tool delay

async def test_tool_delay_actually_sleeps_the_configured_amount(captured_sleeps):
    """A configured delay paces every tool call. Mutate `before_tool` to skip the
    sleep and this fails."""
    t = SessionThrottle(tool_delay_seconds=2.5)
    assert t.enabled is True
    waited = await t.before_tool()
    assert waited == 2.5
    assert captured_sleeps == [2.5]


async def test_tool_delay_paces_each_invocation(captured_sleeps):
    """It is a per-invocation pause, not a one-shot — three tool calls, three
    waits."""
    t = SessionThrottle(tool_delay_seconds=1.0)
    for _ in range(3):
        await t.before_tool()
    assert captured_sleeps == [1.0, 1.0, 1.0]


async def test_tool_delay_does_not_pace_llm_calls(captured_sleeps):
    """The tool knob is not the LLM knob: a tool delay alone leaves LLM calls
    un-spaced."""
    t = SessionThrottle(tool_delay_seconds=3.0, llm_rpm=0)
    await t.before_llm()
    assert captured_sleeps == []


# ------------------------------------------------------------- llm rpm

async def test_first_llm_call_never_waits(captured_sleeps):
    """There is nothing to space the first call against, so it must not stall the
    start of a run."""
    t = SessionThrottle(llm_rpm=60)
    clock = {"t": 1000.0}
    t._clock = lambda: clock["t"]
    assert await t.before_llm() == 0.0
    assert captured_sleeps == []


async def test_llm_rpm_spaces_the_second_call(captured_sleeps):
    """60 rpm = one call per second. A second call 0.2s later waits the remaining
    ~0.8s. Mutate the interval math and the captured wait moves off 0.8."""
    t = SessionThrottle(llm_rpm=60)  # interval 1.0s
    clock = {"t": 1000.0}
    t._clock = lambda: clock["t"]

    await t.before_llm()          # first call, no wait
    clock["t"] = 1000.2           # 0.2s later
    waited = await t.before_llm()
    assert waited == pytest.approx(0.8, abs=1e-9)
    assert captured_sleeps == [pytest.approx(0.8, abs=1e-9)]


async def test_llm_rpm_does_not_wait_when_the_slot_has_passed(captured_sleeps):
    """If a whole interval has already elapsed, the next call goes out
    immediately — pacing is a ceiling, not a fixed cadence."""
    t = SessionThrottle(llm_rpm=60)
    clock = {"t": 1000.0}
    t._clock = lambda: clock["t"]

    await t.before_llm()
    clock["t"] = 1002.0           # 2s later, well past the 1s slot
    assert await t.before_llm() == 0.0
    assert captured_sleeps == []


async def test_higher_rpm_is_a_shorter_interval(captured_sleeps):
    """120 rpm = 0.5s spacing. Guards the 60/rpm arithmetic against being
    hard-coded or inverted."""
    t = SessionThrottle(llm_rpm=120)  # interval 0.5s
    clock = {"t": 500.0}
    t._clock = lambda: clock["t"]

    await t.before_llm()
    clock["t"] = 500.1            # 0.1s later
    waited = await t.before_llm()
    assert waited == pytest.approx(0.4, abs=1e-9)


# --------------------------------------------------------- construction guards

def test_negative_values_are_floored_to_off():
    """A negative delay must not become a negative sleep; a negative rpm must not
    become a negative interval."""
    t = SessionThrottle(tool_delay_seconds=-5, llm_rpm=-10)
    assert t.tool_delay_seconds == 0.0
    assert t.llm_rpm == 0
    assert t.enabled is False


def test_none_is_treated_as_off():
    """resolve() hands 0 through, but a defensive None must not crash the ctor."""
    t = SessionThrottle(tool_delay_seconds=None, llm_rpm=None)
    assert t.tool_delay_seconds == 0.0
    assert t.llm_rpm == 0


# ---------------------------------------------------------------- wiring guard
# The tunables in this codebase have shipped un-read before; a knob nothing
# honours is its signature defect. These assert the loop actually threads the
# throttle through — the same shape as test_runconfig's provider wiring guard.

def _main_src() -> str:
    return (pathlib.Path(__file__).resolve().parents[1]
            / "orchestrator" / "main.py").read_text()


def test_agent_loop_constructs_a_throttle_from_the_run_config():
    src = _main_src()
    assert "SessionThrottle(" in src
    assert 'runcfg.get("tool_delay_seconds"' in src
    assert 'runcfg.get("llm_rpm"' in src


def test_agent_loop_paces_both_the_llm_and_the_tool_calls():
    """before_llm before the generation call, before_tool before execution —
    both must be awaited or the knob is inert."""
    src = _main_src()
    assert "await throttle.before_llm()" in src
    assert "await throttle.before_tool()" in src


def test_every_target_touching_step_is_paced():
    """The tool-delay tooltip promises to pause before EVERY target-touching
    step. Four reach the target: the agent-loop run_tool, run_case, the Nettacker
    pre-scan, and each PoC re-verification curl. Drop the pace from any one and
    this count falls — the honesty gap the review flagged (findings 1)."""
    src = _main_src()
    assert src.count("await throttle.before_tool()") >= 4, (
        "run_tool, run_case, the pre-scan and PoC re-verify must all be paced")


def test_every_session_llm_call_is_paced():
    """The llm_rpm ceiling is 'for THIS session', so it must cover every model
    call the session makes: the agent-loop generation, the AI review, and the
    report analysis pass (finding 2)."""
    src = _main_src()
    assert src.count("await throttle.before_llm()") >= 3, (
        "the generation call, the AI review and the report LLM call must "
        "all be paced")


def test_the_side_helpers_accept_and_are_handed_a_throttle():
    """A helper that reaches the target or the model but takes no throttle can
    never be paced. poc_reverify_session, run_ai_review and _generate_report all
    carry the parameter, and the loop passes it to each."""
    src = _main_src()
    for fn in ("poc_reverify_session", "run_ai_review", "_generate_report"):
        assert f"async def {fn}(" in src, fn
    assert src.count('throttle: "SessionThrottle | None" = None') >= 3, (
        "a target/model-touching helper is missing the throttle parameter")
    assert src.count("throttle=throttle") >= 3, (
        "the loop is not handing the throttle to every helper that needs it")


# ------------------------------------------------- the two limiters cannot drift
# before_llm and llm_client._pace both space calls client-side. They used to
# carry two copies of the same arithmetic; a shared helper keeps them honest.

def test_spacing_wait_is_off_when_the_interval_is_off():
    from orchestrator.throttle import spacing_wait
    assert spacing_wait(100.0, 0.0, 100.0) == 0.0
    assert spacing_wait(100.0, -1.0, 100.0) == 0.0


def test_spacing_wait_returns_zero_once_the_slot_has_elapsed():
    from orchestrator.throttle import spacing_wait
    assert spacing_wait(100.0, 1.0, 102.0) == 0.0


def test_spacing_wait_returns_the_remaining_slot():
    from orchestrator.throttle import spacing_wait
    assert spacing_wait(100.0, 1.0, 100.3) == pytest.approx(0.7, abs=1e-9)


def test_both_client_side_limiters_go_through_the_shared_helper():
    """Guards against the copies drifting back apart: both the per-session and
    the process-wide limiter must source their wait from spacing_wait."""
    import inspect
    import orchestrator.llm_client as L
    from orchestrator.throttle import SessionThrottle
    assert "spacing_wait" in inspect.getsource(L._pace)
    assert "spacing_wait" in inspect.getsource(SessionThrottle.before_llm)


# ---------------------------------------------------------- dashboard wiring
# Convention 2: a capability stays visible. A knob wired to the resolver but not
# to the panel is invisible; a knob on the panel but not in the run payload is
# inert. Both fail silently, so both are guarded — the same trap the skills
# tunables shipped with (see test_tunables).

def _index_html() -> str:
    return (pathlib.Path(__file__).resolve().parents[1]
            / "dashboard" / "templates" / "index.html").read_text()


def _js_body(name: str) -> str:
    """The body of a JS function declaration, by brace matching."""
    src = _index_html()
    i = src.index(f"function {name}(")
    start = src.index("{", i)
    depth, k = 0, start
    while True:
        depth += (src[k] == "{") - (src[k] == "}")
        if depth == 0:
            return src[start:k + 1]
        k += 1


def test_the_pacing_controls_are_on_the_panel():
    h = _index_html()
    assert 'id="rc-tool-delay"' in h
    assert 'id="rc-llm-rpm"' in h


def test_the_controls_are_labelled_with_a_tooltip():
    """Consistent with the other run-config controls, which all carry an
    explanatory tooltip rather than a bare input."""
    h = _index_html()
    td = h[h.index('id="rc-tool-delay"') - 800:h.index('id="rc-tool-delay"')]
    rpm = h[h.index('id="rc-llm-rpm"') - 800:h.index('id="rc-llm-rpm"')]
    assert "TOOL DELAY" in td and "data-tip" in td
    assert "LLM RATE" in rpm and "data-tip" in rpm


def test_the_run_payload_carries_the_pacing_knobs():
    """The failure this exists for: a control an operator sets that never
    reaches the run. buildRunConfig() is the payload that starts a session."""
    body = _js_body("buildRunConfig")
    assert "tool_delay_seconds:" in body
    assert "llm_rpm:" in body


def test_an_untouched_control_stays_off():
    """A blank input must post null, not 0-with-a-nudge — Number.isFinite guards
    the parse so an empty field cannot silently pace (or claim to pace) a run."""
    body = _js_body("buildRunConfig")
    assert "Number.isFinite(_td) ? _td : null" in body
    assert "Number.isFinite(_rpm) ? _rpm : null" in body


def test_the_served_page_actually_renders_the_controls():
    """Not just the template on disk — the page the app serves. Renders through
    FastAPI's TestClient, the same path test_tunables uses for its panel."""
    import warnings
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    from fastapi.testclient import TestClient
    import orchestrator.main as M
    html = TestClient(M.app).get("/").text
    assert 'id="rc-tool-delay"' in html
    assert 'id="rc-llm-rpm"' in html
