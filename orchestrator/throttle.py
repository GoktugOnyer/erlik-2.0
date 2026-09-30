"""Per-session pacing for the agent loop (roadmap R1).

The agent loop fires tool calls and LLM calls back-to-back; the only pacing
that existed was the process-wide, OpenAI-only `_pace` in `llm_client`, which
cannot differ per session. Against a paid customer target that means hammering
the host as fast as the model emits actions.

This adds two knobs, resolved per session in `runconfig.resolve()`:

  - `tool_delay_seconds` — a fixed pause before each tool invocation
  - `llm_rpm`            — a ceiling on LLM calls per minute, spaced client-side

**Both default to 0 = OFF, and 0 is an EXACT no-op.** With both at 0 not a
single extra `await` happens on the hot path, so the recorded thesis arms run
byte-for-byte unchanged. That is the whole reason the defaults are 0 rather
than a "sensible" positive pace: an off-by-default knob cannot perturb a
measurement nobody re-ran.

The state lives on the instance, so it is *per session* by construction — each
`agent_loop` invocation owns one `SessionThrottle`. This is deliberately unlike
`llm_client._pace`, which is process-wide because concurrent sessions share one
hosted key; here the constraint being respected is the customer's target, and
that is per session.
"""

from __future__ import annotations

import asyncio
import time


def spacing_wait(last_call_at: float, interval: float, now: float) -> float:
    """Seconds to wait so consecutive calls are at least `interval` apart.

    The one piece of arithmetic shared by the two client-side limiters in this
    codebase — this per-session `SessionThrottle` and the process-wide
    `llm_client._pace` — extracted so they cannot drift. `interval <= 0` (the
    limiter is off) and a slot that has already elapsed both return 0.0.
    """
    if interval <= 0:
        return 0.0
    return max(0.0, last_call_at + interval - now)


class SessionThrottle:
    """Paces one agent session's tool and LLM calls.

    Construct it once per `agent_loop` from the resolved run-config. `enabled`
    is False when both knobs are off, which callers use to skip the observable
    log line rather than to skip the await (the await is already a no-op).
    """

    def __init__(self, tool_delay_seconds: float = 0.0, llm_rpm: int = 0):
        self.tool_delay_seconds = max(0.0, float(tool_delay_seconds or 0.0))
        self.llm_rpm = max(0, int(llm_rpm or 0))
        # Minimum spacing between LLM calls, in seconds. 0 when the knob is off.
        self._llm_interval = 60.0 / self.llm_rpm if self.llm_rpm > 0 else 0.0
        self._last_llm_at = 0.0
        # Injectable so a test can drive time deterministically instead of
        # sleeping the wall clock.
        self._clock = time.monotonic

    @property
    def enabled(self) -> bool:
        return self.tool_delay_seconds > 0 or self.llm_rpm > 0

    async def before_tool(self) -> float:
        """Pause before a tool invocation. Returns seconds actually waited.

        With the knob off this returns 0.0 WITHOUT awaiting — the exact no-op
        that protects the thesis arms. Only when a real delay is configured
        does a real `asyncio.sleep` happen.
        """
        if self.tool_delay_seconds <= 0:
            return 0.0
        await asyncio.sleep(self.tool_delay_seconds)
        return self.tool_delay_seconds

    async def before_llm(self) -> float:
        """Space LLM calls to at most `llm_rpm` per minute. Returns seconds waited.

        Client-side spacing, not a reaction to 429s: the first call of a session
        never waits (there is nothing to space it against), and each later call
        waits only for the remainder of its slot. Off (`llm_rpm <= 0`) returns
        0.0 without awaiting.
        """
        if self.llm_rpm <= 0:
            return 0.0
        wait = spacing_wait(self._last_llm_at, self._llm_interval, self._clock())
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_llm_at = self._clock()
        return wait
