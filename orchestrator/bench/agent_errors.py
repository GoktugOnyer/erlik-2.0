"""Classify LLM failures so a benchmark sweep aborts on a fatal condition.

Adapted from transilienceai/communitytools (MIT),
benchmarks/_shared/agent_errors.py. See THIRD_PARTY_LICENSES.md.

The upstream classifier reads a subprocess's stdout/stderr (the `claude`/`codex`
CLIs). erlik instead calls its LLM over httpx (orchestrator/llm_client.py), so
this version inspects the raised exception — its text and, for
httpx.HTTPStatusError, the HTTP status code — against the Ollama /
OpenAI-compatible error surface (HTTP 429 / 401 / 403, quota/usage/auth text).

A rate-limit / usage-limit / auth failure is fatal: every session in an
overnight sweep would fail the same way, so the runner should stop rather than
burn through the remaining iterations. Transient errors (timeouts, connection
blips) are NOT fatal — they stay per-session.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Optional

USAGE_LIMIT_MARKERS = (
    "usage limit", "hit your usage", "quota exceeded",
    "insufficient_quota", "insufficient quota", "credit balance", "billing",
)

RATE_LIMIT_MARKERS = (
    "rate limit", "rate_limit_exceeded", "too many requests", "429",
)

AUTH_MARKERS = (
    "invalid api key", "invalid_api_key", "unauthenticated", "not authenticated",
    "authentication failed", "authentication error", "401 unauthorized",
    "openai_api_key is not set", "403 forbidden",
)


@dataclass
class LLMErrorClass:
    kind: str       # "usage_limit" | "rate_limit" | "auth"
    message: str    # one-line summary for logs
    is_fatal: bool  # if True, the caller should abort the remaining sweep


def _status_code(exc: BaseException) -> Optional[int]:
    resp = getattr(exc, "response", None)
    return getattr(resp, "status_code", None) if resp is not None else None


def classify_llm_error(exc: BaseException) -> Optional[LLMErrorClass]:
    """Return a fatal classification for known limit/auth failures, else None."""
    text = f"{type(exc).__name__}: {exc}".lower()
    code = _status_code(exc)

    if code == 429 or any(m in text for m in RATE_LIMIT_MARKERS):
        return LLMErrorClass("rate_limit", f"rate limit (status={code or 'text'})", True)
    if any(m in text for m in USAGE_LIMIT_MARKERS):
        return LLMErrorClass("usage_limit", "usage/quota limit", True)
    if code in (401, 403) or any(m in text for m in AUTH_MARKERS):
        return LLMErrorClass("auth", f"authentication failure (status={code or 'text'})", True)
    return None


# --- process-level abort signal for sequential benchmark sweeps ------------ #
# Benchmark sessions in a sweep run sequentially in one process, so a single
# module-level flag is sufficient. The runner clears it at the start of a sweep.

_lock = threading.Lock()
_abort_reason: Optional[str] = None


def request_abort(reason: str) -> None:
    global _abort_reason
    with _lock:
        _abort_reason = reason


def abort_requested() -> Optional[str]:
    with _lock:
        return _abort_reason


def clear_abort() -> None:
    global _abort_reason
    with _lock:
        _abort_reason = None
