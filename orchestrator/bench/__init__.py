"""Benchmark result SDK + LLM fatal-error classification (Phase 5).

- result_types.BenchmarkResult / results_io: a stable, suite-agnostic result
  schema + JSON writer, vendored from transilienceai/communitytools (MIT).
- agent_errors: classify LLM failures (rate / usage / auth) so an overnight
  sweep aborts on a fatal condition instead of running N identical failures.
"""

from .agent_errors import (
    LLMErrorClass, classify_llm_error,
    request_abort, abort_requested, clear_abort,
)
from .result_types import BenchmarkResult
from .results_io import save_results_json, run_with_retries

__all__ = [
    "BenchmarkResult", "save_results_json", "run_with_retries",
    "LLMErrorClass", "classify_llm_error",
    "request_abort", "abort_requested", "clear_abort",
]
