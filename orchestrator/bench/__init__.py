"""LLM fatal-error classification for long-running sweeps.

`agent_errors` classifies LLM failures (rate / usage / auth) so an overnight
sweep aborts on a fatal condition instead of running N identical failures.

Until now this package also re-exported a vendored benchmark-result SDK
(`result_types.BenchmarkResult`, `results_io.save_results_json` /
`run_with_retries`). Nothing in the repository ever imported any of the three:
benchmark runs persist to the `benchmark_results` table instead. Both modules
and their re-exports were removed rather than left as an SDK with no user.
"""

from .agent_errors import (
    LLMErrorClass, classify_llm_error,
    request_abort, abort_requested, clear_abort,
)

__all__ = [
    "LLMErrorClass", "classify_llm_error",
    "request_abort", "abort_requested", "clear_abort",
]
