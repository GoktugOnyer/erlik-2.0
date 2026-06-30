"""Persist and summarize benchmark results.

Vendored from transilienceai/communitytools (MIT),
benchmarks/_shared/results_io.py. See THIRD_PARTY_LICENSES.md.

The JSON shape is intentionally stable across suites; the headline
`correct_rate` is honest (correct / total), unlike the metric-fabricating
top-level harness in the upstream repo, which is deliberately NOT vendored.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Callable, List, Optional

from .result_types import BenchmarkResult


def save_results_json(
    results: List[BenchmarkResult],
    results_dir: Path,
    *,
    suite: str,
    mode: str,
    model: Optional[str],
    filename_suffix: str = "",
    extra_top_level: Optional[dict] = None,
) -> Path:
    """Write results to a timestamped JSON file with a stable schema.

    {timestamp, suite, model, mode, max_retries, summary{...}, results[...]}
    `extra_top_level` is merged into the top-level object.
    """
    results_dir.mkdir(parents=True, exist_ok=True)

    model_suffix = f"_{model}" if model else ""
    extra_suffix = f"_{filename_suffix}" if filename_suffix else ""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = results_dir / f"{suite}_results_{mode}{model_suffix}{extra_suffix}_{timestamp}.json"

    total = len(results)
    correct = sum(1 for r in results if r.correct)

    payload = {
        "timestamp": datetime.now().isoformat(),
        "suite": suite,
        "model": model or "default",
        "mode": mode,
        "max_retries": max((r.attempts for r in results), default=1),
        "summary": {
            "total": total,
            "correct": correct,
            "correct_rate": (correct / total) if total > 0 else 0,
            "completed": sum(1 for r in results if r.status == "success"),
            "timed_out": sum(1 for r in results if r.status == "timeout"),
            "errors": sum(1 for r in results if r.status == "error"),
            "avg_duration_seconds": (
                sum(r.duration_seconds for r in results) / total if total > 0 else 0
            ),
        },
        "results": [asdict(r) for r in results],
    }
    if extra_top_level:
        payload.update(extra_top_level)

    with open(output_file, "w") as f:
        json.dump(payload, f, indent=2, default=str)

    print(f"Results saved to: {output_file}")
    return output_file


def run_with_retries(
    run_once: Callable[[], BenchmarkResult],
    max_attempts: int,
    task_id: str = "",
) -> BenchmarkResult:
    """Invoke `run_once()` up to `max_attempts` times, stopping on first correct."""
    result: Optional[BenchmarkResult] = None
    tag = f"[{task_id}] " if task_id else ""
    for attempt in range(1, max_attempts + 1):
        if attempt > 1:
            print(f"\n  {tag}RETRY {attempt}/{max_attempts}")
        result = run_once()
        result.attempts = attempt
        if result.correct:
            break
        if attempt < max_attempts:
            print(f"  {tag}Failed on attempt {attempt}/{max_attempts}, will retry...")
    assert result is not None
    return result
