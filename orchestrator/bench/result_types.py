"""Shared benchmark-result dataclass.

Vendored from transilienceai/communitytools (MIT),
benchmarks/_shared/result_types.py. See THIRD_PARTY_LICENSES.md.

Suite-specific fields go into the `metadata` dict so the type stays stable
while each runner renders its own summary / JSON schema.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class BenchmarkResult:
    task_id: str
    name: str
    suite: str                                  # "wstg" | "juiceshop" | ...
    status: str                                 # "success" | "failed" | "timeout" | "error" | "skipped"
    correct: bool                               # did the agent produce the expected outcome?
    expected_answer: str
    found_answer: str
    duration_seconds: float
    agent_output: str                            # truncated (typically 5000 chars)
    mode: str = "default"                        # e.g. "cold" | "warm" | "skills"
    error: str = ""
    attempts: int = 1
    metadata: Dict[str, Any] = field(default_factory=dict)
