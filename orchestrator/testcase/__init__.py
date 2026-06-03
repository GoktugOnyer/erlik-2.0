"""Test-case driven pentest automation.

Each test case is a YAML file under tests_catalog/ that declares a sequence
of deterministic tool invocations and evaluators (regex, status code, LLM).
This replaces the legacy freeform LLM-driven session as the default mode.
"""

from orchestrator.testcase.schema import TestCase, TestStep, Evaluator
from orchestrator.testcase.loader import load_catalog, load_test_case, find_by_id
from orchestrator.testcase.runner import run_test_case, RunResult
from orchestrator.testcase.chain import run_chain, ChainRun
from orchestrator.testcase.scope import Scope, ScopeViolation

__all__ = [
    "TestCase",
    "TestStep",
    "Evaluator",
    "load_catalog",
    "load_test_case",
    "find_by_id",
    "run_test_case",
    "RunResult",
    "run_chain",
    "ChainRun",
    "Scope",
    "ScopeViolation",
]
