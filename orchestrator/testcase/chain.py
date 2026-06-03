"""Walk a chain of test cases from a single root.

Each test case can declare follow-ups via per-evaluator `chain_to` or the
top-level `chain.on_finding` / `chain.always`. The walker executes them
breadth-first with a depth cap and a visited set so cycles or runaway
chains can't blow up a run.
"""

from typing import Any
from pydantic import BaseModel, Field

from orchestrator.testcase.loader import find_by_id
from orchestrator.testcase.runner import run_test_case, RunResult


DEFAULT_MAX_DEPTH = 3
DEFAULT_MAX_RUNS = 12


class ChainRun(BaseModel):
    root_test_case_id: str
    target: dict[str, Any]
    runs: list[RunResult] = Field(default_factory=list)
    skipped: list[dict[str, Any]] = Field(default_factory=list)
    stopped_reason: str | None = None


async def run_chain(
    root_id: str,
    target: dict[str, Any],
    provider: str | None = None,
    model: str | None = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_runs: int = DEFAULT_MAX_RUNS,
) -> ChainRun:
    """Execute root_id, then recursively any test case it chains to.

    The same target dict flows into every chained test case. Test cases
    whose required fields aren't satisfied by `target` are recorded under
    `skipped` rather than crashing the chain.
    """
    out = ChainRun(root_test_case_id=root_id, target=target)
    visited: set[str] = set()

    # (test_case_id, depth)
    queue: list[tuple[str, int]] = [(root_id, 0)]

    while queue:
        if len(out.runs) >= max_runs:
            out.stopped_reason = f"hit max_runs={max_runs}"
            break

        tc_id, depth = queue.pop(0)
        if tc_id in visited:
            continue
        visited.add(tc_id)

        tc = find_by_id(tc_id)
        if tc is None:
            out.skipped.append({"id": tc_id, "reason": "not found in catalog"})
            continue

        try:
            result = await run_test_case(tc, target, provider=provider, model=model)
        except ValueError as e:
            out.skipped.append({"id": tc_id, "reason": str(e)})
            continue

        out.runs.append(result)

        if depth + 1 > max_depth:
            continue
        for nxt in result.chain_next:
            if nxt not in visited:
                queue.append((nxt, depth + 1))

    return out
