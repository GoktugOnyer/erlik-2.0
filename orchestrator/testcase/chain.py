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

    A parent RETARGETS its children. When a case declares `produces:` and finds
    values, each child that requires one of those fields is queued once per
    produced value, so a robots.txt naming four paths schedules four runs
    instead of one. Fields the parent did not produce fall through unchanged.

    Before this, the same target dict flowed into every chained case — a parent
    physically could not tell a child where to look, which is the deterministic
    half of the "cannot reach the endpoint" bottleneck measured in the agent
    lane. Test cases whose required fields aren't satisfied are recorded under
    `skipped` rather than crashing the chain.
    """
    out = ChainRun(root_test_case_id=root_id, target=target)
    # Keyed by (case, target) rather than case alone: the SAME case against a
    # different URL is different work, and a case-only visited set would run
    # the first fanned-out child and silently drop its siblings.
    visited: set[tuple[str, str]] = set()

    def _key(cid: str, tgt: dict[str, Any]) -> tuple[str, str]:
        return (cid, str(tgt.get("url") or tgt.get("host") or ""))

    # (test_case_id, depth, target)
    queue: list[tuple[str, int, dict[str, Any]]] = [(root_id, 0, target)]

    while queue:
        if len(out.runs) >= max_runs:
            out.stopped_reason = f"hit max_runs={max_runs}"
            break

        tc_id, depth, tc_target = queue.pop(0)
        key = _key(tc_id, tc_target)
        if key in visited:
            continue
        visited.add(key)

        tc = find_by_id(tc_id)
        if tc is None:
            out.skipped.append({"id": tc_id, "reason": "not found in catalog"})
            continue

        try:
            result = await run_test_case(tc, tc_target, provider=provider, model=model)
        except ValueError as e:
            out.skipped.append({"id": tc_id, "reason": str(e),
                                "target": tc_target.get("url")})
            continue

        out.runs.append(result)

        if depth + 1 > max_depth:
            continue
        for nxt in result.chain_next:
            child = find_by_id(nxt)
            if child is None:
                out.skipped.append({"id": nxt, "reason": "not found in catalog"})
                continue
            for child_target in _retarget(child, tc_target, result.produced, max_runs):
                if _key(nxt, child_target) not in visited:
                    queue.append((nxt, depth + 1, child_target))

    return out


def _retarget(child, parent_target: dict[str, Any],
              produced: dict[str, list[str]], cap: int) -> list[dict[str, Any]]:
    """One target per produced value the child actually consumes.

    Only fields the child DECLARES (required or optional) are fanned over —
    producing a field nobody consumes must not multiply the work. Capped at
    `cap`, because a crawl of a large site would otherwise plan an unbounded
    number of runs from one parent.
    """
    wanted = set(child.target_schema.required) | set(child.target_schema.optional)
    fields = [f for f in produced if f in wanted and produced[f]]
    if not fields:
        return [parent_target]
    # Fan over ONE field — the first the child needs. Crossing several
    # fields multiplies runs combinatorially for no established benefit.
    field = fields[0]
    return [{**parent_target, field: v} for v in produced[field][:cap]]
