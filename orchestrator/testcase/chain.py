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

    # (test_case_id, depth, target)
    queue: list[tuple[str, int, dict[str, Any]]] = [(root_id, 0, target)]

    while queue:
        if len(out.runs) >= max_runs:
            out.stopped_reason = f"hit max_runs={max_runs}"
            break

        tc_id, depth, tc_target = queue.pop(0)
        key = queue_key(tc_id, tc_target)
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
                if queue_key(nxt, child_target) not in visited:
                    queue.append((nxt, depth + 1, child_target))

    return out


def queue_key(cid: str, tgt: dict[str, Any]):
    """Identity of a queued run, for loop protection.

    Extracted from `run_chain` so it can be tested directly. It was a closure,
    and a test that could only grep the source for it passed against the exact
    regression below.

    Keyed on the URL ALONE until now, which silently discarded every fan over
    any other field: harvest `q` and `user_id`, chain to a child that needs a
    parameter, and the second target collided with the first and was dropped as
    already-visited. It went unnoticed because the only producer in the
    catalogue emitted `url`, which is in the key.

    Scalars only, and `scope` excluded -- it is a dict, identical on every
    target in a chain, and unhashable. Loop protection is unaffected: a genuine
    cycle revisits an identical target, which still collides.
    """
    scalars = tuple(sorted(
        (k, str(v)) for k, v in tgt.items()
        if k != "scope" and isinstance(v, (str, int, float, bool))))
    return (cid, str(tgt.get("url") or tgt.get("host") or ""), scalars)


def _retarget(child, parent_target: dict[str, Any],
              produced: dict[str, list[str]], cap: int) -> list[dict[str, Any]]:
    """One target per produced value the child actually consumes.

    Only fields the child DECLARES (required or optional) are fanned over —
    producing a field nobody consumes must not multiply the work. Capped at
    `cap`, because a crawl of a large site would otherwise plan an unbounded
    number of runs from one parent.
    """
    required = set(child.target_schema.required)
    wanted = required | set(child.target_schema.optional)
    fields = [f for f in produced if f in wanted and produced[f]]
    if not fields:
        return [parent_target]

    # Fan over ONE field, because crossing several multiplies runs
    # combinatorially for no established benefit -- but over the field that
    # actually UNBLOCKS the child, not merely the first one it mentions.
    #
    # Measured: a parent producing both `url` and `parameter`, chained to a
    # child requiring both and given only `url`, fanned over `url` and
    # discarded every produced parameter. Each child target then failed
    # validation with "Missing required target fields: ['parameter']", so the
    # harvest that would have satisfied it was thrown away one step before it
    # was needed. Preference order:
    #
    #   1. a REQUIRED field the parent target does not already supply -- the
    #      one thing standing between the child and running at all;
    #   2. otherwise the first produced field the child wants, as before.
    missing_required = [f for f in fields
                        if f in required and not parent_target.get(f)]
    field = missing_required[0] if missing_required else fields[0]
    return [{**parent_target, field: v} for v in produced[field][:cap]]
