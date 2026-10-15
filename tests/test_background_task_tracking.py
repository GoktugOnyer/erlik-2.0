"""Background tasks are tracked so their exceptions are not swallowed.

asyncio keeps only a weak reference to a bare `create_task()`, so a
fire-and-forget task (the benchmark sweep was the known offender) can be
garbage-collected mid-flight, and if it raises, the failure surfaces only as a
late "Task exception was never retrieved" at GC time — if at all. `_track_task`
holds a strong reference and attaches a done-callback that logs the exception
where it happens.
"""

import asyncio
import re
from pathlib import Path

import pytest

from orchestrator import main as M

ROOT = Path(__file__).resolve().parents[1]


async def test_a_tracked_task_is_held_while_it_runs():
    started = asyncio.Event()
    release = asyncio.Event()

    async def worker():
        started.set()
        await release.wait()

    task = M._track_task(asyncio.create_task(worker()), "unit")
    await started.wait()
    assert task in M._background_tasks, "a running tracked task must be strongly held"
    release.set()
    await task
    await asyncio.sleep(0)   # let the done-callback run
    assert task not in M._background_tasks, "a finished task must be released"


async def test_a_tracked_task_surfaces_its_exception(capsys):
    async def boom():
        raise ValueError("kaboom-xyz")

    task = M._track_task(asyncio.create_task(boom()), "unit")
    with pytest.raises(ValueError):
        await task
    await asyncio.sleep(0)   # let the done-callback run

    out = capsys.readouterr().out
    assert "unhandled exception" in out, "the failure must be logged, not swallowed"
    assert "kaboom-xyz" in out, "the log must name the actual exception"
    assert task not in M._background_tasks


async def test_a_cancelled_task_is_released_without_noise(capsys):
    """Cancellation is not a failure — it must release the ref but log nothing."""
    async def sleeper():
        await asyncio.sleep(10)

    task = M._track_task(asyncio.create_task(sleeper()), "unit")
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(0)
    assert task not in M._background_tasks
    assert "unhandled exception" not in capsys.readouterr().out


def test_every_create_task_in_main_is_tracked():
    """The guard on the item: a new bare create_task — the exact offender class
    `_run_benchmark_sequence` was — must fail this. Compared on whitespace-
    stripped source so multi-line call formatting does not matter.

    Every `asyncio.create_task(` is covered either inline
    (`_track_task(asyncio.create_task(...`) or via the agent-loop form that
    stores `task = asyncio.create_task(...)` then `... = _track_task(task, ...)`.
    """
    flat = re.sub(r"\s+", "", (ROOT / "orchestrator" / "main.py").read_text())
    total = flat.count("asyncio.create_task(")
    inline = flat.count("_track_task(asyncio.create_task(")
    assigned = flat.count("=_track_task(task,")
    assert total > 0, "no create_task sites found — did main.py move?"
    assert total == inline + assigned, (
        f"an asyncio.create_task site in main.py is not wrapped by _track_task: "
        f"found {total} create_task calls but only {inline} inline + {assigned} "
        f"assigned are tracked")
