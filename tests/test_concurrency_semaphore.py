"""The global concurrency bound on tool subprocess execution.

Every tool run lands in `_sync_docker_exec` on a worker thread. With N parallel
sessions nothing used to bound how many heavy scanners ran at once, so a busy
host could thrash or exhaust file descriptors. `ERLIK_MAX_CONCURRENCY` (default
8, non-positive disables) caps the number of subprocesses in flight.

These assert against the REAL `execute_tool` path — the semaphore is acquired
inside it, around the `run_in_executor` that drives the subprocess — not a
re-implementation of the limiter. `_sync_docker_exec` (the only thing after the
semaphore) is replaced with a recorder that measures peak concurrency.
"""

import asyncio
import concurrent.futures
import threading
import time
import weakref

import pytest

from orchestrator import tool_executor as T


@pytest.fixture
def harness(monkeypatch):
    # The semaphore says WHERE to queue; these guards are orthogonal and would
    # otherwise refuse the probe command before it reaches the subprocess.
    monkeypatch.setenv("ERLIK_SCOPE_ENFORCE", "0")
    monkeypatch.setenv("ERLIK_SAFE_MODE", "0")

    async def _container_ok():
        return True
    monkeypatch.setattr(T, "check_container_running", _container_ok)

    # One semaphore per loop, rebuilt fresh so a per-test MAX_CONCURRENCY
    # override is actually picked up rather than a cached instance.
    monkeypatch.setattr(T, "_exec_semaphores", weakref.WeakKeyDictionary())

    state = {"cur": 0, "max": 0}
    lock = threading.Lock()

    def _recorder(command, timeout, argv=None):
        # Runs in the thread pool — hence the lock around the shared counters.
        with lock:
            state["cur"] += 1
            state["max"] = max(state["max"], state["cur"])
        time.sleep(0.05)
        with lock:
            state["cur"] -= 1
        return {"output": "ok", "returncode": 0, "error": None}

    monkeypatch.setattr(T, "_sync_docker_exec", _recorder)
    return state


async def _run_many(n):
    results = await asyncio.gather(*[
        T.execute_tool("curl http://localhost/", ["curl"],
                       target_url="http://localhost/")
        for _ in range(n)
    ])
    return results


async def test_the_bound_caps_concurrent_subprocesses(harness, monkeypatch):
    monkeypatch.setattr(T, "MAX_CONCURRENCY", 2)
    results = await _run_many(8)
    assert all(r.get("executed", True) and r["success"] for r in results), \
        "the probe command should pass every guard and reach the recorder"
    assert harness["max"] <= 2, (
        f"with MAX_CONCURRENCY=2 at most two subprocesses may run at once; "
        f"peak was {harness['max']}")


async def test_without_the_bound_concurrency_exceeds_the_cap(harness, monkeypatch):
    """The guard on the guard: prove the cap above is doing the work and not
    passing for some unrelated reason (e.g. a thread pool too small to overlap).

    Disabling the bound (<= 0, the historical unbounded behaviour) must let more
    than two overlap — otherwise `test_the_bound_caps_concurrent_subprocesses`
    would stay green with the semaphore deleted.
    """
    monkeypatch.setattr(T, "MAX_CONCURRENCY", 0)
    # Make sure the default executor has room to overlap the eight submissions.
    loop = asyncio.get_running_loop()
    loop.set_default_executor(concurrent.futures.ThreadPoolExecutor(max_workers=8))
    await _run_many(8)
    assert harness["max"] > 2, (
        "with the bound disabled the recorder should have seen more than two "
        f"concurrent subprocesses; peak was {harness['max']}")


def test_disabled_bound_yields_no_semaphore(monkeypatch):
    monkeypatch.setattr(T, "MAX_CONCURRENCY", 0)

    async def _check():
        return T._get_exec_semaphore()
    assert asyncio.run(_check()) is None


def test_semaphore_survives_a_fresh_event_loop(monkeypatch):
    """A module-level asyncio.Semaphore binds to the first loop that awaits it
    and then raises 'bound to a different event loop' on the next. Keying per
    loop must avoid that — each asyncio.run() below spins its own loop."""
    monkeypatch.setattr(T, "MAX_CONCURRENCY", 4)
    monkeypatch.setattr(T, "_exec_semaphores", weakref.WeakKeyDictionary())

    async def _acquire():
        sem = T._get_exec_semaphore()
        async with sem:
            return True

    assert asyncio.run(_acquire()) is True
    # Second independent loop — would raise if the semaphore were loop-bound.
    assert asyncio.run(_acquire()) is True
