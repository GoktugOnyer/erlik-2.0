"""E-033: `POST /stop` had no debounce, and could not say so.

It was `if task and not task.done(): task.cancel()`. The teardown it interrupts is not
instant — a `docker rm -f` of one container measures 207ms, and the integration lane's unwind
releases one collector after another — so a second click during that window found the task
still not done, cancelled it AGAIN, and returned the same "Stop signal sent." as the first.
An operator could not tell whether the second click had done anything, which is the reason
they click a third time.

The damage that used to do is already fixed at the right layer: `service.run`'s teardown is
one shielded task, so a cancellation delivered inside it stops us WAITING rather than stopping
the work. This is the other half — not delivering the redundant signal, and saying which of
the three things happened.

`Task.cancelling()` rather than a set of session ids the API maintains: it is the task's own
count of pending cancellation requests, so it cannot drift out of step, needs no cleanup when
a run ends, and cannot leak an entry for a session that never finished.
"""
import asyncio

import pytest

from orchestrator.main import request_stop, running_tasks


@pytest.fixture
def unwinding():
    """A task whose teardown takes a moment, as a real one's does."""
    released = []

    async def run():
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            # Shielded, exactly as `service.run`'s teardown is: the release keeps going
            # whatever else arrives.
            await asyncio.shield(asyncio.sleep(0.05))
            released.append("done")
            raise

    async def start():
        task = asyncio.get_running_loop().create_task(run())
        await asyncio.sleep(0)
        running_tasks["s"] = task
        return task, released

    yield start
    task = running_tasks.pop("s", None)
    if task and not task.done():
        task.cancel()


async def test_the_first_click_sends_the_signal(unwinding):
    task, _ = await unwinding()
    assert request_stop("s") == "stopping"
    assert task.cancelling() == 1


async def test_the_second_click_sends_nothing_and_says_so(unwinding):
    task, _ = await unwinding()
    assert request_stop("s") == "stopping"
    assert request_stop("s") == "already_stopping"
    assert task.cancelling() == 1, (
        "a second cancellation was delivered into a run that is already unwinding")


async def test_clicking_it_five_times_still_delivers_one(unwinding):
    task, _ = await unwinding()
    outcomes = [request_stop("s") for _ in range(5)]
    assert outcomes == ["stopping"] + ["already_stopping"] * 4, outcomes
    assert task.cancelling() == 1


async def test_the_teardown_still_completes(unwinding):
    """The debounce must not buy tidiness by interfering with the unwind it is protecting."""
    task, released = await unwinding()
    request_stop("s")
    request_stop("s")
    with pytest.raises(asyncio.CancelledError):
        await task
    assert released == ["done"]


async def test_a_session_that_is_not_running_says_that_instead(unwinding):
    assert request_stop("nobody") == "not_running"


async def test_a_finished_run_is_not_running(unwinding):
    task, _ = await unwinding()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert request_stop("s") == "not_running"


# ------------------------------------------------------------------- what the route says


async def test_the_route_keeps_one_status_for_both_stopping_cases(unwinding):
    """A dashboard switches on `status`, and it has to keep meaning "this run is stopping"
    for the first click and the second. The repeat is a fact about the REQUEST."""
    from orchestrator.main import stop_session

    await unwinding()
    first = await stop_session("s")
    second = await stop_session("s")
    assert first["status"] == second["status"] == "stopping"
    assert first["already_requested"] is False
    assert second["already_requested"] is True


async def test_the_repeat_message_says_why_it_is_taking_a_moment(unwinding):
    from orchestrator.main import stop_session

    await unwinding()
    await stop_session("s")
    second = await stop_session("s")
    assert "already requested" in second["message"]
    assert "unwinding" in second["message"] and "container" in second["message"]


async def test_a_stop_on_nothing_is_reported_as_such(unwinding):
    from orchestrator.main import stop_session

    answer = await stop_session("nobody")
    assert answer["status"] == "not_running" and answer["already_requested"] is False


async def test_both_routes_share_the_one_decision():
    """Stopping a chain twice would otherwise deliver a second cancellation to every session
    in it — the same redundant signal one level up. Read from the source of the chain route
    rather than duplicated here, because what matters is that it CALLS the shared decision."""
    import inspect

    from orchestrator.main import stop_chain

    source = inspect.getsource(stop_chain)
    assert "request_stop(" in source, "the chain route cancels sessions on its own again"
    assert "task.cancel()" not in source
