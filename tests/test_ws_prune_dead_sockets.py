"""A WebSocket that errors on send is pruned from the broadcast set.

`broadcast` used to swallow a send failure and leave the socket in
`manager.active`, so a dropped client was broadcast to on every future message
and never collected — one leaked socket per dropped client over a long run.
Pruning on failure keeps the set to live connections, and an emptied session
key is dropped entirely.
"""

import pytest

from orchestrator import main as M


class FakeWS:
    def __init__(self, fail=False):
        self.fail = fail
        self.sent = []

    async def send_text(self, text):
        if self.fail:
            raise RuntimeError("socket closed")
        self.sent.append(text)


async def test_a_dead_socket_is_removed_and_a_live_one_kept():
    mgr = M.ConnectionManager()
    good, bad = FakeWS(), FakeWS(fail=True)
    mgr.active["s1"] = [good, bad]
    await mgr.broadcast("s1", {"type": "log", "message": "hi"})
    assert bad not in mgr.active["s1"], "the failed socket must be pruned"
    assert good in mgr.active["s1"], "the live socket must survive"
    assert len(good.sent) == 1, "the live socket must still receive the message"


async def test_the_session_key_is_dropped_when_every_socket_is_dead():
    mgr = M.ConnectionManager()
    mgr.active["s1"] = [FakeWS(fail=True), FakeWS(fail=True)]
    await mgr.broadcast("s1", {"type": "x"})
    assert "s1" not in mgr.active, "an emptied session must not linger as an empty list"


async def test_a_healthy_broadcast_changes_nothing():
    """The control: no failure means no mutation of the connection list."""
    mgr = M.ConnectionManager()
    a, b = FakeWS(), FakeWS()
    mgr.active["s1"] = [a, b]
    await mgr.broadcast("s1", {"type": "log", "message": "ok"})
    assert mgr.active["s1"] == [a, b]
    assert len(a.sent) == 1 and len(b.sent) == 1


async def test_an_unknown_session_is_a_noop():
    mgr = M.ConnectionManager()
    await mgr.broadcast("nope", {"type": "x"})   # must not raise
    assert "nope" not in mgr.active
