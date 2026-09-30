"""ERLIK_NATIVE must be loud, not silent.

Native mode removes the container boundary — model-authored commands then run as
the orchestrator's own user, on the host that holds the encrypted secret store
and every engagement's evidence. It is off by default and a deliberate operator
choice, but a deliberate choice with that blast radius must announce itself at
startup, not only from a readiness endpoint nobody reads until something breaks
(CLAUDE.md convention 2: declare, don't silently drop).

The startup print and this test read ONE function, so the test holds the exact
string that ships (convention 3), and reverting the notice to always-None makes
these fail.
"""

import orchestrator.main as main
import orchestrator.tool_executor as te


def test_no_warning_when_native_is_off(monkeypatch):
    monkeypatch.setattr(te, "ERLIK_NATIVE", False)
    assert main._native_mode_warning() is None


def test_warning_fires_and_names_the_risk_when_native_is_on(monkeypatch):
    monkeypatch.setattr(te, "ERLIK_NATIVE", True)
    msg = main._native_mode_warning()
    assert msg, "ERLIK_NATIVE on must produce a startup warning"
    # The notice has to name the variable and what it gives up, or it is a
    # warning that warns of nothing.
    assert "ERLIK_NATIVE" in msg
    assert "container" in msg.lower()
    assert "write" in msg.lower()
