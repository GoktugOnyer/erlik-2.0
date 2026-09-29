r"""A shell step that the host's own bash cannot parse runs nothing, and says nothing.

Measured 2026-09-29 on macOS, whose /bin/bash is 3.2.57. WSTG-SESS-02's step is one
large `$(...)` and contained a `case` statement inside it:

    case "$(printf "%s" "$N" | tr "A-Z" "a-z")" in *sess*|*sid*) ;; *) continue;; esac

bash 3.2's parser reads the pattern's `)` as closing the command substitution and
dies on the `;;`. So the step produced an empty capture against a target serving
`Set-Cookie: session=abc123; Path=/` -- the textbook finding the case is named for
-- and the case reported clean. Eighteen tests failed and none of them named the
cause; the same suite was green on CI, where bash is 5.x.

That is the characteristic defect of this codebase wearing a new hat: a confident
result from a path that did not run. A verdict that depends on a shell is only as
portable as the shell, and "it works in the container" is not the whole claim --
these cases also run natively (ERLIK_NATIVE) and are developed on a laptop.

So every `bash -c` step in the catalogue is parsed by the bash that is actually
here. It is a syntax check, not an execution: nothing is run and nothing is
contacted.
"""
import re
import shlex
import subprocess
import tempfile
from pathlib import Path

import pytest

from orchestrator.testcase import load_catalog

SHELL_STEPS = [(tid, st) for tid, tc in sorted(load_catalog().items())
               for st in tc.steps if st.command.strip().startswith(("bash -c", "sh -c"))]


def _script(command: str) -> str:
    """The program a `bash -c` step runs, with placeholders filled.

    `shlex`, not hand-parsing, and the reason is that the catalogue uses BOTH
    quoting styles: most steps write `bash -c '...'` but WSTG-CONF-06 and
    WSTG-ERRH-01 write `bash -c "...\"...\""`. A reader for one of them reported
    the other as unparseable, which is a broken extractor wearing the costume of a
    broken step -- the thing this whole file exists to tell apart.

    It also handles arguments AFTER the script, which WSTG-BUSL-04 has: the
    operator's request is passed positionally rather than interpolated, so the
    script is one token in the middle and not the tail of the string.
    """
    # Placeholders first: one stands for a value the operator supplies, and `x` is
    # inert, so neither shlex nor bash sees syntax the case did not write.
    rendered = re.sub(r"\{\{[a-z_0-9]+\}\}", "x", command.strip())
    tokens = shlex.split(rendered)
    assert len(tokens) >= 3 and tokens[0] in ("bash", "sh") and tokens[1] == "-c", (
        f"not a `bash -c` invocation after rendering: {rendered[:100]!r}")
    return tokens[2]


def test_there_are_shell_steps_to_check():
    """Guard on the guard: an extraction that stopped matching would make every
    assertion below hold over nothing."""
    assert SHELL_STEPS, "no `bash -c` steps found -- the catalogue scan is broken"


@pytest.mark.parametrize("tid,step", SHELL_STEPS, ids=lambda v: getattr(v, "name", v))
def test_the_hosts_own_bash_can_parse_it(tid, step):
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as handle:
        handle.write(_script(step.command))
        path = handle.name
    try:
        done = subprocess.run(["bash", "-n", path], capture_output=True, text=True)
    finally:
        Path(path).unlink(missing_ok=True)
    assert done.returncode == 0, (
        f"{tid}/{step.name} does not parse under this host's bash "
        f"({_bash_version()}):\n{done.stderr.strip()}\n\n"
        "The step will produce nothing here and the case will report clean. "
        "`case` inside `$(...)` is the known offender on bash 3.2 — an "
        "`if`/`grep` says the same thing and parses everywhere.")


def _bash_version() -> str:
    out = subprocess.run(["bash", "--version"], capture_output=True, text=True).stdout
    return out.splitlines()[0] if out else "unknown"


def test_the_check_would_catch_the_original():
    """Guard on the guard, the other way: the construct that caused this must still
    be rejected where it is rejected, so a host with a newer bash does not turn this
    file into a no-op it cannot notice."""
    original = ('X=$(printf "a\\n" | while IFS= read -r L; do '
                'case "$L" in a) ;; *) continue;; esac; done)')
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as handle:
        handle.write(original)
        path = handle.name
    try:
        done = subprocess.run(["bash", "-n", path], capture_output=True, text=True)
    finally:
        Path(path).unlink(missing_ok=True)
    if done.returncode == 0:
        pytest.skip(f"this host's bash parses it ({_bash_version()}); "
                    "the catalogue check above still applies, this control does not")
    assert ";;" in done.stderr or "syntax error" in done.stderr
