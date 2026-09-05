"""A step that writes shell must wrap it in `bash -c`, or it never runs.

`_command_segments` splits a command at every point a new program name can
appear -- unquoted `;` `|` `&`, and `$(` -- and `_segment_violation` then
checks each segment against the session toolset. Shell syntax is not a
program, but the splitter does not know that, so a step that writes `if`,
`[` or a subshell directly is refused before any request goes out:

    TOOLSET: command segment runs '(', which is not in this session's toolset

Measured 2026-09-05. Three steps were in that state and had never executed:

    WSTG-INPV-05.6  operator_differential        runs 'if'
    WSTG-INPV-06    wildcard_differential        runs '('
    WSTG-INPV-06    blind_boolean_differential   runs 'if'

which is why INPV-05.6 reported "not assessed" against a target that honours
the operator it probes for -- the probe was its differential step.

The convention every other shell-writing case already followed is to wrap the
logic in `bash -c '...'`: the body is then one single-quoted segment, and the
guard admits it via the step's declared `tool:`. These tests hold the whole
catalogue to it, because the failure is quiet -- a refused step reads like a
missing tool, and the case above it reads as "not assessed" or clean.

The payload-side counterpart is in test_payload_quoting.py.
"""

import re

import pytest

from orchestrator.testcase import load_catalog
from orchestrator.testcase.runner import _TOOLS_ALL
from orchestrator.tool_executor import _extract_tool_names, _segment_violation

ALIASES = {"nc": "netcat", "ncat": "netcat", "zap-cli": "zap-cli",
           "jwt_tool.py": "jwt_tool", "theharvester": "theHarvester"}

# Constructs that mean the command is a shell program, not a single invocation.
SHELL_SYNTAX = re.compile(r"(?:^|\s)(?:if|then|else|elif|fi|while|until|do|done"
                          r"|case|esac|\[|\[\[)\s|\$\(\(|;\s*\w+=")

ALL_STEPS = [(tid, st) for tid, tc in sorted(load_catalog().items())
             for st in tc.steps]


def _render(command: str) -> str:
    return re.sub(r"\{\{[a-z_0-9]+\}\}", "x", command)


class TestShellIsWrapped:
    @pytest.mark.parametrize("tid,step", ALL_STEPS, ids=lambda v: getattr(v, "name", v))
    def test_a_step_that_writes_shell_wraps_it(self, tid, step):
        cmd = step.command
        if cmd.strip().startswith("bash -c") or cmd.strip().startswith("sh -c"):
            return
        m = SHELL_SYNTAX.search(cmd)
        assert not m, (
            f"{tid}/{step.name} writes shell ({m.group(0).strip()!r}) without "
            "wrapping it in `bash -c '...'`. _command_segments reads that as a "
            "program name and the admission guard refuses the step, so it "
            "never runs."
        )

    @pytest.mark.parametrize("tid,step", ALL_STEPS, ids=lambda v: getattr(v, "name", v))
    def test_every_step_survives_the_admission_guard(self, tid, step):
        """The property that actually matters, checked through the real guard
        rather than through a rule about how commands should look."""
        err = _segment_violation(_render(step.command), list(_TOOLS_ALL),
                                 step.tool, ALIASES)
        assert err is None, f"{tid}/{step.name}: {err}"

    @pytest.mark.parametrize("tid,step", ALL_STEPS, ids=lambda v: getattr(v, "name", v))
    def test_a_wrapped_step_is_seen_as_one_program(self, tid, step):
        cmd = _render(step.command)
        if not cmd.strip().startswith("bash -c"):
            return
        names = _extract_tool_names(cmd)
        assert names == ["bash"], (
            f"{tid}/{step.name}: the wrapper leaks -- parsed {names}. Something "
            "in the body has escaped the single quotes."
        )


class TestTheDetectorWorks:
    """Guards on the guards. Both tests above pass vacuously if the syntax
    regex stops matching or the admission guard stops refusing."""

    UNWRAPPED = ('A=$(curl -s -o /dev/null -w "%{http_code}" "http://x/a"); '
                 'if [ "$A" = "200" ]; then echo YES; fi')

    def test_the_syntax_detector_catches_an_unwrapped_step(self):
        assert SHELL_SYNTAX.search(self.UNWRAPPED)

    def test_the_guard_refuses_an_unwrapped_step(self):
        err = _segment_violation(self.UNWRAPPED, list(_TOOLS_ALL), "curl", ALIASES)
        assert err is not None

    def test_wrapping_that_same_command_fixes_it(self):
        """The negative control: it is the wrapping that makes it pass, not the
        guard having stopped looking."""
        wrapped = "bash -c '" + self.UNWRAPPED + "'"
        assert not SHELL_SYNTAX.search(wrapped.split("bash -c ", 1)[0])
        assert _segment_violation(wrapped, list(_TOOLS_ALL), "curl", ALIASES) is None

    def test_a_plain_single_invocation_is_not_flagged(self):
        plain = 'curl -s -b "" -H "" -i "http://x/a"'
        assert not SHELL_SYNTAX.search(plain)
        assert _segment_violation(plain, list(_TOOLS_ALL), "curl", ALIASES) is None


class TestTheThreeStepsThatWereFixed:
    """Named explicitly, because "no step is refused" passes just as well on a
    catalogue where these three were deleted."""

    FIXED = [("WSTG-INPV-05.6", "operator_differential"),
             ("WSTG-INPV-06", "wildcard_differential"),
             ("WSTG-INPV-06", "blind_boolean_differential")]

    @pytest.mark.parametrize("tid,name", FIXED)
    def test_it_still_exists_and_is_admitted(self, tid, name):
        step = [st for t, st in ALL_STEPS if t == tid and st.name == name]
        assert step, f"{tid}/{name} is gone"
        assert _segment_violation(_render(step[0].command), list(_TOOLS_ALL),
                                  step[0].tool, ALIASES) is None

    @pytest.mark.parametrize("tid,name", FIXED)
    def test_its_probes_are_intact(self, tid, name):
        """Wrapping must not have changed what is sent. The NoSQL operators and
        the LDAP filters ARE the test; a quoting fix that ate them would leave
        a step that runs and proves nothing."""
        step = [st for t, st in ALL_STEPS if t == tid and st.name == name][0]
        cmd = step.command
        if tid == "WSTG-INPV-05.6":
            # `\$ne` inside the double quotes, so the inner shell sees a
            # literal `$` and does not expand a variable named `ne`.
            assert "[\\$ne]" in cmd and "[\\$eq]" in cmd, cmd
            assert "$ne]" not in cmd.replace("\\$ne]", ""), (
                "an unescaped $ne would expand to nothing before the request"
            )
        else:
            assert "%2A" in cmd
            if name == "blind_boolean_differential":
                assert "objectClass%3D%2A" in cmd  # always-true filter
                assert "objectClass%3D%78" in cmd  # always-false filter
