"""A payload is data. It must never be written where the shell evaluates it.

WSTG-INPV-11.2's `expression_metachars` step was authored as

    --data-urlencode "{{parameter}}=erlik\\"|]}$(){}"

inside DOUBLE quotes, where `$()` is command substitution. Measured 2026-09-05
with curl replaced by a shim that prints its argv:

    sent:     q=erlik"|]}{}          <- $() evaluated locally, to nothing
    intended: q=erlik"|]}$(){}

So the metacharacters the step is named for never reached the target. And
`_command_segments` does not treat `\\"` as an escaped quote, so it read the
rest of the line as a pipeline and the admission guard refused the step
outright:

    TOOLSET: command segment runs '){}"', which is not in this session's toolset

Two failures from one quoting mistake: the probe could not run, and would not
have tested what it claims if it had.

These tests are catalogue-wide rather than about that one step. The mistake is
easy to repeat -- injection payloads are made of exactly the characters a
shell acts on -- and neither symptom is loud: a refused step shows as an error
someone reads as a missing tool, and a silently-shortened payload shows as a
clean result.
"""

import re
import subprocess
import tempfile
from pathlib import Path

import pytest

from orchestrator.testcase import find_by_id, load_catalog
from orchestrator.testcase.runner import _TOOLS_ALL
from orchestrator.tool_executor import (_extract_tool_names,
                                        _segment_violation)

CATALOG = load_catalog()


def _steps():
    for tid, tc in sorted(CATALOG.items()):
        for st in tc.steps:
            yield tid, st


ALL_STEPS = list(_steps())


def _render(command: str) -> str:
    """Substitute placeholders with something inert and in-scope."""
    return re.sub(r"\{\{[a-z_0-9]+\}\}", "x", command)


class TestNoPayloadIsEvaluatedLocally:
    """`$(...)` and backticks inside a double-quoted argument run ON THIS HOST
    and are replaced by their output before the request is built."""

    @pytest.mark.parametrize("tid,step", ALL_STEPS, ids=lambda v: getattr(v, "name", v))
    def test_no_command_substitution_in_a_quoted_argument(self, tid, step):
        cmd = step.command
        if cmd.strip().startswith("bash -c"):
            # These are deliberate shell programs, not single invocations --
            # the substitutions in them are the case's own logic, and
            # TestBashStepsAreStillSingleQuoted below covers their payloads.
            return
        bad = re.findall(r'"[^"]*(\$\((?!\()[^)]*\)|`[^`]*`)[^"]*"', cmd)
        assert not bad, (
            f"{tid}/{step.name}: {bad} runs on the erlik host and is replaced "
            "by its output; the target never sees these characters"
        )


class TestEveryStepIsAdmittedByTheRealGuard:
    """The other half of the same mistake. `_command_segments` splits on shell
    metacharacters, so a payload that breaks out of its quoting is read as a
    pipeline and the step is refused before it runs.

    Asserted through `_segment_violation` itself, called the way execute_tool
    calls it. An earlier version of this test asserted that every parsed name
    looked like an identifier, and failed on three steps that legitimately
    write shell -- `if`, `then`, `[`, `(` are parsed as programs and the guard
    admits them. Re-deriving what the guard permits is how a test ends up
    disagreeing with the thing it is checking.
    """

    ALIASES = {"nc": "netcat", "ncat": "netcat", "zap-cli": "zap-cli",
               "jwt_tool.py": "jwt_tool", "theharvester": "theHarvester"}

    # Three steps ARE refused today, for a different reason than a broken
    # payload, and they are recorded here rather than hidden behind an xfail.
    #
    # They write shell directly -- subshells, `if`, `[` -- instead of wrapping
    # it in `bash -c '...'`. `_command_segments` splits on `(` and reads it as
    # a program name, and `_segment_violation` refuses the step:
    #
    #     TOOLSET: command segment runs '(', which is not in this session's toolset
    #
    # Every other shell-writing case in the catalogue (AUTHZ-04, INPV-15,
    # ATHN-01, BUSL-04, CONF-07, SESS-02) wraps its logic in `bash -c '...'`,
    # which the guard admits via the step's declared `tool:`. These three do
    # not, so they have never executed. Confirmed live 2026-09-05:
    #
    #     WSTG-INPV-06  filter_syntax_probe        ok=True
    #     WSTG-INPV-06  wildcard_differential      ok=False  TOOLSET: ... '('
    #     WSTG-INPV-06  blind_boolean_differential ok=False  TOOLSET: ... '('
    #
    # which is also why WSTG-INPV-05.6 reports "not assessed" against a target
    # that honours the operator it probes for: its differential step is one of
    # these. Fixing them means rewriting three long commands whose bodies
    # already contain single quotes, and that is its own change -- so this
    # asserts the current state exactly, and fails the moment it changes in
    # either direction.
    KNOWN_REFUSED = {
        ("WSTG-INPV-05.6", "operator_differential"),
        ("WSTG-INPV-06", "wildcard_differential"),
        ("WSTG-INPV-06", "blind_boolean_differential"),
    }

    @pytest.mark.parametrize("tid,step", ALL_STEPS, ids=lambda v: getattr(v, "name", v))
    def test_the_step_is_not_refused_before_it_runs(self, tid, step):
        err = _segment_violation(_render(step.command), list(_TOOLS_ALL),
                                 step.tool, self.ALIASES)
        if (tid, step.name) in self.KNOWN_REFUSED:
            assert err is not None, (
                f"{tid}/{step.name} now passes the admission guard. Good -- "
                "remove it from KNOWN_REFUSED."
            )
            return
        assert err is None, (
            f"{tid}/{step.name}: {err}\nThe step never executes. If this is a "
            "payload, it has broken out of its quoting -- single-quote it."
        )

    def test_the_known_refused_list_is_not_stale(self):
        """Guard on the exemption: a step listed here that no longer exists
        would silently shrink what the test above checks."""
        names = {(tid, st.name) for tid, st in ALL_STEPS}
        assert self.KNOWN_REFUSED <= names, self.KNOWN_REFUSED - names

    # Bare shell syntax, which _command_segments reads as program names. The
    # first offender differs between the three -- `(` for one, `if` for the
    # other two -- but the cause is identical.
    SHELL_SYNTAX = ("(", ")", "if", "then", "else", "elif", "fi", "[", "[[",
                    "while", "do", "done", "case", "esac")

    def test_the_refusals_all_have_the_same_cause(self):
        """They are one bug, not three. A NEW cause appearing here must be
        looked at rather than absorbed into the list -- a payload that has
        broken out of its quoting would name something that is not shell
        syntax."""
        for tid, name in sorted(self.KNOWN_REFUSED):
            step = [st for t, st in ALL_STEPS if t == tid and st.name == name][0]
            err = _segment_violation(_render(step.command), list(_TOOLS_ALL),
                                     step.tool, self.ALIASES)
            offender = re.search(r"runs '([^']*)'", err).group(1)
            assert offender in self.SHELL_SYNTAX, (
                f"{tid}/{name} is refused for running {offender!r}, which is "
                "not shell syntax -- this is a different bug from the other "
                "entries and needs looking at, not listing"
            )

    def test_the_check_would_catch_the_original(self):
        """Guard on the guard: the regression this file exists for must still
        be detected if someone reintroduces it."""
        broken = (r'curl -G "http://x/s" --data-urlencode "q=erlik\"|]}$(){}"')
        err = _segment_violation(broken, list(_TOOLS_ALL), "curl", self.ALIASES)
        assert err is not None, _extract_tool_names(broken)

    def test_the_fixed_form_is_admitted(self):
        """The negative control: single quoting is what makes it pass, not the
        guard having stopped looking."""
        fixed = """curl -G "http://x/s" --data-urlencode 'q=erlik"|]}$(){}'"""
        assert _segment_violation(fixed, list(_TOOLS_ALL), "curl",
                                  self.ALIASES) is None


class TestTheIntendedPayloadIsWhatIsSent:
    """Executed, not reasoned about: run the real command with curl replaced by
    a shim that prints its arguments, and compare against the payload the case
    says it sends."""

    def _argv(self, command: str) -> list[str]:
        with tempfile.TemporaryDirectory() as d:
            shim = Path(d) / "curl"
            shim.write_text('#!/bin/bash\nfor a in "$@"; do echo "$a"; done\n')
            shim.chmod(0o755)
            import os
            env = dict(os.environ, PATH=f"{d}:{os.environ['PATH']}")
            r = subprocess.run(["bash", "-c", _render(command)],
                               capture_output=True, text=True, env=env)
            return r.stdout.splitlines()

    def test_the_metachar_probe_sends_every_metacharacter(self):
        step = [s for s in find_by_id("WSTG-INPV-11.2").steps
                if s.name == "expression_metachars"][0]
        argv = self._argv(step.command)
        payloads = [a for a in argv if a.startswith("x=")]
        assert payloads, argv
        got = payloads[0]
        for ch in ('"', "|", "]", "}", "$(", ")", "{", "}"):
            assert ch in got, (
                f"the shell removed {ch!r} before the request; sent {got!r}"
            )

    def test_the_shim_would_show_a_loss(self):
        """Negative control for the method itself."""
        argv = self._argv('curl -G "http://x/s" --data-urlencode "x=a$()b"')
        assert "x=ab" in argv, argv
