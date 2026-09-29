"""The stand-in two suites check the catalogue through must not drift.

`catalogue_render.render` decides whether a placeholder holds a PROGRAM or a VALUE,
and both `test_payload_quoting.py` and `test_shell_steps.py` run the whole catalogue
through it before asking the real admission guard what it thinks. That makes it a
guard on a guard, and it can fail in both directions:

  too narrow — a case that takes a whole command from the operator is rendered as a
               command named `x`, the guard refuses it, and a case with nothing
               wrong with it is reported broken. That is the state this replaced.

  too wide   — a PAYLOAD rendered as `curl -s http://x/` turns a step that breaks
               out of its quoting into one that parses cleanly, and the suite stops
               detecting the thing it was written for. Nothing about that is loud.

So the set is pinned. A case that legitimately joins it changes this list, in a
commit where someone has looked at why.
"""
import re

import pytest

from tests.catalogue_render import COMMAND_STANDIN, VALUE_STANDIN, command_placeholders, render
from orchestrator.testcase import load_catalog

# (case id, step name, placeholder) — every position in the catalogue that holds a
# whole command rather than a value.
#
# WSTG-BUSL-04 IS DELIBERATELY ABSENT and takes a whole command too. It wraps its
# logic in `bash -c '...'` and passes the operator's request positionally, after the
# quoted script, so the program the guard sees is `bash` and the request is an
# argument. Rendering it as a command would be wrong about where it sits, and the
# guard is satisfied either way — which is the whole reason the rule is positional.
TAKES_A_WHOLE_COMMAND = {
    ("WSTG-AUTHZ-02", "read_transfer_read", "read_request"),
    ("WSTG-AUTHZ-02", "read_transfer_read", "transfer_request"),
    ("WSTG-BUSL-05", "use_it_twice", "request_template"),
    ("WSTG-BUSL-06", "skip_to_final_step", "final_request"),
}

CATALOG = load_catalog()


def measured() -> set[tuple[str, str, str]]:
    return {(tid, st.name, name)
            for tid, tc in sorted(CATALOG.items()) for st in tc.steps
            for name in command_placeholders(st.command)}


def test_exactly_these_placeholders_hold_a_command():
    found = measured()
    assert found == TAKES_A_WHOLE_COMMAND, (
        f"new: {sorted(found - TAKES_A_WHOLE_COMMAND)}\n"
        f"gone: {sorted(TAKES_A_WHOLE_COMMAND - found)}\n"
        "A NEW entry means a case now takes a whole command from the operator — check "
        "that it really does before adding it, because rendering a payload as a command "
        "stops the quoting suite from seeing payloads that escape their quotes. An entry "
        "that has GONE means the case changed shape and nothing is checking it here.")


def test_every_pinned_case_still_declares_that_field():
    """A stale entry would widen nothing, but it would describe a case that is gone."""
    for tid, step_name, field in sorted(TAKES_A_WHOLE_COMMAND):
        tc = CATALOG.get(tid)
        assert tc is not None, f"{tid} is no longer in the catalogue"
        step = next((s for s in tc.steps if s.name == step_name), None)
        assert step is not None, f"{tid} no longer has a step called {step_name!r}"
        declared = set(tc.target_schema.required or []) | set(tc.target_schema.optional or [])
        assert field in declared, (
            f"{tid}/{step_name} renders {{{{{field}}}}} as a command, but the case's "
            f"target_schema does not declare {field} — so nothing supplies it")


@pytest.mark.parametrize("tid,step_name,field", sorted(TAKES_A_WHOLE_COMMAND))
def test_a_command_placeholder_renders_as_a_command(tid, step_name, field):
    step = next(s for s in CATALOG[tid].steps if s.name == step_name)
    assert COMMAND_STANDIN in render(step.command)


def test_a_value_placeholder_is_still_inert():
    """The negative control. Rendering everything as a command would pass every test
    above and destroy the quoting suite, so one ordinary payload is checked directly."""
    command = 'curl -G "http://t/" --data-urlencode \'q={{parameter}}\''
    assert command_placeholders(command) == set()
    assert render(command) == 'curl -G "http://t/" --data-urlencode \'q=x\''
    assert COMMAND_STANDIN not in render(command)


def test_the_rule_would_still_catch_the_original_mistake():
    """The regression the quoting suite exists for, rendered: it must stay refusable."""
    broken = r'curl -G "http://x/s" --data-urlencode "q={{parameter}}\"|]}$(){}"'
    assert command_placeholders(broken) == set(), (
        "a payload after --data-urlencode is not a command position")
    assert VALUE_STANDIN in render(broken)


def test_a_placeholder_after_a_separator_is_a_command_position():
    """What the positional rule actually claims, stated on its own rather than only
    through the catalogue — so a regex that stopped matching would fail here first."""
    for separator in (";", "|", "&&", "||", "$(", "("):
        command = f"curl -s http://t/ {separator} {{{{other}}}}"
        assert command_placeholders(command) == {"other"}, separator
    assert command_placeholders("{{lead}} --flag") == {"lead"}
    assert command_placeholders("curl -s {{url}}") == set()


def test_nothing_else_reimplements_this_rule():
    """Two suites depend on it; a third copy would drift from both.

    Matched on what a placeholder renderer DOES — a substitution over `{{...}}` — and
    not on the name `_render`, which two report-rendering fixtures also use for
    something unrelated. Both of those were sitting here as false positives when this
    was written against the name.
    """
    import pathlib
    here = pathlib.Path(__file__).resolve().parent
    substitutes_placeholders = re.compile(r"\.sub\([^\n]*\{\{|\{\{\[a-z")
    offenders = sorted(p.name for p in here.glob("test_*.py")
                       if substitutes_placeholders.search(p.read_text()))
    assert offenders == [], (
        f"{offenders} substitute catalogue placeholders themselves. Import "
        "`tests.catalogue_render.render` instead, or this file stops describing what "
        "the catalogue suites actually do.")
