"""How a catalogue command looks once the runner has filled in its placeholders.

Several suites check a property of `step.command` that only means anything after
substitution — whether the admission guard would refuse the step, whether a payload
escapes its quoting. They cannot use the real target dict, because the point is to
check every case rather than the few with fixtures, so they substitute a stand-in.

`x` FOR EVERYTHING WAS WRONG IN ONE PLACE, and it was wrong in the direction that
invents failures rather than hiding them. Four cases take a WHOLE COMMAND from the
operator rather than a value:

    WSTG-BUSL-04   {{request_template}}    fired N times in parallel
    WSTG-BUSL-05   {{request_template}}    sent twice
    WSTG-BUSL-06   {{final_request}}       sent without its prerequisite
    WSTG-AUTHZ-02  {{read_request}}, {{transfer_request}}

Rendered as `x`, each became a command named `x`, and `_segment_violation` refused
it — reporting a defect in the case where the only defect was in the stand-in. What
runs there in production is `curl …`, which the guard admits or refuses on its own
merits at run time.

The rule is POSITIONAL, not a list of names: a placeholder that begins a command —
at the start, or after `;` `|` `&` `(` `$(` — holds a program, and everything else
holds a value. A list would need maintaining and would quietly stop matching; this
cannot, and `tests/test_catalogue_render.py` holds it to firing on exactly the cases
above and on nothing else.
"""
import re

# A stand-in command: in the toolset, harmless, and in scope for the fixtures that
# pair this with a scope object. It is deliberately NOT the `x` used elsewhere.
COMMAND_STANDIN = "curl -s http://x/"
VALUE_STANDIN = "x"

# MULTILINE because `_command_segments` splits on newlines too, so the start of a
# line is a command position exactly as the start of the string is.
_COMMAND_POSITION = re.compile(r"(?:^|[;|&(]|\$\(|&&|\|\|)\s*\{\{([a-z_0-9]+)\}\}",
                               re.MULTILINE)
_ANY_PLACEHOLDER = re.compile(r"\{\{[a-z_0-9]+\}\}")


def command_placeholders(command: str) -> set[str]:
    """The placeholder names this command uses in a program position."""
    return set(_COMMAND_POSITION.findall(command))


def render(command: str) -> str:
    """Substitute placeholders with something inert, in-scope, and correctly shaped."""
    in_command_position = command_placeholders(command)

    def one(match: re.Match) -> str:
        name = match.group(0)[2:-2]
        return COMMAND_STANDIN if name in in_command_position else VALUE_STANDIN

    return _ANY_PLACEHOLDER.sub(one, command)
