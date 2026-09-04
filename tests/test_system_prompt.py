"""The agent's system prompt must reach the model fully resolved.

TOOL_USE_SYSTEM_PROMPT is a plain string with `{placeholder}` markers filled in
by a chain of `.replace()` calls. That design has one failure mode and it is
silent: add a marker to the template, forget the matching replace, and the
model is shown the marker itself. Nothing raises, nothing logs, and the only
symptom is a model copying a broken example.

It happened. The gobuster and ffuf lines read `{_discovery_filter(target_url)}`
-- an expression, not a marker -- and `.replace("{target_url}", ...)` does not
touch it, because the literal `{target_url}` is not a substring of
`(target_url)`. Both DISCOVERY-phase examples carried a raw Python expression
where the size-filter flag belongs.

These tests run the real `render_system_prompt`. A test that re-implemented the
replace chain would have passed throughout the bug's life, since it would have
reproduced the same omission.
"""

import re

import pytest

import orchestrator.main as M

TARGETS = [
    "http://localhost:3000",
    "https://acme.test",
    "http://10.0.0.5:8080",
]

# The response-format section shows literal JSON objects. Those braces are
# content, not placeholders, and must survive rendering untouched.
_JSON_EXAMPLE = re.compile(r'"action"\s*:')


def _leaked(rendered: str) -> list[str]:
    return [m for m in re.findall(r"\{[^}\n]*\}", rendered)
            if not _JSON_EXAMPLE.search(m)]


@pytest.mark.parametrize("target", TARGETS)
def test_no_placeholder_survives_rendering(target):
    assert _leaked(M.render_system_prompt(target)) == []


def test_the_detector_would_actually_catch_a_leak():
    """Guard on the guard. If _leaked's regex stopped matching, every test
    above would pass against a prompt full of unresolved markers."""
    assert _leaked("run x with {not_substituted} here") == ["{not_substituted}"]


def test_json_examples_are_not_mistaken_for_placeholders():
    """The negative control for that detector: the response-format block must
    not be reported as a leak, or the tests above become unfixable noise."""
    out = M.render_system_prompt("http://localhost:3000")
    assert '"action": "run_tool"' in out, "the format block vanished"
    assert _leaked(out) == []


@pytest.mark.parametrize("target", TARGETS)
def test_the_discovery_examples_carry_a_real_flag(target):
    """The specific regression: both examples must end in a usable flag, not an
    expression. gobuster and ffuf take different flags for the same idea."""
    out = M.render_system_prompt(target)
    gob = [l for l in out.splitlines() if l.startswith("- gobuster dir")]
    ffuf = [l for l in out.splitlines() if l.startswith("- ffuf ")]
    assert gob and ffuf, out[:400]
    assert "_discovery_filter" not in out, "the expression reached the model"
    assert "--exclude-length" in gob[0], gob[0]
    assert "-fs " in ffuf[0], ffuf[0]


@pytest.mark.parametrize("target", TARGETS)
def test_the_target_is_substituted_everywhere(target):
    out = M.render_system_prompt(target)
    assert target in out
    # The prompt was Juice-Shop-specific once; no residue may survive for a
    # different target, or the agent is told to attack the wrong host.
    if "juice-shop" not in target:
        assert "juice-shop" not in out


def test_port_defaults_follow_the_scheme():
    assert "-p 443" in M.render_system_prompt("https://acme.test")
    assert "-p 80" in M.render_system_prompt("http://acme.test")
    assert "-p 8080" in M.render_system_prompt("http://acme.test:8080")


def test_every_marker_in_the_template_has_a_replacement():
    """Forward-looking: catches a marker added to the template without a
    matching replace, which is how this broke in the first place."""
    markers = {m for m in re.findall(r"\{[a-z_][a-z0-9_]*\}", M.TOOL_USE_SYSTEM_PROMPT)}
    assert markers, "no markers found -- the template or this regex changed"
    unresolved = markers & set(_leaked(M.render_system_prompt("http://acme.test:8080")))
    assert not unresolved, f"template markers with no replacement: {sorted(unresolved)}"
