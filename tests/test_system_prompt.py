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


# --- Dynamic phase-scoped tool menu (ERLIK_DYNAMIC_MENU, OFF by default) ---
#
# These run the real render_system_prompt, never a re-implementation of the
# transform (CLAUDE.md #3). The transform lives in main.py; a test that rebuilt
# it here would reproduce whatever bug it carried and pass.

_MENU_START = "TOOL USAGE EXAMPLES"
_MENU_END = "AVAILABLE RESOURCES ON THIS SYSTEM:"
# Matches an OTHER-TOOLS index line: "- <phase>: toolA, toolB".
_INDEX_LINE = re.compile(r"^- (recon|discovery|vuln_scan|exploitation): (.+)$")


def _menu_block(rendered: str) -> str:
    return rendered[rendered.index(_MENU_START):rendered.index(_MENU_END)]


def _all_example_tools() -> set[str]:
    """Every tool named by a `- <tool> ...` example line in the raw template's
    examples block (other sections also use `- ` bullets — scope to the block)."""
    block = _menu_block(M.TOOL_USE_SYSTEM_PROMPT)
    return {t for t in (M._example_tool(l) for l in block.split("\n")) if t}


def _menu_tools(rendered: str) -> set[str]:
    """Tools the rendered menu makes visible: expanded example lines PLUS the
    name-only index. This is the declare-don't-drop surface."""
    tools: set[str] = set()
    for line in _menu_block(rendered).split("\n"):
        m = _INDEX_LINE.match(line)
        if m:  # index line first -- its leading token is a phase label, not a tool
            tools.update(x.strip() for x in m.group(2).split(","))
            continue
        tool = M._example_tool(line)
        if tool:
            tools.add(tool)
    return tools


def test_the_menu_block_markers_still_bound_the_block():
    """Guard on the guard (CLAUDE.md #5): if the header/footer wording drifts,
    _menu_block() would slice the wrong region and the menu tests would assert
    against nothing. Keep this canary honest."""
    raw = M.TOOL_USE_SYSTEM_PROMPT
    assert raw.index(_MENU_START) < raw.index(_MENU_END)
    block = _menu_block(M.render_system_prompt("http://acme.test"))
    assert block.startswith(_MENU_START)
    assert "- nmap" in block and "- sqlmap" in block


def test_off_is_the_default_and_leaves_todays_prompt_untouched():
    """OFF by default: no flag, no args -> none of the dynamic-menu scaffolding
    appears, and the flat example list is intact."""
    out = M.render_system_prompt("http://acme.test:8080")
    assert "CURRENT PHASE:" not in out
    assert "OTHER TOOLS (available now" not in out
    # The flat list carried repeated and multi-line examples; they must survive.
    assert out.count("- zap-cli") == 3
    assert "- jwt_tool <token> -X a" in out


def test_off_path_is_byte_identical_however_it_is_disabled(monkeypatch):
    """The no-op guarantee: env-unset, explicit False, and a stray env `0` must
    each produce exactly the same string, and exactly today's prompt."""
    monkeypatch.delenv("ERLIK_DYNAMIC_MENU", raising=False)
    baseline = M.render_system_prompt("http://acme.test:8080")
    assert M.render_system_prompt("http://acme.test:8080", dynamic_menu=False) == baseline
    monkeypatch.setenv("ERLIK_DYNAMIC_MENU", "0")
    assert M.render_system_prompt("http://acme.test:8080") == baseline
    # ...and enabling it is the ONLY thing that changes the output.
    monkeypatch.setenv("ERLIK_DYNAMIC_MENU", "1")
    assert M.render_system_prompt("http://acme.test:8080") != baseline


def test_explicit_override_beats_the_env(monkeypatch):
    monkeypatch.setenv("ERLIK_DYNAMIC_MENU", "1")
    assert "CURRENT PHASE:" not in M.render_system_prompt(
        "http://acme.test", dynamic_menu=False)
    monkeypatch.setenv("ERLIK_DYNAMIC_MENU", "0")
    assert "CURRENT PHASE:" in M.render_system_prompt(
        "http://acme.test", dynamic_menu=True)


@pytest.mark.parametrize("phase", ["recon", "discovery", "vuln_scan", "exploitation"])
def test_on_expands_only_the_current_phase(phase):
    """ON: the phase's own tools keep their full example line; a tool from a
    different phase does not (it drops to the name-only index)."""
    out = M.render_system_prompt("http://acme.test:8080",
                                 dynamic_menu=True, phase=phase)
    assert f"CURRENT PHASE: {phase.replace('_', ' ').upper()}" in out
    block = _menu_block(out)
    expanded = {M._example_tool(l) for l in block.split("\n")
                if M._example_tool(l) and not _INDEX_LINE.match(l)}
    for tool, tphase in M._DYNAMIC_MENU_TOOL_PHASE.items():
        if tphase == phase:
            assert tool in expanded, f"{tool} ({phase}) should be expanded"
        else:
            assert tool not in expanded, f"{tool} ({tphase}) leaked into {phase}"
    assert "curl" in expanded, "curl is universal and must never be collapsed"


@pytest.mark.parametrize("phase", ["recon", "discovery", "vuln_scan", "exploitation"])
def test_on_declares_every_tool_it_does_not_expand(phase):
    """Declare-don't-drop (CLAUDE.md #2): a tool hidden for a phase must still
    be named in the menu, so the model knows it is reachable. The union of
    expanded + indexed tools equals the full flat set, with nothing lost."""
    out = M.render_system_prompt("http://acme.test:8080",
                                 dynamic_menu=True, phase=phase)
    assert _menu_tools(out) == _all_example_tools()


def test_the_declare_check_would_catch_a_dropped_tool():
    """Guard on the guard (CLAUDE.md #5): _menu_tools must actually read the
    index, or the declare-don't-drop test above passes against a menu that
    silently dropped every out-of-phase tool."""
    recon = M.render_system_prompt("http://acme.test", dynamic_menu=True, phase="recon")
    # hydra is an exploitation tool: absent from the recon examples, present in
    # the index. A _menu_tools that ignored the index would miss it.
    assert "hydra" not in {M._example_tool(l) for l in _menu_block(recon).split("\n")
                           if M._example_tool(l) and not _INDEX_LINE.match(l)}
    assert "hydra" in _menu_tools(recon)


@pytest.mark.parametrize("phase", ["recon", "discovery", "vuln_scan", "exploitation"])
def test_on_resolves_every_placeholder_too(phase):
    """The menu transform runs before substitution, so the ON path must leave
    no marker behind either -- the whole reason render_system_prompt exists."""
    out = M.render_system_prompt("http://acme.test:8080",
                                 dynamic_menu=True, phase=phase)
    assert _leaked(out) == []
    assert "_discovery_filter" not in out


def test_an_unknown_phase_falls_back_to_recon():
    out = M.render_system_prompt("http://acme.test", dynamic_menu=True, phase="nonsense")
    assert "CURRENT PHASE: RECON" in out
