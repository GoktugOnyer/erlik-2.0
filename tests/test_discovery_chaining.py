"""Tests for discovery feeding tool targeting.

Two runs — Juice Shop and DVWA — showed the agent discovering paths and then
attacking invented ones: it ran `sqlmap -u "http://dvwa/endpoint?param=test"`
while gobuster had already found /config, /database, /php.ini, /phpinfo.php and
/server-status.

The cause was a one-character mismatch, not agent behaviour.
_parse_tool_output emitted bare names ("  config (status 301)") because gobuster
3.x prints them without a leading slash, while _build_chaining_hint matched on
`  (/\\S+)` and so found NOTHING. Discovery worked, the hint builder worked, and
between them every discovered path was dropped — so the agent was handed no
concrete targets and made some up.

Paths are now normalised to a leading slash in the parser, which is the single
place all consumers read.
"""

import pytest

from orchestrator.main import _build_chaining_hint, _parse_tool_output

GOBUSTER = """===============================================================
Gobuster v3.8.2
===============================================================
config               (Status: 301) [Size: 337] [--> http://dvwa/config/]
database             (Status: 301) [Size: 339]
php.ini              (Status: 200) [Size: 154]
phpinfo.php          (Status: 302) [Size: 0] [--> login.php]
api                  (Status: 301) [Size: 300]
==============================================================="""

FFUF = """admin                   [Status: 200, Size: 100, Words: 10]
rest                    [Status: 301, Size: 120, Words: 12]"""

DIRB = """+ http://dvwa/config (CODE:301|SIZE:337)
+ http://dvwa/phpinfo.php (CODE:200|SIZE:154)"""


# --- the regression -------------------------------------------------------

def test_gobuster_paths_are_normalised_to_a_leading_slash():
    """gobuster 3.x prints bare names; every downstream consumer expects /path."""
    parsed = _parse_tool_output("gobuster", GOBUSTER, "gobuster dir -u http://dvwa -w w")
    assert "DISCOVERED PATHS" in parsed
    for want in ("/config", "/database", "/php.ini", "/phpinfo.php", "/api"):
        assert f"  {want} (status" in parsed, want
    # and never the bare form that broke the chain
    assert "  config (status" not in parsed


def test_discovered_paths_reach_the_agent_as_concrete_commands():
    """The whole point: discovery must produce targets, not just a list."""
    parsed = _parse_tool_output("gobuster", GOBUSTER, "gobuster dir -u http://dvwa -w w")
    hint = _build_chaining_hint("gobuster", parsed, "gobuster dir -u http://dvwa -w w",
                                "http://dvwa")
    assert hint, "discovery produced no next-step hints"
    assert "http://dvwa/config" in hint or "http://dvwa/api" in hint


def test_an_api_path_becomes_an_injection_target():
    """Instead of inventing /endpoint?param=test, aim at something discovered."""
    parsed = _parse_tool_output("gobuster", GOBUSTER, "gobuster dir -u http://dvwa -w w")
    hint = _build_chaining_hint("gobuster", parsed, "gobuster dir -u http://dvwa -w w",
                                "http://dvwa")
    assert "sqlmap" in hint
    assert "/api" in hint


@pytest.mark.parametrize("tool, raw", [
    ("gobuster", GOBUSTER),
    ("ffuf", FFUF),
    ("dirb", DIRB),
])
def test_every_discovery_tool_produces_hints(tool, raw):
    parsed = _parse_tool_output(tool, raw, f"{tool} -u http://dvwa")
    hint = _build_chaining_hint(tool, parsed, f"{tool} -u http://dvwa", "http://dvwa")
    assert "DISCOVERED PATHS" in parsed, tool
    assert hint, tool


def test_dirb_absolute_urls_become_paths_not_urls():
    """dirb prints full URLs; appending one to the target would give
    http://dvwa/http://dvwa/config."""
    parsed = _parse_tool_output("dirb", DIRB, "dirb http://dvwa")
    assert "  /config (status" in parsed
    assert "http://dvwa/http" not in _build_chaining_hint(
        "dirb", parsed, "dirb http://dvwa", "http://dvwa")


# --- target correctness ---------------------------------------------------

def test_hints_use_the_session_target_not_a_hardcoded_host():
    parsed = _parse_tool_output("gobuster", GOBUSTER, "gobuster dir -u http://dvwa -w w")
    hint = _build_chaining_hint("gobuster", parsed, "gobuster dir -u http://dvwa -w w",
                                "http://dvwa")
    assert "juice-shop" not in hint


def test_no_hints_without_discoveries():
    parsed = _parse_tool_output("gobuster", "no results found", "gobuster dir -u http://x -w w")
    assert _build_chaining_hint("gobuster", parsed, "gobuster dir -u http://x -w w",
                                "http://x") == ""
