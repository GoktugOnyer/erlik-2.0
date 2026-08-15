"""Tests for the exploit-primitive store.

Two things are pinned here.

EXTRACTION/FORMATTING (orchestrator/primitives.py) had no coverage at all, even
though the commit that added it described the module as "pure + unit-tested".

REPLAY (`main._load_primitives`) is the fix for the store not carrying anything
forward. Capture wrote rows and announced each token on the single turn it was
first seen; the table was then read back only by its own de-duplication SELECT.
Carry-forward therefore depended on the LLM message history surviving untrimmed,
and — because every chain phase runs as its own session id — a later phase began
blind to credentials an earlier phase had already captured. The chain test below
is the one that fails without the fix.
"""

import asyncio

import pytest

import orchestrator.database as db_mod
import orchestrator.primitives as P
from orchestrator.primitives import extract_primitives, format_for_agent

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.abcd1234efgh"


# --- extraction -----------------------------------------------------------

def test_extracts_a_jwt():
    prims = extract_primitives(f"token is {JWT} ok", "curl")
    assert [p["kind"] for p in prims] == ["jwt"]
    assert prims[0]["value"] == JWT
    assert prims[0]["tool"] == "curl"


def test_extracts_set_cookie_without_trailing_attributes():
    prims = extract_primitives("Set-Cookie: session=abc123def; Path=/; HttpOnly", "curl")
    cookies = [p["value"] for p in prims if p["kind"] == "cookie"]
    assert cookies == ["session=abc123def"]


def test_extracts_bearer_and_json_token_fields():
    out = 'Authorization: Bearer aaaaaaaaaaaa1234\n{"access_token": "zzzzzzzzzzzz9999"}'
    kinds = {p["kind"] for p in extract_primitives(out)}
    assert "bearer" in kinds
    assert "token" in kinds


def test_extracts_basic_auth_and_csrf():
    out = 'Authorization: Basic YWRtaW46cGFzcw==\ncsrf_token: "Ab3-xY9_zzzzzz"'
    kinds = {p["kind"] for p in extract_primitives(out)}
    assert "basic_auth" in kinds
    assert "csrf" in kinds


def test_repeated_value_is_reported_once():
    prims = extract_primitives(f"{JWT} and again {JWT}")
    assert len(prims) == 1


def test_empty_output_yields_nothing():
    assert extract_primitives("") == []
    assert extract_primitives(None) == []


def test_value_is_truncated_for_storage():
    long_cookie = "Set-Cookie: s=" + "a" * 900
    prims = extract_primitives(long_cookie)
    assert prims and all(len(p["value"]) <= 400 for p in prims)


# --- formatting -----------------------------------------------------------

def test_format_is_empty_when_there_is_nothing_to_say():
    assert format_for_agent([]) == ""


def test_format_lists_each_primitive_with_its_reuse_hint():
    text = format_for_agent(extract_primitives(f"{JWT}"))
    assert "jwt" in text
    assert "Authorization: Bearer" in text


def test_format_respects_the_limit():
    prims = [{"kind": "token", "value": f"value{i}0000", "hint": "h", "tool": "t"}
             for i in range(30)]
    assert format_for_agent(prims, limit=5).count("\n") == 5   # header + 5 rows


def test_format_elides_long_values_for_display():
    prims = [{"kind": "jwt", "value": "x" * 200, "hint": "h", "tool": "t"}]
    assert "…" in format_for_agent(prims)


def test_custom_header_replaces_the_default_lead_in():
    prims = [{"kind": "jwt", "value": "abcdef123456", "hint": "h", "tool": "t"}]
    text = format_for_agent(prims, header="[PRIMITIVES] replayed:")
    assert text.startswith("[PRIMITIVES] replayed:")
    assert "captured from earlier steps" not in text


# --- automatic reuse in commands ------------------------------------------
#
# Announcing a captured credential in the agent's context is not enough. Across
# two real runs against Juice Shop the agent captured a session cookie and then
# never sent it, so every request stayed anonymous, the authenticated surface was
# never reachable, and access-control coverage was zero both times. Reuse has to
# be automatic.

CREDS = [{"kind": "cookie", "value": "token=abc123def456"},
         {"kind": "jwt", "value": JWT}]


def test_bearer_is_attached_to_an_unauthenticated_curl():
    out, note = P.inject_credentials(
        "curl -s http://juice-shop:3000/rest/basket/1", CREDS, target_host="juice-shop")
    assert note == "reused captured bearer"
    assert f'-H "Authorization: Bearer {JWT}"' in out


@pytest.mark.parametrize("cmd, expect", [
    ("sqlmap -u http://juice-shop:3000/x --batch", "--headers="),
    ("ffuf -u http://juice-shop:3000/FUZZ -w l.txt", "-H "),
    ("nuclei -u http://juice-shop:3000", "-H "),
])
def test_other_http_tools_get_the_right_flag(cmd, expect):
    out, note = P.inject_credentials(cmd, CREDS, target_host="juice-shop")
    assert note and expect in out


def test_non_http_tools_are_left_alone():
    for cmd in ("nmap -sV juice-shop", "john hash.txt", "whois juice-shop"):
        out, note = P.inject_credentials(cmd, CREDS, target_host="juice-shop")
        assert note is None and out == cmd


# --- the safety property --------------------------------------------------

def test_credentials_are_never_sent_off_target():
    """A captured session token attached to a request leaving the engagement
    would be credential exfiltration performed by our own tool."""
    cmd = "curl -s https://evil.example.com/collect"
    out, note = P.inject_credentials(cmd, CREDS, target_host="juice-shop")
    assert note is None and out == cmd
    assert JWT not in out


def test_a_mixed_command_touching_another_host_is_refused():
    cmd = "curl -s http://juice-shop:3000/x https://attacker.test/y"
    out, note = P.inject_credentials(cmd, CREDS, target_host="juice-shop")
    assert note is None and out == cmd


def test_a_command_with_no_explicit_url_is_not_guessed_at():
    out, note = P.inject_credentials("curl -s /rest/basket", CREDS, target_host="juice-shop")
    assert note is None


def test_a_different_port_on_the_same_host_is_still_in_scope():
    out, note = P.inject_credentials(
        "curl -s http://juice-shop:8080/x", CREDS, target_host="juice-shop")
    assert note is not None


@pytest.mark.parametrize("cmd", [
    'curl -H "Authorization: Bearer mine" http://juice-shop:3000/x',
    'curl -b "session=mine" http://juice-shop:3000/x',
    'sqlmap -u http://juice-shop:3000/x --cookie="a=b"',
    'ffuf -u http://juice-shop:3000/FUZZ -H "Cookie: a=b"',
])
def test_an_already_authenticated_command_is_untouched(cmd):
    """Re-adding would duplicate the header or override a credential the agent
    chose deliberately."""
    out, note = P.inject_credentials(cmd, CREDS, target_host="juice-shop")
    assert note is None and out == cmd


def test_nothing_happens_without_credentials():
    out, note = P.inject_credentials("curl http://juice-shop:3000/x", [], target_host="juice-shop")
    assert note is None and out == "curl http://juice-shop:3000/x"


# --- credential preference ------------------------------------------------

def test_a_jwt_is_preferred_over_a_weaker_token():
    creds = P.best_credentials([{"kind": "token", "value": "weak12345678"},
                                {"kind": "jwt", "value": JWT}])
    assert creds["bearer"] == JWT


def test_cookie_and_bearer_are_tracked_separately():
    creds = P.best_credentials(CREDS)
    assert creds["bearer"] == JWT
    assert creds["cookie"] == "token=abc123def456"


def test_cookie_is_used_when_no_bearer_exists():
    out, note = P.inject_credentials(
        "curl -s http://juice-shop:3000/x",
        [{"kind": "cookie", "value": "session=xyz789abc"}], target_host="juice-shop")
    assert note == "reused captured cookie"
    assert '-b "session=xyz789abc"' in out


# --- replay (the fix) -----------------------------------------------------

@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    """Point the database module at a throwaway file and build the schema."""
    monkeypatch.setattr(db_mod, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(db_mod, "DB_DIR", tmp_path)
    asyncio.run(db_mod.init_db())
    return tmp_path


def _seed(sessions, primitives):
    """sessions: [(id, chain_id, position)]; primitives: [(session_id, kind, value)]"""
    async def go():
        db = await db_mod.get_db()
        try:
            for sid, chain_id, pos in sessions:
                await db.execute(
                    "INSERT INTO sessions (id, target_url, chain_id, chain_position) "
                    "VALUES (?, ?, ?, ?)",
                    (sid, "http://juice-shop:3000", chain_id, pos))
            for sid, kind, value in primitives:
                await db.execute(
                    "INSERT INTO session_primitives (session_id, kind, value, hint, source_tool) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (sid, kind, value, "reuse it", "curl"))
            await db.commit()
        finally:
            await db.close()
    asyncio.run(go())


def _load(session_id, chain_id=None):
    from orchestrator.main import _load_primitives
    return asyncio.run(_load_primitives(session_id, chain_id))


def test_a_session_reloads_its_own_primitives(temp_db):
    _seed([("s1", None, 0)], [("s1", "jwt", JWT)])
    loaded = _load("s1")
    assert [p["kind"] for p in loaded] == ["jwt"]
    assert loaded[0]["value"] == JWT
    assert loaded[0]["hint"] == "reuse it"
    assert loaded[0]["tool"] == "curl"


def test_a_later_chain_phase_inherits_the_earlier_phase_credentials(temp_db):
    """The regression: phase 2 must see what phase 1 captured."""
    _seed(
        [("s1", "chain-a", 0), ("s2", "chain-a", 1)],
        [("s1", "jwt", JWT)],
    )
    # Without the chain_id the new phase is blind — this was the whole bug.
    assert _load("s2") == []
    # With it, the credential carries forward.
    assert [p["value"] for p in _load("s2", "chain-a")] == [JWT]


def test_replay_is_deduped_across_sibling_sessions(temp_db):
    _seed(
        [("s1", "chain-a", 0), ("s2", "chain-a", 1), ("s3", "chain-a", 2)],
        [("s1", "jwt", JWT), ("s2", "jwt", JWT), ("s2", "cookie", "session=abc123")],
    )
    loaded = _load("s3", "chain-a")
    assert len(loaded) == 2
    assert {p["kind"] for p in loaded} == {"jwt", "cookie"}


def test_other_chains_are_not_leaked_in(temp_db):
    _seed(
        [("s1", "chain-a", 0), ("s2", "chain-a", 1), ("x1", "chain-b", 0)],
        [("s1", "jwt", JWT), ("x1", "cookie", "session=other-chain")],
    )
    values = [p["value"] for p in _load("s2", "chain-a")]
    assert JWT in values
    assert "session=other-chain" not in values


def test_unknown_session_loads_nothing(temp_db):
    _seed([("s1", None, 0)], [("s1", "jwt", JWT)])
    assert _load("does-not-exist") == []


def test_loader_never_raises(monkeypatch, tmp_path):
    """A broken store must not take the session down with it."""
    monkeypatch.setattr(db_mod, "DB_PATH", tmp_path / "nonexistent" / "no.db")
    assert _load("s1") == []
