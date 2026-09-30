"""agent_auth: an agent-invoked WSTG case runs authenticated from the
engagement's VERIFIED sessions, or not at all -- never unauthenticated while
claiming otherwise.

The wire is `_merge_agent_auth`, exercised here against the REAL
`credentials.auth_inputs` (not a re-implementation): the agent's own target
values win, credentials arrive as HANDLES (never plaintext), and a target with
no verified session is returned unchanged so the case skips out loud.
"""

import asyncio
import json

from orchestrator import credentials as C

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop"


def _run(tmp_path, monkeypatch, case_target, *, seed=True):
    import orchestrator.database as db_mod
    monkeypatch.setattr(db_mod, "DB_PATH", str(tmp_path / "aa.db"))
    from orchestrator.main import _merge_agent_auth

    async def go():
        await db_mod.init_db()
        if seed:
            db = await db_mod.get_db()
            cid = await C.store(db, "http://t.example", "a", "u", "p", role="high")
            await C.save_session(db, cid, "t.example:80", token=JWT,
                                 status="verified")
            await db.commit()
            await db.close()
        return await _merge_agent_auth(case_target, "http://t.example")

    return asyncio.run(go())


class TestMergeAgentAuth:
    def test_a_verified_session_fills_missing_credential_fields(self, tmp_path, monkeypatch):
        merged = _run(tmp_path, monkeypatch,
                      {"url": "http://t.example/x",
                       "scope": {"allow_hosts": ["t.example"]}})
        # The case now carries an auth_header HANDLE it did not supply...
        assert "auth_header" in merged
        assert C.HANDLE_RX.fullmatch(merged["auth_header"]), merged["auth_header"]
        # ...and the agent's own fields are preserved untouched.
        assert merged["url"] == "http://t.example/x"
        assert merged["scope"] == {"allow_hosts": ["t.example"]}

    def test_the_agent_value_wins_over_the_credential(self, tmp_path, monkeypatch):
        merged = _run(tmp_path, monkeypatch,
                      {"url": "http://t.example/x", "auth_header": "AGENT_SET"})
        assert merged["auth_header"] == "AGENT_SET"

    def test_no_plaintext_secret_reaches_the_case_target(self, tmp_path, monkeypatch):
        merged = _run(tmp_path, monkeypatch, {"url": "http://t.example/x"})
        assert JWT not in json.dumps(merged), "raw token leaked into the case target"

    def test_no_verified_session_leaves_the_target_unchanged(self, tmp_path, monkeypatch):
        original = {"url": "http://t.example/x",
                    "scope": {"allow_hosts": ["t.example"]}}
        merged = _run(tmp_path, monkeypatch, dict(original), seed=False)
        assert merged == original, "a target with no session must not gain fields"


def test_the_run_case_action_gates_the_merge_on_the_lever():
    """Wiring guard: a run_config key nothing reads is this codebase's signature
    defect. agent_auth must gate the merge in the run_case action."""
    import pathlib
    src = (pathlib.Path(__file__).resolve().parents[1]
           / "orchestrator" / "main.py").read_text()
    assert 'if runcfg.get("agent_auth"):' in src
    assert "await _merge_agent_auth(case_target, target_url)" in src
