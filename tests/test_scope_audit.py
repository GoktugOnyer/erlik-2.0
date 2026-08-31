"""Report-time scope audit — non-blocking by design.

erlik enforces scope at COMMAND time. This audits the findings that ended up in
a deliverable. It is deliberately NOT a gate:

A finding's URL at the auto-detect site is derived from the executed command,
and that command already passed `_scope_violation`. So this can only fire when
command-time enforcement was off, or on a hostname the MODEL invented. It is a
hallucination detector far more than a legal control, and blocking a client's
exports over a host erlik never sent a packet to is the wrong severity —
finding 27 in the recorded corpus (session target `http://dvwa`, finding url
`http://juice-shop:3000`) would 409 all five exports for a real session.

The scope it checks against is SNAPSHOTTED at session creation. Reading ambient
env at report time would make the verdict depend on which process served the
request, so the same session could audit clean in one shell and dirty in
another. A legal boundary must not be re-derived from ambient state months
after the engagement.
"""

import json
import sqlite3
from pathlib import Path

import pytest

import orchestrator.main as M
from orchestrator.tool_executor import extract_hosts

from tests import corpus  # noqa: E402

TARGET = "http://juice-shop:3000"


def _f(fid, url):
    return {"id": fid, "vuln_type": "XSS", "severity": "medium",
            "url": url, "parameter": "", "evidence": "e"}


class TestSharedExtraction:
    def test_audit_uses_the_executors_own_extractor(self):
        """A second host-extraction implementation would drift, and then the
        report would classify hosts by rules the executor does not apply."""
        assert extract_hosts("curl http://a.example/x http://b.example/y") == \
            ["a.example", "b.example"]

    def test_malformed_authority_does_not_raise(self):
        extract_hosts("curl 'http://a[b].com/'")
        M._scope_audit([_f(1, "http://a[b].com/")], TARGET, [])


class TestVerdicts:
    def test_in_scope_finding(self):
        a = M._scope_audit([_f(1, "http://juice-shop:3000/x")], TARGET, [])
        assert a["audited"] and a["in_scope"] == 1 and a["out_of_scope"] == 0
        assert a["by_id"][1] == "in_scope"

    def test_model_invented_host_is_flagged(self):
        """Positive control: the case this actually detects."""
        a = M._scope_audit([_f(1, "http://totally-made-up.example/admin")], TARGET, [])
        assert a["out_of_scope"] == 1
        assert a["by_id"][1] == "out_of_scope"
        assert "totally-made-up.example" in a["hosts"]

    def test_snapshot_widens_scope_not_ambient_env(self, monkeypatch):
        """The verdict must come from the snapshot, so setting the env at
        report time changes nothing."""
        finding = [_f(1, "http://cb.client-oast.example/x")]
        assert M._scope_audit(finding, TARGET, [])["out_of_scope"] == 1
        assert M._scope_audit(finding, TARGET, ["*.client-oast.example"])["out_of_scope"] == 0
        # ambient env is NOT consulted
        monkeypatch.setenv("ERLIK_SCOPE_EXTRA_HOSTS", "*.client-oast.example")
        assert M._scope_audit(finding, TARGET, [])["out_of_scope"] == 1

    def test_no_target_is_unaudited_not_clean(self):
        a = M._scope_audit([_f(1, "http://x.example/")], "", [])
        assert a["audited"] is False


class TestTheAuditIsLoadBearing:
    def test_mutation_check(self, monkeypatch):
        """A no-op assertion ("the corpus audits clean") would pass against a
        `return {}` stub. Force _scope_allows to refuse everything and assert
        the audit actually notices."""
        import orchestrator.tool_executor as T
        findings = [_f(i, "http://juice-shop:3000/x") for i in range(5)]
        assert M._scope_audit(findings, TARGET, [])["out_of_scope"] == 0
        monkeypatch.setattr(T, "_scope_allows", lambda h, t, e: False)
        assert M._scope_audit(findings, TARGET, [])["out_of_scope"] == 5


class TestScopeBlockRendering:
    def test_unaudited_renders_loudly(self):
        """The failure mode of a governance field is that nobody notices it is
        empty. It must never render as a blank section."""
        out = "\n".join(M.render_scope_block({"audited": False}, TARGET))
        assert "SCOPE NOT AUDITED" in out

    def test_missing_audit_dict_also_renders_loudly(self):
        assert "SCOPE NOT AUDITED" in "\n".join(M.render_scope_block({}, TARGET))
        assert "SCOPE NOT AUDITED" in "\n".join(M.render_scope_block(None, TARGET))

    def test_clean_audit_states_the_target(self):
        a = M._scope_audit([_f(1, "http://juice-shop:3000/x")], TARGET, [])
        out = "\n".join(M.render_scope_block(a, TARGET))
        assert "SCOPE NOT AUDITED" not in out
        assert TARGET in out
        assert "out-of-scope" not in out

    def test_offending_host_is_named(self):
        a = M._scope_audit([_f(1, "http://made-up.example/x")], TARGET, [])
        out = "\n".join(M.render_scope_block(a, TARGET))
        assert "made-up.example" in out
        assert "invented by the model" in out


class TestAgainstTheRealCorpus:
    def test_finding_27_is_flagged_but_nothing_is_blocked(self):
        """The row that motivated dropping the 409 gate: a dvwa session holding
        a juice-shop URL. It must be visible in the report and must not stop
        the export."""
        db = Path(__file__).resolve().parents[1] / "data" / "pentest.db"
        if not db.exists():
            pytest.skip("no recorded corpus")
        corpus.require("findings")
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        rows = [dict(r) for r in con.execute(
            "SELECT f.id, f.url, s.target_url FROM findings f "
            "JOIN sessions s ON s.id = f.session_id")]
        mismatched = 0
        for r in rows:
            a = M._scope_audit([_f(r["id"], r["url"])], r["target_url"], [])
            if a["audited"] and a["out_of_scope"]:
                mismatched += 1
        # Exactly one in the whole 216-finding corpus. Pinned: a broadened
        # audit that starts flagging ordinary findings fails here.
        assert mismatched == 1, f"{mismatched} findings flagged, expected 1"

    def test_audit_adds_a_key_and_changes_nothing_else(self):
        f = _f(1, "http://juice-shop:3000/x")
        before = dict(f)
        M._scope_audit([f], TARGET, [])
        assert f == before, "audit must not mutate findings"


class TestSnapshotIsPersisted:
    def test_session_creation_records_the_scope(self, tmp_path, monkeypatch):
        import asyncio
        import orchestrator.database as db_mod
        monkeypatch.setattr(db_mod, "DB_DIR", tmp_path)
        monkeypatch.setattr(db_mod, "DB_PATH", tmp_path / "t.db")
        monkeypatch.setenv("ERLIK_SCOPE_EXTRA_HOSTS", "*.client-oast.example")
        asyncio.run(db_mod.init_db())

        async def go():
            d = await db_mod.get_db()
            try:
                await d.execute(
                    "INSERT INTO sessions (id, target_url, system_prompt, scope_extra) "
                    "VALUES (?, ?, ?, ?)",
                    ("s1", TARGET, "t", json.dumps(M.current_scope_extra())))
                await d.commit()
                cur = await d.execute("SELECT scope_extra FROM sessions WHERE id='s1'")
                return (await cur.fetchone())[0]
            finally:
                await d.close()
        stored = json.loads(asyncio.run(go()))
        assert "*.client-oast.example" in stored

    def test_current_scope_extra_reads_env(self, monkeypatch):
        monkeypatch.setenv("ERLIK_SCOPE_EXTRA_HOSTS", "a.example, b.example")
        monkeypatch.delenv("ERLIK_DOCKER_TARGET_HOST", raising=False)
        assert M.current_scope_extra() == ["a.example", "b.example"]
