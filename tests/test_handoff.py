"""Deterministic results become the AI agent's starting point.

erlik had both lanes and no path between them:

    main.py mentions v2_findings :  0
    v2 lane writes recon_context :  0

A deterministic run produced facts no agent ever saw, and every agent run
started from a bare URL — rediscovering ports, endpoints and technologies a
scan had already established.
"""

import asyncio

import pytest

import orchestrator.database as db_mod
import orchestrator.main as M
from orchestrator import handoff as H


class F:
    def __init__(self, vt, url="", ev="", tc="WSTG-X"):
        self.vuln_type, self.url, self.evidence, self.test_case_id = vt, url, ev, tc


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(db_mod, "DB_DIR", tmp_path)
    monkeypatch.setattr(db_mod, "DB_PATH", tmp_path / "t.db")
    asyncio.run(db_mod.init_db())
    return tmp_path / "t.db"


def bridge(findings, url="http://juice-shop:3000", run="r1"):
    async def go():
        d = await db_mod.get_db()
        try:
            n = await H.bridge_run(d, run, url, findings)
            await d.commit()
            return n
        finally:
            await d.close()
    return asyncio.run(go())


class TestKeysMatchTheAgent:
    def test_target_key_is_identical_to_mains(self):
        """A different normalisation means the agent looks under a key the
        handoff never wrote — the bridge would silently reach nothing."""
        for u in ("http://juice-shop:3000", "https://x.test", "http://a.b/c?d=1",
                  "juice-shop:3000"):
            assert H.target_key(u) == M._target_key(u), u

    def test_unparseable_target_writes_nothing(self, db):
        assert bridge([F("X")], url="") == 0


class TestBridge:
    def test_findings_reach_recon_context(self, db):
        assert bridge([F("NoSQL Operator Injection", "http://t/s", "$ne")]) == 1

    def test_idempotent_on_rerun(self, db):
        f = [F("NoSQL Operator Injection", "http://t/s", "$ne")]
        assert bridge(f) == 1
        assert bridge(f) == 0, "a rerun multiplied the agent's context"

    def test_findings_without_a_type_are_skipped(self, db):
        assert bridge([F(None)]) == 0

    def test_dict_findings_work_too(self, db):
        assert bridge([{"vuln_type": "X", "url": "http://t/", "evidence": "e",
                        "test_case_id": "WSTG-Y"}]) == 1

    @pytest.mark.parametrize("vt,bucket", [
        ("Spring Actuator Environment Dump Exposed", "endpoint"),
        ("phpinfo() Page Exposed", "endpoint"),
        ("Technology Version Disclosed", "endpoint"),
        ("NoSQL Operator Injection", "finding"),
        ("LDAP Injection", "finding"),
    ])
    def test_classification(self, vt, bucket):
        """`endpoint` reads to the agent as somewhere to look; `finding` as
        already established."""
        assert H._classify(vt) == bucket


class TestAgentActuallySeesIt:
    def test_deterministic_results_appear_in_the_starting_context(self, db):
        bridge([F("Spring Actuator Environment Dump Exposed",
                  "http://juice-shop:3000/actuator/env", "datasource creds",
                  "WSTG-CONF-02")])
        ctx = asyncio.run(M._get_target_memory_context(
            "a-different-session", "http://juice-shop:3000"))
        assert ctx, "agent got no starting context"
        assert "Actuator" in ctx or "WSTG-CONF-02" in ctx

    def test_a_different_target_sees_nothing(self, db):
        """Context is keyed per target; a scan of one host must not leak into a
        run against another."""
        bridge([F("X", "http://a.test/", "e")], url="http://a.test")
        ctx = asyncio.run(M._get_target_memory_context("s2", "http://b.test"))
        assert "X" not in ctx


class TestRecallIsNotInflated:
    def test_bridge_does_not_write_to_findings(self, db):
        """`findings` is what recall and precision are computed from. Copying
        deterministic results there would count one finding twice and make
        agent-lane numbers incomparable with every run before it."""
        import sqlite3
        bridge([F("NoSQL Operator Injection", "http://t/s", "$ne")])
        con = sqlite3.connect(db)
        try:
            assert con.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0
        finally:
            con.close()

    def test_module_never_inserts_into_findings(self):
        import inspect
        src = inspect.getsource(H)
        assert "INSERT INTO findings" not in src


class TestBriefStaysShort:
    def test_empty_input_produces_nothing(self):
        assert H.format_for_agent([]) == ""

    def test_brief_is_facts_not_methodology(self):
        """Injected guidance costs recall dose-dependently, so this is evidence
        rather than instruction."""
        out = H.format_for_agent([{"context_type": "endpoint", "key": "k", "value": "v"}])
        assert "already confirmed" in out
        assert len(out) < 600

    def test_brief_is_capped(self):
        rows = [{"context_type": "endpoint", "key": f"k{i}", "value": "v" * 300}
                for i in range(100)]
        assert len(H.format_for_agent(rows)) < 4000


class TestFailureIsNonFatal:
    def test_persistence_guards_the_bridge(self):
        import inspect
        from orchestrator.testcase import persistence
        src = inspect.getsource(persistence)
        i = src.index("bridge_run")
        window = src[i:i + 500]
        assert "except Exception" in window
        assert "skipped:" in window, "a failed bridge must say so, not vanish"
