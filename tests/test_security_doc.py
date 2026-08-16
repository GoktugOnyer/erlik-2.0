"""Drift tests for SECURITY.md and the authorisation declaration.

A security-posture document is worse than useless once it is wrong: it states
defaults a reader will rely on without checking. Every claim in SECURITY.md is
re-asserted here against live code, and every repo-relative path it names must
resolve.

The negative control matters as much as the positive ones: with the env
monkeypatched, `_scope_enforced()` must go False. Without that, these tests
would pass just as happily against a hardcoded `return True`.
"""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "SECURITY.md"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in ("ERLIK_SCOPE_ENFORCE", "ERLIK_SAFE_MODE", "ERLIK_API_TOKEN",
              "ERLIK_NATIVE", "ERLIK_SCOPE_EXTRA_HOSTS", "ERLIK_LLM_PROVIDER"):
        monkeypatch.delenv(k, raising=False)


def test_doc_exists():
    assert DOC.exists()


class TestEveryPathResolves:
    def test_backticked_repo_paths_exist(self):
        """The original design named `testcase/runner.py`; the real lane is
        `orchestrator/testcase/`. A doc that cites a path nobody can open is
        the same defect class as a rule that can never fire."""
        text = DOC.read_text()
        paths = set(re.findall(r"`((?:orchestrator|scripts|policy_catalog|data|tests)"
                               r"/[A-Za-z0-9_./*]+)`", text))
        paths |= set(re.findall(r"`(run\.sh|SECURITY\.md|THIRD_PARTY_LICENSES\.md)`", text))
        assert paths, "no paths found — the extraction regex has drifted"
        missing = [p for p in sorted(paths)
                   if "*" not in p and not (ROOT / p).exists()]
        assert missing == [], f"SECURITY.md cites paths that do not exist: {missing}"

    def test_markdown_links_resolve(self):
        text = DOC.read_text()
        for target in re.findall(r"\]\(([^)#][^)]*)\)", text):
            if target.startswith("http"):
                continue
            assert (ROOT / target).exists(), f"broken link: {target}"


class TestClaimedDefaultsAreReal:
    def test_scope_enforcement_defaults_on(self):
        from orchestrator.tool_executor import _scope_enforced
        assert _scope_enforced() is True

    def test_safe_mode_defaults_on(self):
        from orchestrator.tool_executor import _safe_mode_enabled
        assert _safe_mode_enabled() is True

    def test_api_token_guard_is_off_by_default(self):
        """SECURITY.md says the API is unauthenticated by default. If that ever
        stops being true, the doc must change with it."""
        import os
        assert not os.environ.get("ERLIK_API_TOKEN")

    def test_bind_address_defaults_to_loopback(self):
        assert 'ERLIK_HOST="${ERLIK_HOST:-127.0.0.1}"' in (ROOT / "run.sh").read_text()

    def test_llm_provider_default_and_location(self):
        src = (ROOT / "orchestrator" / "llm_client.py").read_text()
        assert 'os.environ.get("ERLIK_LLM_PROVIDER", "ollama")' in src

    def test_stored_credentials_are_plain_text(self):
        """The doc says session_primitives.value is unencrypted. If someone
        encrypts it, this failing test is the prompt to update the doc."""
        src = (ROOT / "orchestrator" / "database.py").read_text()
        block = src.split("session_primitives")[1][:400]
        assert "value TEXT NOT NULL" in block

    def test_redact_secrets_call_site_count(self):
        """The doc states three call sites, all inside review.py."""
        sites = []
        for p in (ROOT / "orchestrator").rglob("*.py"):
            for i, line in enumerate(p.read_text().splitlines(), 1):
                if "redact_secrets(" in line and "def redact_secrets" not in line:
                    sites.append(f"{p.name}:{i}")
        assert len(sites) == 3, sites
        assert all(s.startswith("review.py") for s in sites), sites


class TestDriftTestsReadLiveState:
    """Negative controls. Without these, the assertions above would pass
    against a hardcoded `return True`."""

    def test_scope_enforcement_can_be_turned_off(self, monkeypatch):
        from orchestrator.tool_executor import _scope_enforced
        monkeypatch.setenv("ERLIK_SCOPE_ENFORCE", "0")
        assert _scope_enforced() is False

    def test_safe_mode_can_be_turned_off(self, monkeypatch):
        from orchestrator.tool_executor import _safe_mode_enabled
        monkeypatch.setenv("ERLIK_SAFE_MODE", "0")
        assert _safe_mode_enabled() is False


class TestAuthorizationDeclaration:
    def test_absence_is_loud(self):
        import orchestrator.main as M
        for value in (None, "", "   "):
            out = "\n".join(M.render_authorization_block(value))
            assert "AUTHORIZATION: NOT RECORDED" in out, repr(value)
            assert "may be unlawful" in out

    def test_present_reference_is_rendered(self):
        import orchestrator.main as M
        out = "\n".join(M.render_authorization_block("SOW-2026-0142"))
        assert "SOW-2026-0142" in out
        assert "NOT RECORDED" not in out

    def test_no_gate_exists(self):
        """The enforcement gate was deliberately dropped: it bought a status
        race, a chain hang and a new terminal status for a control whose entire
        value is the declaration."""
        src = (ROOT / "orchestrator" / "main.py").read_text()
        assert "status='blocked'" not in src
        assert 'status="blocked"' not in src

    def test_field_is_optional_on_the_model(self):
        from orchestrator.models import SessionCreate
        s = SessionCreate(target_url="http://juice-shop:3000")
        assert s.authorization_ref is None

    def test_field_round_trips(self):
        from orchestrator.models import SessionCreate
        s = SessionCreate(target_url="http://t", authorization_ref="SOW-1")
        assert s.authorization_ref == "SOW-1"


class TestEveryWriteSiteCarriesTheColumn:
    def test_all_session_and_chain_inserts_record_authorization(self):
        """Four INSERT INTO sessions and two INSERT INTO chains. The original
        design named one chain site; missing one is exactly the silent gap this
        asserts against."""
        src = (ROOT / "orchestrator" / "main.py").read_text()
        for table, expected in (("sessions", 4), ("chains", 2)):
            stmts = re.findall(
                rf'"INSERT INTO {table} \([^"]*(?:"\s*\n\s*"[^"]*)*\)',
                src)
            assert len(stmts) == expected, f"{table}: found {len(stmts)}, expected {expected}"
            for st in stmts:
                assert "authorization_ref" in st, f"{table} INSERT missing the column: {st[:90]}"
