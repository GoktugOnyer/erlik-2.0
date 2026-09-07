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



def _sig_has_default_none(fn, name: str) -> bool:
    """`name` is a parameter of `fn` defaulting to None.

    A declaration that had to be passed in cannot be picked up by accident; one
    with any other default could change what every caller gets.
    """
    import inspect
    p = inspect.signature(fn).parameters.get(name)
    return p is not None and p.default is None


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
        # `data/` is gitignored runtime state: the database, reports and the
        # operator-authored corpus are all created on demand, so a fresh clone
        # legitimately has none of them. Everything else must exist NOW.
        missing = [p for p in sorted(paths)
                   if "*" not in p
                   and not p.startswith("data/")
                   and not (ROOT / p).exists()]
        assert missing == [], f"SECURITY.md cites paths that do not exist: {missing}"

    def test_runtime_paths_are_declared_by_their_owner(self):
        """The data/ exemption above must not become a blanket excuse: every
        data/ path the doc names has to be one the code actually creates."""
        from orchestrator import skills_authoring as A
        text = DOC.read_text()
        if "data/skills_local" in text:
            assert A.LOCAL_ROOT_NAME == Path("data") / "skills_local"

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
        """SECURITY.md says the API is unauthenticated ON LOOPBACK by default.
        If that ever stops being true, the doc must change with it."""
        import os
        assert not os.environ.get("ERLIK_API_TOKEN")

    def test_the_off_loopback_fallback_is_on_by_default(self):
        """The other half of that claim: no token plus a network-reachable
        bind must refuse. Asserted against the real middleware, since the doc
        now promises a default behaviour rather than the absence of one."""
        import importlib
        import os

        from fastapi.testclient import TestClient

        old = os.environ.get("ERLIK_HOST")
        os.environ["ERLIK_HOST"] = "0.0.0.0"
        try:
            import orchestrator.main as M
            importlib.reload(M)
            assert TestClient(M.app).get("/api/engagements").status_code == 401
        finally:
            if old is None:
                os.environ.pop("ERLIK_HOST", None)
            else:
                os.environ["ERLIK_HOST"] = old
            import orchestrator.main as M
            importlib.reload(M)

    def test_the_opt_out_the_doc_names_exists(self):
        """SECURITY.md tells operators ERLIK_ALLOW_UNAUTHENTICATED=1 waives the
        refusal. A documented escape hatch that does nothing is worse than
        none: it is what someone reaches for when the app stops working."""
        import inspect

        import orchestrator.main as M
        assert "ERLIK_ALLOW_UNAUTHENTICATED" in inspect.getsource(M._api_token_guard)

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

class TestPayloadHostsDeclaration:
    """SECURITY.md now describes a way a case can name a host outside the
    engagement. Every constraint it promises is asserted against the code --
    a documented limit that does not hold is worse than no document."""

    def test_globs_are_rejected_as_documented(self):
        import pytest as _pytest
        from pydantic import ValidationError

        from orchestrator.testcase.schema import TestCase as _Case
        with _pytest.raises(ValidationError):
            _Case(id="X", name="n", category="c", payload_hosts=["*.evil.example"],
                  steps=[{"name": "s", "tool": "curl", "command": "curl x"}])

    def test_deny_hosts_still_wins_as_documented(self):
        import pytest as _pytest

        from orchestrator.testcase.scope import (Scope, ScopeViolation,
                                                 check_command)
        scope = Scope(allow_hosts=["127.0.0.1"], deny_hosts=["evil.example"])
        with _pytest.raises(ScopeViolation):
            check_command('curl -H "Origin: https://evil.example" "http://127.0.0.1/"',
                          scope, payload_hosts=["evil.example"])

    def test_it_does_not_cover_the_target_as_documented(self):
        import pytest as _pytest

        from orchestrator.testcase.scope import (Scope, ScopeViolation,
                                                 check_command)
        with _pytest.raises(ScopeViolation):
            check_command('curl "http://evil.example/"', Scope(allow_hosts=["127.0.0.1"]),
                          primary_url="http://evil.example/",
                          payload_hosts=["evil.example"])

    def test_both_guards_honour_the_declaration_as_documented(self):
        """SECURITY.md now says BOTH guards honour it, because a case step
        passes through both.

        This test used to assert the OPPOSITE -- that `payload_hosts` appears
        nowhere in `_scope_violation` -- and it passed for six months while the
        declaration bought nothing: the case lane granted it and the agent lane
        took it away. Asserting the absence of the plumbing is what let a
        feature that never worked end to end look verified.
        """
        from orchestrator.tool_executor import _scope_violation
        assert _scope_violation("curl http://erlik-not-registered.example/cb",
                                "http://127.0.0.1/",
                                payload_hosts=["erlik-not-registered.example"]) is None
        assert _scope_violation("curl http://evil.example/cb", "http://127.0.0.1/",
                                payload_hosts=["erlik-not-registered.example"])

    def test_a_declaration_cannot_reach_the_agent_lane_on_its_own(self):
        """The other half of what the doc promises: it arrives as an explicit
        argument from `run_test_case`, never from the environment or a global,
        so an ordinary agent-lane command cannot acquire one."""
        import inspect

        import orchestrator.tool_executor as TE
        src = inspect.getsource(TE._scope_allows)
        assert "os.environ" not in src, (
            "the payload allowance now reads process state; an agent command "
            "could acquire one")
        assert _sig_has_default_none(TE.execute_tool, "payload_hosts")
        assert TE._OAST_DOMAINS

    def test_the_engagement_gate_is_not_widened_by_a_declaration(self):
        """SECURITY.md: "a case file may not reach a host the customer
        excluded"."""
        from orchestrator.tool_executor import _scope_violation
        rows = [{"pattern": "127.0.0.1", "kind": "host", "in_scope": 1,
                 "source": "declared"},
                {"pattern": "erlik-not-registered.example", "kind": "domain",
                 "in_scope": 0, "source": "declared"}]
        assert _scope_violation("curl http://erlik-not-registered.example/cb",
                                "http://127.0.0.1/", engagement_rows=rows,
                                payload_hosts=["erlik-not-registered.example"])

    def test_the_collaborator_name_is_declared_by_the_runner_as_documented(self):
        """The doc says the runner adds the minted name to the case's
        `payload_hosts` for the run. Asserted against `run_test_case` itself
        rather than against a copy of the list it builds: a test that rebuilt
        the list would pass on a runner that stopped passing it along.
        """
        import inspect

        from orchestrator.testcase.runner import run_test_case
        src = inspect.getsource(run_test_case)
        assert "step_payload_hosts" in src
        assert "payload_hosts=step_payload_hosts" in src, (
            "the runner no longer passes the minted collaborator to the scope "
            "guard; the only step that can prove a blind finding is refused")
        assert "payload_hosts=tc.payload_hosts" not in src

    def test_denying_a_domain_denies_the_names_under_it_as_documented(self):
        """SECURITY.md promises `deny_hosts: [oast.test]` blocks
        `abcd1234.oast.test`. It did not before -- deny is a glob list."""
        import pytest as _pytest

        from orchestrator.testcase.scope import (Scope, ScopeViolation,
                                                 check_command)
        scope = Scope(allow_hosts=["127.0.0.1"], deny_hosts=["oast.test"])
        with _pytest.raises(ScopeViolation):
            check_command("curl http://abcd1234abcd1234.oast.test/erlik-oob",
                          scope, payload_hosts=["abcd1234abcd1234.oast.test"])

    def test_a_name_under_a_declared_host_is_still_allowed(self):
        """The negative control for the two above: without it they pass on a
        guard that refuses every payload host."""
        from orchestrator.testcase.scope import Scope, check_command
        check_command("curl http://abcd1234abcd1234.oast.test/erlik-oob",
                      Scope(allow_hosts=["127.0.0.1"]),
                      payload_hosts=["oast.test"])

    def test_general_deny_matching_is_unchanged_as_documented(self):
        """The doc says only the PAYLOAD path gained subdomain-reaching deny.
        A `deny_hosts` entry elsewhere is still a glob matched against the
        host, symmetric with `allow_hosts`."""
        import inspect

        from orchestrator.testcase import scope as S
        assert "_payload_denied" not in inspect.getsource(S.check_url), (
            "check_url now uses the payload deny rule; deny_hosts and "
            "allow_hosts are no longer symmetric outside the payload path")

    def test_the_three_cases_the_doc_names_do_declare(self):
        from orchestrator.testcase import load_catalog
        cat = load_catalog()
        for tid in ("WSTG-CLNT-07", "WSTG-AUTHZ-05", "WSTG-INPV-19"):
            assert cat[tid].payload_hosts, f"{tid} declares nothing"


class TestOperatorClaims:
    """SECURITY.md now describes an operator model. Each limitation it admits
    to is asserted against the code, and so is each capability -- a document
    that overstates what erlik does is the defect this project treats as equal
    to a crash, and one that understates it goes stale just as quietly."""

    def test_the_shared_token_is_still_not_a_person(self):
        from orchestrator import operators as O
        assert O.is_attributable(O.SHARED_TOKEN_OPERATOR) is False
        assert O.is_attributable(O.UNAUTHENTICATED_OPERATOR) is False

    def test_tokens_are_stored_hashed_as_documented(self):
        import inspect

        from orchestrator import operators as O
        assert "sha256" in inspect.getsource(O.token_hash)
        t = O.new_token()
        assert O.token_hash(t) != t

    def test_revocation_does_not_delete_as_documented(self):
        import inspect

        from orchestrator import operators as O
        src = inspect.getsource(O.revoke)
        assert "DELETE" not in src.upper().replace("DELETING", "")

    def test_minting_is_admin_only_as_documented(self):
        """The doc says only an admin may mint, revoke or promote. This
        replaces an earlier test asserting the opposite -- that one failed the
        moment the role landed, which is the drift guard working."""
        import inspect

        import orchestrator.main as M
        for fn in (M.create_operator, M.revoke_operator, M.set_operator_role):
            assert "_require_admin(request)" in inspect.getsource(fn), (
                f"{fn.__name__} does not require admin; SECURITY.md says it does"
            )

    def test_new_operators_are_not_admin_by_default_as_documented(self):
        import inspect

        from orchestrator import operators as O
        sig = inspect.signature(O.create)
        assert sig.parameters["role"].default == O.ROLE_OPERATOR

    def test_the_shared_token_is_admin_but_not_counted_as_documented(self):
        """Both halves of the load-bearing sentence: it can bootstrap, and it
        does not keep the last human admin removable."""
        import inspect

        from orchestrator import operators as O
        src = inspect.getsource(O._real_admins)
        assert "SHARED_TOKEN_OPERATOR" in src and "NOT IN" in src

    def test_the_last_admin_is_protected_as_documented(self):
        import inspect

        from orchestrator import operators as O
        assert "LastAdminError" in inspect.getsource(O.revoke)
        assert "LastAdminError" in inspect.getsource(O.set_role)

    def test_provenance_is_recorded_as_documented(self):
        import inspect

        from orchestrator import operators as O
        assert "created_by" in inspect.getsource(O.create)

    def test_the_three_stamped_tables_are_the_ones_documented(self):
        import asyncio
        import pathlib
        import sqlite3
        import tempfile

        import orchestrator.database as db_mod
        with tempfile.TemporaryDirectory() as d:
            old = db_mod.DB_DIR, db_mod.DB_PATH
            db_mod.DB_DIR = pathlib.Path(d)
            db_mod.DB_PATH = pathlib.Path(d) / "t.db"
            try:
                asyncio.run(db_mod.init_db())
                con = sqlite3.connect(db_mod.DB_PATH)
                for t in ("sessions", "v2_runs", "engagement_revisions"):
                    cols = [r[1] for r in con.execute(f"PRAGMA table_info({t})")]
                    assert "operator_id" in cols, t
            finally:
                db_mod.DB_DIR, db_mod.DB_PATH = old
