"""WSTG-AUTHZ-04 — the case that skipped on every recorded run.

Three things were wrong, and only the first is the one it was filed for:

  1. It required `low_priv_token`/`high_priv_token` and sent
     `-H "Authorization: Bearer ..."`, so it was BEARER-ONLY by construction.
     `auth_inputs` correctly withholds those handles for a cookie session, so
     on DVWA — and on most PHP/Rails/Django apps — no number of verified
     sessions could satisfy it.

  2. Its only finding path was an LLM judge shown ONLY the low-privilege
     response ("you are given the response a low-privileged user got"). It
     never saw the privileged one, so it could not tell a leak from a resource
     that is simply public — and with no model reachable it produced nothing.

  3. Its first step asserted `^[45]\\d\\d` against a BODY (no `-w
     "%{http_code}"`) under `when: previous_failure`, on the FIRST step where
     there is no previous step. It could never fire.
"""

import asyncio
import os
import pathlib
import subprocess
import warnings

import pytest
import yaml

warnings.filterwarnings("ignore", category=DeprecationWarning)

CASE = pathlib.Path("tests_catalog/wstg/AUTHZ-04_idor.yaml")
T = "http://t.example"


@pytest.fixture(scope="module")
def case():
    return yaml.safe_load(CASE.read_text())


class TestTheCaseAcceptsEitherMaterial:
    def test_it_no_longer_requires_a_bearer_token(self, case):
        req = case["target_schema"]["required"]
        assert "low_priv_token" not in req and "high_priv_token" not in req

    def test_each_role_is_an_alternation(self, case):
        groups = [set(g) for g in case["target_schema"]["required_any"]]
        assert {"high_priv_token", "high_priv_cookie"} in groups
        assert {"low_priv_token", "low_priv_cookie"} in groups

    def test_the_command_sends_each_shape_correctly(self, case):
        """A cookie in a Bearer header authenticates nothing, so the two are
        never conflated — the step sends whichever it was actually given."""
        cmd = case["steps"][0]["command"]
        assert 'Authorization: Bearer $HT' in cmd
        assert 'Authorization: Bearer $LT' in cmd
        assert '-b "$HC"' in cmd and '-b "$LC"' in cmd

    def test_the_broken_first_evaluator_is_gone(self, case):
        """`^[45]\\d\\d` against a body, under previous_failure, on step one."""
        for step in case["steps"]:
            for ev in step.get("evaluators") or []:
                pat = ev.get("pattern") or ""
                assert not pat.startswith("^[45]"), (
                    f"{step['name']} still matches a status code against a body")

    def test_the_verdict_does_not_depend_on_a_model(self, case):
        """Ollama is often offline. A case whose only verdict comes from a
        model is not part of the deterministic lane."""
        emitters = [ev for s in case["steps"] for ev in (s.get("evaluators") or [])
                    if ev.get("emit_finding")]
        assert emitters, "the case emits nothing at all"
        assert all(ev["type"] == "regex" for ev in emitters), (
            "a finding still depends on an llm evaluator")


class TestTheThreeWayDifferential:
    """`low == high` alone is not a finding — a public asset is identical for
    everyone. `low != high` alone is not a clean bill of health either — on any
    app with a per-session CSRF token, EVERY page differs. The anonymous fetch
    is what separates them.

    These run the case's REAL command with a stub `curl` on PATH, so the shell
    logic and the normalisation are exercised, not a paraphrase of them.
    """

    @staticmethod
    def _run(case, high_body, low_body, anon_body):
        stub = pathlib.Path(os.environ["PYTEST_TMP"])
        (stub / "curl").write_text(
            "#!/bin/bash\n"
            "for a in \"$@\"; do\n"
            "  case \"$a\" in HIGHMAT) echo -n \"$H_BODY\"; exit 0;; \n"
            "                 LOWMAT)  echo -n \"$L_BODY\"; exit 0;; esac\n"
            "done\n"
            "echo -n \"$A_BODY\"\n")
        (stub / "curl").chmod(0o755)
        cmd = case["steps"][0]["command"]
        for k, v in (("{{high_priv_token}}", ""), ("{{high_priv_cookie}}", "HIGHMAT"),
                     ("{{low_priv_token}}", ""), ("{{low_priv_cookie}}", "LOWMAT"),
                     ("{{url_template}}", "http://t.example/x")):
            cmd = cmd.replace(k, v)
        env = {**os.environ, "PATH": f"{stub}:{os.environ['PATH']}",
               "H_BODY": high_body, "L_BODY": low_body, "A_BODY": anon_body}
        out = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True,
                             env=env, timeout=30).stdout
        for verdict in ("ERLIK-AUTHZ-IDOR", "ERLIK-AUTHZ-INCONCLUSIVE",
                        "ERLIK-AUTHZ-OK"):
            if verdict in out:
                return verdict, out
        return None, out

    @pytest.fixture(autouse=True)
    def _tmp(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PYTEST_TMP", str(tmp_path))

    def test_low_sees_the_privileged_response(self, case):
        """POSITIVE. Measured on DVWA at security=low against
        /vulnerabilities/authbypass/get_user_data.php."""
        v, out = self._run(case, "PRIVILEGED DATA", "PRIVILEGED DATA", "login page")
        assert v == "ERLIK-AUTHZ-IDOR", out

    def test_a_public_resource_is_not_an_idor(self, case):
        """NEGATIVE, and the trap this exists for. All three identical means
        the resource is public, not that access control failed. Measured on
        /dvwa/css/main.css."""
        v, out = self._run(case, "body{}", "body{}", "body{}")
        assert v == "ERLIK-AUTHZ-INCONCLUSIVE", out

    def test_a_low_session_treated_as_anonymous_concludes_nothing(self, case):
        """NEGATIVE. Measured on DVWA at security=high, where the low user gets
        the anonymous response — the test cannot conclude from that."""
        v, out = self._run(case, "PRIVILEGED DATA", "login page", "login page")
        assert v == "ERLIK-AUTHZ-INCONCLUSIVE", out

    def test_discrimination_is_reported_as_ok(self, case):
        v, out = self._run(case, "PRIVILEGED DATA", "your own data", "login page")
        assert v == "ERLIK-AUTHZ-OK", out

    def test_a_csrf_token_alone_does_not_look_like_access_control(self, case):
        """Without normalisation every page of a CSRF-bearing app differs, and
        the case would report OK everywhere. Verified against DVWA: all seven
        pages checked differed byte-for-byte between two users purely because
        of the per-session token."""
        v, out = self._run(
            case,
            'DATA <input name="user_token" value="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">',
            'DATA <input name="user_token" value="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb">',
            "login page")
        assert v == "ERLIK-AUTHZ-IDOR", out

    def test_normalisation_cannot_mask_a_difference_in_the_data(self, case):
        """The control on the control: it strips tokens and whitespace, not
        content."""
        v, out = self._run(case, "user_id=1,2,3", "user_id=1", "login page")
        assert v == "ERLIK-AUTHZ-OK", out


class TestPerRoleCookiesArePlumbed:
    @staticmethod
    def _inputs(tmp_path, material):
        import orchestrator.database as db_mod
        from orchestrator import credentials as C
        old = db_mod.DB_DIR, db_mod.DB_PATH
        db_mod.DB_DIR = tmp_path
        db_mod.DB_PATH = tmp_path / "p.db"
        try:
            async def go():
                await db_mod.init_db()
                db = await db_mod.get_db()
                for role in ("low", "high"):
                    cid = await C.store(db, T, role, role, "p", role=role)
                    await C.save_session(db, cid, C.target_key(T),
                                         status="verified", **{material: "MATERIAL"})
                await db.commit()
                out = await C.auth_inputs(db, T)
                st = await C.auth_state(db, T)
                await db.close()
                return out, st
            return asyncio.run(go())
        finally:
            db_mod.DB_DIR, db_mod.DB_PATH = old

    def test_cookie_sessions_yield_per_role_cookies(self, tmp_path):
        ai, st = self._inputs(tmp_path, "cookie")
        assert {"low_priv_cookie", "high_priv_cookie"} <= set(ai)
        assert st["access_control_ready"] is True

    def test_token_sessions_still_yield_per_role_tokens(self, tmp_path):
        ai, st = self._inputs(tmp_path, "token")
        assert {"low_priv_token", "high_priv_token"} <= set(ai)
        assert st["access_control_ready"] is True

    def test_the_two_are_never_conflated(self, tmp_path):
        """A cookie must never be offered as a token: it would be sent in a
        Bearer header, authenticate nothing, and the case would compare two
        anonymous responses while reporting itself authenticated."""
        ai, _ = self._inputs(tmp_path, "cookie")
        assert "low_priv_token" not in ai and "high_priv_token" not in ai
        ai2, _ = self._inputs(tmp_path / "b", "token")
        assert "low_priv_cookie" not in ai2 and "high_priv_cookie" not in ai2

    def test_the_handle_resolves_and_fails_closed(self, tmp_path):
        import orchestrator.database as db_mod
        from orchestrator import credentials as C
        old = db_mod.DB_DIR, db_mod.DB_PATH
        db_mod.DB_DIR = tmp_path
        db_mod.DB_PATH = tmp_path / "h.db"
        try:
            async def go():
                await db_mod.init_db()
                db = await db_mod.get_db()
                cid = await C.store(db, T, "l", "l", "p", role="low")
                sid = await C.save_session(db, cid, C.target_key(T),
                                           cookie="THE-COOKIE", status="verified")
                await db.commit()
                good, _ = await C.resolve(db, C.handle(sid, "low_priv_cookie"))
                bad, _ = await C.resolve(db, C.handle(sid, "not_a_field"))
                await db.close()
                return good, bad
            good, bad = asyncio.run(go())
        finally:
            db_mod.DB_DIR, db_mod.DB_PATH = old
        assert "THE-COOKIE" in good
        assert "not_a_field" in bad, (
            "an unknown field resolved to something; it must stay a handle so "
            "the runner fails the step rather than sending it unauthenticated")

    def test_the_scope_gate_does_not_mistake_the_new_handles_for_hosts(self):
        from orchestrator.testcase.scope import Scope, check_command
        sc = Scope(allow_hosts=["t.example"], allow_ports=[80])
        for f in ("low_priv_cookie", "high_priv_cookie"):
            check_command(f'curl -b "ERLIK_SECRET.abc123.{f}" http://t.example/x', sc)


class TestAlternationInBuildTarget:
    CASE = {"id": "WSTG-AUTHZ-04", "name": "IDOR", "category": "AUTHZ",
            "severity": "high",
            "target_schema": {"required": ["url_template"],
                              "required_any": [["high_priv_token", "high_priv_cookie"],
                                               ["low_priv_token", "low_priv_cookie"]]}}

    def test_either_member_satisfies_a_group(self):
        from orchestrator.testcase import sweep as S
        for hi, lo in (("high_priv_token", "low_priv_token"),
                       ("high_priv_cookie", "low_priv_cookie"),
                       ("high_priv_token", "low_priv_cookie")):
            t, why = S.build_target(self.CASE, T, {}, {hi: "H", lo: "L"})
            assert t is not None, f"{hi}/{lo}: {why}"
            assert t[hi] == "H" and t[lo] == "L"

    def test_an_unsatisfiable_group_is_a_NAMED_skip(self):
        from orchestrator.testcase import sweep as S
        t, why = S.build_target(self.CASE, T, {}, {"high_priv_cookie": "H"})
        assert t is None
        assert "two authenticated accounts" in why, why

    def test_a_case_without_required_any_is_unchanged(self):
        """The construct must be inert for every other case in the catalogue."""
        from orchestrator.testcase import sweep as S
        plain = {"id": "X", "name": "x", "category": "INPV", "severity": "high",
                 "target_schema": {"required": ["url", "parameter"]}}
        a, _ = S.build_target(plain, T, {"X": {"url": "{base}/p", "parameter": "q"}})
        assert a == S.build_target(
            {**plain, "target_schema": {**plain["target_schema"], "required_any": []}},
            T, {"X": {"url": "{base}/p", "parameter": "q"}})[0]


class TestTheFindingCarriesItsUrl:
    def test_url_template_is_used_when_there_is_no_url(self):
        """A finding with no url cannot be attached to an asset, cannot be
        scope-audited, and renders as N/A in the client report."""
        import inspect
        from orchestrator.testcase import runner
        src = inspect.getsource(runner)
        assert 'target.get("url") or target.get("url_template")' in src

    def test_url_template_is_declarable(self):
        """Otherwise AUTHZ-04 falls back to the base URL, where no privileged
        object lives — it would run and conclude nothing."""
        from orchestrator.testcase import declared as D
        assert "url_template" in D.DECLARABLE
        assert "url_template" in D.PATH_FIELDS
        assert D.validate("url_template", "/vulnerabilities/authbypass/x.php") == ""
        assert D.validate("url_template", "http://evil.example/x")
