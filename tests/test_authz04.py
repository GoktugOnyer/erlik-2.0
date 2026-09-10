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
        never conflated — each step sends whichever its role was actually given.

        The arms are separate steps now, because the evaluator reads them
        individually; the conditional `${HT:+...}` shape is what still lets one
        command carry either material.
        """
        commands = {step["name"]: step["command"] for step in case["steps"]}
        high = commands["fetch_as_high_priv"]
        low = commands["fetch_as_low_priv"]
        assert 'Authorization: Bearer $HT' in high and '-b "$HC"' in high
        assert 'Authorization: Bearer $LT' in low and '-b "$LC"' in low
        # The control arm carries no IDENTITY material. It does carry the
        # application's CONFIGURATION — `config_cookie` — because an arm that
        # differed from the others in two respects was not a control at all; see
        # tests/test_every_arm_shares_the_configuration.py. So this checks the
        # identity fields by name rather than using `-b` as a proxy for them.
        anonymous = commands["fetch_anonymously"]
        for fragment in ("$HT", "$HC", "$LT", "$LC", "Authorization",
                         "high_priv", "low_priv"):
            assert fragment not in anonymous, (
                f"the anonymous arm carries {fragment!r}, so it is not anonymous")
        assert "{{config_cookie}}" in anonymous

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
        # By type, not by allow-listing `regex`: the verdict is a typed `idor`
        # evaluator now, and the requirement was never "must be a regex" — it was
        # "must not need a model to be reachable".
        assert all(ev["type"] != "llm" for ev in emitters), (
            "a finding still depends on an llm evaluator")


class TestTheThreeWayDifferential:
    """The comparison is still three-way; what it compares changed.

    It used to hash three normalised bodies and call `low == high` an IDOR. That
    fires on anything two identities legitimately see the same, and measured over
    3 seeded violations and 11 negative controls on Juice Shop it reported FIVE
    false positives — two absent objects, the low identity's own basket, a public
    review list, and a pair of identical 400 denials read as a shared secret.

    The verdict is now the typed `idor` evaluator: did the privileged object, named
    by a marker the OPERATOR supplies, reach the low arm while not reaching an
    anonymous one? The same six intents are checked, and two of them get stronger —
    CSRF normalisation is no longer needed at all, because a token that differs
    between arms cannot affect whether a marker is present.

    These still run the case's REAL commands with a stub `curl` on PATH, so the
    shell logic is exercised rather than paraphrased; only the verdict is read from
    the evaluator instead of from a canary on stdout.
    """

    MARKER = "PRIVILEGED DATA"

    @staticmethod
    def _run(case, high_body, low_body, anon_body, marker=None):
        import asyncio

        from orchestrator.testcase.runner import _run_evaluator, StepResult
        from orchestrator.testcase.schema import Evaluator, TestCase as _Case, TestStep as _Step

        stub = pathlib.Path(os.environ["PYTEST_TMP"])
        (stub / "curl").write_text(
            "#!/bin/bash\n"
            "for a in \"$@\"; do\n"
            "  case \"$a\" in HIGHMAT) echo -n \"$H_BODY\"; exit 0;; \n"
            "                 LOWMAT)  echo -n \"$L_BODY\"; exit 0;; esac\n"
            "done\n"
            "echo -n \"$A_BODY\"\n")
        (stub / "curl").chmod(0o755)
        env = {**os.environ, "PATH": f"{stub}:{os.environ['PATH']}",
               "H_BODY": high_body, "L_BODY": low_body, "A_BODY": anon_body}

        outputs = {}
        for step in case["steps"]:
            cmd = step["command"]
            for k, v in (("{{high_priv_token}}", ""), ("{{high_priv_cookie}}", "HIGHMAT"),
                         ("{{low_priv_token}}", ""), ("{{low_priv_cookie}}", "LOWMAT"),
                         ("{{url_template}}", "http://t.example/x")):
                cmd = cmd.replace(k, v)
            done = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True,
                                  env=env, timeout=30)
            outputs[step["name"]] = StepResult(step=step["name"], command=cmd, success=True,
                                               duration_ms=1, exit_code=done.returncode,
                                               output="HTTP/1.1 200 OK\r\n\r\n" + done.stdout)

        last = case["steps"][-1]
        evaluator = Evaluator(**last["evaluators"][0])
        prior = [outputs[name] for name in outputs if name != last["name"]]
        finding, _, _, _ = asyncio.run(_run_evaluator(
            evaluator, outputs[last["name"]],
            _Case(id=case["id"], name=case["name"], category="Authorization",
                  steps=[_Step(name=last["name"], tool="curl", command="x")]),
            {"url_template": "http://t.example/x",
             "private_object_marker": marker or TestTheThreeWayDifferential.MARKER,
             "high_priv_cookie": "HIGHMAT", "low_priv_cookie": "LOWMAT"},
            None, None, prior))
        return finding, {k: v.output for k, v in outputs.items()}

    @pytest.fixture(autouse=True)
    def _tmp(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PYTEST_TMP", str(tmp_path))

    def test_low_sees_the_privileged_response(self, case):
        """POSITIVE. Measured on DVWA at security=low against
        /vulnerabilities/authbypass/get_user_data.php."""
        finding, out = self._run(case, "PRIVILEGED DATA", "PRIVILEGED DATA", "login page")
        assert finding is not None, out

    def test_a_public_resource_is_not_an_idor(self, case):
        """NEGATIVE, and the trap this exists for. All three identical means the
        resource is public, not that access control failed. Measured on
        /dvwa/css/main.css, and on Juice Shop's /rest/products/1/reviews — which
        publishes every reviewer's email address to anyone who asks."""
        finding, out = self._run(case, "PRIVILEGED DATA", "PRIVILEGED DATA",
                                 "PRIVILEGED DATA")
        assert finding is None, out

    def test_a_low_session_treated_as_anonymous_concludes_nothing(self, case):
        """NEGATIVE. Measured on DVWA at security=high, where the low user gets the
        anonymous response. The marker never reached the low arm, so nothing
        crossed."""
        finding, out = self._run(case, "PRIVILEGED DATA", "login page", "login page")
        assert finding is None, out

    def test_discrimination_is_reported_as_clean(self, case):
        finding, out = self._run(case, "PRIVILEGED DATA", "your own data", "login page")
        assert finding is None, out

    def test_a_csrf_token_alone_does_not_look_like_access_control(self, case):
        """The intent survives, and the mechanism it needed is gone.

        Normalisation existed because every page of a CSRF-bearing app differs
        between two sessions, so a hash comparison reported OK everywhere. A marker
        comparison is simply indifferent to it: the token can differ freely and the
        question — is the privileged object in this response — is unaffected. The
        case no longer strips 32-hex strings at all.
        """
        finding, out = self._run(
            case,
            'PRIVILEGED DATA <input name="user_token" value="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">',
            'PRIVILEGED DATA <input name="user_token" value="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb">',
            "login page")
        assert finding is not None, out

    def test_two_identical_denials_are_not_a_shared_secret(self, case):
        """The fifth false positive, as a test.

        Measured on Juice Shop: GET /api/Addresss/1 answers 400 "Malicious activity
        detected" to BOTH identities. A hash comparison sees `low == high` and
        reports a critical authorization failure on an endpoint that refused
        everyone. A marker comparison sees that the object is in neither arm.
        """
        finding, out = self._run(case, "Malicious activity detected",
                                 "Malicious activity detected", "please log in")
        assert finding is None, out

    def test_an_absent_object_is_not_a_finding(self, case):
        """The first and second false positives: `200 {"data":null}` and
        `404 Not Found`, identical for both identities."""
        for body in ('{"status":"success","data":null}', '{"message":"Not Found"}'):
            finding, out = self._run(case, body, body, "please log in")
            assert finding is None, out


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
