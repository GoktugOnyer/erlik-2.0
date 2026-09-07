"""Four defects the Juice Shop baseline surfaced, and the tests that missed them.

Every deterministic-lane step passes through TWO independent scope guards in
series: `testcase/scope.py::check_command`, which honours a case's declared
`payload_hosts`, and `tool_executor::_scope_violation`, which knew nothing about
the declaration. So the declaration was granted by the first and taken away by
the second. Measured 2026-09-06 by running the real cases:

    WSTG-CLNT-07   evil.oastify.com              ALLOWED -- via _OAST_DOMAINS
    WSTG-INPV-19   169.254.169.254, localhost    ALLOWED -- via local/private
    WSTG-AUTHZ-05  erlik-not-registered.example  REFUSED -- "SCOPE: out-of-scope"

Two of the three passed for reasons unrelated to the declaration, so the feature
looked like it worked while granting nothing. Every test in
tests/test_payload_hosts.py stops at `check_command`; not one reaches
`execute_tool`, which is exactly why a feature that never worked end to end
passed a whole file. These tests run the real cases through `run_test_case`.
"""

from __future__ import annotations

import asyncio

import pytest

from orchestrator.testcase import find_by_id, load_catalog, run_test_case
from tests.targets.fixtures import _native_mode, targets, tls_cert  # noqa: F401
from tests.targets.servers import serve_oauth

CATALOG = load_catalog()


def _run(case_id: str, **target):
    target.setdefault("scope", {"allow_hosts": ["127.0.0.1"]})
    with _native_mode():
        return asyncio.run(run_test_case(find_by_id(case_id), target))


@pytest.fixture(params=["strict", "prefix", "open"])
def oauth(request):
    srv, port = serve_oauth(request.param)
    try:
        yield request.param, port
    finally:
        srv.shutdown()


class TestBothGuardsHonourTheDeclaration:
    """The gap itself, asserted through the real execution path."""

    DECLARING = ["WSTG-CLNT-07", "WSTG-INPV-19", "WSTG-AUTHZ-05"]

    @pytest.mark.parametrize("cid", DECLARING)
    def test_no_declared_payload_host_is_refused_by_either_guard(self, cid, targets):
        """`SCOPE:` is the agent lane, `scope violation` the case lane. A step
        refused by either is a step the declaration did not actually buy."""
        base = targets["web"]
        port = int(base.rsplit(":", 1)[1])
        r = _run(cid, url=base + "/search", parameter="q", host="127.0.0.1",
                 scheme="http", port=port,
                 scope={"allow_hosts": ["127.0.0.1"], "allow_ports": [port]})
        refused = [(s.step, s.error) for s in r.steps
                   if (s.error or "").startswith(("SCOPE:", "scope violation"))]
        assert not refused, refused

    def test_an_undeclared_host_is_still_refused_by_the_agent_lane(self):
        """The negative control. Without it the tests above pass on a guard
        that stopped checking anything."""
        from orchestrator.tool_executor import _scope_violation
        assert _scope_violation('curl http://evil.example/x', 'http://127.0.0.1/')

    def test_the_declaration_does_not_admit_a_different_host(self):
        from orchestrator.tool_executor import _scope_violation
        assert _scope_violation('curl http://evil.example/x', 'http://127.0.0.1/',
                                payload_hosts=["erlik-not-registered.example"])

    def test_it_admits_the_declared_host_and_names_under_it(self):
        from orchestrator.tool_executor import _scope_violation
        for host in ("erlik-not-registered.example",
                     "app.acme.com.erlik-not-registered.example"):
            assert _scope_violation(f'curl http://{host}/cb', 'http://127.0.0.1/',
                                    payload_hosts=["erlik-not-registered.example"]) is None, host

    def test_a_sibling_of_the_declared_name_is_not_admitted(self):
        """Label boundaries, not substrings -- the same rule the case lane's
        `_is_declared_payload` applies, so the two guards agree."""
        from orchestrator.tool_executor import _scope_violation
        for host in ("erlik-not-registered.example.evil.net",
                     "notmyerlik-not-registered.example"):
            assert _scope_violation(f'curl http://{host}/', 'http://127.0.0.1/',
                                    payload_hosts=["erlik-not-registered.example"]), host

    def test_the_engagement_gate_is_checked_before_the_allowance(self):
        """An engagement is the customer's authorisation record. A case file
        must never reach a host the customer excluded, so the declaration may
        only ever widen this lane's own target heuristic.

        Asserted BEHAVIOURALLY. The first version compared source offsets and
        failed on its own docstring, which names `payload_hosts` before the
        code does -- the same trap as the guard that matched the word `role` in
        its own prose.
        """
        from orchestrator.tool_executor import _scope_violation

        rows = [{"pattern": "127.0.0.1", "kind": "host", "in_scope": 1,
                 "source": "declared"},
                {"pattern": "erlik-not-registered.example", "kind": "domain",
                 "in_scope": 0, "source": "declared"}]
        why = _scope_violation("curl http://erlik-not-registered.example/cb",
                               "http://127.0.0.1/", engagement_rows=rows,
                               payload_hosts=["erlik-not-registered.example"])
        assert why, ("a case file reached a host the customer EXCLUDED; the "
                     "declaration must not override an engagement")

        # And the control: with no engagement, the same declaration admits it,
        # so the refusal above is the engagement's doing and not the guard
        # refusing everything.
        assert _scope_violation("curl http://erlik-not-registered.example/cb",
                                "http://127.0.0.1/",
                                payload_hosts=["erlik-not-registered.example"]) is None

    def test_the_runner_hands_the_same_list_to_both_guards(self):
        """One list, or the two guards disagree about what the case declared."""
        import inspect

        from orchestrator.testcase.runner import run_test_case as R
        src = inspect.getsource(R)
        assert src.count("payload_hosts=step_payload_hosts") == 2, (
            "the two guards are no longer given the same declaration")


class TestARefusalIsNotAResult:
    """`execute_tool`'s docstring says callers must skip detection when
    `executed` is False, because a refusal string once became detection input.
    The case lane was such a caller and ran its evaluators anyway."""

    def test_a_refused_step_reports_not_assessed_rather_than_clean(self, targets):
        r = _run("WSTG-INPV-19", url=targets["web"] + "/search", parameter="q",
                 scope={"allow_hosts": ["127.0.0.1"], "allow_ports": [1]})
        assert r.not_assessed, "a wholly refused case reported nothing at all"
        assert all(not s.executed for s in r.steps), [s.step for s in r.steps]

    def test_a_refused_step_carries_the_structured_flags(self, targets):
        r = _run("WSTG-INPV-19", url=targets["web"] + "/search", parameter="q",
                 scope={"allow_hosts": ["127.0.0.1"], "allow_ports": [1]})
        assert all(s.denied for s in r.steps), [(s.step, s.denied) for s in r.steps]

    def test_a_step_that_ran_is_not_marked_refused(self, targets):
        """The negative control for both of the above."""
        base = targets["web"]
        port = int(base.rsplit(":", 1)[1])
        r = _run("WSTG-CONF-02", url=base, host="127.0.0.1",
                 scope={"allow_hosts": ["127.0.0.1"], "allow_ports": [port]})
        assert r.steps and all(s.executed and not s.denied for s in r.steps)

    def test_an_executor_refusal_carries_the_flags_from_the_executor(self):
        """THE path that matters, and the one the first version of these tests
        missed. A case-lane refusal builds its own StepResult, so it proves
        nothing about whether `raw`'s flags survive; deleting
        `executed=`/`denied=` from the constructor left every assertion here
        green. WSTG-CONF-06's `put_probe` is refused by safe mode INSIDE
        `execute_tool`, so its flags can only have come from the executor.
        """
        srv, port = serve_oauth("strict")
        try:
            r = _run("WSTG-CONF-06", url=f"http://127.0.0.1:{port}",
                     host="127.0.0.1",
                     scope={"allow_hosts": ["127.0.0.1"], "allow_ports": [port]})
        finally:
            srv.shutdown()
        put = next(s for s in r.steps if s.step == "put_probe")
        assert put.executed is False, "the executor's `executed` did not survive"
        assert put.denied is True, "the executor's `denied` did not survive"
        ran = [s for s in r.steps if s.step != "put_probe"]
        assert ran and all(s.executed and not s.denied for s in ran), (
            "the control: the steps that DID run must not be marked refused")

    def test_an_executor_refusal_is_reported_not_assessed(self):
        """The evaluator loop must be skipped for it, and the run must say the
        step was not assessed rather than leaving a silent clean verdict."""
        srv, port = serve_oauth("strict")
        try:
            r = _run("WSTG-CONF-06", url=f"http://127.0.0.1:{port}",
                     host="127.0.0.1",
                     scope={"allow_hosts": ["127.0.0.1"], "allow_ports": [port]})
        finally:
            srv.shutdown()
        na = [n for n in r.not_assessed if n.step == "put_probe"]
        assert na, r.not_assessed
        assert na[0].evaluator == "admission", na[0]

    def test_an_oob_step_the_executor_refused_is_not_counted_as_sent(self,
                                                                     monkeypatch):
        """`oob_sent` was set just BEFORE `execute_tool`, so a blind probe the
        executor refused still reported "payloads were sent, go check your
        collaborator" -- the exact untrue label the variable's own comment says
        it exists to prevent, three lines above the bug.

        Safe mode is the refusal here because it is the one an operator can
        trigger without touching scope, and the collaborator is operator-
        supplied so the run takes the un-pollable branch that emits that text.
        """
        from orchestrator.testcase import schema as SCH
        srv, port = serve_oauth("strict")
        tc = find_by_id("WSTG-CONF-06")
        # Mark the safe-mode-refused step as the out-of-band one, so a refused
        # OOB step is what the run has to account for.
        put = next(st for st in tc.steps if st.name == "put_probe")
        monkeypatch.setattr(put, "oob", True)
        monkeypatch.setattr(tc, "needs_collaborator", True)
        try:
            with _native_mode():
                r = asyncio.run(run_test_case(tc, {
                    "url": f"http://127.0.0.1:{port}", "host": "127.0.0.1",
                    "collaborator_host": "abc.burpcollaborator.net",
                    "scope": {"allow_hosts": ["127.0.0.1"],
                              "allow_ports": [port]}}))
        finally:
            srv.shutdown()
        sent = [n for n in r.not_assessed
                if n.step == "collaborator_poll" and "were sent" in n.reason]
        assert not sent, (
            "a probe the executor refused was reported as sent: " 
            + repr([n.reason for n in sent]))
        assert SCH  # the import is the monkeypatch target's module, kept explicit

    def test_every_executor_refusal_sets_denied(self):
        """The flag was on two of five returns, which made it useless as a
        classifier and left the message prefix as the only signal."""
        import re

        import orchestrator.tool_executor as TE
        src = open(TE.__file__).read()
        body = src[src.index("async def execute_tool"):]
        body = body[:body.index('\n    # Check container is running')]
        refusals = re.findall(r'"executed": False[^}]*\}', body)
        assert len(refusals) >= 5, f"expected 5+ refusal returns, found {len(refusals)}"
        missing = [r for r in refusals if '"denied": True' not in r]
        assert not missing, f"refusal returns without denied=True: {missing}"


class TestTheOAuthProbesFireOnTheFlawAndNotOnTheControl:
    """The suffix probe reported a CRITICAL against a server validating
    redirect_uri strictly by origin -- correct behaviour. The suffix landed in
    the PATH, so the redirect host was the target itself and the code never left
    the origin."""

    def test_verdict_matches_the_server(self, oauth):
        mode, port = oauth
        r = _run("WSTG-AUTHZ-05", url=f"http://127.0.0.1:{port}/oauth/authorize",
                 host="127.0.0.1", scheme="http", port=port,
                 scope={"allow_hosts": ["127.0.0.1"], "allow_ports": [port]})
        got = sorted({f.vuln_type for f in r.findings})
        if mode == "strict":
            assert got == [], f"accused a correct server: {got}"
        else:
            assert got, "the flaw was not reported"
            assert any("redirect_uri" in v for v in got), got

    def test_the_payload_names_an_attacker_host_on_every_target_shape(self):
        """It was built by appending to `{{url}}`, which put the suffix in the
        port on one shape and in the path on another. Only a bare origin was
        right -- and this case's schema note says `url` is the authorise
        endpoint, i.e. exactly the shape that was wrong."""
        from urllib.parse import urlparse

        from orchestrator.testcase.runner import _render
        st = next(x for x in CATALOG["WSTG-AUTHZ-05"].steps
                  if x.name == "redirect_uri_suffix_bypass")
        for scheme, host, url in (
                ("http", "h.test", "http://h.test:3000"),
                ("http", "h.test", "http://h.test:3000/oauth/authorize"),
                ("https", "h.test", "https://h.test/oauth/authorize"),
                ("http", "127.0.0.1", "http://127.0.0.1:8080/authorize")):
            cmd = _render(st.command, {"url": url, "host": host, "scheme": scheme,
                                       "cookie": "", "auth_header": "",
                                       "client_id": "cid"})
            ru = cmd.split("redirect_uri=")[1].split('"')[0]
            h = urlparse(ru).hostname
            assert h and h.endswith(".erlik-not-registered.example"), (url, ru, h)

    @pytest.mark.parametrize("out", [
        "302 http://127.0.0.1:37649/oauth/authorize.erlik-not-registered.example?code=abc",
        "302 http://app.acme.com/oauth/error?bad=https://erlik-not-registered.example/cb",
        "302 http://app.acme.com/login?next=%2Fauth%3Fru%3Derlik-not-registered.example",
        "400 erlik-not-registered.example rejected",
        "302 https://erlik-not-registered.example.attacker.net/cb",
    ])
    def test_the_evaluators_do_not_fire_on_a_mention(self, out):
        """A server that REFUSES the probe commonly echoes the value it
        rejected. The old pattern was the bare domain, unanchored."""
        import re
        # The two redirect_uri steps only. `state_parameter_not_required`
        # legitimately fires on any 302 carrying a `code=`, because ITS probe
        # is the one that omits `state` -- asserting over the whole case would
        # have made this test about a different step's correct behaviour.
        for st in CATALOG["WSTG-AUTHZ-05"].steps:
            if not st.name.startswith("redirect_uri"):
                continue
            for ev in st.evaluators:
                if ev.type == "regex":
                    assert not re.search(ev.pattern, out), (st.name, out)

    @pytest.mark.parametrize("out", [
        "302 https://app.acme.com.erlik-not-registered.example/cb?code=a",
        "302 https://erlik-not-registered.example/cb?code=a",
        "302 https://app.acme.com@erlik-not-registered.example/cb?code=a",
        "302 https://erlik-not-registered.example:8443/cb?code=a",
    ])
    def test_the_evaluators_still_fire_on_a_real_redirect(self, out):
        """The negative control for the parametrised test above: without it
        both pass on a pattern that matches nothing at all."""
        import re
        assert any(re.search(ev.pattern, out)
                   for st in CATALOG["WSTG-AUTHZ-05"].steps
                   if st.name.startswith("redirect_uri")
                   for ev in st.evaluators if ev.type == "regex"), out


class TestConf07CanRun:
    """`port` was optional, and `build_target` filled optional fields only from
    a profile -- never from the derived facts -- so `{{port}}` rendered empty on
    every run. A shell fallback then picked 443 and the guard, seeing a bare
    host, defaulted to 80. `tls_scan` was refused on every https target."""

    @pytest.mark.parametrize("base", ["https://app.example.test",
                                      "https://app.example.test:8443"])
    def test_neither_step_is_refused_on_any_https_target(self, base):
        from orchestrator.testcase.runner import _render
        from orchestrator.testcase.scope import Scope, check_command
        from orchestrator.testcase.sweep import build_target
        tc = CATALOG["WSTG-CONF-07"]
        t, why = build_target({"id": tc.id,
                               "target_schema": tc.target_schema.model_dump()},
                              base, {})
        assert t, why
        for st in tc.steps:
            check_command(_render(st.command, t), Scope(**t["scope"]),
                          payload_hosts=tc.payload_hosts)

    def test_the_port_reaches_the_case(self):
        from orchestrator.testcase.sweep import build_target
        tc = CATALOG["WSTG-CONF-07"]
        t, _ = build_target({"id": tc.id,
                             "target_schema": tc.target_schema.model_dump()},
                            "https://app.example.test:8443", {})
        assert t["port"] == 8443

    def test_the_command_carries_the_port_the_guard_reads(self):
        """Rendering it into a shell variable is what hid it: `$P` is not a port
        the extractor can read, so it scored the bare host as 80."""
        from orchestrator.testcase.runner import _render
        from orchestrator.testcase.sweep import build_target
        tc = CATALOG["WSTG-CONF-07"]
        t, _ = build_target({"id": tc.id,
                             "target_schema": tc.target_schema.model_dump()},
                            "https://app.example.test:8443", {})
        for st in tc.steps:
            assert "app.example.test:8443" in _render(st.command, t), st.name

    def test_a_guess_still_may_not_fill_an_optional_field(self):
        """The allowance is for DERIVED facts only. A guess filling a field
        silently is what made 22 cases report confident negatives about
        parameters nobody had named.

        Asserted BEHAVIOURALLY: the first version grepped the source for the
        word "guessed" and failed on the comment that explains why guesses are
        excluded.
        """
        from orchestrator.testcase.sweep import build_target
        case = {"id": "X", "target_schema": {"required": ["url"],
                                             "optional": ["parameter", "port"]}}
        t, why = build_target(case, "https://app.example.test:8443", {})
        assert t, why
        assert t["port"] == 8443, "a derived fact did not reach an optional field"
        assert "parameter" not in t, (
            "the `?q=` guess filled an optional field; a guess may fill nothing")


class TestTheBaselineClassifierUsesTheFlags:
    def test_it_no_longer_reads_the_message_to_decide_if_it_ran(self):
        import importlib.util
        import pathlib
        import sys

        root = pathlib.Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location(
            "cb_flags", root / "scripts" / "case_baseline.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules["cb_flags"] = mod
        spec.loader.exec_module(mod)

        from orchestrator.testcase.runner import StepResult

        def rec(**kw):
            return StepResult(step=kw.pop("step"), command="c", success=False,
                              output="", duration_ms=0, **kw)

        class R:
            findings = []
            not_assessed = []
            steps = [
                rec(step="agent_scope", error="SCOPE: out-of-scope host 'y'",
                    executed=False, denied=True),
                rec(step="toolset", error="TOOLSET: segment runs 'nc'",
                    executed=False, denied=True),
                rec(step="creds", error="refusing to send it unauthenticated",
                    executed=False, denied=True),
                rec(step="safemode", error="SAFE_MODE: HTTP write verb",
                    executed=False, denied=True),
                rec(step="broken", error="curl: (7) connection refused"),
            ]

        n = mod._normalise(R())
        assert n["refused"] == ["agent_scope", "creds", "toolset"], n
        assert n["denied"] == ["safemode"], n
        assert n["failed_steps"] == ["broken"], n
