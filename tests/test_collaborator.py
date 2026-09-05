"""Out-of-band detection, and the honest limits of testing it here.

A whole class of vulnerability produces no in-band evidence: blind SQLi beyond
timing, blind SSRF, blind XXE, blind command injection. The payload succeeds
and the response is identical to a failure; the only proof is that the TARGET
contacted a name the tester controls.

erlik ADVERTISED this and delivered none of it. `collaborator_host` was an
optional target field on WSTG-INPV-07, WSTG-INPV-19 and WSTG-AUTHZ-05, and
`declared.DECLARABLE` let an operator configure one -- and no step command in
the catalogue referenced `{{collaborator_host}}`. An operator could declare a
collaborator and every probe ignored it.

WHAT IS VERIFIED HERE, and what is not.

Verified end to end through the real runner: a run mints a unique name, an OOB
step renders it into its payload, the poll correlates an interaction back to
that run, and the finding carries it as evidence. Also verified: every way this
can fail to observe something reports that it could not observe it, rather than
reporting a clean result.

NOT verified: a real DNS round trip. That needs a name resolvable from the
internet and a receiver outside the target's network -- `*.localhost` does not
resolve, and this environment's egress policy blocks reaching interact.sh. So
the interaction is delivered to a local receiver speaking the same API rather
than by the target resolving the minted subdomain. The correlation, the
polling, the honest-failure paths and the finding are real; the DNS hop is not
exercised, and an interact.sh adapter has to be written against a live instance
before anyone claims otherwise.
"""

import json
import os

import pytest

from orchestrator import collaborator as C
from tests.targets.fixtures import run_case, targets, tls_cert  # noqa: F401
from tests.targets.servers import Collaborator, Ssrf, serve


@pytest.fixture
def receiver():
    Collaborator.reset()
    srv, port = serve(Collaborator)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        srv.shutdown()


@pytest.fixture
def oast(receiver, monkeypatch):
    monkeypatch.setenv("ERLIK_OAST_DOMAIN", "oast.test")
    monkeypatch.setenv("ERLIK_OAST_RECEIVER", receiver)
    return receiver


@pytest.fixture
def oast_off(monkeypatch):
    monkeypatch.delenv("ERLIK_OAST_DOMAIN", raising=False)
    monkeypatch.delenv("ERLIK_OAST_RECEIVER", raising=False)


class TestItIsOffUnlessConfigured:
    def test_off_by_default(self, oast_off):
        assert C.is_enabled() is False
        assert C.status()["enabled"] is False

    def test_the_reason_names_the_variable(self, oast_off):
        assert "ERLIK_OAST_DOMAIN" in C.status()["reason"]

    def test_a_domain_without_a_receiver_is_not_enough(self, monkeypatch):
        """Payloads could be planted and never read back, which is worse than
        not planting them: it looks like a check ran."""
        monkeypatch.setenv("ERLIK_OAST_DOMAIN", "oast.test")
        monkeypatch.delenv("ERLIK_OAST_RECEIVER", raising=False)
        st = C.status()
        assert st["enabled"] is False
        assert "ERLIK_OAST_RECEIVER" in st["reason"]


class TestCorrelation:
    def test_each_probe_gets_its_own_name(self, oast):
        a, b = C.new_token(), C.new_token()
        assert a != b
        assert C.host_for(a) != C.host_for(b)

    def test_the_name_is_the_token_under_the_domain(self, oast):
        t = C.new_token()
        assert C.host_for(t) == f"{t}.oast.test"

    def test_a_forged_token_is_refused(self, oast):
        """The token is a correlation key that comes back from outside; a
        value that is not one must not be built into a name."""
        for bad in ("", "../x", "not-hex", "a" * 8):
            with pytest.raises((ValueError, C.CollaboratorError)):
                C.host_for(bad)

    def test_only_this_tokens_interactions_are_returned(self, oast, receiver,
                                                        monkeypatch):
        """A shared collaborator sees everyone's traffic. Returning another
        probe's hit would attribute a finding to the wrong payload.

        The receiver is made to return EVERYTHING, deliberately. Its own
        server-side filter masked this completely: deleting the poller's
        correlation entirely passed the whole suite, because the only rows the
        receiver ever sent back were already the right ones. Correlation is
        the client's job -- a self-hosted collaborator returns the account's
        traffic -- so it has to be tested against a receiver that does not do
        it for us.
        """
        import urllib.request
        monkeypatch.setattr(Collaborator, "LEAKS_EVERYTHING", True)
        mine, theirs = C.new_token(), C.new_token()
        for t in (mine, theirs):
            urllib.request.urlopen(f"{receiver}/{t}/hit", timeout=5).read()
        got = C.poll(mine)
        assert len(got) == 1 and got[0]["token"] == mine, got

    def test_the_leaky_receiver_really_does_leak(self):
        """Guards the guard above: if the flag stopped working, that test
        would go green against a receiver filtering for it once more."""
        import json
        import urllib.request
        Collaborator.reset()
        Collaborator.LEAKS_EVERYTHING = True
        srv, port = serve(Collaborator)
        try:
            base = f"http://127.0.0.1:{port}"
            a, b = C.new_token(), C.new_token()
            for t in (a, b):
                urllib.request.urlopen(f"{base}/{t}/hit", timeout=5).read()
            raw = urllib.request.urlopen(
                f"{base}/interactions?token={a}", timeout=5).read()
            assert len(json.loads(raw)["interactions"]) == 2
        finally:
            srv.shutdown()
            Collaborator.LEAKS_EVERYTHING = False


class TestAnUnreachableReceiverIsNotSilence:
    """Returning [] for a poll that never happened turns every blind case into
    a clean result the moment the receiver is down."""

    def test_it_raises_rather_than_returning_empty(self, monkeypatch):
        monkeypatch.setenv("ERLIK_OAST_DOMAIN", "oast.test")
        monkeypatch.setenv("ERLIK_OAST_RECEIVER", "http://127.0.0.1:1")
        with pytest.raises(C.CollaboratorError):
            C.poll(C.new_token(), timeout=1)

    def test_no_interactions_is_a_normal_empty_list(self, oast):
        """The negative control: a reachable receiver with nothing recorded
        must NOT raise, or every clean run looks like an outage."""
        assert C.poll(C.new_token()) == []


class TestTheRunnerWiresItIn:
    """`{{collaborator_host}}` was declared on three cases and rendered by
    none."""

    def test_the_placeholder_is_now_used_by_a_case(self):
        from orchestrator.testcase import load_catalog
        users = [tid for tid, tc in load_catalog().items()
                 for st in tc.steps if "{{collaborator_host}}" in st.command]
        assert users, ("collaborator_host is still declared and never "
                       "rendered — the field promises OOB and delivers none")

    def test_an_oob_step_runs_and_carries_the_minted_name(self, oast, targets):
        r = run_case("WSTG-INPV-19", url=targets["web"] + "/search",
                     parameter="q")
        oob = [s for s in r.steps if s.step == "blind_callback"]
        assert oob, [s.step for s in r.steps]
        assert ".oast.test" in oob[0].command, oob[0].command

    def test_the_scope_guard_does_not_refuse_the_minted_name(self, oast, targets):
        """The name is minted per run, so NO case file can declare it as a
        payload host -- and an undeclared host in a command is refused.

        Written after the first version of these tests passed against a step
        the guard had refused: a refused step still lands in `result.steps`
        with the rendered command, so asserting the name appears in it proves
        the name was RENDERED, not that the probe was SENT.
        """
        r = run_case("WSTG-INPV-19", url=targets["web"] + "/search",
                     parameter="q")
        oob = [s for s in r.steps if s.step == "blind_callback"][0]
        assert "scope violation" not in (oob.error or ""), oob.error
        assert not r.stopped_early, "the run stopped at the OOB step"

    def test_the_guard_sees_it_when_it_is_a_URL_of_its_own(self, oast, targets):
        """WSTG-INPV-19 embeds the collaborator INSIDE the target's own query
        string, so `_URL_RX` swallows the whole thing in one match whose host
        is the in-scope target -- the guard never sees the collaborator host
        by itself, and the test above passes whether or not it is allowed.

        WSTG-INPV-07 names it as a separate URL inside an XML entity, which is
        the shape that actually reaches the check. A mutation deleting the
        allowance survived the entire suite until this ran.
        """
        r = run_case("WSTG-INPV-07", url=targets["web"] + "/search")
        oob = [s for s in r.steps if s.step == "blind_oob_entity"]
        assert oob, [s.step for s in r.steps]
        assert "scope violation" not in (oob[0].error or ""), oob[0].error
        assert not r.stopped_early

    def test_an_operator_supplied_collaborator_is_allowed_too(self, oast_off,
                                                              targets):
        """A `collaborator_host` passed in the target is just as undeclarable
        by the case file as a minted one."""
        r = run_case("WSTG-INPV-19", url=targets["web"] + "/search",
                     parameter="q", collaborator_host="abc.burpcollaborator.net")
        oob = [s for s in r.steps if s.step == "blind_callback"][0]
        assert "scope violation" not in (oob.error or ""), oob.error

    def test_an_undeclared_host_is_still_refused(self, oast, targets):
        """The negative control for the two above. Without it they pass on a
        runner that stopped checking commands at all."""
        from orchestrator.testcase.scope import Scope, ScopeViolation, check_command
        sc = Scope(allow_hosts=["127.0.0.1"])
        with pytest.raises(ScopeViolation):
            check_command("curl http://evil.example/x", sc,
                          payload_hosts=["abcd1234abcd1234.oast.test"])

    def test_a_denied_collaborator_stays_denied(self, targets):
        """Allowing the minted name must not reverse an explicit exclusion.
        `deny_hosts` is the one direction a payload declaration may not move.
        """
        from orchestrator.testcase.scope import Scope, ScopeViolation, check_command
        sc = Scope(allow_hosts=["127.0.0.1"], deny_hosts=["oast.test"])
        with pytest.raises(ScopeViolation):
            check_command("curl http://abcd1234abcd1234.oast.test/erlik-oob", sc,
                          payload_hosts=["abcd1234abcd1234.oast.test"])

    def test_the_name_is_unique_per_run(self, oast, targets):
        def host_of(res):
            s = [x for x in res.steps if x.step == "blind_callback"][0]
            return s.command.split("http://")[-1].split("/")[0]
        a = host_of(run_case("WSTG-INPV-19", url=targets["web"] + "/search",
                             parameter="q"))
        b = host_of(run_case("WSTG-INPV-19", url=targets["web"] + "/search",
                             parameter="q"))
        assert a != b, "two runs shared a name; an interaction cannot be attributed"

    def test_with_oast_off_the_step_is_not_run_and_says_so(self, oast_off, targets):
        """The property that matters most: a payload nobody can read back must
        not leave the case reporting a clean verdict."""
        r = run_case("WSTG-INPV-19", url=targets["web"] + "/search",
                     parameter="q")
        assert not [s for s in r.steps if s.step == "blind_callback"]
        na = [n for n in r.not_assessed if n.step == "blind_callback"]
        assert na, r.not_assessed
        assert "ERLIK_OAST_DOMAIN" in na[0].reason

    def test_the_other_probes_still_run_with_oast_off(self, oast_off, targets):
        """Per-STEP, not per-case. WSTG-INPV-19 proves most of its findings in
        band, and disabling the whole case would lose coverage that works."""
        r = run_case("WSTG-INPV-19", url=targets["web"] + "/search",
                     parameter="q")
        assert [s for s in r.steps if s.step != "blind_callback"]


class TestTheFinding:
    def _token_of(self, res):
        s = [x for x in res.steps if x.step == "blind_callback"][0]
        return s.command.split("http://")[-1].split(".")[0]

    # `test_an_interaction_becomes_a_finding` and
    # `test_the_evidence_names_what_was_contacted` lived here and stubbed
    # `poll` to deliver the interaction themselves. They are gone:
    # `TestTheWholeLoopWithNoTestSeamOnErliksSide` proves the same two things
    # with a real target making a real call and erlik's own poll unpatched, so
    # keeping the stubbed pair meant carrying a weaker duplicate of a test that
    # can no longer fail independently of it.

    def test_no_interaction_means_no_finding(self, oast, targets):
        """The negative control. Without it the tests above pass on a runner
        that reports a callback whether or not one happened."""
        r = run_case("WSTG-INPV-19", url=targets["web"] + "/search",
                     parameter="q")
        assert not [f for f in r.findings if f.step == "collaborator_poll"]

    def test_a_dead_receiver_is_not_assessed_not_clean(self, targets, monkeypatch):
        monkeypatch.setenv("ERLIK_OAST_DOMAIN", "oast.test")
        monkeypatch.setenv("ERLIK_OAST_RECEIVER", "http://127.0.0.1:1")
        r = run_case("WSTG-INPV-19", url=targets["web"] + "/search",
                     parameter="q")
        assert not [f for f in r.findings if f.step == "collaborator_poll"]
        na = [n for n in r.not_assessed if n.step == "collaborator_poll"]
        assert na, r.not_assessed
        assert "could not be read back" in na[0].reason


class TestTheOperatorsOwnCollaboratorWins:
    def test_a_supplied_host_is_used_verbatim(self, oast, targets):
        """Someone running their own Burp Collaborator has a name erlik cannot
        mint."""
        r = run_case("WSTG-INPV-19", url=targets["web"] + "/search",
                     parameter="q", collaborator_host="abc.burpcollaborator.net")
        oob = [s for s in r.steps if s.step == "blind_callback"][0]
        assert "abc.burpcollaborator.net" in oob.command
        assert ".oast.test" not in oob.command


class TestTheOperatorIsToldBeforeRunning:
    """`not_assessed` reports it AFTER the fact. An operator planning a sweep
    has to be able to see it BEFORE, because a blind case with OAST off
    produces exactly the findings list a clean target produces."""

    def _status(self):
        import asyncio
        from orchestrator.main import v2_oast_status
        return asyncio.run(v2_oast_status())

    def test_the_api_reports_it_off_with_the_reason(self, oast_off):
        d = self._status()
        assert d["enabled"] is False
        assert "ERLIK_OAST_DOMAIN" in d["reason"]

    def test_the_api_reports_it_on(self, oast):
        d = self._status()
        assert d["enabled"] is True and d["domain"] == "oast.test"

    def test_it_names_the_cases_that_depend_on_it(self, oast_off):
        assert "WSTG-INPV-19" in self._status()["cases"]

    def test_the_case_listing_carries_the_flag(self):
        import asyncio
        from orchestrator.main import list_test_cases
        cases = {c["id"]: c for c in asyncio.run(list_test_cases())["test_cases"]}
        assert cases["WSTG-INPV-19"]["needs_collaborator"] is True
        others = [c for c in cases.values() if not c["needs_collaborator"]]
        assert others, "every case claims to need a collaborator — the flag is inert"

    def test_the_dashboard_fetches_it(self):
        """An endpoint with no caller is a promise nothing keeps. Six /api/v2/*
        routes were once exactly that."""
        import pathlib
        src = (pathlib.Path(__file__).resolve().parents[1]
               / "dashboard" / "templates" / "index.html").read_text()
        assert "/api/v2/oast" in src, "the endpoint is fetched by nothing"
        assert 'id="tl-oast"' in src, "nowhere to render it"
        i = src.index("/api/v2/oast")
        near = src[i:i + 1200]
        assert "oa.reason" in near, "the OFF state renders without its reason"


class TestACaseCannotAdvertiseWhatItDoesNotDo:
    """The original defect in schema form: `collaborator_host` was offered by
    three cases and rendered by none. The guard ties the field, the `oob:`
    steps and `needs_collaborator` together so no two can drift apart again.
    """

    STEP = {"name": "s", "tool": "curl", "command": "curl {{url}}"}
    OOB = {"name": "o", "tool": "curl", "oob": True,
           "command": "curl http://{{collaborator_host}}/x"}

    def _case(self, **kw):
        from orchestrator.testcase.schema import TestCase
        base = dict(id="X", name="n", category="c", steps=[self.STEP])
        base.update(kw)
        return TestCase(**base)

    def test_a_valid_combination_constructs(self):
        """The negative control. Without it every assertion below passes on a
        validator that rejects everything."""
        self._case(steps=[self.STEP, self.OOB], needs_collaborator=True,
                   target_schema={"required": ["url"],
                                  "optional": ["collaborator_host"]})

    def test_offering_the_field_with_no_oob_step_is_refused(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError, match="never performs"):
            self._case(target_schema={"required": ["url"],
                                      "optional": ["collaborator_host"]})

    def test_an_oob_step_without_the_field_is_refused(self):
        """An operator with their own Burp Collaborator would have no way to
        supply it, and the step would only ever run off a minted name."""
        from pydantic import ValidationError
        with pytest.raises(ValidationError, match="cannot supply"):
            self._case(steps=[self.OOB], needs_collaborator=True,
                       target_schema={"required": ["url"]})

    def test_an_oob_step_without_the_flag_is_refused(self):
        """`needs_collaborator` is what makes the runner mint a name. With it
        unset the step is skipped on every single run -- silently, and looking
        exactly like a case that found nothing."""
        from pydantic import ValidationError
        with pytest.raises(ValidationError, match="never minted|skipped"):
            self._case(steps=[self.STEP, self.OOB], needs_collaborator=False,
                       target_schema={"required": ["url"],
                                      "optional": ["collaborator_host"]})

    def test_the_flag_without_an_oob_step_is_refused(self):
        """The field is deliberately NOT offered here: offering it trips the
        earlier check, and a test that passed on the wrong branch would go
        green against a validator that had lost this one entirely."""
        from pydantic import ValidationError
        with pytest.raises(ValidationError, match="no\\s+`oob:` step to use one"):
            self._case(needs_collaborator=True,
                       target_schema={"required": ["url"]})


class TestTheCatalogueHolds:
    """Guards the guard: the schema validator runs at load, so a catalogue
    that stopped tripping it would leave every assertion above green against
    nothing real."""

    def test_no_committed_case_offers_a_collaborator_it_ignores(self):
        from orchestrator.testcase import load_catalog
        for tid, tc in load_catalog().items():
            offers = "collaborator_host" in (tc.target_schema.optional or [])
            uses = any(s.oob for s in tc.steps)
            assert offers == uses, f"{tid}: offers={offers} uses={uses}"

    def test_the_cases_that_can_only_be_proven_out_of_band_have_a_probe(self):
        from orchestrator.testcase import load_catalog
        cat = load_catalog()
        for tid in ("WSTG-INPV-07", "WSTG-INPV-19"):
            assert [s for s in cat[tid].steps if s.oob], f"{tid} has no oob step"

    def test_the_oauth_case_stopped_offering_one(self):
        """It has no blind probe to run: every step reads the authorisation
        server's own Location header, which comes straight back."""
        from orchestrator.testcase import load_catalog
        tc = load_catalog()["WSTG-AUTHZ-05"]
        assert "collaborator_host" not in (tc.target_schema.optional or [])
        assert not any(s.oob for s in tc.steps)

    def test_the_blind_xxe_probe_does_not_exfiltrate(self):
        """The case comment promises it fetches a URL and nothing else -- no
        parameter-entity trick appending a file's contents to the callback.
        Confirming a blind XXE by sending a client's internal data to a third
        party proves the same thing at a cost no engagement asked for."""
        from orchestrator.testcase import load_catalog
        cmd = [s for s in load_catalog()["WSTG-INPV-07"].steps if s.oob][0].command
        assert "{{collaborator_host}}" in cmd
        for leak in ("file://", "php://", "%file", "%exfil", "&file"):
            assert leak not in cmd, f"the OOB probe carries {leak!r}"


class TestASuppliedCollaboratorIsNotPolledAndSaysSo:
    """erlik cannot read a Burp Collaborator: the receiver API is keyed by the
    token it minted, and a third-party instance has neither. Without a report,
    the probe would be SENT and nothing said either way -- no finding, no
    not-assessed -- which is exactly the clean-looking non-result this whole
    change exists to prevent."""

    def test_the_run_says_the_operator_has_to_check_it(self, oast, targets):
        r = run_case("WSTG-INPV-19", url=targets["web"] + "/search",
                     parameter="q", collaborator_host="abc.burpcollaborator.net")
        na = [n for n in r.not_assessed if n.step == "collaborator_poll"]
        assert na, r.not_assessed
        assert "abc.burpcollaborator.net" in na[0].reason
        assert "check it yourself" in na[0].reason

    def test_a_minted_collaborator_is_polled_instead(self, oast, targets):
        """The negative control: with no supplied host the run polls and stays
        silent, rather than telling every operator to go read a collaborator."""
        r = run_case("WSTG-INPV-19", url=targets["web"] + "/search",
                     parameter="q")
        assert not [n for n in r.not_assessed
                    if n.step == "collaborator_poll"], r.not_assessed

    def test_a_probe_that_never_left_is_not_reported_as_sent(self, oast_off,
                                                             targets):
        """A dry run renders every command and sends none. Claiming payloads
        were sent, and telling the operator to go read their collaborator, is
        the same untrue interface label as the silence it replaces.

        A dry run rather than "OAST off": with OAST off and no supplied host
        there is no collaborator at all, so the branch is skipped for the
        wrong reason and the test discriminates nothing. Replacing the
        condition with `any(st.oob for st in tc.steps)` survived until this.
        """
        import asyncio

        from orchestrator.testcase import find_by_id, run_test_case
        from tests.targets.fixtures import _native_mode
        tc = find_by_id("WSTG-INPV-19")
        target = {"url": targets["web"] + "/search", "parameter": "q",
                  "collaborator_host": "abc.burpcollaborator.net",
                  "scope": {"allow_hosts": ["127.0.0.1"]}}
        with _native_mode():
            r = asyncio.run(run_test_case(tc, target, dry_run=True))
        assert [s for s in r.steps if s.step == "blind_callback"], \
            "the OOB step was not even planned; the test proves nothing"
        assert not [n for n in r.not_assessed
                    if n.step == "collaborator_poll"], r.not_assessed


class TestTheWholeLoopWithNoTestSeamOnErliksSide:
    """The strongest version available here: erlik mints the name, plants it,
    a REAL target fetches it, the receiver records it, and erlik's own `poll`
    correlates it into a finding. Nothing on erlik's side is patched.

    The one hop still simulated is DNS. The minted name is a subdomain of a
    domain nothing here resolves -- `*.localhost` does not resolve on Linux and
    egress blocks a real OAST provider -- so the TARGET's resolver is stood in
    for by `Ssrf.RESOLVE`, which maps the name onto the local receiver. That is
    a seam in the target, not in the code under test. See this module's
    docstring.
    """

    def _ssrf_target(self, receiver, monkeypatch):
        monkeypatch.setattr(Ssrf, "RESOLVE", (".oast.test", receiver))
        return serve(Ssrf)

    def test_a_target_that_calls_out_produces_a_finding(self, oast, receiver,
                                                        monkeypatch):
        srv, port = self._ssrf_target(receiver, monkeypatch)
        try:
            r = run_case("WSTG-INPV-19", url=f"http://127.0.0.1:{port}/fetch",
                         parameter="url")
        finally:
            srv.shutdown()
        oob = [f for f in r.findings if f.step == "collaborator_poll"]
        assert oob, [f.vuln_type for f in r.findings]
        assert "ssrf" in oob[0].vuln_type.lower()
        assert ".oast.test" in oob[0].evidence

    def test_a_target_that_refuses_produces_none(self, oast, receiver,
                                                 monkeypatch):
        """The negative control, and the one that matters most: without it the
        test above passes on a runner that reports a callback whether or not
        one happened. Same case, same collaborator, a target that parses the
        parameter and declines to fetch it."""
        monkeypatch.setattr(Ssrf, "FETCHES", False)
        srv, port = self._ssrf_target(receiver, monkeypatch)
        try:
            r = run_case("WSTG-INPV-19", url=f"http://127.0.0.1:{port}/fetch",
                         parameter="url")
        finally:
            srv.shutdown()
        assert not [f for f in r.findings if f.step == "collaborator_poll"]
        assert not [n for n in r.not_assessed if n.step == "collaborator_poll"]
