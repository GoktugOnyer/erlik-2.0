"""A case may declare hosts it names as DATA. Nothing else changes.

Three cases could not run at all. `scope.check_command` extracts every
host-shaped substring of a rendered command and refuses anything outside the
engagement -- right for a guard on where erlik CONNECTS, but their probes name
a host in a header or parameter VALUE and cannot be written any other way:

    WSTG-CLNT-07   `Origin: https://evil.oastify.com`      header value
    WSTG-AUTHZ-05  `redirect_uri=...erlik-not-registered.example`  query value
    WSTG-INPV-19   `?url=http://169.254.169.254/...`       query value

In each, curl connects only to the in-scope target. Each aborted at its first
step on every run, so none had ever produced a result. Measured 2026-09-05;
verified after the change that CLNT-07 finds the flaw on a target that
reflects any Origin with credentials, and stays silent on one that does not.

The declaration lives in committed, reviewed YAML and is deliberately weak.
These tests pin every way it is weak, because a per-case allowance that
quietly generalises is worse than the refusals it replaced.
"""

import re

import pytest
from pydantic import ValidationError

from orchestrator.testcase import load_catalog
from orchestrator.testcase.schema import TestCase as _Case  # not TestX: pytest collects TestX*
from orchestrator.testcase.scope import (Scope, ScopeViolation, check_command,
                                         payload_allowlist)

CATALOG = load_catalog()
STEP = [{"name": "s", "tool": "curl", "command": "curl x"}]


def _case(**kw):
    return _Case(id="X", name="n", category="c", steps=STEP, **kw)


CMD = 'curl -H "Origin: https://evil.oastify.com" "http://127.0.0.1/"'
IN_SCOPE = Scope(allow_hosts=["127.0.0.1"])


class TestTheDeclarationWorks:
    def test_without_it_the_step_is_refused(self):
        """The state all three cases were in."""
        with pytest.raises(ScopeViolation, match="evil.oastify.com"):
            check_command(CMD, IN_SCOPE)

    def test_with_it_the_step_runs(self):
        check_command(CMD, IN_SCOPE, payload_hosts=["evil.oastify.com"])

    def test_declaring_a_different_host_does_not_help(self):
        """It is not a switch that turns the guard off."""
        with pytest.raises(ScopeViolation):
            check_command(CMD, IN_SCOPE, payload_hosts=["other.example"])


class TestDenyHostsAlwaysWins:
    """The one direction the declaration must never move. An operator who
    excluded a host must not have that reversed by a case file."""

    def test_the_allowlist_itself_drops_denied_hosts(self):
        """Pinned directly on `payload_allowlist`, not only through
        `check_command`. The deny check exists in BOTH places on purpose --
        once when the set is built and once against the full host, so a denied
        subdomain of a declared domain is caught too -- and removing either one
        alone left the whole suite green. Belt and braces on the one direction
        that must never move needs a test per layer."""
        scope = Scope(allow_hosts=["127.0.0.1"], deny_hosts=["evil.oastify.com"])
        assert payload_allowlist(["evil.oastify.com", "ok.example"], scope) == \
            {"ok.example"}

    def test_the_allowlist_keeps_what_is_not_denied(self):
        """Negative control for the line above."""
        assert payload_allowlist(["evil.oastify.com"], IN_SCOPE) == \
            {"evil.oastify.com"}

    def test_an_explicitly_denied_host_is_still_refused(self):
        scope = Scope(allow_hosts=["127.0.0.1"], deny_hosts=["evil.oastify.com"])
        with pytest.raises(ScopeViolation, match="denied"):
            check_command(CMD, scope, payload_hosts=["evil.oastify.com"])

    def test_denying_one_subdomain_of_a_declared_domain_works(self):
        """Subdomains are permitted by a declaration, so the denial has to be
        checked against the FULL host and not only the declared one."""
        scope = Scope(allow_hosts=["127.0.0.1"], deny_hosts=["bad.oastify.com"])
        cmd = 'curl -H "Origin: https://bad.oastify.com" "http://127.0.0.1/"'
        with pytest.raises(ScopeViolation):
            check_command(cmd, scope, payload_hosts=["oastify.com"])

    def test_a_glob_denial_also_wins(self):
        scope = Scope(allow_hosts=["127.0.0.1"], deny_hosts=["*.oastify.com"])
        with pytest.raises(ScopeViolation):
            check_command(CMD, scope, payload_hosts=["evil.oastify.com"])

    def test_the_sibling_is_still_allowed(self):
        """Negative control: the denial must be narrow, or these tests pass
        against a guard that refuses everything."""
        scope = Scope(allow_hosts=["127.0.0.1"], deny_hosts=["bad.oastify.com"])
        check_command(CMD, scope, payload_hosts=["oastify.com"])


class TestItNeverWidensTheTarget:
    def test_a_declaration_does_not_authorise_aiming_at_that_host(self):
        """The primary target is checked against the engagement scope alone.
        If this ever passed, a case file could redirect a run."""
        with pytest.raises(ScopeViolation):
            check_command('curl "http://elsewhere.example/"', IN_SCOPE,
                          primary_url="http://elsewhere.example/",
                          payload_hosts=["elsewhere.example"])

    def test_an_undeclared_host_elsewhere_in_the_command_still_fails(self):
        cmd = ('curl -H "Origin: https://evil.oastify.com" '
               '"http://127.0.0.1/" -x http://proxy.attacker.example:8080')
        with pytest.raises(ScopeViolation, match="proxy.attacker.example"):
            check_command(cmd, IN_SCOPE, payload_hosts=["evil.oastify.com"])


class TestSubdomainsNotGlobs:
    """Names UNDER a declared domain are permitted -- AUTHZ-05's suffix probe
    builds `{{url}}.erlik-not-registered.example`, and OAST assigns a unique
    subdomain per probe. That is not the same as a wildcard."""

    PERMITTED = {"erlik-not-registered.example", "oastify.com"}

    @pytest.mark.parametrize("host,ok", [
        ("erlik-not-registered.example", True),
        ("app.erlik-not-registered.example", True),
        ("a.b.oastify.com", True),
        # The confusions a naive `in` or `endswith` would wave through.
        ("oastify.com.evil.net", False),
        ("notoastify.com", False),
        ("evil-oastify.com", False),
        ("erlik-not-registered.test", False),
        ("example", False),
        ("", False),
    ])
    def test_boundaries(self, host, ok):
        from orchestrator.testcase.scope import _is_declared_payload
        assert _is_declared_payload(host, self.PERMITTED) is ok


class TestTheSchemaRefusesPatterns:
    """A glob is how a per-case allowance becomes a general bypass."""

    @pytest.mark.parametrize("bad", [
        ["*.example.com"], ["*"], ["evil?.example"], ["[a-z].example"],
        ["http://evil.example"], ["evil.example/path"], ["evil example"], [""],
    ])
    def test_rejected(self, bad):
        with pytest.raises(ValidationError):
            _case(payload_hosts=bad)

    def test_an_exact_host_is_accepted_and_lowercased(self):
        assert _case(payload_hosts=["EVIL.Oastify.COM"]).payload_hosts == \
            ["evil.oastify.com"]

    def test_the_default_is_empty(self):
        assert _case().payload_hosts == []


class TestTheCatalogue:
    DECLARED = {tid: tc.payload_hosts for tid, tc in CATALOG.items()
                if tc.payload_hosts}

    def test_only_the_cases_that_need_it_declare_anything(self):
        assert set(self.DECLARED) == {"WSTG-CLNT-07", "WSTG-AUTHZ-05",
                                      "WSTG-INPV-19"}, self.DECLARED

    @pytest.mark.parametrize("tid", sorted(DECLARED))
    def test_every_declared_host_is_actually_named_by_a_step(self, tid):
        """No dead permissions. A host left declared after the probe that used
        it was rewritten is an allowance nothing justifies any more."""
        commands = " ".join(st.command for st in CATALOG[tid].steps)
        unused = [h for h in CATALOG[tid].payload_hosts if h not in commands]
        assert not unused, (
            f"{tid} declares {unused}, which no step names. Remove them."
        )

    # A minted collaborator name, in the shape `collaborator.host_for` builds.
    # It is NOT declared in any case file and cannot be: the token is minted
    # per run, so `run_test_case` appends it to the case's declaration for the
    # duration of that run. This sweep has to do the same or it audits a
    # command the runner never sends.
    OAST = "abcd1234abcd1234.oast.example"

    def test_no_step_in_the_catalogue_is_refused(self):
        """The property the whole change exists for."""
        scope = Scope(allow_hosts=["app.example.test"])
        refused = []
        for tid, tc in sorted(CATALOG.items()):
            for st in tc.steps:
                cmd = re.sub(r"\{\{(url|login_url|url_template|request_template)\}\}",
                             "http://app.example.test/x", st.command)
                cmd = re.sub(r"\{\{host\}\}", "app.example.test", cmd)
                cmd = re.sub(r"\{\{collaborator_host\}\}", self.OAST, cmd)
                cmd = re.sub(r"\{\{[a-z_0-9]+\}\}", "q", cmd)
                declared = list(tc.payload_hosts)
                if st.oob:
                    declared.append(self.OAST)
                try:
                    check_command(cmd, scope, payload_hosts=declared)
                except ScopeViolation as e:
                    refused.append(f"{tid}/{st.name}: {e}")
        assert not refused, refused

    # What the guard sees under REAL rendering, measured 2026-09-05 with
    # `{{url}}` expanded to a full `http://app.example.test/fetch` — the shape
    # the runner actually sends, which the sweep above does not reproduce
    # because it substitutes a bare hostname for `{{url}}`.
    #
    #   WSTG-INPV-07/blind_oob_entity           REFUSED without the allowance
    #   WSTG-AUTHZ-05/redirect_uri_not_validated REFUSED without the allowance
    #   WSTG-CLNT-07/origin_reflection           REFUSED without the allowance
    #   WSTG-INPV-19/*                           ALLOWED either way
    #
    # The last line is a real property of the guard, not an oversight in these
    # tests. `_URL_RX` is greedy, so in
    #
    #   curl "http://app.example.test/fetch?q=http://169.254.169.254/latest/"
    #
    # the whole string matches as ONE URL whose host is the in-scope target.
    # A payload host appended to the target's own query string is therefore
    # never host-checked, and INPV-19's three declarations are inert. That is
    # permissive, not unsafe -- the declaration exists to allow, and the guard
    # was already allowing -- but it means the sweep above cannot be read as
    # "every declaration is load-bearing".
    RENDERED_REFUSALS = {
        "WSTG-INPV-07": "blind_oob_entity",
        "WSTG-AUTHZ-05": "redirect_uri_not_validated",
        "WSTG-CLNT-07": "origin_reflection",
    }

    @pytest.mark.parametrize("tid,step_name", sorted(RENDERED_REFUSALS.items()))
    def test_the_allowance_is_load_bearing_under_real_rendering(self, tid,
                                                                step_name):
        """The sweep above renders `{{url}}` as a bare hostname, which changes
        which substring `_URL_RX` matches. These are the steps whose host the
        guard genuinely sees in the command the runner sends, so these are the
        ones where withholding the declaration must refuse."""
        from orchestrator.testcase.runner import _render
        ctx = {"url": "http://app.example.test/fetch", "parameter": "q",
               "cookie": "", "auth_header": "", "client_id": "cid",
               "collaborator_host": self.OAST}
        st = next(x for x in CATALOG[tid].steps if x.name == step_name)
        cmd = _render(st.command, ctx)
        with pytest.raises(ScopeViolation):
            check_command(cmd, Scope(allow_hosts=["app.example.test"]),
                          payload_hosts=[])
        # ... and permitted once declared, or the refusal proves only that the
        # host is out of scope, which was never in doubt.
        declared = list(CATALOG[tid].payload_hosts)
        if st.oob:
            declared.append(self.OAST)
        check_command(cmd, Scope(allow_hosts=["app.example.test"]),
                      payload_hosts=declared)

    def test_a_payload_host_in_the_targets_query_string_is_not_checked(self):
        """The property behind the INPV-19 line above, asserted directly so it
        cannot quietly change. If `_URL_RX` is ever tightened this fails, and
        whoever tightens it has to revisit the declarations that became
        load-bearing overnight."""
        check_command(
            'curl "http://app.example.test/fetch?q=http://169.254.169.254/x"',
            Scope(allow_hosts=["app.example.test"]), payload_hosts=[])

    def test_the_audit_above_would_catch_a_regression(self):
        """Guard on the guard: with the declarations withheld, the same sweep
        must fail -- otherwise it is passing for some unrelated reason."""
        scope = Scope(allow_hosts=["app.example.test"])
        refused = []
        for tid in sorted(self.DECLARED):
            for st in CATALOG[tid].steps:
                cmd = re.sub(r"\{\{[a-z_0-9]+\}\}", "app.example.test", st.command)
                try:
                    check_command(cmd, scope)          # no payload_hosts
                except ScopeViolation:
                    refused.append(f"{tid}/{st.name}")
                    break
        assert len(refused) == 3, refused


class TestTheRunnerPassesThemThrough:
    def test_the_declaration_reaches_the_guard(self):
        """The schema and the guard being right is worth nothing if the runner
        does not hand one to the other."""
        import inspect

        import orchestrator.testcase.runner as R
        src = inspect.getsource(R.run_test_case)
        # The list handed to the guard is built FROM the case declaration and
        # then extended with the run's minted collaborator, which no case file
        # can name. Both halves are asserted: passing `tc.payload_hosts`
        # straight through would refuse every out-of-band step, and building
        # the list without seeding it from the case would drop every declared
        # payload host the in-band probes depend on.
        assert "step_payload_hosts = list(tc.payload_hosts)" in src, (
            "run_test_case no longer seeds the guard from the case's declaration"
        )
        assert "step_payload_hosts.append(oast_host)" in src, (
            "the run's minted collaborator is not added, so the only step that "
            "can prove a blind finding is refused by the scope guard"
        )
        assert "payload_hosts=step_payload_hosts" in src, (
            "run_test_case calls check_command without the declaration"
        )
