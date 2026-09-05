"""`_sanitize_command` must not invent a destination it was never given.

The rewrite exists for a real reason: a fine-tuned 7B emits `juice-shop:3000`
from training-data bias, and under docker a loopback host names the CONTAINER
rather than the target. So the command is re-pointed at the target before it
runs.

With `target_url=None` it re-pointed commands at a target that does not exist.
`target_host`/`target_port` default to "localhost"/80 at the top of the
function, and the rewrite then treats those placeholders as the real target:

    http://127.0.0.1:9020/login   ->  http://localhost:80/login
    https://127.0.0.1:9022/login  ->  http://localhost:80/login

The written port is discarded and https is DOWNGRADED to http. Measured
2026-09-05 against live local targets.

`runner.py` passed `target.get("url")`, and four of the 29 cases do not use
that key -- WSTG-ATHN-01 (`login_url`), AUTHZ-04 (`url_template`), BUSL-04
(`request_template`), CONF-07 (`host`). Every one of them reached the shell
rewritten. ATHN-01 exists to decide whether credentials travel encrypted, so
rewriting its probe to cleartext port 80 does not weaken that test, it inverts
it: the case then reports on a channel it never touched.

Both halves are fixed and both are asserted here -- the rewrite no longer
invents a destination, and the runner supplies the real one.
"""

import re

import pytest

import orchestrator.tool_executor as TE
from orchestrator.testcase.runner import _primary_url


@pytest.fixture
def native(monkeypatch):
    monkeypatch.setattr(TE, "ERLIK_NATIVE", True)


@pytest.fixture
def docker(monkeypatch):
    monkeypatch.setattr(TE, "ERLIK_NATIVE", False)
    monkeypatch.setattr(TE, "LEGACY_DOCKER_TARGET_HOST", "")


class TestNoTargetMeansNoRewrite:
    """Native mode: nothing to rewrite to, so nothing moves."""

    @pytest.mark.parametrize("cmd", [
        'curl -s "http://127.0.0.1:9020/login"',
        'curl -s "https://127.0.0.1:9022/login"',
        'curl -s "http://localhost:8080/x"',
        'curl -s "https://example.test:8443/a"',
    ])
    def test_command_survives_untouched(self, native, cmd):
        assert TE._sanitize_command(cmd, None) == cmd

    def test_the_port_is_not_replaced_with_80(self, native):
        out = TE._sanitize_command('curl "http://127.0.0.1:9020/login"', None)
        assert ":9020" in out, out
        assert ":80/" not in out, out

    def test_https_is_not_downgraded(self, native):
        """The specific inversion. A case that asks whether the channel is
        encrypted must not have its own probe rewritten to cleartext."""
        out = TE._sanitize_command('curl "https://127.0.0.1:9022/login"', None)
        assert out.startswith('curl "https://'), out


class TestDockerStillReachesTheHost:
    """The rewrite's original job survives: under docker a loopback host names
    the container, so it still becomes the gateway -- but that is a HOST
    substitution, and the scheme and written port are facts about the target."""

    def test_loopback_becomes_the_gateway(self, docker):
        out = TE._sanitize_command('curl "http://127.0.0.1:9020/login"', None)
        assert TE.DOCKER_HOST_GATEWAY in out, out

    def test_but_the_port_and_scheme_survive(self, docker):
        out = TE._sanitize_command('curl "https://127.0.0.1:9022/login"', None)
        assert out == f'curl "https://{TE.DOCKER_HOST_GATEWAY}:9022/login"', out

    def test_a_real_target_still_re_points_juice_shop(self, docker):
        """The negative control: the training-data rewrite is why this function
        exists and must keep working when a target IS known."""
        out = TE._sanitize_command('curl "http://juice-shop:3000/x"',
                                   "http://10.0.0.5:8080/")
        assert "juice-shop" not in out
        assert "10.0.0.5:8080" in out, out


class TestTheRunnerSuppliesTheRealTarget:
    """The other half. A case whose schema does not say `url` still has a
    target, and the runner has to find it or the fix above only means those
    cases are left un-rewritten under docker instead of mis-rewritten."""

    @pytest.mark.parametrize("target,want", [
        ({"url": "http://a/x"}, "http://a/x"),
        ({"login_url": "https://b:9022/login"}, "https://b:9022/login"),
        ({"url_template": "http://c/api/1"}, "http://c/api/1"),
        ({"host": "example.test", "port": 443}, "https://example.test:443"),
        ({"host": "example.test"}, "http://example.test"),
        ({"request_template": "curl -s -X POST http://d:8080/redeem"},
         "http://d:8080/redeem"),
        ({"success_marker": "OK"}, None),
        ({}, None),
    ])
    def test_it_finds_the_url(self, target, want):
        assert _primary_url(target) == want

    def test_url_still_wins(self):
        """Nothing may change for the 25 cases that already worked."""
        assert _primary_url({"url": "http://a/", "login_url": "http://b/"}) == "http://a/"

    def test_every_catalogue_case_resolves_a_target(self):
        """Guard on the whole catalogue rather than the four cases known today:
        a case added later with a differently-named target key fails here
        instead of silently running against the wrong host."""
        from orchestrator.testcase import load_catalog

        unresolved = []
        for tc_id, tc in sorted(load_catalog().items()):
            probe = {}
            for key in tc.target_schema.required:
                if key == "host":
                    probe[key] = "example.test"
                elif "url" in key or "template" in key:
                    probe[key] = "http://example.test:8080/probe"
                else:
                    probe[key] = "x"
            if _primary_url(probe) is None:
                unresolved.append((tc_id, tc.target_schema.required))
        assert not unresolved, (
            f"these cases give the executor no target to resolve: {unresolved}"
        )


class TestTheRunnerActuallyUsesIt:
    """`_primary_url` being correct is worth nothing if the runner still passes
    `target.get("url")`. Reverting that one line left every test above green --
    they all exercised the helper in isolation and none of them exercised the
    wiring. This runs a real case end to end with the executor intercepted.
    """

    def _capture(self, monkeypatch):
        seen = {}

        async def fake_execute_tool(command, **kw):
            seen["target_url"] = kw.get("target_url")
            seen["command"] = command
            return {"success": True, "output": "ERLIK_ATHN_OK", "tool": "curl",
                    "duration_ms": 1, "error": None, "executed": True}

        import orchestrator.testcase.runner as R
        monkeypatch.setattr(R, "execute_tool", fake_execute_tool)
        return seen

    def test_a_login_url_case_reaches_the_executor_with_its_target(self, monkeypatch):
        import asyncio

        from orchestrator.testcase import find_by_id, run_test_case

        seen = self._capture(monkeypatch)
        tc = find_by_id("WSTG-ATHN-01")
        target = {"login_url": "https://127.0.0.1:9022/login",
                  "scope": {"allow_hosts": ["127.0.0.1"]}}
        asyncio.run(run_test_case(tc, target))
        assert seen["target_url"] == "https://127.0.0.1:9022/login", (
            "the runner handed the executor None, so _sanitize_command has no "
            "destination and falls back to its placeholder default"
        )

    def test_a_plain_url_case_is_unchanged(self, monkeypatch):
        """Negative control: the 25 cases that already worked must be
        untouched."""
        import asyncio

        from orchestrator.testcase import find_by_id, run_test_case

        seen = self._capture(monkeypatch)
        tc = find_by_id("WSTG-CLNT-09")
        target = {"url": "http://127.0.0.1:9010/",
                  "scope": {"allow_hosts": ["127.0.0.1"]}}
        asyncio.run(run_test_case(tc, target))
        assert seen["target_url"] == "http://127.0.0.1:9010/"
