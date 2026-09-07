"""WSTG-CONF-07 checked HSTS on a different port than it scanned.

Three defects, measured 2026-09-05 by rendering the case rather than reading
it.

1. THE TWO HALVES DESCRIBED DIFFERENT SERVICES. `port` exists precisely
   because a TLS service may not be on 443, and the HSTS steps ignored it:

       target host=127.0.0.1 port=9023
       tls_scan   -> testssl ... "127.0.0.1:9023"
       hsts_check -> curl -sI "https://127.0.0.1/"       <- port 443

2. `port` IS OPTIONAL AND HAD NO DEFAULT. Omitted, the scan rendered as
   `testssl ... "127.0.0.1:"`, which is not a target.

3. THE HSTS STEP COULD NOT REACH A VERDICT. `hsts_check` carried two
   evaluators with the same pattern and NO `emit_finding` on either.
   runner.py emits a finding only `if ev.emit_finding`, so both were dead by
   construction. The verdict was delegated to a THIRD step that re-issued the
   identical request and asked a model whether a header was present -- so on
   any deployment with no model reachable, which is every offline run, the
   entire HSTS check produced nothing.

Verified live against four endpoints: TLS without HSTS (finding), TLS with it
(silent), a dead port and a plain-http port (both no-response, no finding).
"""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / "tests_catalog" / "wstg" / "CONF-07_tls.yaml"


@pytest.fixture(scope="module")
def case():
    return yaml.safe_load(CASE.read_text())


@pytest.fixture(scope="module")
def hsts(case):
    steps = [s for s in case["steps"] if "hsts" in s["name"]]
    assert len(steps) == 1, (
        f"expected one HSTS step, found {[s['name'] for s in steps]} -- the "
        "case used to have two, one of which could not conclude"
    )
    return steps[0]


class TestBothHalvesUseTheSamePort:
    def test_the_scan_applies_the_port(self, case):
        scan = [s for s in case["steps"] if s["name"] == "tls_scan"][0]
        assert '{{port}}' in scan["command"]

    # The empty port is GONE from this list, and that is the change: `port` is
    # now required, so `build_target` derives it from the base URL and
    # `run_test_case` refuses a hand-written target that omits it. There is no
    # longer a state in which the case has to invent one. See
    # `test_a_missing_port_is_refused_not_invented` below.
    @pytest.mark.parametrize("port,expect", [
        ("9023", ":9023/"), ("8443", ":8443/"), ("443", ":443/"),
    ])
    def test_the_port_reaches_the_url_the_probe_requests(self, hsts, tmp_path,
                                                         port, expect):
        """Asserting `'{{port}}' in command` is not enough -- it is satisfied by
        the assignment alone, and passed against the exact mutation that sends
        the probe back to 443. This RUNS the step's shell with curl shimmed to
        print its arguments, so the URL actually requested is what is checked.
        """
        import os
        import subprocess

        shim = tmp_path / "curl"
        shim.write_text('#!/bin/bash\nfor a in "$@"; do echo "$a"; done\n')
        shim.chmod(0o755)
        rendered = (hsts["command"].replace("{{host}}", "127.0.0.1")
                    .replace("{{port}}", port))
        assert rendered.startswith("bash -c ")
        env = dict(os.environ, PATH=f"{tmp_path}:{os.environ['PATH']}")
        out = subprocess.run(["bash", "-c", rendered[len("bash -c "):].strip("'")],
                             capture_output=True, text=True, env=env).stdout
        urls = [l for l in out.splitlines() if l.startswith("https://")]
        assert urls, out[:400]
        assert all(u.endswith(expect) for u in urls), urls

    def test_the_default_is_resolved_by_the_planner(self):
        """It used to be a shell prologue -- `case "$P" in ""|*[!0-9]*) P=443`
        -- and that is exactly what hid the port from the scope guard: `$P` is
        not a port the guard can read, so it scored `{{host}}:$P` as a bare host
        and defaulted it to 80. Measured 2026-09-06, `tls_scan` was refused on
        EVERY https target, always. The default now lives where the port is a
        fact about the target."""
        from orchestrator.testcase.sweep import build_target
        c = {"id": "WSTG-CONF-07",
             "target_schema": {"required": ["host", "port"], "optional": []}}
        for base, expect in (("https://app.example.test", 443),
                             ("https://app.example.test:8443", 8443)):
            t, why = build_target(c, base, {})
            assert t and t["port"] == expect, (base, t, why)

    def test_a_missing_port_is_refused_not_invented(self):
        """`required` means the case cannot run without knowing this, and
        inventing 443 does not make it known. A hand-written target that omits
        it is refused by name rather than silently scanned on the wrong port."""
        import asyncio

        from orchestrator.testcase import find_by_id, run_test_case
        with pytest.raises(ValueError, match="port"):
            asyncio.run(run_test_case(find_by_id("WSTG-CONF-07"),
                                      {"host": "127.0.0.1"}))

    def test_no_step_hides_the_port_in_a_shell_variable(self, case):
        """The guard reads the rendered command. A port assembled at runtime is
        invisible to it, which is how both halves came to be refused."""
        for step in case["steps"]:
            assert "$P" not in step["command"], step["name"]
            assert "{{host}}:{{port}}" in step["command"], step["name"]


class TestTheHstsStepReachesAVerdict:
    def test_it_emits_a_finding_itself(self, hsts):
        """The dead evaluators. An evaluator with no emit_finding contributes
        nothing -- runner.py builds a Finding only `if ev.emit_finding`."""
        emitting = [ev for ev in hsts["evaluators"] if ev.get("emit_finding")]
        assert emitting, (
            "every evaluator on this step is inert; the step issues a request "
            "and concludes nothing"
        )

    def test_no_evaluator_is_inert(self, case):
        """Across the whole case: an evaluator that can neither emit a finding
        nor chain nor stop is dead weight that reads like a check."""
        for step in case["steps"]:
            for ev in step["evaluators"]:
                assert (ev.get("emit_finding") or ev.get("chain_to")
                        or ev.get("stop_after")), (
                    f"{step['name']}: evaluator {ev.get('pattern')!r} does "
                    "nothing at all"
                )

    def test_the_verdict_does_not_need_a_model(self, hsts):
        """'Is this header present' is what a regex answers. Routing it to an
        LLM meant the check produced nothing on every offline run."""
        assert all(ev["type"] == "regex" for ev in hsts["evaluators"]), (
            [ev["type"] for ev in hsts["evaluators"]]
        )

    @pytest.mark.parametrize("verdict,findings", [
        ("ERLIK_HSTS_ABSENT", 1),
        ("ERLIK_HSTS_PRESENT", 0),
        ("ERLIK_HSTS_NO_RESPONSE", 0),
    ])
    def test_each_verdict_fires_the_right_evaluators(self, hsts, verdict, findings):
        hits = [ev for ev in hsts["evaluators"]
                if re.search(ev["pattern"], f"{verdict}: explanation")]
        assert len(hits) == findings, [ev["pattern"] for ev in hits]

    def test_an_unreachable_service_is_not_reported_as_missing_hsts(self, hsts):
        assert "ERLIK_HSTS_NO_RESPONSE" in hsts["command"]
        ui = (ROOT / "dashboard" / "templates" / "index.html").read_text()
        rx = re.search(r"const TL_NOT_ASSESSED = /([^/]+)/", ui).group(1)
        assert re.search(rx, "ERLIK_HSTS_NO_RESPONSE"), (
            "a port that answered nothing would render as a clean TLS result"
        )


class TestTheProbeIsAGet:
    def test_it_does_not_use_head(self, hsts):
        """`curl -sI` sends HEAD. Measured against a local TLS server with no
        HEAD handler: 501 and no headers, so the case would report Missing
        HSTS for a service whose GET sets it."""
        assert " -sI" not in hsts["command"], (
            "HEAD is not answered by every server; take the headers off a GET"
        )
        assert "-D -" in hsts["command"] and "-o /dev/null" in hsts["command"]


class TestItSurvivesTheScopeGuard:
    def test_the_rendered_command_clears_the_guard(self, case):
        """`https://host:$P/` written literally raises on the port inside
        scope.check_url, which is now a refusal -- so the step would never run.
        The URL is assembled into a variable for that reason."""
        from orchestrator.testcase.scope import Scope, check_command
        for step in case["steps"]:
            rendered = (step["command"].replace("{{host}}", "127.0.0.1")
                        .replace("{{port}}", "9023"))
            check_command(rendered, Scope(allow_hosts=["127.0.0.1"]))

    def test_the_guard_would_still_refuse_a_foreign_host(self, case):
        from orchestrator.testcase.scope import Scope, ScopeViolation, check_command
        rendered = (case["steps"][1]["command"].replace("{{host}}", "evil.example")
                    .replace("{{port}}", "9023"))
        with pytest.raises(ScopeViolation):
            check_command(rendered, Scope(allow_hosts=["127.0.0.1"]))
