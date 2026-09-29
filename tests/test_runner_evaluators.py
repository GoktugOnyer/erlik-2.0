import pytest
from orchestrator.testcase.runner import StepResult, _run_evaluator, run_test_case
from orchestrator.testcase.schema import TestCase as Case, Evaluator


def step(output, code=0, name="probe", command="curl"):
    return StepResult(step=name, command=command, success=code == 0, output=output, duration_ms=1, exit_code=code)


def case():
    return Case(id="test", name="test", category="test", steps=[])


@pytest.mark.asyncio
async def test_real_exit_code():
    ev = Evaluator(type="status_code", expect=[7], emit_finding={})
    assert (await _run_evaluator(ev, step("", 8), case(), {}, None, None))[0] is None
    assert (await _run_evaluator(ev, step("", 7), case(), {}, None, None))[0] is not None


@pytest.mark.asyncio
async def test_race_marker_count_across_lines():
    ev = Evaluator(type="count", emit_finding={})
    result = await _run_evaluator(ev, step('success[1]\nsuccess[1]'), case(), {"success_marker": "success[1]"}, None, None)
    assert result[0] is not None
    assert (await _run_evaluator(ev, step('success[1]'), case(), {"success_marker": "success[1]"}, None, None))[0] is None


CORS_RESPONSE = ("HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: {origin}\r\n"
                 "Access-Control-Allow-Credentials: true\r\n\r\npublic")


@pytest.mark.asyncio
async def test_cors_wildcard_never_means_credentialed_read():
    """A browser refuses the wildcard the moment credentials are attached, so
    reporting it as a credentialed read is a false positive with a severity on it."""
    ev = Evaluator(type="cors", emit_finding={})
    wildcard = step(CORS_RESPONSE.format(origin="*"))
    assert (await _run_evaluator(ev, wildcard, case(), {}, None, None))[0] is None

    reflected = step(CORS_RESPONSE.format(origin="https://evil.oastify.com"))
    finding = (await _run_evaluator(ev, reflected, case(), {}, None, None))[0]
    assert finding.confidence == "suspected"


@pytest.mark.asyncio
async def test_cors_judges_the_origin_the_step_actually_sent():
    """The evaluator used to compare against a constant, and the constant drifted
    away from the origin the case sends -- so a server reflecting the attacker
    origin with credentials produced no finding at all, which reads as a correctly
    configured application. It reads the Origin off the step's own command now.

    The origin here is deliberately neither the constant nor anything in the
    catalogue: the only way to match it is to have read the command.
    """
    ev = Evaluator(type="cors", emit_finding={})
    command = 'curl -s -i -H "Origin: https://attacker.example" "https://app.test/"'
    reflected = step(CORS_RESPONSE.format(origin="https://attacker.example"),
                     command=command)
    assert (await _run_evaluator(ev, reflected, case(), {}, None, None))[0] is not None


@pytest.mark.asyncio
async def test_cors_does_not_fire_on_an_origin_the_step_did_not_send():
    """The negative half. A server that reflects SOMEONE ELSE'S origin has not
    reflected ours, and a check that accepted any reflected origin would report
    every correctly configured allowlist as a finding."""
    ev = Evaluator(type="cors", emit_finding={})
    command = 'curl -s -i -H "Origin: https://attacker.example" "https://app.test/"'
    other = step(CORS_RESPONSE.format(origin="https://trusted.example"), command=command)
    assert (await _run_evaluator(ev, other, case(), {}, None, None))[0] is None


@pytest.mark.asyncio
async def test_cors_lets_the_target_override_the_origin():
    """`test_origin` still wins, for a caller that sends its own header."""
    ev = Evaluator(type="cors", emit_finding={})
    command = 'curl -s -i -H "Origin: https://attacker.example" "https://app.test/"'
    reflected = step(CORS_RESPONSE.format(origin="https://chosen.example"), command=command)
    assert (await _run_evaluator(ev, reflected, case(),
                                 {"test_origin": "https://chosen.example"},
                                 None, None))[0] is not None


@pytest.mark.asyncio
async def test_idor_needs_baseline_marker_and_distinct_identities():
    ev = Evaluator(type="idor", emit_finding={})
    output = "HTTP/1.1 200 OK\r\n\r\nprivate-canary"
    target = {"private_object_marker": "private-canary", "low_priv_token": "user", "high_priv_token": "admin"}
    prior = [step(output, name="fetch_as_high_priv")]
    assert (await _run_evaluator(ev, step(output), case(), target, None, None, prior))[0].confidence == "confirmed"
    assert (await _run_evaluator(ev, step(output), case(), target, None, None, []))[0] is None
    target["low_priv_token"] = "admin"
    assert (await _run_evaluator(ev, step(output), case(), target, None, None, prior))[0] is None


@pytest.mark.asyncio
async def test_step_timeout_forwarded(monkeypatch):
    from unittest.mock import AsyncMock
    import orchestrator.testcase.runner as runner
    execute = AsyncMock(return_value={"success": True, "output": "ok", "exit_code": 0})
    monkeypatch.setattr(runner, "execute_tool", execute)
    tc = Case(id="test", name="test", category="test", steps=[{"name": "probe", "tool": "curl", "command": "curl https://app.test", "timeout": 17}])
    await run_test_case(tc, {"url": "https://app.test", "scope": {"allow_hosts": ["app.test"]}})
    assert execute.call_args.kwargs["custom_timeout"] == 17
