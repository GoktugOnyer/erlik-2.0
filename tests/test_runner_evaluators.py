import pytest
from orchestrator.testcase.runner import StepResult, _run_evaluator, run_test_case
from orchestrator.testcase.schema import TestCase as Case, Evaluator


def step(output, code=0, name="probe"):
    return StepResult(step=name, command="curl", success=code == 0, output=output, duration_ms=1, exit_code=code)


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


@pytest.mark.asyncio
async def test_cors_wildcard_never_means_credentialed_read():
    ev = Evaluator(type="cors", emit_finding={})
    response = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Credentials: true\r\n\r\npublic"
    assert (await _run_evaluator(ev, step(response), case(), {}, None, None))[0] is None
    response = response.replace("Origin: *", "Origin: https://evil.oast.test")
    finding = (await _run_evaluator(ev, step(response), case(), {}, None, None))[0]
    assert finding.confidence == "suspected"


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
