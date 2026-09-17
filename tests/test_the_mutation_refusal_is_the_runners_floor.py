"""E-033: the mutation refusal was one gate per lane, and one lane's was optional.

The entry read "the mutation refusal is a lane opt-in, not the runner's floor. Safe mode now
covers every lane, so this is two gates agreeing rather than one floor." The second sentence
is wrong, and it is what made the first look acceptable.

Safe mode lives in `execute_tool`. A caller that supplies its own `executor` never reaches it
— and the integration lane supplies one: `deterministic.execute` goes from `curl_request`
straight to `sandbox.run`, touching `_safe_mode_violation` nowhere. So that lane's only
mutation gate is `step_policy`, an optional keyword argument, and a lane that brought an
executor without one had no gate at all. Measured with a recording executor that sends
nothing:

    curl -X PUT     ...   SENT, refused by nothing
    curl -X DELETE  ...   SENT, refused by nothing
    curl -F @upload ...   refused — but by `curl_request`'s syntax rule, not by any
                          decision about mutation

The two that went through are exactly the two safe mode exists to stop.

So the floor is applied in `run_test_case`, where every caller passes whatever executor they
brought. It is deliberately redundant for the legacy lane: `execute_tool` refuses the same
commands again, and a second gate that never fires is what a floor is for.
"""
import pytest

from orchestrator.testcase.runner import run_test_case
from orchestrator.testcase.schema import TestCase as Case, TestStep as Step

SCOPE = {"allow_hosts": ["app.test"], "allow_ports": [80]}
WRITES = {
    "put": 'curl -s -i -X PUT "http://app.test/erlik_put_test.txt"',
    "delete": 'curl -s -i -X DELETE "http://app.test/records/1"',
    "patch": 'curl -s -i -X PATCH "http://app.test/records/1"',
}


async def run(command, **kwargs):
    """Run one step with an executor that RECORDS and sends nothing."""
    sent = []

    async def recorder(cmd, *a, **kw):
        sent.append(cmd)
        return {"success": True, "output": "", "error": None, "duration_ms": 1}

    case = Case(id="T", name="t", category="authz", severity="high",
                steps=[Step(name="s", tool="curl", command=command)])
    result = await run_test_case(case, {"url": "http://app.test/x", "scope": SCOPE},
                                 executor=recorder, allow_llm=False, **kwargs)
    return sent, result.steps[0]


# ------------------------------------------------------------------- the hole


@pytest.mark.parametrize("verb", sorted(WRITES))
async def test_a_lane_that_brought_its_own_executor_is_still_refused(verb):
    """The measured hole. No `step_policy`, so before this nothing stopped it."""
    sent, step = await run(WRITES[verb])
    assert sent == [], f"the request was issued: {sent}"
    assert step.skipped is True and step.error.startswith("SAFE_MODE: "), step


async def test_the_refusal_is_recorded_rather_than_dropped():
    """A report that omits a refused step reads as if the case ran clean — the rule the
    step-policy branch above it already follows."""
    _, step = await run(WRITES["put"])
    assert step.command == WRITES["put"]
    assert "HTTP write verb" in step.error, step.error
    assert "Safe mode is on" in step.error, step.error


async def test_a_read_is_untouched():
    """The floor must not become a reason nothing runs."""
    sent, step = await run('curl -s -i "http://app.test/x"')
    assert sent and step.skipped is False, step


async def test_the_floor_says_which_gate_spoke():
    """`SAFE_MODE:` distinguishes it from the lane's own step-policy refusal, which reads
    "skipped: this step would mutate…". A reader needs to know which decision to change."""
    _, floor = await run(WRITES["put"])
    _, lane = await run('curl -s -i -X POST -d "a=b" "http://app.test/login"',
                        step_policy=lambda step, cmd: "skipped: this step would mutate")
    assert floor.error.startswith("SAFE_MODE: ")
    assert not lane.error.startswith("SAFE_MODE: ")


# --------------------------------------------------- and what it must not change


async def test_the_lane_policy_still_speaks_first():
    """Safe mode deliberately allows POST — "a login step and a search probe are both
    POSTs". The integration lane refuses it anyway, and the floor must not displace that
    narrower rule with its own silence."""
    sent, step = await run('curl -s -i -X POST -d "a=b" "http://app.test/login"',
                           step_policy=lambda s, c: "skipped: this step would mutate with POST")
    assert sent == []
    assert step.error == "skipped: this step would mutate with POST", step.error


async def test_a_post_is_not_refused_by_the_floor_alone():
    """The other half of the same rule, and the one that would silently gut the catalogue
    if it were wrong: with no lane policy, a POST still runs."""
    sent, step = await run('curl -s -i -X POST -d "a=b" "http://app.test/login"')
    assert sent, step.error


async def test_an_authorised_engagement_can_still_write(monkeypatch):
    """`ERLIK_SAFE_MODE=0` is how destructive testing is authorised, and the floor has to
    honour it or the fix is a new way to break a real engagement. It reads the same
    environment `execute_tool` reads — the test-case lane never had a per-session override,
    which is what makes one source of truth correct here rather than a shortcut."""
    monkeypatch.setenv("ERLIK_SAFE_MODE", "0")
    sent, step = await run(WRITES["put"])
    assert sent == [WRITES["put"]], step.error


async def test_the_floor_is_read_from_the_one_rule_set():
    """A second copy of "what is destructive" is the defect this codebase names about its
    own catalogue lists. The floor must call `_safe_mode_violation`, not re-list verbs."""
    import inspect

    from orchestrator.testcase import runner

    source = inspect.getsource(runner.run_test_case)
    assert "_safe_mode_violation(cmd)" in source, (
        "the floor no longer defers to the one implementation of the safe-mode rules")


async def test_every_safe_mode_rule_reaches_the_floor():
    """Behavioural companion to the test above: whatever `_SAFE_MODE_RULES` names, the
    runner refuses. Reading the rule set rather than restating it, so a rule added later is
    covered without this file being edited."""
    from orchestrator.tool_executor import _SAFE_MODE_RULES

    samples = {
        "http-write-verb": WRITES["put"],
        "http-file-upload": 'curl -s -F "f=@-;filename=c.php" "http://app.test/u"',
        "sqlmap-os-takeover": 'sqlmap -u "http://app.test/x?id=1" --os-shell',
        "sqlmap-max-risk": 'sqlmap -u "http://app.test/x?id=1" --risk 3',
        # Found by this test rather than by reading the list — which is the reason it reads
        # the list. It caught `http-local-file-read` the same way three increments later.
        "sql-ddl-dml": 'curl -s "http://app.test/x?q=1;DROP TABLE users--"',
        "http-local-file-read": 'curl -d @/etc/passwd "http://app.test/x"',
    }
    assert {rule for rule, _, _ in _SAFE_MODE_RULES} <= set(samples), (
        f"a safe-mode rule has no sample here: "
        f"{{r for r, _, _ in _SAFE_MODE_RULES}} - {set(samples)}")
    for rule, command in samples.items():
        sent, step = await run(command)
        assert sent == [], f"{rule}: the request was issued"
        assert step.skipped is True, f"{rule}: {step.error}"
