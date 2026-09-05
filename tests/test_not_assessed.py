"""An evaluator that could not decide must not read as a clean verdict.

`matched = False` carried two meanings: "checked, the target is fine" and
"could not check". The llm branch caught its exception, set matched = False and
printed to stderr, so a run against an unreachable LLM returned

    {"findings": [], "steps": [{"success": true, "error": null}]}

Nothing in the response, the database or the dashboard distinguished that from a
pass. On a paid engagement it reports a control as sound when it was never
tested — the same class of defect as WSTG-CLNT-09's
ERLIK_FRAMING_NOT_ASSESSED_REDIRECT, which this follows.

Reproduced live before the fix: WSTG-SESS-02 (its only evaluator is `llm`)
fetched `Set-Cookie: session=abc123; Path=/` — no Secure, no HttpOnly, no
SameSite — and reported zero findings with the backend down.
"""

import asyncio

import pytest

import orchestrator.testcase.runner as R
from orchestrator.testcase.schema import Evaluator, TargetSchema, TestCase


def _tc():
    return TestCase(id="X", name="x", category="c", severity="info",
                    target_schema=TargetSchema(required=[]), steps=[])


def _sr(output="HTTP/1.0 200 OK\nSet-Cookie: session=abc123; Path=/"):
    return R.StepResult(step="fetch_headers", command="curl -i http://t/",
                        success=True, output=output, duration_ms=1)


def _run(ev, monkeypatch=None):
    return asyncio.run(R._run_evaluator(ev, _sr(), _tc(), {}, None, None))


class TestAnUnreachableJudgeIsNotACleanBillOfHealth:
    def test_llm_backend_failure_is_reported(self, monkeypatch):
        async def _boom(*a, **k):
            raise RuntimeError("All connection attempts failed")
        monkeypatch.setattr(R.llm_client, "chat_json", _boom)

        finding, _, _, _, unassessed = _run(
            Evaluator(type="llm", instruction="are the cookie flags set?"))
        assert finding is None
        assert unassessed is not None, (
            "the evaluator could not run and said nothing — indistinguishable "
            "from a clean verdict"
        )
        assert unassessed.evaluator == "llm"
        assert unassessed.step == "fetch_headers"
        assert "All connection attempts failed" in unassessed.reason

    def test_a_working_judge_that_says_no_is_not_reported(self, monkeypatch):
        """The negative control, and the one that keeps this useful: if every
        findings-free run were flagged, the flag would mean nothing."""
        async def _no(*a, **k):
            return {"matched": False, "reason": "flags are set"}
        monkeypatch.setattr(R.llm_client, "chat_json", _no)

        finding, _, _, _, unassessed = _run(
            Evaluator(type="llm", instruction="are the cookie flags set?"))
        assert finding is None
        assert unassessed is None

    def test_a_judge_that_says_yes_still_emits(self, monkeypatch):
        async def _yes(*a, **k):
            return {"matched": True, "reason": "no HttpOnly"}
        monkeypatch.setattr(R.llm_client, "chat_json", _yes)

        finding, _, _, _, unassessed = _run(Evaluator(
            type="llm", instruction="check",
            emit_finding={"vuln_type": "Insecure Cookie Attributes",
                          "severity": "medium"}))
        assert finding is not None
        assert unassessed is None


class TestOtherWaysAnEvaluatorCanAssertNothing:
    def test_llm_without_an_instruction(self):
        _, _, _, _, unassessed = _run(Evaluator(type="llm"))
        assert unassessed is not None and "instruction" in unassessed.reason

    def test_a_type_the_runner_does_not_implement(self):
        """A typo in a case, or a type added to the schema before the runner
        learned it. It asserted nothing and must not count as asserting 'no'."""
        ev = Evaluator(type="regex", pattern="x")
        object.__setattr__(ev, "type", "smtp_banner")
        _, _, _, _, unassessed = _run(ev)
        assert unassessed is not None
        assert "smtp_banner" in unassessed.reason

    def test_a_regex_that_simply_does_not_match_is_a_real_no(self):
        """Guard on the guard above: an implemented evaluator reaching 'no' is
        a verdict, not an absence of one."""
        _, _, _, _, unassessed = _run(Evaluator(type="regex", pattern="NOPE"))
        assert unassessed is None


class TestItReachesTheOperator:
    def test_the_run_result_carries_it(self):
        assert "not_assessed" in R.RunResult.model_fields

    def test_the_dashboard_verdict_reads_it(self):
        import pathlib
        ui = (pathlib.Path(__file__).resolve().parents[1]
              / "dashboard" / "templates" / "index.html").read_text()
        i = ui.index("function tlVerdict")
        # Slice to the function's real closing brace, not a character count.
        # A fixed window has now failed three times in this repo the moment a
        # comment was added above the line under test.
        blk = ui[i:ui.index("\n        }", i)]
        assert "not_assessed" in blk, "the verdict ignores the structured field"
        # It must be consulted BEFORE the green path, or a run with an
        # unreachable judge still renders as 'no finding'.
        assert blk.index("not_assessed") < blk.index("nofinding")

    def test_it_is_persisted(self):
        import pathlib
        src = (pathlib.Path(__file__).resolve().parents[1]
               / "orchestrator" / "testcase" / "persistence.py").read_text()
        assert "not_assessed_json" in src, (
            "a stored run cannot answer 'was this actually checked?'"
        )
