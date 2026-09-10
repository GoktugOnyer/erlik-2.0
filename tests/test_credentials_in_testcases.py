"""Redaction must protect what is stored without deciding what is detected.

A credential is removed by SUBSTRING replacement. The runner used to apply that
to each step's output as it arrived, which meant the evaluators read the redacted
text — so an identity whose secret value happened to be a word a pattern needs
turned every real finding into a clean result. Found while measuring the lane on
2026-09-10, where the DVWA identity's `security=low` cookie rewrote the
application's own robots.txt as `Disal[REDACTED]: /` in stored evidence.
"""
import pytest

from orchestrator import credentials as CRED
from orchestrator.testcase.loader import find_by_id
from orchestrator.testcase.runner import (
    Finding, RunResult, StepResult, _scrub_for_storage, run_test_case)

LEAK = ("<b>Fatal error</b>:  Uncaught mysqli_sql_exception: You have an error in your SQL "
        "syntax; check the manual that corresponds to your MySQL server version for the "
        "right syntax to use near ''probe'' at line 1")


class _Store:
    """A db whose only job is to turn one handle into one plaintext value."""

    def __init__(self, secret):
        self.secret = secret

    async def execute(self, *_a, **_k):
        return self

    async def fetchone(self):
        return None


@pytest.mark.parametrize("secret", ["low", "SQL", "error", "near", "syntax", "manual", "probe"])
async def test_a_credential_value_cannot_disable_detection(secret, monkeypatch):
    """The decisive test: resolve a real handle to `secret`, then check the case
    still reports the real database error the application sent.

    Without the fix the evaluator read `You have an [REDACTED] in your SQL
    syntax...` and WSTG-INPV-05.2 found nothing at all."""
    async def _plaintext(db, session_id, field):
        return secret

    monkeypatch.setattr(CRED, "_plaintext", _plaintext)
    handle = CRED.handle("11111111-1111-1111-1111-111111111111", "cookie")
    seen = {}

    async def executor(command, **kwargs):
        # The command reaching the executor must carry the SECRET, not the handle.
        seen["command"] = command
        body = LEAK if "erlik'probe" in command else "<p>no rows</p>"
        return {"success": True, "exit_code": 0, "output": body, "error": None}

    run = await run_test_case(
        find_by_id("WSTG-INPV-05.2"),
        {"url": "http://app.test/x", "parameter": "id", "cookie": handle,
         "scope": {"allow_hosts": ["app.test"]}},
        db=_Store(secret), executor=executor, allow_llm=False)

    assert secret in seen["command"], "the handle never resolved; this proves nothing"
    assert run.findings, f"a secret value of {secret!r} suppressed a real finding"


@pytest.mark.parametrize("secret", ["error", "syntax", "s3cr3tvalue"])
async def test_and_what_is_stored_is_still_redacted(secret, monkeypatch):
    """The other half. Detection reads what the application sent; everything
    that LEAVES run_test_case is scrubbed — step outputs, step errors, and a
    finding's evidence and basis.

    Only values of four characters or more: both redaction layers guard on that
    length, because a three-character secret is not protectable by substring
    search and replacing it shreds ordinary text instead."""
    async def _plaintext(db, session_id, field):
        return secret

    monkeypatch.setattr(CRED, "_plaintext", _plaintext)
    handle = CRED.handle("11111111-1111-1111-1111-111111111111", "cookie")

    async def executor(command, **kwargs):
        body = LEAK if "erlik'probe" in command else "<p>no rows</p>"
        return {"success": True, "exit_code": 0, "output": body, "error": None}

    run = await run_test_case(
        find_by_id("WSTG-INPV-05.2"),
        {"url": "http://app.test/x", "parameter": "id", "cookie": handle,
         "scope": {"allow_hosts": ["app.test"]}},
        db=_Store(secret), executor=executor, allow_llm=False)

    assert run.findings
    for step in run.steps:
        assert secret not in step.output, f"{secret!r} survived into a stored step output"
    for finding in run.findings:
        assert secret not in finding.evidence
        assert secret not in finding.basis


def test_the_scrub_pass_covers_every_field_that_leaves():
    result = RunResult(test_case_id="t", target={})
    result.steps.append(StepResult(step="s", command="curl", success=True,
                                   output="token=s3cr3tvalue here", duration_ms=1,
                                   error="failed for s3cr3tvalue"))
    result.findings.append(Finding(test_case_id="t", step="s", evidence="saw s3cr3tvalue",
                                   basis="matched s3cr3tvalue"))
    _scrub_for_storage(result, ("s3cr3tvalue",))
    assert "s3cr3tvalue" not in result.steps[0].output
    assert "s3cr3tvalue" not in (result.steps[0].error or "")
    assert "s3cr3tvalue" not in result.findings[0].evidence
    assert "s3cr3tvalue" not in result.findings[0].basis


@pytest.mark.parametrize("short", ["low", "abc", "1", "id"])
def test_a_short_identity_value_does_not_rewrite_ordinary_text(short):
    """Both layers guard on length, and they must guard on the SAME length.

    Measured on the 2026-09-10 lane run before this was aligned: a DVWA identity
    carrying `security=low` stored the application's own robots.txt as
    `Disal[REDACTED]: /`. orchestrator.credentials.scrub had always skipped
    values under four characters; orchestrator.integrations.security.redact had
    no guard at all, so stored evidence stopped matching the bytes received."""
    from orchestrator.integrations.security import redact
    body = "User-agent: *\nDisallow: /\nLocation: /index.php"
    assert redact(body, (short,)) == body
    assert CRED.scrub(body, [short]) == body


def test_a_real_credential_is_still_removed_by_both_layers():
    from orchestrator.integrations.security import redact
    body = "Set-Cookie: PHPSESSID=1da920c8055f4e1; echoed=1da920c8055f4e1"
    for cleaned in (redact(body, ("1da920c8055f4e1",)), CRED.scrub(body, ["1da920c8055f4e1"])):
        assert "1da920c8055f4e1" not in cleaned
