"""Existing catalogue evaluators, executed only in the assessment sandbox."""
import json
import shlex
import re
from urllib.parse import urlsplit
from orchestrator.testcase.runner import run_test_case
from orchestrator.testcase.loader import find_by_id
from orchestrator.testcase.scope import ScopeViolation, check_url
from .adapters import BaseAdapter, record
from .contracts import StageResult, IntegrationFinding, fingerprint
from .egress_policy import EgressPolicy
from .inventory import seeds, eligible_test_cases
from .runtime import JobOutput
from .security import redact
from . import persistence as db


def curl_request(command):
    """Parse a deliberately small argv dialect; never pass catalogue text to a shell."""
    args = shlex.split(command)
    if not args or args.pop(0) != "curl":
        raise ScopeViolation("unsupported deterministic execution tool")
    method, urls, headers, data = "GET", [], [], False
    # argv is REBUILT from what was validated, never echoed back raw, so an
    # option this parser decided to drop cannot reach the sandbox anyway.
    emitted: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-s", "-i", "-sS", "-L", "--silent", "--include", "--location"):
            emitted.append(arg)
        elif arg in ("-I", "--head"):
            method = "HEAD"
            emitted.append(arg)
        elif arg in ("-X", "--request", "-H", "--header", "--data", "-d", "-b", "--cookie"):
            i += 1
            if i == len(args):
                raise ScopeViolation("missing curl option value")
            value = args[i]
            # A catalogue case written for the legacy lane carries
            # `-b "{{cookie}}" -H "{{auth_header}}"`. In an assessment those
            # target fields do not exist — identity is attached by the proxy,
            # per stage — so they render to the empty string. An empty option
            # is not a request to send nothing in particular; it is an option
            # that was never filled in, and dropping it is what the operator
            # meant. Refusing it instead made every auth-capable case in the
            # catalogue unrunnable here.
            if value == "" and arg in ("-H", "--header", "-b", "--cookie"):
                i += 1
                continue
            if arg in ("-X", "--request"):
                method = value.upper()
            elif arg in ("-H", "--header"):
                if value.split(":", 1)[0].lower() not in ("origin", "accept", "content-type") or any(c in value for c in "\r\n"):
                    raise ScopeViolation("unsupported catalogue header")
                headers.append(value)
            elif arg in ("-b", "--cookie"):
                # A NON-empty cookie would be the case authenticating itself,
                # behind the back of the stage's identity. The lane's isolation
                # guarantee — one identity per stage, applied by the proxy — is
                # only worth anything if a case cannot opt out of it.
                raise ScopeViolation(
                    "catalogue requests cannot carry their own credentials; "
                    "identity is applied per stage by the assessment proxy")
            else:
                if value.startswith("@"):
                    raise ScopeViolation("catalogue requests cannot read local files")
                data = True
            emitted.extend([arg, value])
        elif urlsplit(arg).scheme in ("http", "https"):
            urls.append(arg)
            emitted.append(arg)
        else:
            raise ScopeViolation("unsupported curl option or execution syntax")
        i += 1
    if len(urls) != 1 or (data and method == "GET"):
        raise ScopeViolation("expected one explicit HTTP destination and method")
    return ["curl", *emitted], urls[0], method


class CatalogueAdapter(BaseAdapter):
    name = "testcases"

    async def run(self, ctx, sandbox, collector=None):
        result = StageResult(metadata={"catalogue": [], "executed_checks": 0})
        policy = EgressPolicy(sandbox.policy)
        def check(command, scope, primary_url=None):
            _, url, method = curl_request(command)
            check_url(url, scope)
            permitted, reason = policy.check(url, method)
            if not permitted:
                raise ScopeViolation(reason)

        def step_policy(step, command):
            try:
                _, url, method = curl_request(command)
            except ScopeViolation:
                return None  # The checker reports unsupported paths as a failure.
            if method not in ("GET", "HEAD", "OPTIONS") and not policy.check(url, method)[0]:
                return "skipped: state-changing operation not selected"
            return None

        async def execute(command, **kwargs):
            argv, _, _ = curl_request(command)
            output = await sandbox.run([*argv, "--max-time", str(kwargs.get("custom_timeout") or 20),
                                        "--proxy", sandbox.proxy_url, "--cacert", "/input/ca.pem"])
            blocked = bool(re.search(r"(?im)^x-erlik-blocked:\s*true", output.stdout))
            return {"success": output.code == 0 and not blocked, "output": output.stdout,
                    "exit_code": output.code, "error": "request refused by scope policy" if blocked else output.stderr or None}

        targets = await seeds(ctx, sandbox.policy)
        for case_id in ctx.config.test_cases:
            tc = find_by_id(case_id)
            if not tc:
                raise ValueError("selected catalogue test is unavailable: " + case_id)
            case_targets = ([probe for probe in ctx.config.callback.probes] if case_id == "WSTG-INPV-19" and ctx.config.callback
                            else [{"url": url} for url in targets if case_id in eligible_test_cases(url)])
            for target in case_targets:
                target = {**target, "scope": ctx.config.scope.model_dump()}
                if case_id == "WSTG-INPV-19":
                    if not collector:
                        result.status, result.reason = "partial", "SSRF check incomplete: callback collector unavailable"
                        continue
                    run = await collector.run_test_case(tc, target, sandbox)
                else:
                    run = await run_test_case(tc, target, executor=execute, step_policy=step_policy,
                                              command_checker=check, allow_llm=False)
                evidence_id = await db.evidence(ctx.session_id, ctx.stage_id, "testcase:" + case_id,
                                                run.model_dump_json(), ctx.known)
                result.evidence_ids.append(evidence_id)
                result.metadata["executed_checks"] += sum(not s.skipped for s in run.steps)
                result.observations.append({"type": "test_case", "test_case_id": case_id, "url": target["url"],
                    "steps": [{"name": s.step, "success": s.success, "skipped": s.skipped, "error": s.error} for s in run.steps],
                    "evidence_id": evidence_id})
                for finding in run.findings:
                    rule = case_id + ":" + finding.step
                    result.findings.append(IntegrationFinding(fingerprint=fingerprint(ctx.target, rule, "GET", target["url"], identity=ctx.identity_id),
                        title=finding.vuln_type or tc.name, url=target["url"], rule=rule, source="testcase", identity=ctx.identity_id,
                        severity=finding.severity, confidence=finding.confidence, basis=finding.basis or "Deterministic catalogue evaluator matched the captured HTTP response",
                        methodology=[case_id], evidence_ids=[evidence_id]))
                if any(not s.success and not s.skipped for s in run.steps):
                    result.status, result.reason = "partial", "one or more catalogue checks could not complete"
            result.metadata["catalogue"].append(case_id)
        if not result.metadata["executed_checks"] and result.status == "completed":
            result.status, result.reason = "skipped", "no applicable selected checks"
        return await record(ctx, sandbox, JobOutput(0, json.dumps(redact(result.observations, ctx.known)), ""), result)
