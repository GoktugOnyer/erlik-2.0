"""Structured adapters. Tool output never becomes a confirmed finding by default."""
from __future__ import annotations
import asyncio
import hashlib
import json
import re
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit, urljoin, urlencode, parse_qsl, urlunsplit
import yaml

from .contracts import (AssessmentConfig, Endpoint, IntegrationFinding, StageResult,
                        fingerprint, parameter_names)
from .runtime import Sandbox, IMAGES, JobOutput
from .security import SecretStore, secret_values, redact
from . import persistence as db


@dataclass
class Context:
    session_id: str
    stage_id: str
    target: str
    config: AssessmentConfig
    identity_id: str = "anonymous"
    identity: dict | None = None

    @property
    def known(self):
        return secret_values(self.identity or {})


class Adapter(Protocol):
    name: str
    async def available(self) -> dict: ...
    async def cancel(self, sandbox: Sandbox) -> None: ...
    async def run(self, context: Context, sandbox: Sandbox) -> StageResult: ...


class BaseAdapter:
    required_images = ("proxy", "worker")

    async def available(self):
        from .runtime import availability
        images = await availability()
        return {key: images[key] for key in self.required_images}

    async def cancel(self, sandbox):
        await sandbox.close()


async def rpc(sandbox, request):
    path = sandbox.write(uuid.uuid4().hex + ".json", request)
    output = await sandbox.run(["python", "/opt/erlik/worker.py", path], timeout=60)
    if output.code:
        raise RuntimeError("HTTP worker failed: " + output.stderr[-500:])
    return json.loads(output.stdout)


async def record(context, sandbox, output, result, accepted_codes=(0,)):
    result.exit_code = output.code
    result.metadata["images"] = sandbox.images
    result.metadata["erlik_output_truncated"] = False
    # An EMPTY artifact is not evidence, and must not be cited as if it were.
    # Every finding inherits result.evidence_ids below, so a scanner that
    # exited cleanly with nothing on stderr was attaching a zero-byte
    # `erlik-job-<id>.stderr` to each of its findings: 22 of them in the
    # benchmark, which then reported 0 of 17 findings as evidence-backed. The
    # stage still records that it ran — exit_code, metadata and the audit log
    # all survive — but a finding now points only at bytes that exist.
    async def keep(kind: str, content: str):
        if content:
            result.evidence_ids.append(
                await db.evidence(context.session_id, context.stage_id, kind, content, context.known))

    await keep("stdout", output.stdout)
    await keep("stderr", output.stderr)
    for path in sorted(sandbox.output.rglob("*")):
        if path.is_file() and not path.is_symlink():
            await keep(path.name, path.read_text(errors="replace"))
    audit = sandbox.directory / "audit" / "requests.jsonl"
    if audit.exists():
        audit_text = audit.read_text()
        await keep("requests", audit_text)
        events = [json.loads(line) for line in audit_text.splitlines() if line.strip()]
        result.metadata["request_count"] = sum("allowed" in e for e in events)
        result.metadata["blocked_requests"] = sum(e.get("allowed") is False for e in events)
        if any(e.get("reason") in ("request budget exhausted", "URL budget exhausted") for e in events):
            result.status, result.reason = "partial", "request or URL budget exhausted"
    for finding in result.findings:
        finding.evidence_ids = sorted(set(finding.evidence_ids + result.evidence_ids))
    if output.timed_out:
        result.status, result.reason = "partial", "stage timed out; available evidence retained"
    elif output.code not in accepted_codes and result.status == "completed":
        result.status = "partial" if result.findings or result.observations else "failed"
        result.reason = f"scanner exited with {output.code}"
    return result


def json_lines(text):
    entries = []
    for line in text.splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if not isinstance(item, dict):
            raise ValueError("expected JSON object per line")
        entries.append(item)
    return entries


def parse_zap(document, ctx):
    result = StageResult()
    for site in document.get("site", []):
        for alert in site.get("alerts", []):
            rule = "zap:" + str(alert.get("pluginid", alert.get("alertRef", "unknown")))
            for item in alert.get("instances", []):
                url = item.get("uri", "")
                if not url:
                    continue
                method, parameter = item.get("method", "GET"), item.get("param", "")
                # `parameter` is NOT passed on for discovery, though it is
                # tempting: ZAP names the input vector its alert fired on, and
                # that is a cookie or a header at least as often as a query
                # parameter. This repo already proves it — the real-ZAP
                # assertion in tests/test_integration_lifecycle.py pins
                # zap:10010 reporting `fixture_session` on /zap/private, a
                # COOKIE name on a URL with no query string at all. Feeding it
                # here would have produced `?fixture_session=<payload>` and
                # `?X-Frame-Options=<payload>` probes.
                #
                # And its marginal value is exactly the wrong set: when ZAP
                # attacks a real GET query parameter the instance URI carries
                # that query, so parse_qsl already recovers the name. Anything
                # `parameter` adds BEYOND the URI is, by construction, a name
                # that was not a query parameter.
                result.endpoints.append(Endpoint(url=url, method=method, source="zap",
                                                 identity=ctx.identity_id,
                                                 parameters=parameter_names(url)))
                result.findings.append(IntegrationFinding(
                    fingerprint=fingerprint(ctx.target, rule, method, url, parameter, ctx.identity_id),
                    title=alert.get("name", alert.get("alert", rule)), url=url, rule=rule, source="zap", method=method,
                    parameter=parameter, identity=ctx.identity_id,
                    severity={"0": "informational", "1": "low", "2": "medium", "3": "high"}.get(str(alert.get("riskcode")), "medium"),
                    confidence="suspected", basis="ZAP alert; " + str(item.get("evidence", "")),
                    cwe=str(alert["cweid"]) if alert.get("cweid") else None,
                    methodology={"89": ["WSTG-INPV-05"], "79": ["WSTG-INPV-01"], "352": ["WSTG-SESS-05"]}.get(str(alert.get("cweid")), [])))
    return result


async def schema_file(ctx, sandbox):
    source = ctx.config.schema_input
    if not source:
        return None, None
    content = source.content
    if source.url:
        response = await rpc(sandbox, {"action": "request", "request": {"url": source.url}})
        if response["status"] != 200 or response["blocked"]:
            raise ValueError("schema retrieval failed or was blocked")
        content = response["body"]
    if source.kind == "openapi":
        document = yaml.safe_load(content)
        if not isinstance(document, dict) or not ("openapi" in document or "swagger" in document):
            raise ValueError("invalid OpenAPI document")
        async def bundle(node, base, ancestors=()):
            if isinstance(node, list):
                return [await bundle(n, base, ancestors) for n in node]
            if not isinstance(node, dict):
                return node
            ref = node.get("$ref", "")
            if ref and not ref.startswith("#"):
                uri = urljoin(base or "", ref)
                parts = urlsplit(uri)
                if parts.scheme not in ("http", "https") or uri in ancestors or len(ancestors) >= 8:
                    raise ValueError("unsupported, recursive, or non-HTTP external schema reference")
                response = await rpc(sandbox, {"action": "request", "request": {"url": uri.split("#")[0]}})
                if response["status"] != 200 or response["blocked"]:
                    raise ValueError("external schema reference refused or unavailable")
                loaded = yaml.safe_load(response["body"])
                for part in parts.fragment.removeprefix("/").split("/") if parts.fragment else []:
                    loaded = loaded[part.replace("~1", "/").replace("~0", "~")]
                # Local references inside external files cannot retain the root document's base.
                def rebase(value):
                    if isinstance(value, dict):
                        return {k: uri.split("#")[0] + v if k == "$ref" and isinstance(v, str) and v.startswith("#") else rebase(v) for k, v in value.items()}
                    return [rebase(v) for v in value] if isinstance(value, list) else value
                return await bundle(rebase(loaded), uri, ancestors + (uri,))
            return {key: await bundle(value, base, ancestors) for key, value in node.items()}
        document = await bundle(document, source.url)
        # Supplied target is authoritative; schema servers never expand scan scope.
        if "openapi" in document:
            document["servers"] = [{"url": ctx.target}]
        content = json.dumps(document)
    return sandbox.write("schema.graphql" if source.kind == "graphql" else "schema.json", content), hashlib.sha256(content.encode()).hexdigest()


class ZapAdapter(BaseAdapter):
    name = "zap"
    required_images = ("proxy", "worker", "zap")

    def plan(self, ctx, schema_path=None, inventory=None):
        target = ctx.target
        context = {"name": "erlik", "urls": [target], "includePaths": [re.escape(target.rstrip("/")) + ".*"],
                   "excludePaths": [re.escape(target.rstrip("/")) + re.escape(p) + ".*" for p in ctx.config.excluded_paths]}
        jobs = []
        if inventory:
            jobs.append({"type": "requestor", "requests": [{"url": url, "method": "GET"} for url in inventory]})
        if schema_path:
            kind = ctx.config.schema_input.kind
            jobs.append({"type": kind, "parameters": {("schemaFile" if kind == "graphql" else "apiFile"): schema_path,
                                                        ("endpoint" if kind == "graphql" else "targetUrl"): target}})
        jobs += [{"type": "spider", "parameters": {"context": "erlik", "maxDuration": max(1, ctx.config.budget.stage_seconds // 120),
                                                    "maxDepth": ctx.config.crawl_depth}},
                 {"type": "passiveScan-wait", "parameters": {"maxDuration": 2}}]
        if ctx.config.active:
            jobs += [{"type": "activeScan", "parameters": {"context": "erlik", "maxScanDurationInMins": max(1, ctx.config.budget.stage_seconds // 60)}}]
        jobs += [{"type": "report", "parameters": {"template": "traditional-json-plus", "reportDir": "/output", "reportFile": "zap.json"}}]
        return {"env": {"contexts": [context], "parameters": {"failOnError": True, "failOnWarning": False}}, "jobs": jobs}

    async def run(self, ctx, sandbox):
        schema, digest = await schema_file(ctx, sandbox)
        from .inventory import seeds
        inventory = await seeds(ctx, sandbox.policy)
        plan = self.plan(ctx, schema, inventory)
        path = sandbox.write("zap.yaml", yaml.safe_dump(plan))
        proxy = urlsplit(sandbox.proxy_url)
        config = ["network.connection.httpProxy.enabled=true", f"network.connection.httpProxy.host={proxy.hostname}",
                  f"network.connection.httpProxy.port={proxy.port}", "network.connection.httpProxy.exclusions.exclusion(0).enabled=false",
                  "api.disablekey=false", f"api.key={uuid.uuid4().hex}"]
        argv = ["zap.sh", "-cmd", "-autorun", path]
        for value in config:
            argv += ["-config", value]
        output = await sandbox.run(argv, image=IMAGES["zap"])
        report = sandbox.output / "zap.json"
        if report.exists():
            result = parse_zap(json.loads(report.read_text()), ctx)
        else:
            result = StageResult(status="failed", reason="ZAP did not produce its JSON report")
        result.metadata.update(image=IMAGES["zap"], schema_sha256=digest, inventory_seed_count=len(inventory),
                               plan_sha256=hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest())
        return await record(ctx, sandbox, output, result, accepted_codes=(0, 2))


class KatanaAdapter(BaseAdapter):
    name = "katana"

    async def run(self, ctx, sandbox):
        argv = ["katana", "-u", ctx.target, "-j", "-silent", "-jc", "-jsl", "-d", str(ctx.config.crawl_depth),
                "-c", str(ctx.config.budget.concurrency), "-rl", str(max(1, int(ctx.config.budget.requests_per_second))),
                "-proxy", sandbox.proxy_url, "-cs", re.escape(ctx.target.rstrip("/")) + ".*", "-duc"]
        browser_endpoints = []
        if ctx.config.headless or (ctx.identity or {}).get("storage_state"):
            browser = await rpc(sandbox, {"action": "browser", "url": ctx.target, "storage_state": (ctx.identity or {}).get("storage_state")})
            for request in browser["requests"]:
                browser_endpoints.append(Endpoint(url=request["url"], method=request["method"], source="playwright",
                                                  identity=ctx.identity_id, parameters=parameter_names(request["url"])))
            seeds = [ctx.target, *browser["links"], *[e.url for e in browser_endpoints]]
            from .egress_policy import EgressPolicy
            seeds = [u for u in dict.fromkeys(seeds) if EgressPolicy(sandbox.policy).check(u)[0]][:ctx.config.max_urls]
            seed_path = sandbox.write("seeds.txt", "\n".join(seeds))
            argv[1:3] = ["-list", seed_path]
        if ctx.config.headless:
            argv += ["-headless", "-no-sandbox", "-system-chrome", "-headless-options", "disable-quic,proxy-bypass-list=<-loopback>"]
        output = await sandbox.run(argv)
        result = StageResult(endpoints=browser_endpoints, metadata={"version": "1.2.2", "depth": ctx.config.crawl_depth})
        seen = {(e.url, e.method) for e in browser_endpoints}
        for row in json_lines(output.stdout):
            request = row.get("request", {})
            url, method = request.get("endpoint"), request.get("method", "GET")
            if url and (url, method) not in seen:
                seen.add((url, method))
                if len(result.endpoints) < ctx.config.max_urls:
                    result.endpoints.append(Endpoint(url=url, method=method, source="katana",
                                                     identity=ctx.identity_id, parameters=parameter_names(url)))
        if len(seen) > ctx.config.max_urls:
            result.status, result.reason = "partial", "URL inventory limit reached"
        return await record(ctx, sandbox, output, result)


class SchemathesisAdapter(BaseAdapter):
    name = "schemathesis"

    async def run(self, ctx, sandbox):
        schema, digest = await schema_file(ctx, sandbox)
        phases = "examples,coverage,fuzzing,stateful" if ctx.config.state_changing else "examples,coverage,fuzzing"
        argv = ["schemathesis", "run", schema, "--url", ctx.target, "--workers", str(ctx.config.budget.concurrency),
                "--phases", phases, "--seed", str(ctx.config.seed), "--max-examples", "30", "--request-timeout", "15",
                "--proxy", sandbox.proxy_url, "--tls-verify", "/input/ca.pem", "--report", "junit,har",
                "--report-junit-path", "/output/results.xml", "--report-har-path", "/output/requests.har",
                "--output-truncate", "false", "--generation-database", "none"]
        workflow = ctx.config.workflow
        if workflow:
            for operation in workflow.operations:
                argv += ["--include-operation-id", operation]
            path = sandbox.write("workflow.json", {"action": "workflow", "fixtures": [r.model_dump() for r in workflow.fixtures],
                "cleanup": [r.model_dump() for r in workflow.cleanup], "argv": argv,
                "scan_seconds": max(1, ctx.config.budget.stage_seconds - 45)})
            output = await sandbox.run(["python", "/opt/erlik/worker.py", path])
        else:
            if ctx.config.schema_input.kind == "openapi":
                argv += ["--include-method", "GET", "--include-method", "HEAD", "--include-method", "OPTIONS"]
            output = await sandbox.run(argv)
        result = StageResult(metadata={"version": "4.0.14", "seed": ctx.config.seed, "schema_sha256": digest})
        report = sandbox.output / "results.xml"
        if report.exists():
            for case in ET.fromstring(report.read_text()).iter("testcase"):
                for failure in list(case):
                    if failure.tag in ("failure", "error"):
                        result.observations.append({"type": "api_contract_failure", "operation": case.get("name"),
                                                    "details": failure.text or "", "security_finding": False})
                        if failure.tag == "error":
                            result.status, result.reason = "partial", "API test execution errors; inspect observations"
        else:
            result.status, result.reason = "failed", "Schemathesis produced no test report"
        har = sandbox.output / "requests.har"
        if har.exists():
            for entry in json.loads(har.read_text()).get("log", {}).get("entries", []):
                request = entry["request"]
                result.endpoints.append(Endpoint(url=request["url"], method=request["method"], source="schemathesis",
                                                 identity=ctx.identity_id, parameters=parameter_names(request["url"])))
        if workflow:
            detail = json.loads(output.stdout)
            result.observations.append({"type": "workflow", **detail})
            if detail.get("error") or any(not c.get("ok") for c in detail.get("cleanup", [])):
                result.status, result.reason = "partial", "workflow or cleanup failed; inspect evidence before retry"
        for assertion in ctx.config.security_assertions:
            if assertion.identity_id != ctx.identity_id:
                continue
            response = await rpc(sandbox, {"action": "request", "request": assertion.request.model_dump()})
            result.observations.append({"type": "security_assertion", "response": response})
            if not response["blocked"] and response["status"] == assertion.request.expected_status and assertion.forbidden_marker in response["body"]:
                rule = "erlik:authorization:" + hashlib.sha256(assertion.description.encode()).hexdigest()[:16]
                result.findings.append(IntegrationFinding(fingerprint=fingerprint(ctx.target, rule, "GET", assertion.request.url, identity=ctx.identity_id),
                    title=assertion.description, url=assertion.request.url, rule=rule, source="schemathesis", identity=ctx.identity_id,
                    confidence="confirmed", basis="Explicit forbidden-content assertion reproduced with the configured identity", severity="high",
                    methodology=["WSTG-AUTHZ-04"]))
        return await record(ctx, sandbox, output, result, accepted_codes=(0, 1))


ADAPTERS = {"zap": ZapAdapter(), "katana": KatanaAdapter(), "schemathesis": SchemathesisAdapter()}


async def run_deterministic_integrations(target: str, configuration: dict) -> dict:
    """Use the exact REST assessment pipeline from deterministic callers/test cases."""
    from . import service
    config = AssessmentConfig.model_validate(configuration)
    await service.preflight(target, config)
    key = uuid.uuid4().hex[:12]
    await db.execute("INSERT INTO sessions(id,target_url) VALUES(?,?)", (key, target))
    await service.register(key, target, config)
    await service.run(key)
    return await service.report(key)
