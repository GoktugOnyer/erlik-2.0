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
                        fingerprint, form_endpoint, parameter_names)
from .runtime import Sandbox, IMAGES, JobOutput
from .security import SecretStore, secret_values, redact, safe_evidence
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


# A finding's evidence is target-controlled text that travels into a report and
# into a client's issue tracker. Bounded here as well as at the runner seam.
MAX_EVIDENCE_CHARS = 1500


def _marker_window(body: str, marker: str, window: int = 200) -> str:
    """The neighbourhood of the forbidden content, not the whole response."""
    at = body.find(marker)
    if at < 0:
        return ""
    start = max(0, at - window // 4)
    return body[start:start + window]


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
    async def keep(kind: str, content: str, *, artifact: bool = False):
        # An empty FILE is a valid attachment — an empty STREAM is not.
        #
        # A scanner that wrote a zero-byte log did write one, and the fact that
        # it had nothing to say is worth keeping. A scanner that printed nothing
        # on stderr produced no artifact at all, and attaching one was the
        # original defect: 22 findings each citing a zero-byte
        # `erlik-job-<id>.stderr`, which then made every one of them read as
        # unsupported. The clause asks for empty diagnostic FILES to be valid
        # attachments, not for empty streams to become files.
        if content or artifact:
            result.evidence_ids.append(
                await db.evidence(context.session_id, context.stage_id, kind, content, context.known))

    await keep("stdout", output.stdout)
    await keep("stderr", output.stderr)
    for path in sorted(sandbox.output.rglob("*")):
        if path.is_file() and not path.is_symlink():
            await keep(path.name, path.read_text(errors="replace"), artifact=True)
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
        # A finding that already cites its OWN evidence keeps ONLY that. The
        # union is for scanner findings, which arrive citing nothing and have
        # only the stage's report to point at — ZAP's and the security
        # assertions' both do.
        #
        # Measured on the 2026-09-10 lane run: the catalogue attaches exactly
        # one evidence id per finding, the id of the run that produced it, and
        # this loop then unioned the whole stage onto it. All nine DVWA findings
        # came out citing the SAME 772 ids, so a client reading the report could
        # not tell which of 772 captured responses proved a given HIGH-severity
        # SQL injection. Precise attribution is the whole value of per-case
        # evidence, and it was being averaged away at the last step.
        if not finding.evidence_ids:
            finding.evidence_ids = sorted(result.evidence_ids)
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


def _zap_evidence(rule: str, item: dict, ctx) -> str:
    """Everything ZAP says about one instance, not just its `evidence` field.

    ZAP hands over `attack` — the payload it sent — and `otherinfo`, which is
    often where the actual reasoning is. Both were parsed and discarded, so a
    client reading a ZAP SQL-injection finding got the string
    `ZAP alert zap:40018` and nothing else, while the instance in hand held
    `attack="1' AND '1'='1' -- "`. The payload is the one thing that makes a
    scanner finding replayable.

    `attack` is ZAP's own text; `evidence` and `otherinfo` are quoted from the
    application. All three are treated as target-controlled, because separating
    them per field buys nothing and assuming wrongly costs a leak.
    """
    # The payload is quoted with repr() because its whitespace is significant and
    # invisible: MySQL's `-- ` comment needs its trailing space, and a reader
    # replaying a stripped payload gets a different query. The other two rows are
    # prose quoted from the application and read better plain.
    rows = [("payload sent", repr(str(item.get("attack", "")))
             if str(item.get("attack", "")).strip() else ""),
            ("matched", str(item.get("evidence", "")).strip()),
            ("reported by ZAP", str(item.get("otherinfo", "")).strip())]
    body = "\n".join(f"    {label:<16} {value}" for label, value in rows if value)
    if not body:
        return ""
    header = f"ZAP {rule}" + (f" on parameter {item['param']}" if item.get("param") else "")
    return safe_evidence(redact(header + "\n" + body, ctx.known))[:MAX_EVIDENCE_CHARS]


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
                    confidence="suspected", basis="ZAP alert " + rule,
                    # ZAP's own evidence used to be concatenated onto `basis`,
                    # which is how the two got conflated in the first place: the
                    # grounds for the claim and the target's own bytes in one
                    # string, so a consumer could render neither safely. It is
                    # the same kind of thing as a catalogue evaluator's proof and
                    # belongs in the same field.
                    evidence=_zap_evidence(rule, item, ctx),
                    cwe=str(alert["cweid"]) if alert.get("cweid") else None,
                    methodology={"89": ["WSTG-INPV-05"], "79": ["WSTG-INPV-01"], "352": ["WSTG-SESS-05"]}.get(str(alert.get("cweid")), [])))
    return result


async def schema_file(ctx, sandbox):
    source = ctx.config.schema_input
    if not source:
        return None, None, None
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
    return (sandbox.write("schema.graphql" if source.kind == "graphql" else "schema.json", content),
            hashlib.sha256(content.encode()).hexdigest(),
            document if source.kind == "openapi" else None)


def schema_endpoints(document, target, identity):
    """Endpoints and their QUERY parameters, as the OpenAPI document declares them.

    The best parameter source in the lane, and the only one that is not
    target-controlled: the operator supplied this schema, and it states each
    parameter's location outright (`in: query`) instead of leaving it to be
    inferred from a URL. A name from here cannot be planted by the application
    under test, so it cannot be chosen to match a case's own evidence.

    Templated paths (`/items/{id}`) are skipped: the template is not a URL, and
    the concrete ones arrive anyway from the request log Schemathesis leaves.
    """
    found = []
    for path, operations in (document or {}).get("paths", {}).items():
        if not isinstance(operations, dict) or "{" in path:
            continue
        shared = operations.get("parameters", [])
        for method, operation in operations.items():
            if method.lower() not in ("get", "head") or not isinstance(operation, dict):
                continue
            names = [item.get("name", "") for item in [*shared, *operation.get("parameters", [])]
                     if isinstance(item, dict) and item.get("in") == "query"]
            url = urljoin(target, path)
            if names:
                found.append(Endpoint(url=url, method=method.upper(), source="openapi",
                                      identity=identity, parameters=parameter_names(url, *names)))
    return found


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
        schema, digest, document = await schema_file(ctx, sandbox)
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


def wants_rendered_pass(config) -> bool:
    """Should this ASSESSMENT run the rendered (Playwright) discovery pass?

    It is the only producer of `source="form"` and `source="playwright"` endpoints,
    and on DVWA every one of the eight (url, parameter) pairs the lane finds comes
    from it.

    This used to be asked per stage, as
    `ctx.config.headless or (ctx.identity or {}).get("storage_state")`. Two things
    were wrong with that. The proxy injects `identity.headers`, `identity.cookies`
    AND `storage_state.cookies` on every in-scope request, so an identity
    authenticated by plain cookies was fully authenticated and discovered nothing —
    measured against real DVWA with the browser context created as
    `storage_state=None` in both arms:

        anonymous             1342 bytes (the login page)   1 link    1 form
        cookie-only identity  6436 bytes                   31 links  13 forms

    And the obvious repair — "run it when THIS identity carries material" — is
    itself a fork generator. E-008's matrix starts at "anonymous, two ordinary users
    in different tenants, and one privileged lab identity", and an operator may name
    `anonymous` alongside real handles; under a per-arm test that arm alone would
    have no rendered surface, the arms could never agree, and `compare_arms` would
    refuse every differential drawn from the assessment. §3 moved identity isolation
    into R0 precisely to stop that.

    So the question is asked of the ASSESSMENT, and takes the config alone — it
    cannot see an identity, so it cannot branch on one. Every arm answers the same.

    An assessment that selected no identity and did not ask for a rendered crawl
    still gets none: the pass launches Chromium, and nobody should pay for it
    unasked.
    """
    return bool(config.headless or config.identity_ids)


class KatanaAdapter(BaseAdapter):
    name = "katana"

    async def run(self, ctx, sandbox):
        argv = ["katana", "-u", ctx.target, "-j", "-silent", "-jc", "-jsl", "-d", str(ctx.config.crawl_depth),
                "-c", str(ctx.config.budget.concurrency), "-rl", str(max(1, int(ctx.config.budget.requests_per_second))),
                "-proxy", sandbox.proxy_url, "-cs", re.escape(ctx.target.rstrip("/")) + ".*", "-duc"]
        browser_endpoints = []
        if wants_rendered_pass(ctx.config):
            browser = await rpc(sandbox, {"action": "browser", "url": ctx.target, "storage_state": (ctx.identity or {}).get("storage_state")})
            for request in browser["requests"]:
                browser_endpoints.append(Endpoint(url=request["url"], method=request["method"], source="playwright",
                                                  identity=ctx.identity_id, parameters=parameter_names(request["url"])))
            for form in browser.get("forms") or []:
                built = form_endpoint(form, browser.get("url") or ctx.target)
                if not built:
                    continue
                url, names = built
                browser_endpoints.append(Endpoint(url=url, method="GET", source="form",
                                                  identity=ctx.identity_id, parameters=names))
            # A form-synthesised URL is NOT a page, and must never be crawled.
            #
            # form_endpoint builds `/vulnerabilities/csrf/?Change=Change` so a
            # parameter probe can reach the form's handler. Handing it to katana
            # as a seed makes katana FETCH it, and fetching it submits the form
            # with every field blank. Measured on DVWA, 2026-09-10, in a run
            # declaring state_changing: false: that one crawl request set the
            # admin password to md5(""), because the handler runs on
            # `isset($_GET['Change'])` and compares two absent fields, NULL to
            # NULL. The lane changed the target's credentials while merely
            # enumerating it.
            #
            # These URLs stay in result.endpoints — that is how the catalogue
            # finds the parameters on them, which is the whole point of form
            # discovery and produced the run's only true positives. They simply
            # are not pages to visit.
            crawlable = [e.url for e in browser_endpoints if e.source != "form"]
            seeds = [ctx.target, *browser["links"], *crawlable]
            from .egress_policy import EgressPolicy
            seeds = [u for u in dict.fromkeys(seeds) if EgressPolicy(sandbox.policy).check(u)[0]][:ctx.config.max_urls]
            seed_path = sandbox.write("seeds.txt", "\n".join(seeds))
            argv[1:3] = ["-list", seed_path]
        # katana is NOT asked to launch its own browser, even in headless mode.
        # Its headless path extracts a `leakless` helper into /tmp and execs it,
        # and the job tmpfs is mounted noexec — which is correct for a sandbox
        # running scanners against a hostile target, and not something to
        # weaken for a crawler's convenience. Measured: katana exits 1 with
        # "fork/exec /tmp/leakless-…: permission denied" and the whole stage
        # fails, discarding a crawl that had otherwise worked.
        #
        # Nothing is lost. The rendered pass is Playwright's, above, and katana
        # is seeded with everything it found; katana's own browser would be a
        # second renderer doing the same work.
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
        elif not result.endpoints:
            # A crawler that finds nothing and exits 0 is indistinguishable from
            # a target with no attack surface, and everything downstream is
            # sized by this inventory: no endpoints means no parameters, which
            # means every case that tests one reports nothing. Measured against
            # DVWA — katana emits no output at all and exits 0 there, while
            # working normally on Juice Shop — and the stage was recorded
            # "completed", which reads as a clean result for an application
            # that is famously full of holes.
            result.status = "partial"
            result.reason = ("discovery returned no endpoints; the target may be unreachable, "
                             "behind a login this identity does not satisfy, or served in a form "
                             "this crawler cannot follow — nothing downstream has an inventory to test")
        return await record(ctx, sandbox, output, result)


class SchemathesisAdapter(BaseAdapter):
    name = "schemathesis"

    async def run(self, ctx, sandbox):
        schema, digest, document = await schema_file(ctx, sandbox)
        # Recorded before the run, not after: these come from the operator's own
        # schema, so they are known whether or not Schemathesis reaches anything.
        schema_declared = schema_endpoints(document, ctx.target, ctx.identity_id)
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
        result.endpoints.extend(schema_declared)
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
                    # The marker's neighbourhood, so the reader can see the
                    # forbidden content rather than be told it was there.
                    evidence=safe_evidence(redact(_marker_window(response["body"], assertion.forbidden_marker),
                                    ctx.known))[:MAX_EVIDENCE_CHARS],
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
