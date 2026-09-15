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

from .contracts import (canonical_origin, AssessmentConfig, Endpoint, IntegrationFinding, StageResult,
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
    # What each declared SecurityAssertion's URL answers with NO identity, probed once per
    # assessment in the identity-free sandbox `authentication_controls` already builds. A
    # property of the URL and the application rather than of a stage, for the same reason
    # given there — and the only thing that can tell a gated record from a public one.
    assertion_controls: dict | None = None

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
# Re-exported: the bound lives beside the field it bounds.
from .contracts import MAX_EVIDENCE_CHARS  # noqa: F401


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
    # NO `erlik_output_truncated` FLAG. It was assigned the constant False on every stage
    # and set True nowhere, so it reported "nothing was truncated" whether or not anything
    # was — a protection-shaped field that could not fire. Nothing read it either.
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
        await keep("requests", audit.read_text(errors="replace"))
        events, unreadable = audit_events(audit)
        result.metadata["request_count"] = sum("allowed" in e for e in events)
        result.metadata["blocked_requests"] = sum(e.get("allowed") is False for e in events)
        # SAID, not dropped. With holes in the log these counts are floors, and a reader
        # comparing `request_count` against a budget needs to know which it is.
        if unreadable:
            result.metadata["unreadable_audit_lines"] = unreadable
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


def audit_events(path) -> tuple[list, int]:
    """The proxy audit log, read tolerantly: `(events, unreadable_lines)`.

    THE AUDIT LOG IS WRITTEN BY A PROCESS THAT CAN BE KILLED. `json_lines` raises on the
    first line it cannot parse, and both readers of this file called it bare — so one
    truncated last line, which is exactly what a killed mitmproxy leaves, raised
    `json.JSONDecodeError` out of `Collector.finish()` and out of `record()`. Measured:

        a clean log                           1 event
        a truncated last line                 JSONDecodeError: Unterminated string
        invalid utf-8                         UnicodeDecodeError out of read_text()

    Out of `finish()` that was the whole assessment: the exception escaped the stage loop
    and the run was recorded `completed` (see the `except Exception` in `service.run`). A
    half-written diagnostic line must not be able to do that.

    `errors="replace"`, because the bytes are a diagnostic record rather than a protocol,
    and a log that cannot be decoded should still yield the lines that can.

    IT RETURNS THE COUNT rather than dropping quietly. `finish()` already counts malformed
    CALLBACK lines and degrades the stage to `partial` for them; the audit log gets the
    same treatment, because a request history with holes in it is a request history whose
    counts are floors and the caller has to be able to say so.
    """
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return [], 0
    events, unreadable = [], 0
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except ValueError:
            unreadable += 1
            continue
        if not isinstance(item, dict):
            unreadable += 1
            continue
        events.append(item)
    return events, unreadable


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


def load_openapi_document(content, source: str = "the supplied schema"):
    """Parse and validate an OpenAPI document, saying what is wrong when it is not one.

    E-012: "missing or incompatible schemas should not disappear into a generic scanner
    failure." Measured on the committed code, for the five ways a schema can be wrong:

        malformed YAML        a raw multi-line `yaml.ParserError` in both readers
        a YAML scalar         `AttributeError: 'str' object has no attribute 'get'`
        a YAML list           `AttributeError: 'list' object has no attribute 'get'`
        an HTML error page    `AttributeError: 'str' object has no attribute 'get'`
        JSON that is not a
        specification         "selected operation IDs are missing from schema"

    Those reasons reach the operator: the stage row carries `redact(str(exc))`. The last is
    the worst of them — it is not generic, it is WRONG, and it sends someone to check the
    operation IDs they typed when the document is not a specification at all.

    ONE VALIDATOR, because there were two readers of the same bytes that disagreed.
    `schema_file` validated the document and `operation_routes` did not, so the same schema
    produced "invalid OpenAPI document" in one lane and an AttributeError in the other. Two
    copies of one fact is the defect this codebase names about its own catalogue lists.

    The HTML case is called out by name because it is the common one in practice: a schema
    URL that answers 200 with a login page, an error page, or documentation ABOUT the API.
    """
    try:
        document = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        # One line. `yaml`'s own message is a multi-line mark dump that renders as noise in
        # a stage `reason`, and the useful part is the first line and the position.
        detail = " ".join(str(exc).split())[:180]
        raise ValueError(f"{source} is not parseable as YAML or JSON: {detail}") from exc
    if isinstance(document, str) and document.lstrip()[:1] == "<":
        raise ValueError(
            f"{source} returned markup rather than a specification — a schema URL that "
            f"answers 200 with a login page, an error page, or documentation ABOUT the API "
            f"is the usual cause")
    if not isinstance(document, dict):
        kind = type(document).__name__
        raise ValueError(
            f"{source} parsed as a {kind}, not an OpenAPI document; check that the URL or "
            f"content is the specification itself")
    if not ("openapi" in document or "swagger" in document):
        raise ValueError(
            f"{source} has no `openapi` or `swagger` key, so it is not an OpenAPI "
            f"specification; its top-level keys are "
            f"{sorted(str(k) for k in document)[:8]}")
    return document

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
        document = load_openapi_document(
            content, f"the schema at {source.url}" if source.url else "the supplied schema")
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
        base = re.escape(target.rstrip("/"))
        # ZAP runs its own spider, and the operator's excluded_paths are prefixes —
        # so nothing told it about `/users/sign_out` or `/Account/LogOff`. The proxy
        # refuses those (egress_policy.ends_the_session) and the session survives
        # either way, but ZAP spent a request discovering that. Telling it the same
        # thing saves the budget.
        #
        # Matched per WHOLE segment, the same rule the proxy applies, so the two
        # layers agree about one list rather than approximating each other: the
        # segment must start right after a slash AND end at a slash, a query or the
        # end of the path. `/blog/how-to-logout-safely` and `/docs/signout-api` are
        # pages and stay crawlable.
        #
        # `(?i)` because ASP.NET MVC ships `/Account/LogOff` — understood by both
        # Java's regex engine, which is ZAP's, and Python's, which is the test's.
        from .egress_policy import SESSION_ENDING_SEGMENTS
        excluded = [base + re.escape(p) + ".*" for p in ctx.config.excluded_paths]
        excluded += ["(?i)" + base + ".*/" + re.escape(segment) + "(?:[/?].*)?"
                     for segment in sorted(SESSION_ENDING_SEGMENTS)]
        context = {"name": "erlik", "urls": [target], "includePaths": [base + ".*"],
                   "excludePaths": excluded}
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


MAX_INFERRED_SCRIPTS = 6


async def infer_from_scripts(ctx, sandbox, endpoints) -> tuple[list, dict | None]:
    """Routes the application's own JavaScript names, which no crawler follows.

    Discovery is the lane's binding constraint and this is the measured reason. On
    Juice Shop the lane reports 136 endpoints, 4 parameters and 2 informational
    findings, while the application's error-based SQL injection sits behind an Angular
    XHR — and the route is in `main.js`, a file the lane already fetched and recorded:

        .get(`${this.hostServer}/rest/products/search?q=${e}`)

    Handed that URL directly the lane reports it HIGH in 21 seconds. Recovered from the
    real bundle, with the four off-origin candidates in the same file refused:

        /rest/products/search        q          the SQL injection
        /redirect                    to         the known open redirect
        /rest/user/security-question email
        /api/Challenges/             key
        /rest/user/change-password   current    a MUTATING endpoint

    THE LAST ROW IS WHY THESE ARE PROPOSALS AND NOT TARGETS. Nothing syntactic
    separates the first from the last, and a GET of `change-password?current=` as an
    authenticated identity reaches the real password-change logic — measured: it
    answers 401 anonymously, so authentication is the only thing standing between the
    lane and changing a credential while enumerating. So an inferred endpoint is
    recorded with `source="javascript"` and WITHHELD from `seeds()` and
    `parameters_by_url()`. It appears in the inventory for an operator to select, which
    is what E-007 means by keeping an inferred operation distinct from a tested one and
    E-010 by "templates fill configuration; they do not expand authorization".

    Bounded to `MAX_INFERRED_SCRIPTS` bodies, and only same-origin ones the crawl
    already fetched, so this costs a handful of GETs for static assets the browser had
    already downloaded.
    """
    from urllib.parse import urldefrag
    from orchestrator.engagement import looks_injectable
    from .contracts import canonical_origin, infer_endpoints
    from .egress_policy import EgressPolicy

    policy = EgressPolicy(sandbox.policy)
    scripts = []
    for endpoint in endpoints:
        url = urldefrag(endpoint.url)[0]
        if not url.lower().split("?")[0].endswith(".js"):
            continue
        if canonical_origin(url) != canonical_origin(ctx.target):
            continue
        if looks_injectable(url) or not policy.check(url, "GET")[0]:
            continue
        if url not in scripts:
            scripts.append(url)
        if len(scripts) >= MAX_INFERRED_SCRIPTS:
            break

    inferred, per_script = [], {}
    for url in scripts:
        try:
            response = await rpc(sandbox, {"action": "request", "request": {"url": url}})
        except Exception:
            continue                       # an unreadable script is not a failure
        if response.get("blocked") or not isinstance(response.get("body"), str):
            continue
        routes = infer_endpoints(response["body"], base=url)
        if routes:
            per_script[url] = [path for path, _ in routes]
        for path, names in routes:
            candidate = canonical_origin(ctx.target) + path
            if looks_injectable(candidate) or not policy.check(candidate, "GET")[0]:
                continue
            inferred.append(Endpoint(url=candidate, method="GET", source="javascript",
                                     identity=ctx.identity_id, parameters=names))

    if not inferred:
        return [], None
    # Stated, because an inferred route that looks like a discovered one is a claim of
    # coverage nobody earned.
    observation = {
        "type": "inferred_from_javascript", "url": None, "steps": [],
        "scripts_read": len(scripts), "operations": sorted({e.url for e in inferred}),
        "detail": (f"{len(set(e.url for e in inferred))} route(s) were read out of "
                   f"{len(scripts)} script body/bodies and are NOT probed: a route the "
                   f"crawler never reached has never been requested either, and nothing "
                   f"syntactic separates a search endpoint from a password change. "
                   f"Select one to test it."),
    }
    return inferred, observation


def crawl_truncation(browser: dict) -> dict | None:
    """The rendered crawl's page cap, stated rather than left to be inferred.

    The cap is worse than most caps, and in both directions. Two arms publishing
    DIFFERENT menus truncate at different places, so the cap manufactures a surface
    difference; two arms publishing the SAME menu truncate identically and the cap
    HIDES a real one. Measured on DVWA: changing only the crawl root from
    `/index.php` to `/` moved the boundary by one link and revealed
    `/vulnerabilities/cryptography/`, a GET form at `security=impossible` and not at
    `low`. An earlier audit had called the cap benign precisely because both arms
    truncated identically, which is the reading this observation exists to prevent.

    Returns None when the cap did not fire — an observation on every run is how an
    observation stops being read.
    """
    remaining = browser.get("pages_not_visited") or 0
    if not remaining:
        return None
    visited = browser.get("pages_visited")
    return {
        "type": "crawl_truncated", "url": None, "steps": [],
        "pages_visited": visited, "pages_not_visited": remaining,
        "detail": (f"the rendered crawl stopped at {visited} pages with {remaining} "
                   f"same-origin link(s) unvisited; raise form_pages to cover them. "
                   f"Two arms that truncate at different points are not the same "
                   f"surface, and two that truncate identically can still be hiding "
                   f"a difference beyond the cap"),
    }


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
        browser_truncation = None
        inferred, inference_note = [], None
        browser = None
        browser_failure = None
        if wants_rendered_pass(ctx.config):
            # A RENDERED PASS THAT FAILS IS LOST COVERAGE, NOT A FAILED STAGE.
            #
            # `rpc` raises when the worker exits non-zero, and that exception used to
            # propagate out of this adapter and abort the whole stage — discarding the
            # katana crawl, which is the half that works. Measured on Juice Shop, whose
            # Angular front end never reaches `networkidle`: `Page.goto: Timeout
            # 30000ms exceeded`, and a stage that would otherwise have reported 136
            # endpoints reported nothing at all.
            #
            # E-029 is why this matters now. Before it, the rendered pass ran only when
            # an operator asked for it or an identity carried a storage_state; it now
            # runs for every authenticated assessment, so a front end that defeats the
            # crawler takes the whole stage with it far more often.
            try:
                browser = await rpc(sandbox, {"action": "browser", "url": ctx.target, "storage_state": (ctx.identity or {}).get("storage_state")})
            except Exception as exc:
                browser = None
                browser_failure = {
                    "type": "rendered_pass_failed", "url": ctx.target, "steps": [],
                    "detail": ("the rendered crawl did not complete, so no form or "
                               "JavaScript-derived surface was discovered; the fetched "
                               "crawl below is unaffected. An application whose front "
                               "end never goes idle defeats this pass — "
                               + str(exc)[-300:]),
                }
        if browser:
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
            browser_truncation = crawl_truncation(browser)
            # Routes the application's own JavaScript names, which no crawler follows.
            # Recorded as proposals — see infer_from_scripts for why they are never
            # probed — so they must not reach `crawlable` or the katana seed list below.
            inferred, inference_note = await infer_from_scripts(ctx, sandbox, browser_endpoints)
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
        if browser_failure:
            result.observations.append(browser_failure)
            result.status = "partial"
            result.reason = "the rendered crawl did not complete; form and JavaScript surface is missing"
        if browser_truncation:
            result.observations.append(browser_truncation)
        if inference_note:
            result.endpoints.extend(inferred)
            result.observations.append(inference_note)
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
        arm_findings, arm_observations = await assertion_findings(ctx, sandbox)
        result.findings.extend(arm_findings)
        result.observations.extend(arm_observations)
        return await record(ctx, sandbox, output, result, accepted_codes=(0, 1))


async def assertion_findings(ctx, sandbox):
    """Every SecurityAssertion for THIS arm: does it fire, and what does firing prove?

    Extracted from the adapter for the reason `assertion_verdict` and
    `generic_response` were before it: this emits HIGH findings whose grade decides
    `verified` on a client's tracker, and while it lived inside a method that needs
    schemathesis output and a container, the only thing a test could reach was the
    decision functions it calls. Replacing the grade here with a constant — which is
    what the defect was — broke nothing.

    Returns (findings, observations). The caller owns the StageResult.
    """
    findings, observations = [], []
    # ONE CONTROL PER ORIGIN: what this application answers for a path that cannot exist.
    # See `assertion_verdict` — a single-page application returns its shell for every route
    # its server does not know, and that shell carries the product's own name, so a
    # forbidden-marker assertion fired on index.html. The path is derived from the session
    # id, so it is stable within a run and unpredictable across them.
    controls: dict = {}

    for assertion in ctx.config.security_assertions:
        if assertion.identity_id != ctx.identity_id:
            continue
        response = await rpc(sandbox, {"action": "request", "request": assertion.request.model_dump()})
        observations.append({"type": "security_assertion", "response": response})
        fires, refused = assertion_verdict(
            assertion, response,
            await generic_response(sandbox, assertion.request.url, ctx.session_id, controls))
        if refused:
            observations.append({"type": "security_assertion_refused",
                                        "url": assertion.request.url, **refused})
        if fires:
            rule = "erlik:authorization:" + hashlib.sha256(assertion.description.encode()).hexdigest()[:16]
            confidence, basis, caveat = assertion_grade(
                assertion, (ctx.assertion_controls or {}).get(assertion.request.url))
            if caveat:
                observations.append(caveat)
            findings.append(IntegrationFinding(fingerprint=fingerprint(ctx.target, rule, "GET", assertion.request.url, identity=ctx.identity_id),
                title=assertion.description, url=assertion.request.url, rule=rule, source="schemathesis", identity=ctx.identity_id,
                confidence=confidence,
                basis=basis,
                severity="high",
                # The marker's neighbourhood, so the reader can see the
                # forbidden content rather than be told it was there.
                evidence=safe_evidence(redact(_marker_window(response["body"], assertion.forbidden_marker),
                                ctx.known))[:MAX_EVIDENCE_CHARS],
                methodology=["WSTG-AUTHZ-04"]))
    return findings, observations

async def generic_response(sandbox, url, session_id, cache: dict):
    """What this application answers for a path that cannot exist, fetched once per origin.

    Module level, not a closure, so the decision has a test: it is what keeps a
    SecurityAssertion from firing on a single-page application's shell, and that assertion
    emits HIGH `confirmed`.

    The probe path is derived from the session id, so it is stable within a run — two
    assertions on one origin share one fetch — and unpredictable across runs, so a target
    cannot special-case it.

    A REFUSED OR ERRORED CONTROL IS NOT A CONTROL. Returning it would make every assertion on
    that origin compare against erlik's own 403, which is the "our own refusal is not the
    target's answer" defect this project has now found four times. `None` leaves the assertion
    evaluated exactly as it was before the control existed.
    """
    origin = canonical_origin(url)
    if origin not in cache:
        token = hashlib.sha256(str(session_id).encode()).hexdigest()[:16]
        probe = f"{origin}/erlik-control-{token}"
        try:
            answer = await rpc(sandbox, {"action": "request", "request": {"url": probe}})
        except Exception:
            answer = None
        cache[origin] = (None if not answer or answer.get("blocked") or answer.get("error")
                         else answer)
    return cache[origin]


def assertion_grade(assertion, identity_free) -> tuple[str, str, dict | None]:
    """What a fired SecurityAssertion ESTABLISHES, and the grade that follows from it.

    Separate from `assertion_verdict` because they are two questions: whether the operator's
    assertion held, and what holding proves. The first was tested; the second was a constant.

    IT WAS `confirmed` WHILE ITS OWN BASIS SAID OTHERWISE. The basis read "ONE ARM, ONE
    RESPONSE: there is no second identity and no anonymous control here, so this does not
    establish that the content is private" — and the grade beside it was `confirmed`, which
    `defectdojo.py` maps straight to `"verified": True` on a client's tracker. The two
    contradicted each other in the same object, and the export believed the grade.

    The repository's own rule decides it, stated twice already — in `login._verify` and in
    `authenticate`: AN ASSERTION THAT HOLDS WITHOUT THE CREDENTIAL ESTABLISHES NOTHING. The
    generic-404 control that already guards this path rules out a single-page application's
    shell; it does not ask whether the content was gated at all. Measured on the canonical
    counter-example this repository already documents — Juice Shop returns
    `/rest/products/1/reviews`, author addresses included, "to admin, to jim and to nobody at
    all" — an operator asserting that the customer must not see jim's email there got HIGH
    `confirmed`, exported verified, about content that is public.

    So the differential is run and the grade follows it:

    - the marker is NOT in any identity-free answer -> the content is gated on this
      credential and was returned to an identity the operator declared must not see it.
      That is a differential, and `confirmed` is earned.
    - the marker IS in an identity-free answer -> anybody can read it. The disclosure is
      real and still reported, but the claim is not per-identity authorization, and the
      `erlik:authorization` rule this finding carries is not what was established.
    - no usable control -> A MISSING CONTROL IS NOT A PASS, the same answer `authenticate`
      gives with `control_unavailable`.

    Either non-confirmed outcome is `likely` rather than dropped: the operator declared the
    marker forbidden there and it was returned, which is worth a reader's time. What changes
    is that it stops arriving pre-verified.
    """
    usable = [sample for sample in (identity_free or [])
              if sample and not sample.get("blocked") and not sample.get("error")]
    if not usable:
        return ("likely",
                "Explicit forbidden-content assertion reproduced with the configured "
                "identity. The same request with the identity DROPPED could not be made, so "
                "nothing here distinguishes content gated on this credential from content "
                "the application publishes to anybody — a clause nobody ran is not a clause "
                "that passed. Re-run with the control reachable before treating this as an "
                "authorization failure",
                {"type": "security_assertion_control_unavailable",
                 "url": assertion.request.url,
                 "reason": "the identity-free control for this URL was not obtained, so the "
                           "finding is graded on one arm and one response"})
    # ANY sample, and the status is deliberately not required to match. This decides whether
    # a grade that sets `verified` on a client's tracker is awarded, so the marker appearing
    # in an identity-free answer at all is enough to withhold it.
    public = [sample for sample in usable
              if assertion.forbidden_marker in (sample.get("body") or "")]
    if public:
        return ("likely",
                "Explicit forbidden-content assertion reproduced with the configured "
                "identity — AND with no identity at all. The same request with the identity "
                "dropped returned the same forbidden content, so the application publishes "
                "it: this is a disclosure, not a failure of authorization for this "
                "identity, and the rule and methodology on this finding describe the wrong "
                "thing. Decide whether the content should be public before triaging it as "
                "an access-control defect",
                {"type": "security_assertion_marker_is_public",
                 "url": assertion.request.url,
                 "reason": "the forbidden marker was returned to a caller carrying no "
                           "credential, so nothing was gated"})
    return ("confirmed",
            "Explicit forbidden-content assertion reproduced with the configured identity, "
            "and REFUTED with the identity dropped: the same request carrying no credential "
            f"did not return the forbidden content in {len(usable)} attempt(s). The content "
            "is therefore gated on this credential and was returned to an identity the "
            "operator declared must not receive it, which is a differential rather than one "
            "arm's say-so",
            None)

def assertion_verdict(assertion, response, control=None) -> tuple[bool, dict | None]:
    """Does one SecurityAssertion fire on one response, and if not, why not?

    Extracted from the adapter so the decision can be tested without a sandbox — it emits a
    HIGH `confirmed` finding, which is the grade that marks a finding verified on a client's
    tracker, and it had no test of its own.

    THE RESPONSE MUST BE THE ONE THAT WAS ASSERTED ON. `worker.request` follows up to five
    redirects and reports the FINAL url, so the status and the body can belong to wherever
    the target sent us. Measured on DVWA: `GET /vulnerabilities/exec/` landed on `login.php`
    and the marker "Login" emitted a HIGH finding whose `url` field named
    /vulnerabilities/exec/ while its evidence was the login page. A redirected answer is
    evidence about the redirect target.

    A BLOCKED RESPONSE ESTABLISHES NOTHING either, and it is reported rather than quietly
    treated as a clean assertion.
    """
    from .inventory import worker_response_signature

    landed = str(response.get("url") or "")
    asserted = assertion.request.url
    if response.get("blocked"):
        return False, {"reason": "the assessment proxy refused this request; the target was "
                                 "never contacted, so the assertion was not evaluated"}
    if landed and (canonical_origin(landed) + urlsplit(landed).path
                   != canonical_origin(asserted) + urlsplit(asserted).path):
        return False, {"landed_on": landed,
                       "reason": "the response came from a different URL, so it is not "
                                 "evidence about the asserted one"}
    # THE APPLICATION'S GENERIC ANSWER IS NOT AN ANSWER ABOUT THIS URL.
    #
    # A single-page application serves its shell for every route its server does not know, and
    # that shell contains the product's own name — so an operator asserting "this identity must
    # not see 'Juice Shop' at /administration" got a HIGH `confirmed` finding out of
    # index.html. Measured: `/administration`, `/accounting`, `/Edge/` and `/` all produce one
    # response signature, and so does a path that cannot exist. `control` is a fetch of such a
    # path; if the asserted URL answered with the same response, the marker was found in a
    # document that is not about the asserted URL at all.
    #
    # It discriminates rather than blanket-refusing: on the same application `/api/Users`,
    # `/api/Users/1` and `/rest/user/whoami` all differ from the control, and on DVWA `/`
    # differs while `/administration` does not.
    if control is not None and (worker_response_signature(response)
                                == worker_response_signature(control)):
        return False, {"reason": "the asserted URL answered with the application's generic "
                                 "response — the same one a path that cannot exist returns — "
                                 "so the marker was not found in anything specific to it",
                       "control_url": str(control.get("url") or "")}
    if response.get("status") != assertion.request.expected_status:
        return False, None
    if assertion.forbidden_marker not in (response.get("body") or ""):
        return False, None
    return True, None


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
