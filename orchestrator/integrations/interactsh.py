"""A self-hosted Interactsh collector with one generated payload per probe."""
from __future__ import annotations
import asyncio
import hashlib
import json
import time
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
import yaml
from orchestrator.testcase.scope import check_url
from .adapters import Context, rpc, record, json_lines
from .contracts import StageResult, IntegrationFinding, fingerprint
from .runtime import Sandbox, JobOutput
from .security import SecretStore, redact, safe_evidence


# The callback record is written by whatever made the callback — the target, or
# anything the target's request reached. Same provenance as a response body.
# Re-exported: the bound lives beside the field it bounds.
from .contracts import MAX_EVIDENCE_CHARS  # noqa: F401


def _callback_evidence(host, probe, protocol, event, context) -> str:
    """What a reader needs to believe an out-of-band interaction happened.

    The unique probe host is the whole argument: it appears in one request erlik
    sent and nowhere else, so a lookup of it could only have come from something
    that parsed that request. The host is quoted for exactly that reason — a
    reader who cannot see it cannot check the uniqueness the claim rests on.
    """
    lines = [
        "callback correlated to a probe host only this assessment knew",
        f"    probe host     {host}",
        f"    reached via    {probe.get('parameter')} on {probe.get('url')}",
        f"    protocol       {protocol}",
        f"    first seen     {event.get('timestamp')}",
    ]
    for label, key in (("from", "remote-address"), ("resolved by", "unique-id")):
        if event.get(key):
            lines.append(f"    {label:<14} {event[key]}")
        
    raw = json.dumps(event, sort_keys=True, indent=1)[:800]
    lines += ["", "raw callback record:", raw]
    return safe_evidence(redact("\n".join(lines), context.known))[:MAX_EVIDENCE_CHARS]


def correlate(events, payloads: dict, context):
    result = StageResult()
    seen = set()
    for event in events:
        full_id = str(event.get("full-id", "")).lower().rstrip(".")
        match = next((host for host in payloads if full_id in (host, urlsplit("https://" + host).hostname, host.split(".")[0])), None)
        if not match:
            continue
        protocol = str(event.get("protocol", "unknown")).lower()
        # Keep every distinct callback as evidence, including repeated protocols.
        # A single probe/protocol produces one stable finding with multiple events.
        event_key = (match, protocol, json.dumps(event, sort_keys=True))
        if event_key in seen:
            continue
        seen.add(event_key)
        probe = payloads[match]
        result.observations.append({"type": "oob_callback", "probe": probe, "protocol": protocol,
                                   "timestamp": event.get("timestamp"), "event": event})
        rule = "erlik:oob:" + protocol
        if any(f.rule == rule and f.url == probe["url"] and f.parameter == probe["parameter"] for f in result.findings):
            continue
        result.findings.append(IntegrationFinding(
            fingerprint=fingerprint(context.target, rule, "GET", probe["url"], probe["parameter"], context.identity_id),
            title="Out-of-band interaction observed", url=probe["url"], parameter=probe["parameter"], rule=rule,
            source="interactsh", identity=context.identity_id, confidence="likely", severity="medium",
            basis=f"Correlated {protocol} callback to a unique probe; callback alone does not prove SSRF impact",
            # THE CALLBACK IS THE PROOF, and it used to reach nothing but the
            # evidence blob. An out-of-band finding is the hardest kind for a
            # reader to reconstruct — there is no response body to look at, and
            # the whole claim rests on something arriving at a host only this
            # assessment knew about. Without the host, the protocol and the time,
            # a client is told an interaction happened and given no way to
            # believe it.
            evidence=_callback_evidence(match, probe, protocol, event, context),
            methodology=["WSTG-INPV-19"]))
    return result


class Collector:
    def __init__(self, context):
        self.ctx = context
        self.sandbox = None
        self.task = None
        self.payloads = {}
        self.issued_payloads = set()
        self.probe_evidence = []

    def _assignments(self):
        probes = self.ctx.config.callback.probes
        if len({(p["url"], p["parameter"]) for p in probes}) != len(probes):
            raise ValueError("duplicate callback probes are not supported")
        engines = ["nuclei"]
        if "WSTG-INPV-19" in getattr(self.ctx.config, "test_cases", []):
            engines.append("testcase")
        return [{**probe, "engine": engine, "test_case_id": "WSTG-INPV-19"}
                for engine in engines for probe in probes]

    async def start(self):
        callback = self.ctx.config.callback
        assignments = self._assignments()
        self.sandbox = Sandbox(self.ctx.config, services=[callback.server])
        self.sandbox.assessment_context = {"session_id": self.ctx.session_id, "stage_id": self.ctx.stage_id}
        await self.sandbox.__aenter__()
        token = SecretStore().get(callback.secret_id).get("token") if callback.secret_id else None
        # Credentials go into a config file, never into docker process arguments.
        config = {}
        if token:
            config["token"] = token
        path = self.sandbox.write("interactsh.yaml", yaml.safe_dump(config))
        self.task = asyncio.create_task(self.sandbox.run(["interactsh-client", "-config", path, "-s", callback.server,
                    "-n", str(len(assignments)), "-json", "-ps", "-psf", "/output/payloads.txt", "-o", "/output/callbacks.jsonl",
                    "-pi", "2", "-nf", "-duc"],
                                                        timeout=self.ctx.config.budget.assessment_seconds,
                                                        env={"INTERACTSH_TLS_VERIFY": "true"}))
        payload_file = self.sandbox.output / "payloads.txt"
        try:
            for _ in range(120):
                if self.task.done():
                    output = await self.task
                    raise RuntimeError("callback registration failed: " + output.stderr[-300:])
                if payload_file.exists():
                    hosts = [line.strip().lower().rstrip(".") for line in payload_file.read_text().splitlines() if line.strip()]
                    server = urlsplit(callback.server).hostname
                    if len(hosts) == len(assignments) and len(set(hosts)) == len(hosts) and all((urlsplit("https://" + h).hostname or "").endswith("." + server) for h in hosts):
                        self.payloads = {host: {**probe, "probe_id": hashlib.sha256(host.encode()).hexdigest()[:24]}
                                         for host, probe in zip(hosts, assignments)}
                        return self
                await asyncio.sleep(0.25)
            raise RuntimeError("callback registration did not supply unique payloads")
        except BaseException:
            await self.close()
            raise

    async def probe(self, target_sandbox):
        templates = []
        for index, (host, probe) in enumerate(self.payloads.items()):
            if probe["engine"] != "nuclei":
                continue
            if host in self.issued_payloads:
                raise ValueError("a callback payload must never be reused for another probe")
            url = self._probe_url(host, probe)
            # Use explicit generated URLs with Nuclei's automatic OAST disabled:
            # no default public service may ever be registered by a scanner.
            template = {"id": f"erlik-oob-{index}", "info": {"name": "Erlik callback probe", "author": "erlik", "severity": "info"},
                        "http": [{"method": "GET", "path": [url], "matchers": [{"type": "status", "status": [200]}]}]}
            content = yaml.safe_dump(template)
            path = target_sandbox.write(f"oob-{index}.yaml", content)
            templates.extend(["-t", path])
            self.probe_evidence.append({"payload": host, "probe": probe, "template_sha256": hashlib.sha256(content.encode()).hexdigest()})
            self.issued_payloads.add(host)
        if not templates:
            raise ValueError("no registered Nuclei callback probes")
        output = await target_sandbox.run(["nuclei", "-u", self.ctx.target, *templates, "-ni", "-duc", "-jsonl", "-silent",
                                          "-proxy", target_sandbox.proxy_url, "-retries", "0"])
        if output.code != 0:
            raise RuntimeError("Nuclei callback probe failed")
        return await record(self.ctx, target_sandbox, output, StageResult(observations=self.probe_evidence))

    def _probe_url(self, host, probe):
        check_url(probe["url"], self.ctx.config.scope)
        u = urlsplit(probe["url"])
        params = [(k, v) for k, v in parse_qsl(u.query, keep_blank_values=True) if k != probe["parameter"]]
        params.append((probe["parameter"], f"https://{host}"))
        return urlunsplit((u.scheme, u.netloc, u.path, urlencode(params), ""))

    async def run_test_case(self, tc, target, target_sandbox):
        """Run INPV-19's bounded callback variant through the integration worker.

        The deterministic adapter dispatches here only for an explicitly selected
        case and configured probe. Legacy standalone cases keep their own steps.
        Callback findings are attached by ``finish`` after the shared final window;
        accepting a target request is deliberately not a positive SSRF evaluator.
        """
        from orchestrator.testcase.runner import RunResult, StepResult
        if tc.id != "WSTG-INPV-19" or tc.id not in getattr(self.ctx.config, "test_cases", []):
            raise ValueError("SSRF callback test case must be explicitly selected")
        if not self.ctx.config.active or not self.task or self.task.done():
            raise RuntimeError("SSRF callback collector is unavailable; check is incomplete")
        match = next(((host, probe) for host, probe in self.payloads.items()
                      if probe["engine"] == "testcase" and probe["url"] == target.get("url")
                      and probe["parameter"] == target.get("parameter")), None)
        if not match:
            raise ValueError("SSRF endpoint and parameter must match an explicitly configured callback probe")
        host, probe = match
        if host in self.issued_payloads:
            raise ValueError("SSRF callback probe was already issued; a new run is required for retry")
        url = self._probe_url(host, probe)
        self.issued_payloads.add(host)
        started = time.monotonic()
        response = await rpc(target_sandbox, {"action": "request", "request": {"url": url, "method": "GET"}})
        ok = not response.get("blocked", False)
        observation = {"type": "oob_probe", "payload": host, "probe": probe,
                       "status": "awaiting_callback" if ok else "blocked", "response": response}
        self.probe_evidence.append(observation)
        elapsed = int((time.monotonic() - started) * 1000)
        return RunResult(test_case_id=tc.id, target=target, duration_ms=elapsed,
                         steps=[StepResult(step="self_hosted_callback", command=json.dumps({"method": "GET", "url": url}),
                                           success=ok, output=json.dumps(observation), duration_ms=elapsed,
                                           exit_code=0 if ok else 1, error=None if ok else "scope proxy refused probe")])

    async def finish(self, wait=True):
        if wait:
            await asyncio.sleep(self.ctx.config.callback.grace_seconds)
        early_exit = self.task.done()
        # Stop the actual process, allowing callbacks already written to remain available.
        if not self.task.done():
            self.task.cancel()
        try:
            await self.task
        except asyncio.CancelledError:
            pass
        path = self.sandbox.output / "callbacks.jsonl"
        events, malformed = [], 0
        if path.exists():
            for line in path.read_text().splitlines():
                try:
                    events.extend(json_lines(line))
                except (ValueError, TypeError):
                    malformed += 1
        result = correlate(events, {host: self.payloads[host] for host in self.issued_payloads}, self.ctx)
        result.observations.extend(self.probe_evidence)
        audit = self.sandbox.directory / "audit" / "requests.jsonl"
        history = json_lines(audit.read_text()) if audit.exists() else []
        polls = [e for e in history if "/poll?" in e.get("url", "") and ("status" in e or "error" in e)]
        if early_exit:
            result.status, result.reason = "partial", "callback collector exited before the observation window ended"
        elif malformed:
            result.status, result.reason = "partial", "malformed callback output; valid events and raw evidence retained"
        elif not polls or any(e.get("error") or e.get("status", 0) != 200 for e in polls):
            result.status, result.reason = "partial", "callback polling was unavailable or incomplete"
        elif not result.findings:
            result.reason = "no correlated callback within the configured observation window; not proof of absence"
        result.metadata["malformed_callback_records"] = malformed
        return await record(self.ctx, self.sandbox, JobOutput(0, json.dumps(events), ""), result)

    async def close(self):
        """Release the sandbox and the client task. Safe to call more than once.

        Two paths can now reach it for the same collector — the local guard at
        the ownership boundary in service.run(), and the sweep over registered
        collectors — and exiting a Sandbox twice is not a defined operation.
        """
        if self.task and not self.task.done():
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
        sandbox, self.sandbox = self.sandbox, None
        if sandbox:
            await sandbox.__aexit__(None, None, None)
