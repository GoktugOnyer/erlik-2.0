"""Loaded by mitmdump. This is the only scanner connection to external networks."""
import asyncio
import json
import os
import time
from pathlib import Path
from urllib.parse import urlsplit
from mitmproxy import http
from egress_policy import EgressPolicy, origin


class Guard:
    def __init__(self):
        self.config = json.loads(Path("/policy/policy.json").read_text())
        self.policy = EgressPolicy(self.config)
        self.next_request = 0.0
        self.lock = asyncio.Lock()
        self.semaphore = asyncio.Semaphore(self.config.get("concurrency", 2))
        self.active = set()
        self.count = 0
        self.urls = set()

    def record(self, event):
        with open("/audit/requests.jsonl", "a") as f:
            f.write(json.dumps(event) + "\n")

    def http_connect(self, flow):
        host = flow.request.host
        authority = f"[{host}]" if ":" in host else host
        allowed, reason = self.policy.check(f"https://{authority}:{flow.request.port}/", "GET")
        if not allowed:
            self.record({"url": f"https://{authority}:{flow.request.port}/", "method": "CONNECT", "allowed": False, "reason": reason})
            flow.response = http.Response.make(403, b"CONNECT destination outside scope")

    async def request(self, flow: http.HTTPFlow):
        allowed, reason = self.policy.check(flow.request.pretty_url, flow.request.method)
        if not allowed and reason == "state-changing requests disabled" and self.config.get("graphql_url") == flow.request.pretty_url:
            # A POST carrying query-only GraphQL operations is read-only. Parse the AST;
            # string searching would allow mutations hidden in multi-operation documents.
            try:
                from graphql import parse, OperationDefinitionNode, OperationType
                body = json.loads(flow.request.content)
                tree = parse(body["query"])
                operations = [node for node in tree.definitions if isinstance(node, OperationDefinitionNode)]
                if operations and all(node.operation == OperationType.QUERY for node in operations):
                    allowed, reason = True, "read-only GraphQL query"
            except Exception:
                pass
        if flow.request.headers.get("upgrade", "").lower() == "websocket":
            allowed, reason = False, "WebSocket execution is unsupported"
        self.count += 1
        self.urls.add((flow.request.method, flow.request.pretty_url))
        if self.count > self.config.get("max_requests", 10000):
            allowed, reason = False, "request budget exhausted"
        if not self.config.get("service_only") and len(self.urls) > self.config.get("max_urls", 500):
            allowed, reason = False, "URL budget exhausted"
        self.record({"url": flow.request.pretty_url, "method": flow.request.method, "allowed": allowed, "reason": reason, "timestamp": time.time()})
        if not allowed:
            # The marker goes in the BODY as well as the header. A catalogue
            # step that prints only the response body — `curl -s -G` with no
            # -i and no -D, which is exactly what WSTG-INPV-18 and
            # WSTG-INPV-11.2 use — otherwise sees a 403 body reading "URL
            # budget exhausted", curl exits 0, the step reports success, the
            # evaluator matches nothing, and the case reports CLEAN for a
            # request that never left this proxy.
            flow.response = http.Response.make(
                403, f"X-Erlik-Blocked: true\n{reason}\n".encode(),
                {"X-Erlik-Blocked": "true"})
            return
        await self.semaphore.acquire()
        self.active.add(flow.id)
        async with self.lock:
            now = time.monotonic()
            await asyncio.sleep(max(0, self.next_request - now))
            self.next_request = time.monotonic() + 1 / self.config.get("requests_per_second", 5)
        identity = self.config.get("identity") or {}
        if identity and origin(flow.request.pretty_url) == origin(identity["target_origin"]):
            for key, value in identity.get("headers", {}).items():
                flow.request.headers[key] = value
            cookies = identity.get("cookies", []) + (identity.get("storage_state") or {}).get("cookies", [])
            host = flow.request.host.lower()
            accepted = []
            for c in cookies:
                domain = c.get("domain", host).lower()
                domain_ok = host == domain or (domain.startswith(".") and (host == domain[1:] or host.endswith(domain)))
                if domain_ok and flow.request.path.startswith(c.get("path", "/")) and (not c.get("secure") or flow.request.scheme == "https") and (c.get("expires", -1) <= 0 or c["expires"] > time.time()):
                    accepted.append(f"{c['name']}={c['value']}")
            if accepted:
                flow.request.headers["cookie"] = "; ".join(accepted)

    def response(self, flow):
        self.record({"url": flow.request.pretty_url, "status": flow.response.status_code, "timestamp": time.time()})
        self.release(flow)

    def error(self, flow):
        self.record({"url": flow.request.pretty_url, "error": str(flow.error), "timestamp": time.time()})
        self.release(flow)

    def release(self, flow):
        if flow.id in self.active:
            self.active.remove(flow.id)
            self.semaphore.release()


addons = [Guard()]
