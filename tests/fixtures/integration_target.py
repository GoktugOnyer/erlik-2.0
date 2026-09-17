"""Deliberately flawed local-only HTTP fixture. Never deployed with the product."""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

REQUESTS = []
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        path = urlsplit(self.path).path
        if path != "/requests":
            REQUESTS.append({"path": self.path, "authorization": self.headers.get("Authorization")})
        status, content_type = 200, "text/html"
        if path == "/requests":
            body = json.dumps(REQUESTS)
            content_type = "application/json"
        elif path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://recorder:8080/unauthorized")
            self.end_headers()
            return
        elif path in ("/me", "/private"):
            status = 200 if self.headers.get("Authorization") == "Bearer lab-token" else 401
            body = "reader private-object-canary" if status == 200 else "unauthorized"
        elif path == "/openapi.json":
            content_type = "application/json"
            body = json.dumps({"openapi": "3.0.3", "info": {"title": "Integration fixture", "version": "1"},
                               "paths": {"/bug": {"get": {"operationId": "bug", "parameters": [{"in": "query", "name": "q", "schema": {"type": "string"}}],
                                    "responses": {"200": {"description": "OK"}}}},
                                         "/private": {"get": {"operationId": "private", "responses": {"200": {"description": "OK"}}}},
                                         "/items": {"post": {"operationId": "createItem", "responses": {"201": {"description": "Created"}}}},
                                         # NEVER selected by any workflow, and that is its whole job.
                                         # Before it existed the schema declared exactly ONE mutation,
                                         # `createItem`, which every workflow test also selected — so
                                         # "unselected mutations never execute" was asserted against a
                                         # schema with no unselected mutation in it. The assertion could
                                         # not fail, which is not the same as passing.
                                         "/admin/promote": {"post": {"operationId": "promoteUser", "responses": {"200": {"description": "OK"}}}}}})
        elif path == "/bug":
            status, body = 500, "seeded server failure"
        elif path == "/app.js":
            content_type, body = "application/javascript", "fetch('/js-only').then(r=>r.text()).then(t=>document.body.dataset.result=t);"
        elif path == "/js-only":
            body = "javascript discovered endpoint"
        elif path == "/fetch":
            # Simulated blind callback delivered to the local protocol fixture only.
            import urllib.request
            import ssl
            from datetime import datetime, timezone
            payload = parse_qs(urlsplit(self.path).query).get("url", [""])[0]
            host = urlsplit(payload).hostname or ""
            if host.endswith(".oast.test"):
                event = {"full-id": host, "unique-id": host.split(".")[0], "protocol": "http",
                         "timestamp": datetime.now(timezone.utc).isoformat(), "remote-address": "127.0.0.1",
                         "raw-request": "GET / HTTP/1.1", "raw-response": "HTTP/1.1 200 OK"}
                request = urllib.request.Request("https://oast.test/inject", data=json.dumps(event).encode(), headers={"Content-Type": "application/json"})
                urllib.request.urlopen(request, context=ssl._create_unverified_context(), timeout=5).read()
            body = "queued"
        elif path == "/":
            body = '<html><head><title>Erlik fixture</title></head><body><a href="/private">Private</a><a href="/redirect">Redirect</a><script src="/app.js"></script></body></html>'
        else:
            body = "fixture"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body.encode())))
        self.end_headers()
        self.wfile.write(body.encode())

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        REQUESTS.append({"path": self.path, "method": "POST"})
        self.send_response(201 if self.path == "/items" else 500 if self.path == "/cleanup-fail" else 200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"data":{"hello":"world"}}')

ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
