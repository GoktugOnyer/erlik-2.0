"""Fixed local benchmark v1: three declared flaws and a safe control route."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

SCHEMA = {"openapi": "3.0.3", "info": {"title": "Erlik coverage fixture", "version": "1.0"}, "paths": {
    path: {"get": {"operationId": operation, "responses": {"200": {"description": "OK"}}}}
    for path, operation in [("/visible", "safeControl"), ("/hidden", "javascriptSurface"),
                            ("/api/private", "privateObject"), ("/api/error", "seededContractFailure")]}}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_OPTIONS(self):
        self.respond(200, "", extra={"Allow": "GET, HEAD, OPTIONS"})

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/me":
            self.respond(200 if self.headers.get("Authorization") == "Bearer reader-token" else 401, "reader")
        elif path == "/":
            self.respond(200, '<html><head><title>Coverage fixture v1</title></head><body><a href="/visible">Safe control</a><script src="/app.js"></script></body></html>')
        elif path == "/app.js":
            self.respond(200, "fetch('/hidden').then(r => r.text());", "application/javascript")
        elif path == "/openapi.json":
            self.respond(200, json.dumps(SCHEMA), "application/json")
        elif path == "/api/private":
            # The BODY is gated, not only the status. This returned the canary with the 401
            # too, so the private object was shipped to every caller and only the status
            # line said otherwise — which made the identity-free control inconclusive and
            # cost the benchmark its authorization rule. Its sibling fixture
            # (integration_target.py) already modelled a refusal this way.
            authorised = self.headers.get("Authorization") == "Bearer reader-token"
            self.respond(200 if authorised else 401,
                         "admin-object-canary" if authorised else "unauthorized",
                         "text/plain")
        elif path == "/api/error":
            self.respond(500, "seeded API contract failure", "text/plain")
        elif path == "/hidden":
            self.respond(200, "hidden data", "text/plain", {"Set-Cookie": "session=benchmark-cookie; Path=/",
                "Access-Control-Allow-Origin": self.headers.get("Origin", "https://example.invalid"),
                "Access-Control-Allow-Credentials": "true"})
        elif path == "/visible":
            self.respond(200, "safe control", "text/plain", {"Set-Cookie": "session=control; Path=/; HttpOnly; SameSite=Strict"})
        else:
            self.respond(404, "not found", "text/plain")

    def respond(self, status, body, content_type="text/html", extra=None):
        self.send_response(status)
        headers = {"Content-Type": content_type, "Content-Length": str(len(body.encode())),
            "Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"}
        for name, value in {**headers, **(extra or {})}.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body.encode())


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
