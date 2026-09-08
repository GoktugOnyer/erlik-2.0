"""Local-only deterministic expiry, passive-alert, and in-flight scan fixture."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

EVENTS = []
LOCK = threading.Lock()
EXPIRED = False


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        global EXPIRED
        path = urlsplit(self.path).path
        authorization = self.headers.get("Authorization", "")
        if path == "/events":
            with LOCK:
                self.respond(200, json.dumps(EVENTS), "application/json")
            return
        with LOCK:
            EVENTS.append({"path": self.path, "method": "GET", "authorization": authorization,
                           "timestamp": time.time()})
            authenticated = authorization == "Bearer renewed-lifecycle-token" or (
                authorization == "Bearer expiring-lifecycle-token" and not EXPIRED)
            if path == "/expiry/" and authorization == "Bearer expiring-lifecycle-token":
                EXPIRED = True
        if path == "/expiry/me":
            self.respond(200 if authenticated else 401, "reader" if authenticated else "expired")
        elif path == "/expiry/":
            self.respond(200 if authenticated else 401,
                         '<html><head><title>Expiry lab</title></head><body><a href="/expiry/private">Private</a></body></html>')
        elif path == "/expiry/private":
            self.respond(200 if authenticated else 401, "private expiry canary" if authenticated else "expired")
        elif path.startswith("/slow"):
            # Keep the actual scanner blocked while its orchestrator is cancelled/killed.
            time.sleep(120)
            self.respond(200, "slow scan fixture")
        elif path.startswith("/zap"):
            if authorization != "Bearer zap-lifecycle-token":
                self.respond(401, "unauthorized")
                return
            self.respond(200, '<html><head><title>Authenticated passive lab</title></head>'
                              '<body><a href="/zap/private">Private</a>private-zap-canary</body></html>',
                         cookie="fixture_session=fixture-value; Path=/zap")
        else:
            self.respond(200, "lifecycle fixture")

    def respond(self, status, body, content_type="text/html", cookie=None):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
