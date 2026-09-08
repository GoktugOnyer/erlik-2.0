"""Local HTTPS protocol fixture for Interactsh registration/poll and Dojo reimport."""
import json
import ssl
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
    "-keyout", "/tmp/key.pem", "-out", "/tmp/cert.pem", "-subj", "/CN=oast.test",
    "-addext", "subjectAltName=DNS:oast.test,DNS:dojo.test"], check=True, capture_output=True)
EVENTS = []
EXPORTS = []
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def reply(self, content, status=200):
        body = json.dumps(content).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        if self.path.startswith("/poll"):
            extra = list(EVENTS)
            EVENTS.clear()
            self.reply({"data": [], "extra": [json.dumps(e) for e in extra]})
        elif self.path == "/exports":
            self.reply(EXPORTS)
        else:
            self.reply({"ready": True})
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.path == "/register":
            data = json.loads(body)
            assert data.get("correlation-id") and data.get("public-key") and data.get("secret-key")
            self.reply({"message": "registration successful"})
        elif self.path == "/inject":
            EVENTS.append(json.loads(body))
            self.reply({"ok": True})
        elif self.path == "/api/v2/reimport-scan/":
            EXPORTS.append({"body": body.decode(), "authorization": self.headers.get("Authorization")})
            self.reply({"test": 42})
        else:
            self.reply({"ok": True})
server = ThreadingHTTPServer(("0.0.0.0", 443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("/tmp/cert.pem", "/tmp/key.pem")
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
