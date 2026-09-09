"""Naive redirect validators, one per class, as a positive control for payloads.

WSTG-CLNT-04 sends payloads; this is the thing that has to be fooled by them.
Writing the validators independently is the point — a payload proved only
against the case's own regex proves nothing about the technique.

Each route implements one shape of check that appears in real applications:

    /startswith   target must begin with the app's own origin
    /contains     target must contain the app's own host anywhere
    /scheme       "http://" and "https://" are blocked, nothing else is
    /leadingslash a leading "//" is blocked, nothing else is
    /allowlist    target must contain one of a hardcoded REMOTE url

The last is Juice Shop's shape and is here to be measured, not defeated: a
scanner cannot guess a hardcoded remote allowlist, and a payload battery that
appears to beat it would mean the fixture is wrong.

Run: python open_redirect_validators.py [port]
"""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

OWN_ORIGIN = "http://localhost:PORT"
OWN_HOST = "localhost"
ALLOWLIST = ["https://github.com/example/project"]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        parts = urlsplit(self.path)
        target = (parse_qs(parts.query).get("to") or [""])[0]
        route = parts.path.rstrip("/")
        if route == "/startswith":
            ok = target.startswith(OWN_ORIGIN)
        elif route == "/contains":
            ok = OWN_HOST in target
        elif route == "/scheme":
            ok = not (target.lower().startswith("http://") or target.lower().startswith("https://"))
        elif route == "/leadingslash":
            ok = not target.startswith("//")
        elif route == "/allowlist":
            ok = any(a in target for a in ALLOWLIST)
        else:
            self.send_response(404)
            self.end_headers()
            return
        if ok and target:
            self.send_response(302)
            self.send_header("Location", target)
            self.end_headers()
            return
        self.send_response(406)
        self.end_headers()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9094
    OWN_ORIGIN = OWN_ORIGIN.replace("PORT", str(port))
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
