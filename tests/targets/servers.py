"""The target applications themselves.

Pure stdlib http.server so CI needs nothing beyond Python: no docker, no
network, no Kali image. TLS uses a certificate generated at fixture time.
"""

from __future__ import annotations

import html
import json
import re
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

_TOKEN_RX = re.compile(r"^[0-9a-f]{16}$")

JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
       ".eyJzdWIiOiIxMjMiLCJuYW1lIjoiYWxpY2UifQ"
       ".dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk")

LOGIN_FORM = ('<html><body><form method="post" action="{action}">'
              '<input name="username"><input name="password" type="password">'
              '<button>Sign in</button></form></body></html>')

DIRECTORY = [f"uid=user{i:03d},ou=people,dc=example,dc=com" for i in range(60)]

ROBOTS = ("User-agent: *\n"
          "Disallow: /admin\n"
          "Disallow: /search?q=\n"
          "Disallow: /profile?user_id=\n")


class _Base(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "erlik-test-target"
    sys_version = ""
    VULNERABLE = True

    def log_message(self, *a):  # keep pytest output readable
        pass

    def _send(self, code, body=b"", ctype="text/html", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        self.do_GET()


class Web(_Base):
    """The general web target: cookies, CORS, framing, redirects, metafiles."""

    def _headers(self):
        out = {}
        if self.VULNERABLE:
            # SESS-02: no HttpOnly, no SameSite. The value is a JWT, which is
            # also what SESS-02's producer harvests for SESS-10.
            out["Set-Cookie"] = f"session={JWT}; Path=/"
        else:
            out["Set-Cookie"] = f"session={JWT}; Path=/; HttpOnly; SameSite=Lax"
            # CLNT-09: the control declares a framing policy.
            out["X-Frame-Options"] = "DENY"
        origin = self.headers.get("Origin")
        if origin is not None:
            if self.VULNERABLE:
                # CLNT-07 / CLNT-07b: reflect ANY origin, with credentials.
                out["Access-Control-Allow-Origin"] = origin
                out["Access-Control-Allow-Credentials"] = "true"
            elif origin == "https://trusted.example":
                out["Access-Control-Allow-Origin"] = origin
                out["Access-Control-Allow-Credentials"] = "true"
                out["Vary"] = "Origin"
        return out

    def do_OPTIONS(self):
        self._send(204, b"", extra={**self._headers(),
                                    "Access-Control-Allow-Methods": "GET, PUT, OPTIONS"})

    def do_TRACE(self):
        if self.VULNERABLE:
            # CONF-06: echo the request back (cross-site tracing).
            body = f"TRACE {self.path} HTTP/1.1\r\n"
            return self._send(200, body, "message/http", self._headers())
        self._send(405, "method not allowed", extra=self._headers())

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query, keep_blank_values=True)
        h = self._headers()
        p = u.path

        if p == "/robots.txt":
            # INFO-03: discloses paths, and NAMES two parameters.
            return self._send(200, ROBOTS, "text/plain", h)

        if p == "/login":
            # ATHN-01: a real login form. Over http this is the finding; the
            # TLS target below is what makes the other branches reachable.
            return self._send(200, LOGIN_FORM.format(action="/login"), extra=h)

        if p == "/redirect":
            dest = (q.get("url") or [""])[0]
            if self.VULNERABLE and dest.startswith(("http://", "https://", "//")):
                # CLNT-04: 302 to any absolute destination.
                return self._send(302, b"", extra={**h, "Location": dest})
            return self._send(200, "redirect refused", extra=h)

        if p == "/error":
            if self.VULNERABLE:
                # ERRH-01: a stack trace.
                return self._send(500,
                    'Traceback (most recent call last):\n'
                    '  File "/srv/app/views.py", line 88, in handler\n'
                    '    return render(request)\n'
                    "RuntimeError: template 'x' not found", "text/plain", h)
            return self._send(500, "an error occurred", "text/plain", h)

        if p == "/debug":
            if self.VULNERABLE:
                # CONF-02: a debug endpoint disclosing credentials.
                return self._send(200, json.dumps({
                    "DATABASE_URL": "postgres://appuser:hunter2@db.internal:5432/app",
                    "SECRET_KEY": "s3cr3t",
                }), "application/json", h)
            return self._send(404, "not found", extra=h)

        if p in ("/.git/config", "/backup.zip", "/.env"):
            if self.VULNERABLE:
                # CONF-04: unreferenced artefacts.
                body = {"/.git/config": "[core]\n\trepositoryformatversion = 0\n",
                        "/backup.zip": "PK\x03\x04backup",
                        "/.env": "DB_PASSWORD=hunter2\n"}[p]
                return self._send(200, body, "text/plain", h)
            return self._send(404, "not found", extra=h)

        if p == "/search":
            v = (q.get("q") or [""])[0]
            if "'" in v:
                if self.VULNERABLE:
                    # INPV-05: a raw driver error.
                    return self._send(500,
                        "You have an error in your SQL syntax; check the manual "
                        "that corresponds to your MySQL server version for the "
                        f"right syntax to use near '{v}' at line 1",
                        "text/plain", h)
                return self._send(400, "invalid search term", extra=h)
            # INPV-01: reflected with no output encoding.
            shown = v if self.VULNERABLE else html.escape(v)
            return self._send(200, f"<html><body>Results for {shown}</body></html>",
                              extra=h)

        return self._send(200, "<html><body>home</body></html>", extra=h)


class Ldap(_Base):
    """WSTG-INPV-06's two differential steps, which decide on RESPONSE SIZE."""

    WILDCARD_ESCAPED = False

    def do_GET(self):
        u = urlparse(self.path)
        raw = (parse_qs(u.query, keep_blank_values=True).get("q") or [""])[0]
        if not self.VULNERABLE:
            hits = [d for d in DIRECTORY if raw and raw in d]
        elif "objectClass=*" in raw:
            hits = DIRECTORY                       # an always-true filter landed
        elif "objectClass=x" in raw:
            hits = []                              # always-false
        elif "*" in raw and self.WILDCARD_ESCAPED:
            hits = [d for d in DIRECTORY if raw in d]      # literal `*`
        elif raw == "*":
            hits = DIRECTORY
        elif raw.endswith("*"):
            hits = [d for d in DIRECTORY if raw[:-1] in d]
        else:
            hits = [d for d in DIRECTORY if raw and raw in d]
        self._send(200, ("\n".join(hits) or "no results"), "text/plain")


class Tls(_Base):
    """Served over TLS. `HSTS` and `FORM_ACTION` pick the ATHN-01/CONF-07 branch."""

    HSTS = False
    FORM_ACTION = "/login"

    def do_GET(self):
        extra = {}
        if self.HSTS:
            extra["Strict-Transport-Security"] = "max-age=31536000"
        self._send(200, LOGIN_FORM.format(action=self.FORM_ACTION), extra=extra)


class Redirector(_Base):
    """Plain http that 301s to TLS -- the correct configuration ATHN-01 used
    to report as a HIGH finding."""

    LOCATION = ""

    def do_GET(self):
        self.send_response(301)
        self.send_header("Location", self.LOCATION)
        self.send_header("Content-Length", "0")
        self.end_headers()


def serve(handler, tls: tuple[str, str] | None = None) -> tuple[ThreadingHTTPServer, int]:
    """Start `handler` on an EPHEMERAL port. Returns (server, port).

    Port 0 so parallel CI jobs and a developer's own services never collide --
    the scratchpad version hard-coded ports and would have.
    """
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(tls[0], tls[1])
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, port


class Collaborator(_Base):
    """A receiver speaking the interaction API `orchestrator.collaborator` polls.

    Real OAST needs a name resolvable from the internet and a server outside
    the target's network, neither of which a test has. This records HTTP hits
    by the token in their Host header or path and serves them back, which is
    exactly the contract the poller depends on -- so mint, inject, target
    fetches, poll and correlate are all exercised for real.

    What it does NOT exercise is DNS-only interaction, or interact.sh's own
    wire protocol. Those need an instance on the internet.
    """

    INTERACTIONS: dict = {}

    # A receiver that returns EVERYTHING it has, ignoring the token filter.
    # Not a hypothetical: a shared or self-hosted collaborator sees every
    # probe on the account, and correlation is the client's job. With this
    # False the receiver filters server-side, which silently masks whether the
    # poller correlates at all -- a mutation that deleted the client-side
    # filter passed the whole suite until this existed.
    LEAKS_EVERYTHING = False

    @classmethod
    def reset(cls):
        cls.INTERACTIONS = {}

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/interactions":
            token = (parse_qs(u.query).get("token") or [""])[0]
            if self.LEAKS_EVERYTHING:
                rows = [i for v in self.INTERACTIONS.values() for i in v]
            else:
                rows = self.INTERACTIONS.get(token, [])
            return self._send(200, json.dumps({"interactions": rows}),
                              "application/json")
        # Anything else is a HIT. The token arrives as the leftmost label of
        # the Host header -- which is how a real collaborator sees it -- and a
        # test may also drive it by path when it cannot control DNS.
        host = (self.headers.get("Host") or "").split(":")[0]
        token = host.split(".")[0] if "." in host else ""
        if not token or not _TOKEN_RX.match(token):
            token = u.path.strip("/").split("/")[0]
        if _TOKEN_RX.match(token or ""):
            self.INTERACTIONS.setdefault(token, []).append({
                "token": token, "protocol": "http",
                "remote_addr": self.client_address[0],
                "at": "now", "detail": f"GET {self.path}",
            })
        self._send(200, "ok", "text/plain")


class Ssrf(_Base):
    """A target that FETCHES a user-supplied URL -- the flaw itself.

    The control parses the parameter and refuses to fetch it, so a case that
    fires on both is caught.
    """

    FETCHES = True

    # STANDING IN FOR DNS, as (host suffix, receiver base URL).
    #
    # The minted collaborator name is a subdomain of a domain nothing here can
    # resolve: `*.localhost` does not resolve on Linux and this environment's
    # egress blocks a real OAST provider. A target that fetched the name
    # verbatim would get NXDOMAIN and prove nothing. This maps it onto the
    # local receiver instead, which is the ONE hop the harness cannot perform
    # for real. Everything on erlik's side is untouched: it mints the name,
    # plants it, polls and correlates with no test seam at all.
    RESOLVE = ("", "")

    def _resolved(self, dest: str) -> str:
        suffix, base = self.RESOLVE
        if not (suffix and base):
            return dest
        p = urlparse(dest)
        if p.hostname and p.hostname.endswith(suffix):
            return f"{base}/{p.hostname.split('.')[0]}{p.path or '/'}"
        return dest

    def do_GET(self):
        u = urlparse(self.path)
        dest = self._resolved((parse_qs(u.query).get("url") or [""])[0])
        if self.FETCHES and dest.startswith("http://"):
            try:
                import urllib.request
                with urllib.request.urlopen(dest, timeout=3):
                    pass            # blind: the response is discarded
            except Exception:
                pass
            return self._send(200, "fetched", "text/plain")
        self._send(400, "url parameter refused", "text/plain")


class Ssti(_Base):
    """WSTG-INPV-18's target. The flaw renders a query value through a template
    engine; the control echoes it literally.

    The case's evidence is arithmetic that cannot occur by chance: `{{31337*7}}`
    is a finding only if the response contains `219359`. So the flaw evaluates
    `{{ ... }}` (Jinja/Twig-shaped) and the control html-escapes and reflects the
    raw braces -- `219359` appears on one and never on the other. Nothing here
    executes; the "engine" only multiplies and repeats, which is all the case's
    inert payloads exercise.
    """

    def _eval(self, expr: str) -> str:
        expr = expr.strip()
        m = re.fullmatch(r"(\d+)\s*\*\s*(\d+)", expr)              # 31337*7
        if m:
            return str(int(m.group(1)) * int(m.group(2)))
        m = re.fullmatch(r"(\d+)\s*\*\s*'([^']*)'", expr)         # 7*'7'
        if m:
            return m.group(2) * int(m.group(1))
        m = re.fullmatch(r"'([^']*)'\s*\*\s*(\d+)", expr)         # '7'*7
        if m:
            return m.group(1) * int(m.group(2))
        raise ValueError(expr)

    def _rendered(self, val: str) -> str | None:
        """Evaluate the first {{ ... }} expression, as a template engine would."""
        m = re.search(r"\{\{(.+?)\}\}", val)
        if not m:
            return None
        return self._eval(m.group(1))

    def do_GET(self):
        u = urlparse(self.path)
        vals = [v for vs in parse_qs(u.query, keep_blank_values=True).values()
                for v in vs]
        payload = vals[0] if vals else ""
        if self.VULNERABLE:
            try:
                out = self._rendered(payload)
            except ValueError:
                # The engine tried to compile the expression and refused. It
                # names itself in the error -- which is the case's `high` step.
                return self._send(200, "jinja2.exceptions.TemplateSyntaxError: "
                                  "unexpected char while parsing expression",
                                  "text/plain")
            if out is not None:
                return self._send(200, f"<html><body>Hello {out}</body></html>")
        # Control (and the flaw on a non-template value): reflect, encoded.
        return self._send(200,
                          f"<html><body>Hello {html.escape(payload)}</body></html>")


class Deser(_Base):
    """WSTG-INPV-11's target. The flaw feeds the POST body (or the session
    cookie) to a language deserializer and leaks the runtime's own exception;
    the control validates the input and returns a generic rejection.

    Every probe the case sends is a WELL-FORMED but EMPTY serialized object, and
    the evidence is the deserializer's exception text -- `__PHP_Incomplete_Class`,
    `java.io.StreamCorruptedException`, `_pickle.UnpicklingError`. Those strings
    do not occur in ordinary output; they occur when a deserializer was handed
    something and objected. Nothing here deserializes for real: the flaw MATCHES
    the payload's format and returns the exception that format would raise.
    """

    def _exception_for(self, blob: str) -> str | None:
        b = blob.strip().strip('"')
        if re.match(r'O:\d+:"', b):                       # PHP serialized object
            return ("Notice: unserialize(): Error at offset 0 of 19 bytes\n"
                    "object(__PHP_Incomplete_Class)")
        if b.startswith("rO0AB"):                          # Java stream, base64
            return ("java.io.StreamCorruptedException: invalid stream header\n"
                    "\tat java.io.ObjectInputStream.readStreamHeader(...)")
        if b.startswith("gAS") or b.startswith("gA"):      # Python pickle proto 2+
            return "_pickle.UnpicklingError: invalid load key, '\\x00'."
        if b.startswith("AAEAAAD"):                        # .NET BinaryFormatter
            return ("System.Runtime.Serialization.SerializationException: "
                    "End of Stream encountered before parsing was completed")
        return None

    def _handle(self, blob: str):
        if self.VULNERABLE:
            exc = self._exception_for(blob)
            if exc is not None:
                # The deserializer was reached and objected -- the finding.
                return self._send(500, exc, "text/plain")
            return self._send(200, "ok", "text/plain")
        # Control: never deserialize, never leak internals.
        return self._send(400, "input rejected: unrecognised payload", "text/plain")

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode("latin-1") if n else ""
        # The probes send `data=<blob>`; the Java one posts a raw base64 body.
        blob = (parse_qs(body, keep_blank_values=True).get("data") or [body])[0]
        return self._handle(blob)

    def do_GET(self):
        # serialized_cookie_probe: `-b 'session=O:8:"stdClass":0:{}'`.
        cookie = self.headers.get("Cookie") or ""
        m = re.search(r"session=([^;]+)", cookie)
        if m:
            return self._handle(m.group(1))
        return self._send(200, "home", "text/plain")
