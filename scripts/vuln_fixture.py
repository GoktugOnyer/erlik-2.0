#!/usr/bin/env python3
"""A deliberately vulnerable HTTP fixture for validating erlik test cases.

WHY THIS EXISTS
---------------
A test case that loads and executes without error has not been shown to DETECT
anything. Several cases in tests_catalog/wstg/ ran cleanly against Juice Shop and
reported nothing, which is indistinguishable from a case that can never fire.
This serves the exact response signatures a vulnerable app would produce, so each
case can be positive-controlled, and matching /safe endpoints so it can be
negative-controlled too.

No real MongoDB, LDAP server or git repository is needed: every erlik case
detects through the HTTP response — an error string, a header, or a body-size
differential — so reproducing the response is sufficient and keeps the fixture a
single dependency-free file.

RUN IT INSIDE THE LAB NETWORK, NOT ON LOOPBACK
----------------------------------------------
    docker cp scripts/vuln_fixture.py kali-tools:/tmp/
    docker exec -d kali-tools python3 /tmp/vuln_fixture.py
    python -m orchestrator.testcase.cli run WSTG-INPV-06 \
        --target url=http://kali-tools:8098/ldap --target parameter=u \
        --scope kali-tools

Address it as kali-tools:8098. Do NOT use localhost or 127.0.0.1: tool_executor
rewrites loopback to the session target (see its _LOOPBACK_HOSTS/aliases), so the
probe silently hits the real target instead and the "positive control" describes
a different server entirely. That mistake produced a convincing false pass once
already.

Endpoints
    /nosql        operator injection, array cast error, $ne differential
    /ldap         filter syntax error, wildcard and blind boolean differentials
    /noframe      no X-Frame-Options and no CSP frame-ancestors
    /allowfrom    X-Frame-Options: ALLOW-FROM (never enforced by browsers)
    /redirect     open redirect honouring ?url=
    /cors         reflects any Origin, including null, with credentials
    /.git/HEAD    exposed VCS working copy
    /*-safe       the same handlers, correctly implemented
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import unquote

PORT = 8098

SMALL = b'{"results":[]}'
LARGE = b'{"results":[' + b','.join(b'{"id":%d,"name":"user%d"}' % (i, i)
                                    for i in range(40)) + b']}'


class Handler(BaseHTTPRequestHandler):
    server_version = "erlik-fixture/1.0"

    def log_message(self, *args):
        pass

    def _send(self, code, body=b"", ctype="application/json", headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    # --- injection handlers ------------------------------------------------

    def _nosql(self, q):
        """Express + Mongoose with the query object passed straight to find()."""
        if "[$" in q and "[$ne]" not in q and "[$eq]" not in q:
            op = q.split("[$", 1)[1].split("]", 1)[0]
            return self._send(500, (
                "MongoServerError: unknown top level operator: $%s. If you have a "
                "field name that starts with a dollar sign, consider using "
                "$getField." % op).encode(), "text/plain")
        if "[]=" in q:
            return self._send(500, (
                "CastError: Cast to String failed for value "
                "\"[ 'erlikprobe9zq7' ]\" (type Array) at path \"name\"").encode(),
                "text/plain")
        if "[$ne]" in q:
            return self._send(200, LARGE)      # negation matches every record
        return self._send(200, SMALL)          # literal and [$eq] match nothing

    def _ldap(self, q):
        """A search filter built by string concatenation."""
        val = q.split("=", 1)[1] if "=" in q else ""
        if ")" in val and val.count("(") != val.count(")"):
            if "objectClass" not in val:
                return self._send(500, (
                    "javax.naming.directory.InvalidSearchFilterException: "
                    "Unbalanced parenthesis; remaining name 'ou=users'").encode(),
                    "text/plain")
            # an injected always-true filter returns the directory; always-false
            # returns nothing
            return self._send(200, LARGE if val.startswith("*") else SMALL)
        if val == "*":
            return self._send(200, LARGE)      # bare wildcard matches everything
        return self._send(200, SMALL)          # literal, or literal* matching nothing

    # --- routing -----------------------------------------------------------

    def do_GET(self):
        path, _, query = self.path.partition("?")
        q = unquote(query)

        if path == "/nosql":
            return self._nosql(q)
        if path == "/ldap":
            return self._ldap(q)

        if path == "/noframe":
            return self._send(200, b"<html>framable</html>", "text/html")
        if path == "/allowfrom":
            return self._send(200, b"<html>ok</html>", "text/html",
                              {"X-Frame-Options": "ALLOW-FROM https://example.com"})
        if path == "/redirect":
            dest = q.split("url=", 1)[1] if "url=" in q else "https://evil.example.com/"
            return self._send(302, b"", "text/html", {"Location": dest})
        if path == "/cors":
            origin = self.headers.get("Origin", "*")
            return self._send(200, SMALL, "application/json",
                              {"Access-Control-Allow-Origin": origin,
                               "Access-Control-Allow-Credentials": "true"})
        if path == "/.git/HEAD":
            return self._send(200, b"ref: refs/heads/main\n", "text/plain")

        # correctly implemented equivalents, for negative controls
        if path in ("/nosql-safe", "/ldap-safe"):
            return self._send(200, SMALL)
        if path == "/safe":
            return self._send(200, b"<html>ok</html>", "text/html",
                              {"X-Frame-Options": "DENY",
                               "Content-Security-Policy": "frame-ancestors 'none'"})

        self._send(404, b"not found", "text/plain")


if __name__ == "__main__":
    print(f"[erlik-fixture] listening on 0.0.0.0:{PORT} — "
          f"address it as kali-tools:{PORT}, never loopback", flush=True)
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
