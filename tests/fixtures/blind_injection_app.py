"""An application that is really injectable, and applications that only look it.

WSTG-INPV-05.3 and 05.4 decide by COMPARING responses, so a fixture that fakes
the responses would prove nothing about the comparison. Every route here runs a
real query through a real SQL engine (sqlite3 from the standard library), and
the injectable ones are injectable the ordinary way — the parameter is
concatenated into the statement.

`SLEEP` is registered as a user function so the time-based case has a delay to
find. The delay is caused by the injected payload passing through SQLite's own
parser and evaluator; only the function's existence is arranged, the way it
exists by default on MySQL.

The NEGATIVE routes are the point. Each is a distinct reason a comparison-based
detector reports something for a request that proved nothing:

    /safe            parameterised — the query is not built from the parameter
    /reflect         echoes the parameter, so ANY two probes differ
    /unstable        content changes on its own, so any two probes differ
    /rejects_quotes  a WAF-shaped filter: every payload gets the same refusal
    /slow            uniformly slow — a delay that is real and not caused
    /slow_by_length  slower for longer input, which the equal-length payload
                     pairs are designed to defeat

Every response carries a 32-hex token that changes per request, and the FIRST
response of a process carries a one-shot banner — both are things measured on
DVWA that break a naive comparison, and both must be absorbed.

Run: python blind_injection_app.py [port]
"""
import sqlite3
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

INJECTABLE = {"/quoted", "/unquoted", "/quoted_sleep", "/unquoted_sleep"}
BENIGN = {"/safe", "/reflect", "/unstable", "/rejects_quotes", "/slow", "/slow_by_length"}


def _db(with_sleep: bool) -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id TEXT, uid INTEGER, name TEXT)")
    conn.executemany("INSERT INTO users VALUES (?,?,?)",
                     [("1", 1, "admin"), ("2", 2, "gordonb"), ("3", 3, "pablo")])
    if with_sleep:
        # MySQL has this by default; here it is arranged so the payload has
        # something real to call. The injection itself is not arranged.
        conn.create_function("SLEEP", 1, lambda n: (time.sleep(min(float(n), 10)), 1)[1])
    return conn


class Handler(BaseHTTPRequestHandler):
    served = 0
    counter = 0

    def log_message(self, *a):
        pass

    def _send(self, marker, banner=""):
        Handler.counter += 1
        token = f"{Handler.counter:032x}"
        body = (f"<html><body>{banner}<form>"
                f"<input type='hidden' name='user_token' value='{token}'>"
                f"</form><pre>{marker}</pre></body></html>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parts = urlsplit(self.path)
        value = (parse_qs(parts.query).get("id") or [""])[0]
        route = parts.path.rstrip("/") or "/"
        if route not in INJECTABLE and route not in BENIGN:
            self.send_response(404)
            self.end_headers()
            return

        # A one-shot banner on the very first response of the process, the way
        # DVWA greets the first request after login. Without a discarded
        # warm-up this lands on the first control and invalidates the run.
        Handler.served += 1
        banner = "<div>Welcome back</div>" if Handler.served == 1 else ""

        if route == "/reflect":
            return self._send(f"You asked for {value}", banner)
        if route == "/unstable":
            return self._send(f"Request number {Handler.counter}", banner)
        if route == "/rejects_quotes":
            bad = any(c in value for c in "'\"") or "=" in value
            return self._send("Input rejected" if bad else "User is MISSING", banner)
        if route == "/slow":
            time.sleep(0.4)
            return self._send("User is MISSING", banner)
        if route == "/slow_by_length":
            time.sleep(min(len(value), 60) * 0.02)
            return self._send("User is MISSING", banner)

        conn = _db(with_sleep=route.endswith("_sleep"))
        try:
            if route == "/safe":
                rows = conn.execute("SELECT name FROM users WHERE id = ?", (value,)).fetchall()
            elif route in ("/quoted", "/quoted_sleep"):
                rows = conn.execute("SELECT name FROM users WHERE id = '%s'" % value).fetchall()
            else:
                rows = conn.execute("SELECT name FROM users WHERE uid = %s" % value).fetchall()
        except Exception:
            # Blind on purpose: the engine's error never reaches the response,
            # which is exactly what makes the error-based case blind here.
            rows = []
        finally:
            conn.close()
        self._send("User exists" if rows else "User is MISSING", banner)


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 9096),
               Handler).serve_forever()
