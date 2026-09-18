"""Deliberately flawed local-only HTTP fixture. Never deployed with the product."""
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

REQUESTS = []

# TWO SINGLE-USE COUPONS, one of which is wrong on purpose — the seeded invariant violation
# and the correctly enforced control E-013 asks for, in one fixture so the same bounded
# schedule hits both. Before these existed the shipped WSTG-BUSL-04 case had never been run
# against anything: it appears in the capability index and in no test that executes it, so
# neither "detect one seeded violation" nor "reject a correctly enforced control" had ever
# been shown.
#
# /redeem is CHECK-THEN-ACT with a real gap. The sleep is what makes the race deterministic
# rather than occasional: a test that wins the race one run in five is a flaky test, and a
# flaky negative is indistinguishable from a working control.
#
# /redeem-safe does the same work holding a lock, so exactly one caller wins however many
# arrive together. It is the negative control, and without it the case could report a race
# on every endpoint and still pass.
COUPON = {"redeem": 1, "safe": 1}
COUPON_LOCK = threading.Lock()

# A THREE-STEP CHECKOUT, enforced in one place and not the other — the pair WSTG-BUSL-06
# needs. `/shop/confirm` finalises an order whether or not it was ever paid for, which is
# the circumvented workflow; `/shop-strict/confirm` refuses until the cart is paid.
#
# Ordering is a DIFFERENT invariant from the race above and is checked differently: no
# concurrency, one request, from a cart that has never seen the prerequisite. A case that
# needed a burst to find this would be testing the wrong thing.
CARTS = {}


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
        if self.path == "/apply":
            # A DISCOUNT WITH NO USAGE LIMIT — the WSTG-BUSL-05 positive. It is not racy in
            # the check-then-act sense, because there is no check: it simply has no notion of
            # having been used, so replaying it works forever. That is a different defect
            # from /redeem's, and the reason BUSL-05 is not BUSL-04 with fewer threads.
            body = b'{"status":"APPLIED"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path in ("/redeem", "/redeem-safe"):
            return self._coupon("redeem" if self.path == "/redeem" else "safe",
                                locked=self.path == "/redeem-safe")
        parts = urlsplit(self.path)
        if parts.path in ("/shop/pay", "/shop/confirm",
                          "/shop-strict/pay", "/shop-strict/confirm"):
            cart = (parse_qs(parts.query).get("cart") or [""])[0]
            return self._checkout(parts.path, cart)
        self.send_response(201 if self.path == "/items" else 500 if self.path == "/cleanup-fail" else 200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"data":{"hello":"world"}}')

    def _checkout(self, path, cart):
        """Pay for a cart, or confirm one — strictly or otherwise.

        The lax confirm finalises whatever it is given. The strict confirm looks for the
        prerequisite first, which is the entire difference between the two and the reason
        they make a control pair.
        """
        if path.endswith("/pay"):
            CARTS.setdefault(cart, set()).add("paid")
            body, status = b'{"status":"PAID"}', 200
        elif path == "/shop/confirm":
            body, status = b'{"status":"CONFIRMED"}', 200
        else:
            paid = "paid" in CARTS.get(cart, set())
            body = b'{"status":"CONFIRMED"}' if paid else b'{"error":"payment required"}'
            status = 200 if paid else 409
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _coupon(self, key, *, locked):
        """Redeem a single-use coupon, correctly or otherwise.

        The unlocked path reads the remaining count, yields the GIL for long enough that
        every concurrent caller has read it too, and only then writes. That is the classic
        check-then-act gap and it is what a race-condition case is supposed to find. The
        locked path does the identical work inside a mutex and is supposed to defeat it.
        """
        if locked:
            with COUPON_LOCK:
                won = COUPON[key] > 0
                if won:
                    COUPON[key] -= 1
        else:
            remaining = COUPON[key]
            time.sleep(0.15)          # the window, wide enough to be deterministic
            won = remaining > 0
            if won:
                COUPON[key] = remaining - 1
        body = b'{"status":"REDEEMED"}' if won else b'{"status":"already used"}'
        self.send_response(200 if won else 409)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
