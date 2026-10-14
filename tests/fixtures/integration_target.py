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
# /redeem is CHECK-THEN-ACT with a real gap. A RENDEZVOUS, not a fixed sleep, is what makes
# the race deterministic rather than occasional: a test that wins the race one run in five is
# a flaky test, and a flaky negative is indistinguishable from a working control.
#
# /redeem-safe does the same work holding a lock, so exactly one caller wins however many
# arrive together. It is the negative control, and without it the case could report a race
# on every endpoint and still pass.
COUPON = {"redeem": 1, "safe": 1}
COUPON_LOCK = threading.Lock()

# THE CHECK-THEN-ACT WINDOW, HELD OPEN BY ARRIVALS RATHER THAN THE CLOCK.
#
# This used to be a flat `time.sleep(0.15)` between the read and the write. That made the
# race deterministic ONLY while all N concurrent callers connected within 150ms of the first
# one's read: the first writer decrements at read+150ms, and any curl that had not yet read
# by then saw the coupon already spent and was refused. On an idle box all eight arrived in
# time; under load a straggler occasionally did not, so the burst won 7-of-8 instead of 8-of-8
# and test_the_finding_records_how_many_succeeded flaked (measured ~2-3% of bursts, and a
# quiet-period heuristic still flaked under a heavily oversubscribed CPU).
#
# The gap is now held open until the whole declared burst has ARRIVED, keyed on a count and
# not on any wall-clock interval. A caller that announces its burst size (the `X-Parties`
# header the race case's own requests carry) parks until that many callers are in the gap
# together, then every one of them is released at once — so the window is exactly as wide as
# it needs to be however the scheduler spreads the requests, and a straggler extends it rather
# than losing the race. That is the check-then-act defect the case exists to detect, exhibited
# with no timing assumption at all. A caller that announces NO size (a lone sequential probe —
# BUSL-05 replays /redeem one request at a time) falls back to a quiet-period rendezvous:
# it proceeds once no new caller has arrived for `_GAP_QUIET`, so single-caller behaviour is
# unchanged and no burst size is imposed on callers that did not declare one. `_GAP_CEILING`
# bounds every caller's wait, so a dropped connection that leaves the party short can never
# wedge the fixture — it degrades to acting on whatever did arrive. It is only a safety net:
# a burst fires exactly N local curls, which always arrive, so the barrier trips in
# milliseconds and the ceiling is reached only if a connection is genuinely lost. It is set
# generously so that even a CPU so oversubscribed that the curl processes assemble slowly
# still completes the party rather than timing an early caller out and serialising the rest.
#
# The header only sizes the lab's own window. It does not touch the coupon logic, the success
# marker, or the finding: the race is still genuine (every caller reads the stale count and
# writes), and adding the lock back to this path still makes the case go silent.
_GAP_QUIET = 0.25
_GAP_CEILING = 30.0
_GAP = threading.Condition()
_GAP_LAST_ARRIVAL = 0.0
_BARRIERS = {}
_BARRIERS_LOCK = threading.Lock()


def _party_barrier(parties):
    """One reusable barrier per declared burst size, created on demand."""
    with _BARRIERS_LOCK:
        barrier = _BARRIERS.get(parties)
        if barrier is None:
            barrier = threading.Barrier(parties)
            _BARRIERS[parties] = barrier
        return barrier


def _hold_the_gap_open(parties=None):
    """Park a check-then-act caller until its concurrent burst has assembled.

    With `parties >= 2` known, wait on a barrier of that width: every caller is released the
    instant the last one arrives, together and without consulting a clock, so load cannot
    shrink the window. A barrier is used rather than a live in-flight count because a count
    decremented as callers leave drops below the party size the moment the first one exits,
    which would strand the rest until the ceiling. Without a size (a lone sequential probe),
    release once arrivals have stalled for `_GAP_QUIET`. Either way never park longer than
    `_GAP_CEILING`, so a burst that never fully assembles (a dropped connection) degrades to
    acting on whatever arrived instead of wedging the fixture.
    """
    global _GAP_LAST_ARRIVAL
    if parties and parties >= 2:
        barrier = _party_barrier(parties)
        try:
            barrier.wait(timeout=_GAP_CEILING)
        except threading.BrokenBarrierError:
            # Short party or timeout: reset so a later burst of this size is not born broken,
            # and proceed on the stale read this caller already took.
            with _BARRIERS_LOCK:
                try:
                    barrier.reset()
                except threading.BrokenBarrierError:
                    pass
        return
    deadline = time.monotonic() + _GAP_CEILING
    with _GAP:
        _GAP_LAST_ARRIVAL = time.monotonic()
        _GAP.notify_all()                       # wake earlier arrivals to re-evaluate
        while time.monotonic() < deadline:
            quiet_for = time.monotonic() - _GAP_LAST_ARRIVAL
            if quiet_for >= _GAP_QUIET:
                return
            _GAP.wait(timeout=min(_GAP_QUIET - quiet_for, deadline - time.monotonic()))

# A THREE-STEP CHECKOUT, enforced in one place and not the other — the pair WSTG-BUSL-06
# needs. `/shop/confirm` finalises an order whether or not it was ever paid for, which is
# the circumvented workflow; `/shop-strict/confirm` refuses until the cart is paid.
#
# Ordering is a DIFFERENT invariant from the race above and is checked differently: no
# concurrency, one request, from a cart that has never seen the prerequisite. A case that
# needed a burst to find this would be testing the wrong thing.
CARTS = {}

# AN OBJECT THAT CHANGES HANDS. The invariant is not "can I transfer what I do not own" —
# that is object-level authorization and the `ownership` evaluator already asks it. It is
# whether the FORMER owner's access survives a transfer that should have revoked it.
#
# The realistic shape of that bug is two sources of truth: an owner field and a grant list.
# `/transfer` updates the owner and ADDS the recipient to the grants, leaving the previous
# owner in place — so alice keeps reading a document that is now bob's. `/transfer-strict`
# replaces the grants, which is the same operation done correctly.
OBJECT_OWNER = {}
OBJECT_GRANTS = {}


def _reset_object(name):
    OBJECT_OWNER[name] = "alice"
    OBJECT_GRANTS[name] = {"alice"}


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
        elif path == "/object":
            name = (parse_qs(urlsplit(self.path).query).get("id") or ["doc-1"])[0]
            caller = (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
            if name not in OBJECT_GRANTS:
                _reset_object(name)
            if caller in OBJECT_GRANTS[name]:
                status, body = 200, "OBJECT-BODY quarterly-figures"
            else:
                status, body = 403, "forbidden"
            content_type = "text/plain"
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
        parts_t = urlsplit(self.path)
        if parts_t.path in ("/transfer", "/transfer-strict"):
            query = parse_qs(parts_t.query)
            name = (query.get("id") or ["doc-1"])[0]
            recipient = (query.get("to") or ["bob"])[0]
            if name not in OBJECT_GRANTS:
                _reset_object(name)
            OBJECT_OWNER[name] = recipient
            if parts_t.path == "/transfer-strict":
                OBJECT_GRANTS[name] = {recipient}      # the old owner loses access
            else:
                OBJECT_GRANTS[name].add(recipient)     # and here they do not
            body = b'{"status":"TRANSFERRED"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
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
                                locked=self.path == "/redeem-safe",
                                parties=self.headers.get("X-Parties"))
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

    def _coupon(self, key, *, locked, parties=None):
        """Redeem a single-use coupon, correctly or otherwise.

        The unlocked path reads the remaining count, holds the check-then-act gap open
        until every concurrent caller has read it too, and only then writes. That is the
        classic check-then-act gap and it is what a race-condition case is supposed to find.
        The locked path does the identical work inside a mutex and is supposed to defeat it.

        `parties` (the caller's `X-Parties` header) is the burst size, used ONLY to size the
        gap deterministically; it never touches the coupon arithmetic.
        """
        try:
            parties = int(parties) if parties is not None else None
        except (TypeError, ValueError):
            parties = None
        if locked:
            with COUPON_LOCK:
                won = COUPON[key] > 0
                if won:
                    COUPON[key] -= 1
        else:
            remaining = COUPON[key]        # the CHECK
            _hold_the_gap_open(parties)    # released once the whole burst has arrived
            won = remaining > 0            # the ACT, decided on the stale count
            if won:
                COUPON[key] = remaining - 1
        body = b'{"status":"REDEEMED"}' if won else b'{"status":"already used"}'
        self.send_response(200 if won else 409)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
