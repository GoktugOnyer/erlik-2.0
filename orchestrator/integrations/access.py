"""One authentication boundary for HTTP data and WebSocket streams.

Replaces the older write-only `_api_token_guard`, which let any reader GET
/api/sessions, every finding and every report without presenting anything.

Two rules, because the product has two kinds of surface:

  ERLIK_API_TOKEN set     every /api/ and /ws/ path is protected, READS
                          included. This is stricter than the guard it
                          replaces, and deliberately so: a report is the
                          customer's data, and GET was never a safe exemption.

  ERLIK_API_TOKEN unset   the base product keeps working exactly as before
                          (the guard was documented "off by default"), but the
                          integration surface stays shut. It holds credential
                          handles, browser storage state and client assessment
                          evidence, and there is no token to authenticate
                          with, so the only correct answer is a refusal that
                          says why. `create_session` already refuses an
                          integration_config for the same reason.

Failing open on the whole API when the token is unset would have been the
other way round — and would have taken the dashboard down for every operator
who never set one.
"""
import hmac
import os
from starlette.responses import JSONResponse

# Never gated: liveness, and the endpoint you authenticate AT.
#
# PUBLIC, because `main._api_token_guard` is a second boundary over the same paths
# and must exempt exactly these. Keeping its own copy is what made /api/auth --
# the endpoint whose entire job is to exchange a token for a session cookie --
# require a session cookie: this middleware let it through, the guard behind it
# answered 401, and the dashboard could not log in at all.
EXEMPT_PATHS = ("/api/health", "/api/auth")
_EXEMPT = EXEMPT_PATHS

# Gated whether or not a token exists, because these carry secrets and client
# evidence. With no token configured they are unreachable by construction.
_ALWAYS_PROTECTED = ("/api/integrations/", "/ws/integrations/")

_PROTECTED_PREFIXES = ("/api/", "/ws/")


def expected_token():
    return os.environ.get("ERLIK_API_TOKEN", "").strip()


_TRUTHY = frozenset({"1", "true", "yes", "on"})


def allow_unauthenticated() -> bool:
    """The deliberate opt-out for a deployment behind an authenticating proxy.

    Guarded like the HTTP side: only the listed truthy words open it, so "0" and
    "false" are not read as consent.
    """
    return os.environ.get("ERLIK_ALLOW_UNAUTHENTICATED", "").strip().lower() in _TRUTHY


def is_loopback(host) -> bool:
    """True only for an address that cannot be reached from the network.

    THE ONE DEFINITION shared by both boundaries -- `main._is_loopback` delegates
    here so the HTTP guard and this middleware cannot drift apart about what
    counts as local. Used only to DENY, so an unparseable value must not
    manufacture a denial on a box that is in fact local.
    """
    if not host:
        return False
    import ipaddress
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host in ("localhost", "testclient")


def bind_is_exposed() -> bool:
    """Whether the operator asked to listen beyond loopback (ERLIK_HOST)."""
    host = os.environ.get("ERLIK_HOST", "").strip()
    if not host:
        return False
    if host in ("0.0.0.0", "::", "*"):
        return True
    return not is_loopback(host)


def conn_is_remote(headers, client_host) -> bool:
    """Whether this connection plausibly came from off-box.

    A forwarded header means a proxy sits in front (peer address is then loopback
    and worthless as evidence), so its presence counts as remote on its own.
    Unknown peer is not evidence of remoteness -- a DENY predicate must not
    invent one.
    """
    if headers.get("x-forwarded-for") or headers.get("x-real-ip"):
        return True
    if client_host is None:
        return False
    return not is_loopback(client_host)


def presented(headers, cookies) -> str:
    """The credential this request carries, from whichever channel supplied it."""
    provided = headers.get("x-api-token", "")
    auth = headers.get("authorization", "")
    if not provided and auth.lower().startswith("bearer "):
        provided = auth[7:].strip()
    return provided or cookies.get("erlik_token", "")


async def _is_operator_token(provided: str, *, touch: bool = False) -> bool:
    """Does this resolve to a live operator?

    TWO BOUNDARIES MUST NOT DISAGREE ABOUT WHO IS AUTHENTICATED. For HTTP,
    `main._api_token_guard` is the OUTER guard -- an `@app.middleware("http")`
    registered after this middleware, so it wraps it and runs first -- and it is
    where an operator's personal token is resolved and stamped. This middleware is
    inner there. For websockets that guard does not run at all, so this middleware
    is the only boundary. Either way an operator token must be admitted here:
    while this function did not know about operator tokens, every request carrying
    one was answered 401 and the whole per-operator identity feature was
    unreachable -- minting worked, and nothing the minted token was for did.

    It also has to hold with NO shared secret configured. Retiring
    `ERLIK_API_TOKEN` once an admin operator exists is the documented way to close
    the bootstrap credential (see CLAUDE.md); refusing operator tokens whenever the
    shared secret is absent would make that the one configuration nobody can use.

    A broken or absent store authorises nobody, for the same reason it does not in
    the guard: an exception here is not permission.

    The cost is one indexed lookup, and only for a token with the operator prefix --
    the shared secret never reaches the database. The request is resolved a second
    time in `_api_token_guard`, which is where identity is recorded; this one only
    answers whether to let it past.
    """
    from orchestrator import operators as _ops
    if not _ops.looks_like_token(provided):
        return False
    try:
        from orchestrator.database import get_db
        db = await get_db()
        try:
            op_id, _name, _role = await _ops.resolve(db, provided)
            # The websocket path has no `_api_token_guard` behind it, so an
            # operator's last-seen is stamped here or nowhere; HTTP callers leave
            # touch False because that outer guard already records it.
            if op_id and touch:
                await _ops.touch(db, op_id)
        finally:
            await db.close()
        return bool(op_id)
    except Exception:
        return False


async def authorized(headers, cookies):
    provided = presented(headers, cookies)
    expected = expected_token()
    if expected:
        # compare_digest rejects non-ASCII outright; a malformed header is a
        # failed auth, not a 500.
        try:
            if hmac.compare_digest(provided, expected):
                return True
        except TypeError:
            pass
    return await _is_operator_token(provided)


async def _access_ok(path, headers, cookies, client_host, is_ws) -> bool:
    """Whether a request/connection to `path` may proceed. One boundary, both
    surfaces.

    The base `/api/` and `/ws/` decision when NO shared secret is configured used
    to be "not protected -> pass through", which had two holes this closes:

      * A websocket had no second guard behind it (the HTTP guard is
        `@app.middleware("http")` and never runs for `/ws/`), so an unconfigured
        instance bound off-loopback streamed live agent output and findings to
        anyone who connected. Websockets now fail closed off-loopback exactly as
        the HTTP guard does, unless ERLIK_ALLOW_UNAUTHENTICATED is set.
      * An operator token could not authenticate once the shared secret was
        retired -- the documented way to close the bootstrap credential. For HTTP
        that admission comes from the outer `_api_token_guard`; for websockets,
        which that guard never sees, this middleware now admits (and stamps) an
        operator token itself.

    HTTP off-loopback fail-close (and its labelled `X-Erlik-Auth` 401s) stays the
    job of `main._api_token_guard`; here we only decide whether an HTTP request may
    reach it.
    """
    if path in _EXEMPT:
        return True
    if not path.startswith(_PROTECTED_PREFIXES):
        return True
    if path.startswith(_ALWAYS_PROTECTED):
        return await authorized(headers, cookies)
    # Base /api/ and /ws/.
    if expected_token():
        return await authorized(headers, cookies)
    # No shared secret configured.
    if not is_ws:
        # HTTP: main._api_token_guard is the OUTER guard here -- it already
        # resolves the operator token, stamps it, and fail-closes off-loopback.
        # Re-resolving would just repeat that DB I/O, so let the request reach it.
        return True
    # Websocket: _api_token_guard never runs for /ws/, so an operator token is
    # admitted -- and its last-seen stamped -- here or nowhere.
    if await _is_operator_token(presented(headers, cookies), touch=True):
        return True
    # Unauthenticated ws, no shared secret: allowed only where it cannot be
    # reached from the network, unless explicitly opted out.
    if allow_unauthenticated():
        return True
    return not (bind_is_exposed() or conn_is_remote(headers, client_host))


class AccessMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        from starlette.requests import HTTPConnection
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        connection = HTTPConnection(scope)
        is_ws = scope["type"] == "websocket"
        client_host = connection.client.host if connection.client else None
        if not await _access_ok(scope.get("path", ""), connection.headers,
                                connection.cookies, client_host, is_ws):
            detail = ("Set ERLIK_API_TOKEN and authenticate to access assessment data"
                      if not expected_token() else
                      "missing or invalid API token")
            if is_ws:
                await send({"type": "websocket.close", "code": 4401})
            else:
                await JSONResponse({"detail": detail}, status_code=401)(scope, receive, send)
            return
        await self.app(scope, receive, send)
