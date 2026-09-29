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


def presented(headers, cookies) -> str:
    """The credential this request carries, from whichever channel supplied it."""
    provided = headers.get("x-api-token", "")
    auth = headers.get("authorization", "")
    if not provided and auth.lower().startswith("bearer "):
        provided = auth[7:].strip()
    return provided or cookies.get("erlik_token", "")


async def _is_operator_token(provided: str) -> bool:
    """Does this resolve to a live operator?

    TWO BOUNDARIES MUST NOT DISAGREE ABOUT WHO IS AUTHENTICATED. This one is
    outermost and refuses before `main._api_token_guard` runs, and that guard is
    where an operator's personal token is resolved and stamped on what follows. So
    while this function did not know about operator tokens, every request carrying
    one was answered 401 here and the whole per-operator identity feature was
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


def _protected(path: str) -> bool:
    if path in _EXEMPT:
        return False
    if path.startswith(_ALWAYS_PROTECTED):
        return True
    return bool(expected_token()) and path.startswith(_PROTECTED_PREFIXES)


class AccessMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        from starlette.requests import HTTPConnection
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        connection = HTTPConnection(scope)
        if _protected(scope.get("path", "")) and not await authorized(
                connection.headers, connection.cookies):
            detail = ("Set ERLIK_API_TOKEN and authenticate to access assessment data"
                      if not expected_token() else
                      "missing or invalid API token")
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 4401})
            else:
                await JSONResponse({"detail": detail}, status_code=401)(scope, receive, send)
            return
        await self.app(scope, receive, send)
