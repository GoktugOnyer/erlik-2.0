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
_EXEMPT = ("/api/health", "/api/auth")

# Gated whether or not a token exists, because these carry secrets and client
# evidence. With no token configured they are unreachable by construction.
_ALWAYS_PROTECTED = ("/api/integrations/", "/ws/integrations/")

_PROTECTED_PREFIXES = ("/api/", "/ws/")


def expected_token():
    return os.environ.get("ERLIK_API_TOKEN", "").strip()


def authorized(headers, cookies):
    expected = expected_token()
    if not expected:
        return False
    provided = headers.get("x-api-token", "")
    auth = headers.get("authorization", "")
    if not provided and auth.lower().startswith("bearer "):
        provided = auth[7:].strip()
    provided = provided or cookies.get("erlik_token", "")
    # compare_digest rejects non-ASCII outright; a malformed header is a
    # failed auth, not a 500.
    try:
        return hmac.compare_digest(provided, expected)
    except TypeError:
        return False


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
        if _protected(scope.get("path", "")) and not authorized(connection.headers, connection.cookies):
            detail = ("Set ERLIK_API_TOKEN and authenticate to access assessment data"
                      if not expected_token() else
                      "missing or invalid API token")
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 4401})
            else:
                await JSONResponse({"detail": detail}, status_code=401)(scope, receive, send)
            return
        await self.app(scope, receive, send)
