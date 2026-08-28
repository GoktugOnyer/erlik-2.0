"""Perform a login and capture the session, so later cases can run authenticated.

The secret is decrypted for exactly the duration of one request and never
appears in a stored command, a log line, a step record or a report. That is why
the request is made by httpx here rather than by shelling out to curl: a curl
command line carrying a password would be written into `steps.tool_input` and
read back by anything that renders a run.

VERIFICATION IS PART OF ACQUISITION. A token that was returned is not a token
that works — a login form that answers 200 with "invalid credentials" would
otherwise be stored as a valid session and every downstream case would run
unauthenticated while claiming otherwise. A session is only marked `verified`
when a probe with it reaches a protected resource.
"""

from __future__ import annotations

import json
import re
from http.cookiejar import CookieJar, DefaultCookiePolicy, eff_request_host
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from orchestrator import credentials as C
from orchestrator import secrets as S

# Where a token tends to be in a JSON login response. Checked in order.
_TOKEN_PATHS = ("token", "access_token", "accessToken", "jwt", "id_token",
                "authentication.token", "data.token")

_BEARER_RX = re.compile(r"^[A-Za-z0-9._~+/=-]{8,4096}$")

# Hidden form inputs, for CSRF tokens. Most real login forms carry one, and a
# POST without it is rejected — DVWA's `user_token` is why erlik's first
# authenticated run against it never authenticated anything.
_HIDDEN_RX = re.compile(
    r"""<input\b[^>]*\btype\s*=\s*['"]?hidden['"]?[^>]*>""", re.I)
_ATTR_RX = re.compile(r"""\b(name|value)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]*))""", re.I)

# Bounds. The page is attacker-controlled on a pentest; a login form does not
# legitimately carry hundreds of hidden fields or a megabyte token.
MAX_HIDDEN_FIELDS = 20
MAX_HIDDEN_VALUE = 4096


def hidden_fields(html: str) -> dict[str, str]:
    """Hidden inputs from a login page, for CSRF tokens.

    These are values the TARGET chose, echoed straight back to it in a
    form-encoded POST body. They never reach a shell, a command line or a
    template, so they are bounded rather than validated for injection — a CSRF
    token is opaque by design and a character allowlist would break real ones.
    """
    out: dict[str, str] = {}
    for tag in _HIDDEN_RX.findall(html or "")[:MAX_HIDDEN_FIELDS * 4]:
        attrs = {}
        for m in _ATTR_RX.finditer(tag):
            attrs[m.group(1).lower()] = m.group(2) or m.group(3) or m.group(4) or ""
        name = attrs.get("name", "")
        if name and len(attrs.get("value", "")) <= MAX_HIDDEN_VALUE:
            out[name] = attrs.get("value", "")
        if len(out) >= MAX_HIDDEN_FIELDS:
            break
    return out


def _dig(data: Any, path: str) -> str:
    cur = data
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return ""
        cur = cur[part]
    return cur if isinstance(cur, str) else ""


def extract_token(body: str) -> str:
    """A bearer token from a login response, or ''.

    Shape-checked before it is stored: a token is about to be interpolated into
    an Authorization header, and an error page is not a credential.
    """
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return ""
    for path in _TOKEN_PATHS:
        tok = _dig(data, path).strip()
        if tok.startswith("Bearer "):
            tok = tok[7:].strip()
        if tok and _BEARER_RX.match(tok):
            return tok
    return ""


# ---------------------------------------------------------------------------
# COOKIES ARE TRACKED BY HAND
#
# http.cookiejar implements RFC 2965's "effective request host": a request host
# with no dot in it gets ".local" appended. A cookie set by `localhost` with
# `domain=localhost` is therefore stored and NEVER RETURNED, because its domain
# does not match `localhost.local`.
#
# The failure is completely silent. Against DVWA every request received a fresh
# PHPSESSID, so the CSRF token belonged to a session that no longer existed by
# the time the form was posted, `checkToken` failed, and the login was recorded
# as `rejected` — indistinguishable from a wrong password. curl logs in fine.
#
# It is not a lab-only problem: erlik's recon deliberately accepts single-label
# internal names because `intranet`, `jira` and `vpn` are ordinary targets on a
# client's network, so cookie authentication was broken on exactly the internal
# engagements the feature exists for.
#
# Patching the jar's policy does NOT fix it. httpx rebuilds a fresh
# `Cookies(...)` with the DEFAULT policy while building every request, so any
# policy set on the client's jar is discarded on the next call. Rather than
# fight a library's internals, the cookies are tracked here: Set-Cookie is read
# off each response and the Cookie header is written explicitly.
#
# Redirects are followed by hand for the same reason — httpx would follow them
# internally with its own jar, losing the session mid-chain — and following
# them here also reveals WHERE a login redirected to, which is how DVWA
# distinguishes success (index.php) from failure (login.php).
# ---------------------------------------------------------------------------

MAX_REDIRECTS = 6
_SET_COOKIE_SPLIT = re.compile(r"[;,]")


class Jar:
    """Cookies for exactly one origin, kept as name -> value."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def update(self, response: "httpx.Response") -> None:
        for raw in response.headers.get_list("set-cookie"):
            pair = raw.split(";", 1)[0].strip()
            name, sep, value = pair.partition("=")
            name = name.strip()
            if sep and name:
                self.values[name] = value.strip()

    def header(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.values.items())


async def request(cli: "httpx.AsyncClient", method: str, url: str, jar: Jar,
                  *, data: dict | None = None, json_body: dict | None = None,
                  auth: tuple | None = None) -> "httpx.Response":
    """One request, redirects followed manually, cookies carried by `jar`.

    A redirect to a DIFFERENT ORIGIN is not followed. The page is
    attacker-controlled on a pentest, and following it would send the
    customer's session — and, on a 307/308, their password — to a third party.
    """
    origin = urlparse(url).netloc.lower()
    for _ in range(MAX_REDIRECTS + 1):
        headers = {}
        if jar.header():
            headers["Cookie"] = jar.header()
        r = await cli.request(method, url, data=data, json=json_body,
                              auth=auth, headers=headers)
        jar.update(r)
        location = r.headers.get("location")
        if r.status_code not in (301, 302, 303, 307, 308) or not location:
            return r
        nxt = urljoin(url, location)
        if urlparse(nxt).netloc.lower() != origin:
            return r
        url = nxt
        if r.status_code in (301, 302, 303):
            method, data, json_body, auth = "GET", None, None, None
    return r


# ---------------------------------------------------------------------------
# LOGIN FORM PARSING
#
# A browser does not post {username, password}. It posts EVERY successful
# control in the form: hidden CSRF fields, the submit button that was clicked,
# checked boxes, selected options. Applications gate on all of it.
#
# DVWA gates the entire login branch on `isset($_POST['Login'])` — and `Login`
# is the SUBMIT BUTTON, not a hidden input. erlik sent username+password+CSRF
# and got HTTP 200 with no login attempted at all: the form simply re-rendered.
# Nothing failed, nothing errored, and the session came back "rejected" for a
# reason that had nothing to do with the credentials. Harvesting hidden inputs
# alone was not enough, and would not have been enough for most real forms.
#
# So the whole form is reconstructed the way a browser would submit it.
# ---------------------------------------------------------------------------

# Only ONE submit button is sent by a browser — the one the user clicked. When a
# form has several (Login / Register / Cancel), picking wrong can register an
# account or cancel the request, so a login-ish name wins and the FIRST button
# is only a fallback.
_SUBMIT_PREFERENCE = ("log in", "login", "log-in", "sign in", "signin",
                      "sign-in", "submit", "continue", "enter", "go")

# A password input is what identifies the login form on a page that also
# carries a search box, a newsletter signup and a language picker.
_PASSWORD_TYPES = ("password",)

MAX_FORM_FIELDS = 60
MAX_FIELD_VALUE = 8192


class _FormParser(HTMLParser):
    """Collect every form on a page with the controls a browser would submit."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict[str, Any]] = []
        self._cur: dict[str, Any] | None = None
        self._select: dict[str, Any] | None = None

    def _open_form(self, attrs: dict[str, str]) -> None:
        self._cur = {"action": attrs.get("action", ""),
                     "method": (attrs.get("method") or "post").lower(),
                     "controls": [], "has_password": False}

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v if v is not None else "") for k, v in attrs}
        if tag == "form":
            # Forms do not nest; an unclosed one is closed here.
            if self._cur is not None:
                self.forms.append(self._cur)
            self._open_form(a)
            return
        if self._cur is None:
            # Controls outside any <form> still belong to the page; some apps
            # rely on JS to collect them. Keep them in an implicit form rather
            # than dropping the CSRF token they often carry.
            self._open_form({})
        if tag == "input":
            typ = (a.get("type") or "text").lower()
            if typ in _PASSWORD_TYPES:
                self._cur["has_password"] = True
            self._cur["controls"].append(("input", typ, a))
        elif tag == "select":
            self._select = {"name": a.get("name", ""), "options": [],
                            "selected": None}
        elif tag == "option" and self._select is not None:
            val = a.get("value", "")
            self._select["options"].append(val)
            if "selected" in a:
                self._select["selected"] = val
        elif tag == "textarea":
            self._cur["controls"].append(("textarea", "textarea", a))

    def handle_endtag(self, tag):
        if tag == "select" and self._select is not None and self._cur is not None:
            self._cur["controls"].append(("select", "select", self._select))
            self._select = None
        elif tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None

    def close(self):
        super().close()
        if self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def _submittable(form: dict[str, Any]) -> dict[str, str]:
    """The fields a browser would send for this form."""
    data: dict[str, str] = {}
    submits: list[tuple[str, str]] = []
    for kind, typ, a in form["controls"]:
        if kind == "select":
            name = a["name"]
            if not name:
                continue
            chosen = a["selected"]
            if chosen is None:
                chosen = a["options"][0] if a["options"] else ""
            data[name] = chosen
            continue
        name = a.get("name", "")
        if not name or len(a.get("value", "")) > MAX_FIELD_VALUE:
            continue
        if kind == "textarea":
            data[name] = ""
        elif typ in ("submit", "image"):
            submits.append((name, a.get("value", "")))
        elif typ in ("checkbox", "radio"):
            # Unchecked controls are NOT submitted by a browser.
            if "checked" in a:
                data[name] = a.get("value", "on")
        elif typ == "button" or typ == "reset" or typ == "file":
            continue
        else:                      # hidden, text, email, password, ...
            data[name] = a.get("value", "")
        if len(data) >= MAX_FORM_FIELDS:
            break

    if submits:
        best = None
        for name, value in submits:
            hay = f"{name} {value}".lower()
            if any(p in hay for p in _SUBMIT_PREFERENCE):
                best = (name, value)
                break
        name, value = best or submits[0]
        data[name] = value
    return data


def login_form(html: str, page_url: str, password_field: str = "password"
               ) -> dict[str, Any] | None:
    """The login form on a page, as (action_url, method, prefilled fields).

    Picks the form containing a password input — a login page routinely also
    carries a search box, a newsletter signup and a language picker, and
    submitting those instead is indistinguishable from a wrong password.

    The action URL is resolved against the page, then CONSTRAINED TO THE SAME
    ORIGIN. A form whose action points off-host would otherwise make erlik post
    the customer's password to a third party — the page is attacker-controlled
    on a pentest, and that is the one mistake here that cannot be walked back.
    """
    try:
        p = _FormParser()
        p.feed(html or "")
        p.close()
    except Exception:  # noqa: BLE001 — malformed markup must not abort a login
        return None

    forms = [f for f in p.forms if f["controls"]]
    if not forms:
        return None
    named = [f for f in forms
             if any(a.get("name") == password_field
                    for _, _, a in f["controls"] if isinstance(a, dict))]
    withpw = [f for f in forms if f["has_password"]]
    form = (named or withpw or forms)[0]

    action = (form["action"] or "").strip()
    url = urljoin(page_url, action) if action else page_url
    if urlparse(url).netloc.lower() != urlparse(page_url).netloc.lower():
        # Refuse, do not "fix". Falling back to the page URL silently would
        # hide a hostile form from the operator.
        return {"error": f"login form posts to another origin ({url!r})"}

    return {"url": url, "method": form["method"], "fields": _submittable(form)}


async def authenticate(db, credential_id: str, *, verify_url: str = "",
                       timeout: float = 20.0) -> dict[str, Any]:
    """Log in with a stored credential and record the session.

    Returns a report with NO secret in it. `status` is 'verified' only when a
    probe with the captured session actually reached a protected resource.
    """
    row, password = await C._secret_of(db, credential_id)
    login_url = row.get("login_url") or ""
    if not login_url:
        return {"ok": False, "reason": "credential has no login_url"}

    kind = (row.get("kind") or "form").lower()
    user_field = row.get("username_field") or "username"
    pass_field = row.get("password_field") or "password"
    payload = {user_field: row.get("username") or "", pass_field: password}

    token, cookie, note = "", "", ""
    jar = Jar()
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as cli:
            if kind == "json":
                r = await request(cli, "POST", login_url, jar, json_body=payload)
            elif kind == "basic":
                r = await request(cli, "GET", login_url, jar,
                                  auth=(row.get("username") or "", password))
            else:
                # GET the form first, on the SAME client. Both matter: the CSRF
                # token has to be harvested, and it is bound to the session
                # cookie that same GET sets.
                #
                # Then submit the form the way a BROWSER would — every
                # successful control, including the submit button. DVWA gates
                # its whole login branch on `isset($_POST['Login'])`, so a POST
                # of username+password+CSRF returned 200 with no login
                # attempted; the form simply re-rendered and the session was
                # recorded "rejected" for a reason unrelated to the password.
                #
                # The operator's own values always win over harvested ones, so
                # a field named `password` on the page cannot displace the
                # credential.
                post_url, extra_fields = login_url, {}
                try:
                    page = await request(cli, "GET", login_url, jar)
                    parsed = login_form(page.text or "", str(page.url), pass_field)
                except Exception:  # noqa: BLE001
                    parsed = None
                if parsed and parsed.get("error"):
                    return {"ok": False, "reason": parsed["error"]}
                if parsed:
                    post_url = parsed["url"]
                    extra_fields = parsed["fields"]
                    note = f"submitted {len(extra_fields)} form field(s); "
                r = await request(cli, "POST", post_url, jar,
                                  data={**extra_fields, **payload})
            body = r.text or ""
            token = extract_token(body)
            # The ACCUMULATED jar, not r.cookies — the session cookie is
            # usually set by the first GET, and `r.cookies` holds only what
            # the last response set.
            cookie = jar.header()
            note = f"{note}HTTP {r.status_code}"
    except Exception as e:  # noqa: BLE001 — the message must not carry the payload
        return {"ok": False, "reason": f"login request failed: {type(e).__name__}"}
    finally:
        password = ""     # not a guarantee in CPython, but it shortens the window

    if not token and not cookie:
        return {"ok": False, "reason": f"no token or cookie in the response ({note})"}

    status = "unverified"
    if verify_url:
        status = "verified" if await _verify(verify_url, token, cookie,
                                             row.get("header_name") or "Authorization",
                                             timeout) else "rejected"
    sid = await C.save_session(db, credential_id, row["target_key"],
                               token=token, cookie=cookie, status=status)
    await db.commit()
    return {"ok": status != "rejected", "session_id": sid, "status": status,
            "has_token": bool(token), "has_cookie": bool(cookie), "note": note}


def _fingerprint(r: "httpx.Response") -> tuple:
    """What a response looks like, for comparison. Length is bucketed because
    a page can carry a username or a CSRF token and differ trivially."""
    return (r.status_code,
            (r.headers.get("location") or "").split("?")[0],
            len(r.content) // 512)


async def _verify(url: str, token: str, cookie: str, header_name: str,
                  timeout: float) -> bool:
    """Did the captured session actually reach a protected resource?

    DIFFERENTIAL, not a status allowlist. The first version returned True for
    anything that was not 401/403 — and DVWA answers an unauthenticated
    /index.php with `302 -> login.php`, so it stored a session that had never
    authenticated anything as `verified`. That is the exact failure this
    function exists to prevent, and a status allowlist cannot see it: the
    "protected" response and the rejection are both perfectly ordinary.

    So the probe is made TWICE, with and without the session, and the session
    is verified only when it CHANGES the answer. A response identical to the
    anonymous one proves the credentials did nothing, whatever its status code.
    """
    headers = {}
    if token:
        headers[header_name] = f"Bearer {token}"
    if cookie:
        headers["Cookie"] = cookie
    if not headers:
        return False
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as cli:
            with_session = await cli.get(url, headers=headers)
            anonymous = await cli.get(url)
    except Exception:  # noqa: BLE001
        return False
    if with_session.status_code in (401, 403):
        return False
    return _fingerprint(with_session) != _fingerprint(anonymous)
