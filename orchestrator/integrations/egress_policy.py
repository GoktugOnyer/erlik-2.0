"""Dependency-free policy used inside the enforcing MITM proxy and unit tests."""
from __future__ import annotations
import fnmatch
import re
from urllib.parse import urlsplit


def origin(url):
    u = urlsplit(url)
    return u.scheme.lower(), (u.hostname or "").lower().rstrip("."), u.port or (443 if u.scheme == "https" else 80)


def budget_refusal(config, count, urls, url) -> str:
    """"" if this request is within budget, else the reason it is not.

    Extracted from the mitmproxy addon so it can be tested: mitmproxy is not importable
    outside the proxy image, so while this lived inline nothing exercised it, and the
    interaction below cost a whole assessment.

    ERLIK'S OWN CONTROL TRAFFIC DOES NOT COUNT AGAINST THE DISTINCT-URL CEILING.
    `max_urls` bounds how much of the TARGET an assessment explores; a liveness probe of
    one declared, already scope-checked URL is not exploration. Measured on the first real
    three-arm run: with `max_urls=60`, katana's crawl of Juice Shop consumed the budget and
    the CLOSING liveness check became the 61st distinct URL. It was refused, `satisfies`
    read the refusal as a failed assertion, and the stage was recorded "authentication
    expired during stage; replace credentials and resume" — about a credential that was
    fine. The run then halted every remaining arm, including the anonymous one, which has
    no credential to expire.

    They still count against `max_requests`, and they are still scope-checked, so this
    exempts the ceiling and nothing else.
    """
    if config.get("service_only"):
        return ""
    if count > config.get("max_requests", 10000):
        return "request budget exhausted"
    control = set(config.get("control_urls") or [])
    if url in control:
        return ""
    explored = {pair for pair in urls if pair[1] not in control}
    if len(explored) > config.get("max_urls", 500):
        return "URL budget exhausted"
    return ""


def cookie_applies(cookie, path, scheme, now):
    """Whether one declared cookie belongs on this request."""
    expires = cookie.get("expires", -1)
    return bool(path.startswith(cookie.get("path") or "/")
                and (not cookie.get("secure") or scheme == "https")
                and (expires is None or expires <= 0 or expires > now))


def identity_cookie_applies(cookie, host, path, scheme, now):
    """An identity cookie, which carries a cookie-style `domain` rather than an origin."""
    domain = (cookie.get("domain") or host).lower()
    domain_ok = host == domain or (domain.startswith(".")
                                   and (host == domain[1:] or host.endswith(domain)))
    return bool(domain_ok and cookie_applies(cookie, path, scheme, now))


def merged_cookies(existing, application, identity_cookies, url, path, scheme, now):
    """The `cookie:` header the proxy should send, as an ordered name->value mapping.

    MERGED, NOT REPLACED. The proxy used to finish with
    `flow.request.headers["cookie"] = "; ".join(accepted)`, discarding whatever the request
    already carried. A CATALOGUE case cannot be the source of that — `deterministic.
    curl_request` refuses `-b` with a value and refuses an explicit `Cookie:` header, so a
    case cannot opt out of the stage's identity — but a SCANNER can: ZAP and katana keep
    their own jars, and DVWA answers every single request with
    `Set-Cookie: security=impossible`, so a scanner arm carries the application's own
    configuration back on every later request. The merge is written down here, away from
    mitmproxy, so it can be tested.

    Ablating the dict to the old `"; ".join(...)` was measured: the SAME declared
    configuration then returns 5070 bytes and five usernames or 389 bytes and nothing,
    purely on join order, because PHP takes the FIRST of two cookies with one name.

    ORDER OF AUTHORITY, least to most:
      1. what the request already carried, including anything the target set;
      2. the IDENTITY — the proxy is the authority on WHO an arm is;
      3. the APPLICATION'S CONFIGURATION — the authority on WHICH APPLICATION every arm is
         testing.

    3 OUTRANKS 2 BY MEASUREMENT, not by taste. DVWA sets `security=impossible` on every
    response and `login.py`'s jar is a flat name->value dict that absorbs it, so an identity
    captured by erlik's own credential flow carries `security=impossible` — a cookie the
    operator never declared and has no reason to know is there. With the identity winning,
    declaring `security=low` either did nothing or (in the first draft) aborted the whole
    assessment as a collision. With the application winning, every arm carries the declared
    value whatever its jar picked up, which is the uniformity the whole design rests on.

    `application` entries are gated on the full ORIGIN, scheme host and port, because a
    cookie declared for one in-scope application must not be sent to another.
    """
    jar = {}
    for pair in (existing or "").split(";"):
        if "=" in pair:
            name, _, value = pair.partition("=")
            name = name.strip()
            if name:
                jar[name] = value.strip()
    host = (urlsplit(url).hostname or "").lower()
    for cookie in identity_cookies or ():
        if cookie.get("name") and identity_cookie_applies(cookie, host, path, scheme, now):
            jar[cookie["name"]] = cookie.get("value", "")
    overridden = []
    for cookie in application or ():
        if not cookie.get("name") or origin(url) != origin(cookie.get("target_origin", "")):
            continue
        if not cookie_applies(cookie, path, scheme, now):
            continue
        if cookie["name"] in jar and jar[cookie["name"]] != cookie.get("value", ""):
            overridden.append(cookie["name"])
        jar[cookie["name"]] = cookie.get("value", "")
    return jar, overridden


# A PATH SEGMENT that ends the session, whatever the application calls it.
#
# `excluded_paths` is an operator list matched as a PREFIX, so its default
# ["/logout", "/signout"] refuses `/logout` and misses every framework spelling
# that nests it. Measured against the default:
#
#     refused   /logout  /logout.php  /signout
#     VISITED   /users/sign_out     (Rails/Devise)
#     VISITED   /accounts/logout/   (Django)
#     VISITED   /Account/LogOff     (ASP.NET MVC)
#     VISITED   /auth/logout  /api/v1/logout  /user/logout  /logoff  /sign-out
#
# A crawler that follows one of those ends its own session, and the rest of that
# arm's crawl then sees only login forms — so the arm's surface silently shrinks
# and it is no longer comparable with any other. Nothing reports it, because
# every request still succeeds.
#
# This is the lane's own guard rather than a default in the operator's list: an
# operator replaces `excluded_paths` to ADD an exclusion, and that must not be how
# they silently remove the rule protecting the run from itself. Matched per whole
# segment and case-insensitively, because `LogOff` is real and because a blog post
# at /blog/how-to-logout-safely is a page.
SESSION_ENDING_SEGMENTS = frozenset({
    "logout", "log-out", "log_out", "logoff", "log-off", "log_off",
    "signout", "sign-out", "sign_out", "signoff", "sign-off", "sign_off",
})


def ends_the_session(path: str) -> bool:
    return any(segment.lower() in SESSION_ENDING_SEGMENTS
               for segment in (path or "").split("/"))


class EgressPolicy:
    def __init__(self, config):
        self.config = config

    def check(self, url: str, method="GET") -> tuple[bool, str]:
        try:
            u = urlsplit(url)
            scheme, host, port = origin(url)
            if scheme not in ("http", "https") or not host or u.username or u.password:
                return False, "invalid HTTP destination"
            if any(c in url for c in "\r\n\\"):
                return False, "invalid URL"
            # Control-plane workers receive ONLY control-plane destinations.
            if self.config.get("service_only"):
                allowed = any(origin(s) == (scheme, host, port) for s in self.config.get("services", []))
                return allowed, "service destination" if allowed else "service scope refusal"
            scope = self.config["scope"]
            if any(fnmatch.fnmatchcase(host, p.lower()) for p in scope.get("deny_hosts", [])):
                return False, "explicit deny"
            if not any(fnmatch.fnmatchcase(host, p.lower()) for p in scope["allow_hosts"]):
                return False, "host outside scope"
            if port not in scope["allow_ports"]:
                return False, "port outside scope"
            if any(fnmatch.fnmatchcase(u.path, p + "*") for p in self.config.get("excluded_paths", [])):
                return False, "excluded path"
            if ends_the_session(u.path):
                return False, "excluded path"
            if method.upper() not in ("GET", "HEAD", "OPTIONS"):
                if not self.config.get("state_changing"):
                    return False, "state-changing requests disabled"
                permitted = self.config.get("operation_routes", [])
                if not any(method.upper() == item["method"] and origin(item["origin"]) == (scheme, host, port)
                           and re.fullmatch(item["path_regex"], u.path or "/") for item in permitted):
                    return False, "operation not selected"
            return True, "target destination"
        except (KeyError, ValueError, TypeError):
            return False, "invalid policy or destination"
