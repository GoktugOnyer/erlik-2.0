"""Dependency-free policy used inside the enforcing MITM proxy and unit tests."""
from __future__ import annotations
import fnmatch
import re
from urllib.parse import urlsplit


def origin(url):
    u = urlsplit(url)
    return u.scheme.lower(), (u.hostname or "").lower().rstrip("."), u.port or (443 if u.scheme == "https" else 80)


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
