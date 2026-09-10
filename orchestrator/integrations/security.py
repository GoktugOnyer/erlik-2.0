"""Secrets stay outside SQLite, reports and model prompts."""
from __future__ import annotations
import json
import os
import re
import secrets
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def runtime_root() -> Path:
    root = Path(os.environ.get("ERLIK_INTEGRATION_DATA", "data/integrations")).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.chmod(0o700)
    return root


def private_write(path: Path, content: str | bytes):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(content.encode() if isinstance(content, str) else content)


class SecretStore:
    def path(self, key: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{32}", key):
            raise ValueError("invalid secret reference")
        return runtime_root() / "secrets" / f"{key}.json"

    def put(self, value: dict, key: str | None = None) -> str:
        key = key or secrets.token_hex(16)
        private_write(self.path(key), json.dumps(value))
        return key

    def get(self, key: str) -> dict:
        return json.loads(self.path(key).read_text())


_SENSITIVE = re.compile(r"authorization|cookie|password|secret|token|api.?key|session", re.I)


def redact(value, known: tuple[str, ...] = ()):
    if isinstance(value, dict):
        return {k: "[REDACTED]" if _SENSITIVE.search(k) and k not in ("identity_ids", "identity_id", "secret_id") else redact(v, known) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, known) for v in value]
    if not isinstance(value, str):
        return value
    if value.lstrip().startswith(("{", "[")):
        try:
            structured = json.loads(value)
            if isinstance(structured, (dict, list)):
                return json.dumps(redact(structured, known))
        except (ValueError, TypeError):
            if "\n" in value:
                return "\n".join(redact(line, known) for line in value.splitlines())
    for secret in sorted(set(known), key=len, reverse=True):
        # The SAME length guard orchestrator.credentials.scrub applies. Two
        # layers redacting the same values by two different rules is the defect:
        # this one had no guard, so a three-character identity value shredded
        # ordinary text. Measured on the 2026-09-10 lane run, where a DVWA
        # identity carrying `security=low` stored the application's own
        # robots.txt as `Disal[REDACTED]: /` — evidence that no longer matches
        # the bytes the application sent.
        #
        # A value this short is not protectable by substring search anyway, and
        # the header-level rules below catch the realistic leak path (a Cookie or
        # Authorization line) whatever its length. What remains, knowingly: a
        # 4-to-7 character secret that is a substring of ordinary prose still
        # rewrites that prose. Raising the threshold trades secret coverage for
        # evidence fidelity and is an operator's call, not a silent one.
        if secret and len(secret) >= 4:
            value = value.replace(secret, "[REDACTED]")
    # A cookie header loses its VALUES and keeps its ATTRIBUTES, because the
    # rest of the line is frequently the finding: WSTG-SESS-02's entire claim is
    # "this session cookie lacks HttpOnly / SameSite / Secure", proved by a
    # Set-Cookie line. A blanket rule erased the attributes along with the
    # secret, so the finding said they were missing and the evidence said
    # `Set-Cookie: [REDACTED]` — indistinguishable from a cookie that had them
    # all, and now that evidence travels to a client, unverifiable there too.
    #
    # NOT ANCHORED. An earlier version of this used `^...` with re.MULTILINE and
    # that was a regression against the blanket rule, produced live end to end:
    # a third party's session cookie disclosed inside a response BODY travelled
    # verbatim into a DefectDojo description, because the header was not at the
    # start of a line. Worse, erlik's own blind-differential evidence is
    # normalised to a single line before it is redacted, so it is exactly that
    # shape. Anchoring a redaction rule assumes the secret is politely formatted.
    #
    # Attributes are an ALLOW-LIST rather than "everything after the first
    # semicolon": that earlier form published a quoted value containing a
    # semicolon, a second cookie on the same line, and a secret in a
    # non-standard attribute.
    value = re.sub(_COOKIE_HEADER, _redact_cookie, value)
    value = re.sub(r"(?i)((?:authorization|authentication|proxy-authorization|"
                   r"x-api-key|api-key|x-auth-key|x-auth-token|x-csrf-token)\s*:[ \t]*)[^\r\n]+",
                   r"\1[REDACTED]", value)
    value = re.sub(r"(?i)(Bearer\s+)[\w.~+/=-]+", r"\1[REDACTED]", value)
    value = re.sub(r"\beyJ[\w-]+\.[\w-]+\.[\w-]+", "[REDACTED]", value)
    value = re.sub(r'(?i)(["\']?(?:password|access_token|token|api_key|secret)["\']?\s*[:=]\s*["\']?)[^\s&"\'<>]+', r"\1[REDACTED]", value)
    return value


def secret_values(identity: dict) -> tuple[str, ...]:
    values = list(identity.get("headers", {}).values())
    values += [v.removeprefix("Bearer ") for v in values]
    cookies = identity.get("cookies", []) + (identity.get("storage_state") or {}).get("cookies", [])
    values += [c.get("value", "") for c in cookies]
    for origin in (identity.get("storage_state") or {}).get("origins", []):
        values += [item.get("value", "") for item in origin.get("localStorage", [])]
    return tuple(v for v in values if v)


# Cookie ATTRIBUTE names, which are not secret and are frequently the finding.
# Everything else on a cookie header is a value.
_COOKIE_ATTRIBUTES = frozenset({
    "path", "domain", "expires", "max-age", "samesite", "httponly", "secure",
    "priority", "partitioned", "version", "comment", "commenturl", "discard", "port"})

# A cookie value: a quoted string (Tomcat quotes values containing `;`) or a
# bare token. Bounded, and stopping at whitespace so a header quoted mid-body
# does not swallow the rest of the line.
_COOKIE_VALUE = r'(?:"[^"\r\n]{0,512}"|[^;,\s\r\n]{0,512})'
_COOKIE_PAIR = r"[^=;,\s\r\n]{1,512}(?:=" + _COOKIE_VALUE + r")?"
_COOKIE_HEADER = re.compile(
    r"(?i)((?:set-)?cookie2?\s*:[ \t]*)((?:" + _COOKIE_PAIR + r")(?:\s*;\s*(?:" + _COOKIE_PAIR + r")){0,32})")


def _redact_cookie(match: "re.Match") -> str:
    head, body = match.group(1), match.group(2)

    def pair(m):
        name = m.group(1).strip().strip('"')
        if name.lower() in _COOKIE_ATTRIBUTES:
            return m.group(0)
        return m.group(1) + "=[REDACTED]"

    if "=" not in body:
        # A cookie header with no name=value pair is all value.
        return head + "[REDACTED]"
    return head + re.sub(r"([^=;,\s\r\n]{1,512})=" + _COOKIE_VALUE, pair, body)


# Characters that make quoted text DISPLAY something other than what it holds,
# and characters a downstream store rejects outright.
#
# A finding's evidence is chosen by the application under test and travels into a
# client's issue tracker. Measured: a Set-Cookie line carrying U+202E
# (RIGHT-TO-LEFT OVERRIDE) renders in a browser as
# `Set-Cookie: PHPSESSID=…; Path=/;HttpOnly; SameSite=Strict` while containing
# neither attribute — so a reader closes a TRUE WSTG-SESS-02 finding as erlik's
# error. A zero-width space inside `Ht<ZWSP>tpO<ZWSP>nly` does the converse. A
# code block does not disable bidi reordering, so the four-space quote cannot
# help here; the characters have to stop being characters.
#
# NUL is in the list for a different reason: DefectDojo is Postgres-backed and
# Postgres TEXT rejects U+0000, so one NUL anywhere in a captured response would
# fail the whole export and take every other finding in the batch with it.
_UNSAFE_IN_EVIDENCE = re.compile(
    "[\u0000-\u0008\u000b-\u001f\u007f\u00ad\u200b-\u200f"
    "\u2028\u2029\u202a-\u202e\u2066-\u2069\ufeff]")


def safe_evidence(value: str) -> str:
    """Target bytes made safe to quote, without hiding what they say.

    Every character that survives is the one the application sent; the ones that
    do not are named in place, so a reader sees `<U+202E>` rather than silently
    reading a reordered line. CRLF and a lone CR become a newline, because a bare
    CR rewinds the line in some renderers and is how quoted evidence gets to show
    something other than its own content.
    """
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    return _UNSAFE_IN_EVIDENCE.sub(lambda m: f"<U+{ord(m.group(0)):04X}>", value)


def sensitive_values(value) -> tuple[str, ...]:
    values = []
    if isinstance(value, dict):
        for key, item in value.items():
            if _SENSITIVE.search(key) and isinstance(item, str):
                values.append(item)
            else:
                values.extend(sensitive_values(item))
    elif isinstance(value, list):
        for item in value:
            values.extend(sensitive_values(item))
    return tuple(values)
