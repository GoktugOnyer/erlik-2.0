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
    # A cookie header loses its VALUES and keeps everything else, because the
    # rest of the line is frequently the finding.
    #
    # This used to replace the whole line with [REDACTED]. A finding carries its
    # evidence to the client now, and WSTG-SESS-02's entire claim is "this
    # session cookie lacks HttpOnly / SameSite / Secure" — proved by a
    # Set-Cookie line whose attributes were being erased along with the secret.
    # The finding said the attributes were missing and the evidence said
    # `Set-Cookie: [REDACTED]`, which is unverifiable and indistinguishable from
    # a cookie that had every attribute set.
    #
    # The credential still never travels: the value is what is secret, and an
    # attribute name is not. Authorization and X-Api-Key keep the blanket rule —
    # there is no structure in them worth preserving.
    value = re.sub(r"(?im)^(set-cookie\s*:\s*)([^=;\r\n]{1,256})=[^;\r\n]*",
                   r"\1\2=[REDACTED]", value)
    value = re.sub(r"(?im)^(cookie\s*:\s*)([^\r\n]+)",
                   lambda m: m.group(1) + re.sub(r"([^=;\s]{1,256})=[^;]*", r"\1=[REDACTED]",
                                                m.group(2)), value)
    value = re.sub(r"(?im)((?:authorization|x-api-key)\s*:\s*)[^\r\n]+", r"\1[REDACTED]", value)
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
