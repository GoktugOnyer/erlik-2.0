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
        if secret:
            value = value.replace(secret, "[REDACTED]")
    value = re.sub(r"(?im)((?:authorization|cookie|set-cookie|x-api-key)\s*:\s*)[^\r\n]+", r"\1[REDACTED]", value)
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
