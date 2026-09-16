"""Secrets stay outside SQLite, reports and model prompts."""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import pathlib
import re
import secrets
import tempfile
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


# THE LABEL FOR AN OPERATOR DECLARATION, which must not be a way to recover it.
#
# A finding must say WHICH declaration it rests on — an assessment can use several
# markers — and must not quote the declaration, because a marker names the
# application's private data and a finding travels into an export. The first attempt
# at that was an unsalted `sha256(marker)[:12]`, and it was not a label but an oracle.
# Measured against the digest a real Juice Shop export carries, over a candidate space
# of 4050 strings built from 18 field names, 15 local-parts, 3 domains and 5 separator
# patterns:
#
#     exhausted in 0.0007s, recovered '"email":"admin@juice-sh.op"'
#
# Truncation to 48 bits was not the binding problem; the input's entropy was. A marker
# is short, structured and guessable by construction — it names a field and a value in
# an application's own data — so no digest of the marker ALONE can be published safely.
#
# So the label is keyed. The key is 128 random bits, one per assessment, living in the
# SecretStore like every other secret — outside SQLite, outside every report, 0600 in a
# 0700 directory. Its LOCATION is derived from the session id rather than recorded in a
# column, because the protection here is the filesystem, not the key's address: the
# store's other handles are already in plain SQLite. That also means every assessment
# has a salt home, including rows created without a `config_secret_id`, so there is no
# path that quietly falls back to an unkeyed digest.
#
# Keyed per ASSESSMENT, not globally: a label only has to be unique and stable within
# the one report that carries it, and a global key would make digests comparable across
# every client's engagement.
_MARKER_SALT_BYTES = 16
MARKER_DIGEST_CHARS = 12


def _marker_salt(session_id: str) -> bytes:
    """This assessment's HMAC key, minted on first use.

    A DAMAGED SALT IS FATAL, not "no salt yet". The first version of this caught
    `(FileNotFoundError, KeyError, ValueError)`, and `json.JSONDecodeError` is a
    `ValueError` — so a truncated or corrupt salt file, including the zero-byte one
    `private_write`'s `O_CREAT|O_TRUNC` leaves behind if a crash lands between open and
    write, read as "mint a new one". Every label already exported under the old salt is
    then unreproducible while the report still looks correct, which is this codebase's
    signature defect written fresh. Only a salt that is genuinely ABSENT may be minted.

    `O_EXCL`, so two first uses cannot mint two salts for one assessment. Not reachable
    today — `marker_digest` is called from no thread, there is no `await` between the read
    and the write so concurrent tasks on one loop cannot interleave, and the server runs a
    single worker — but a latent second label for one marker is indistinguishable from two
    declarations, which is the one thing the label exists to tell apart.
    """
    key = hashlib.sha256(f"erlik:marker-salt:{session_id}".encode()).hexdigest()[:32]
    store = SecretStore()
    path = store.path(key)
    # BOUNDED. `while True` here is a hang waiting for a future edit: broaden the `except`
    # below by one word and a salt that cannot be parsed makes the read fail, the mint lose
    # the link race against the file that is already there, and the loop spin forever inside
    # a request handler. Three attempts is more than any real contention needs, and failing
    # loudly is the correct outcome for a store that will not settle.
    for _ in range(3):
        try:
            return bytes.fromhex(json.loads(path.read_text())["marker_salt"])
        except FileNotFoundError:
            pass
        salt = secrets.token_bytes(_MARKER_SALT_BYTES)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # WRITTEN WHOLE, THEN LINKED INTO PLACE. `O_EXCL` on the destination alone would
        # have made exactly one writer win — but it leaves the file EMPTY between the open
        # and the write, and a reader in that window now hits a hard failure, because a
        # damaged salt is deliberately fatal. The two fixes together would have turned a
        # latent double-mint into a crash. `os.link` is atomic and fails if the name exists,
        # so the destination never exists in a partial state and the loser re-reads.
        # `mkstemp`, not a hand-rolled `O_EXCL` open: on a name this function invents the
        # exclusive flag cannot fire, so it was a protection-shaped line that no ablation
        # could reach. mkstemp is the standard way to say "a new private file", creates at
        # 0600, and leaves nothing for a reader to mistake for a guarantee.
        handle, name = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
        staging = pathlib.Path(name)
        try:
            with os.fdopen(handle, "wb") as stream:
                stream.write(json.dumps({"marker_salt": salt.hex()}).encode())
            try:
                os.link(staging, path)
            except FileExistsError:
                continue        # somebody else minted it first; read theirs
        finally:
            staging.unlink(missing_ok=True)
        return salt
    raise RuntimeError(f"could not read or mint the marker salt at {path.name}")


def marker_digest(session_id: str, marker: str) -> str:
    """A stable label for an operator declaration, from which it cannot be recovered.

    Stable for one marker within one assessment; different for the same marker in
    another assessment. An operator who needs to know which marker a digest names
    re-runs the check with that marker and reads the digest back — the checks already
    return it per finding, so this needs no new surface.
    """
    return hmac.new(_marker_salt(session_id), (marker or "").encode(),
                    hashlib.sha256).hexdigest()[:MARKER_DIGEST_CHARS]


_SENSITIVE = re.compile(r"authorization|cookie|password|secret|token|api.?key|session", re.I)


def _redact_header(match) -> str:
    """Replace a sensitive header's VALUE, keeping the quotes that bound it.

    Paired with the conditional group in `redact`: group 1 is the opening quote when the
    header sits inside one — a shell command — and absent when it does not.
    """
    quote = match.group(1) or ""
    return f"{quote}{match.group(2)}[REDACTED]{quote}"


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
    # A QUOTED header loses its VALUE and keeps the rest of the command — the same lesson the
    # cookie rule above already learned, applied to the header it was never applied to.
    #
    # Eating to end-of-line is right in a response capture, where a header value runs to the
    # newline. In a SHELL COMMAND it is not. Measured:
    #
    #   curl -s -i -H "Authorization: $LOW_PRIV_TOKEN" http://app.test/api/Users/1
    #
    # was stored as `curl -s -i -H "Authorization: [REDACTED]` — no closing quote, no URL.
    # E-016 asks a finding to carry "sanitized reproduction instructions", and a command that
    # does not say what it requested is not one. It also erased the PLACEHOLDER name, so a
    # reviewer could not tell which credential to supply.
    #
    # ONE PASS, with a conditional group, rather than a quoted rule followed by the
    # end-of-line one. Two rules meant the second re-matched the first's output — `[REDACTED]"
    # http://…` — and truncated it again, which is how the first attempt at this silently did
    # nothing.
    #
    # The quoted branch terminates on the SAME quote it opened with, so a value containing the
    # other quote is still redacted whole: `'Authorization: a"b"c'` loses all of `a"b"c`.
    # Anything not inside quotes still falls to the end-of-line branch, which is the shape a
    # disclosed header in a response body has — and that shape is why this rule is not
    # anchored, per the note above.
    value = re.sub(r"""(?i)(["'])?((?:authorization|authentication|proxy-authorization|"""
                   r"""x-api-key|api-key|x-auth-key|x-auth-token|x-csrf-token)\s*:[ \t]*)"""
                   r"""(?(1)(?:(?!\1)[^\r\n])+\1|[^\r\n]+)""",
                   _redact_header, value)
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
