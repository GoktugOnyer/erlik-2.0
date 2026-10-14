"""Per-session stateful primitive store — the foundation for stateful chaining.

`orchestrator/primitives.py` already EXTRACTS reusable credentials from a single
tool's output and formats a reuse reminder. What it does not do is HOLD them: the
agent loop re-derives the set each turn from whatever text happens to be in front
of it. This module is the missing middle — a small, typed, in-memory container a
session can carry across turns, so a token captured in step 2 is still answerable
in step 9 without re-scraping the transcript.

It deliberately does nothing clever:

  - **Pure in-memory, one per session id.** No DB, no network, no file I/O. The
    engagement spine (`engagements`, `v2_runs`, `findings`) is where durable state
    lives; this is scratch state for one run and dies with it.
  - **No import from `main.py`.** The agent loop will build on this; this must not
    build on the agent loop, or the dependency that makes the loop testable in
    isolation is lost (see CLAUDE.md convention 3, and why `render_system_prompt`
    was extracted).
  - **Redaction is the store's job, not the caller's.** A store that holds secrets
    and hands them to a logger or an LLM prompt verbatim is the leak. `redact()`
    and `summary_facts()` are the safe surfaces; `auth_headers()` / `cookies()` /
    `csrf_tokens()` return the raw values because their only caller is request
    construction, never a log line.
  - **Host-scoped by default-deny.** Every read takes an optional `host`; given
    one, a primitive comes back only if it was captured from that same host. A
    cookie scoped to origin A is therefore never returned for a request aimed at
    origin B — the credential-exfiltration guard primitives.inject_credentials
    already applies, made structural in the store so a sibling cannot forget it.
    The no-host form returns the whole session and is for callers that have
    already fixed the target.

GATED OFF BY DEFAULT. Nothing here runs unless a session's run config turns on
`stateful_session` (`ERLIK_STATEFUL_SESSION`). The flag exists now so sibling PRs
can wire the store into the loop behind it; this PR ships the primitive and the
gate, not the wiring.
"""

from __future__ import annotations

from dataclasses import dataclass

# The placeholder authority. Reused rather than re-implemented so a secret masked
# by this store reads identically to one masked on the export boundary — same
# `<kind:redacted:digest>` shape, same digest — and a future change to how secrets
# are masked lands in one place. `_digest` is private, but `redaction` itself
# reaches into `primitives._PATTERNS` the same way; cross-module reuse of the
# redaction internals is the established idiom here.
from orchestrator.redaction import MIN_SECRET_LEN, _digest

# The closed vocabulary of primitive kinds. A sibling PR that wants a new kind
# adds it here deliberately; an unknown kind is a bug caught at construction
# rather than a silently-stored value nothing knows how to use.
PRIMITIVE_KINDS = frozenset({"token", "cookie", "csrf", "header", "injection_point"})

# Kinds whose VALUE is a secret and must be masked in anything a human or the LLM
# sees. `injection_point` is the exception: its value is a LOCATION (a URL, a
# parameter name) that the model needs in the clear to act on — masking it would
# throw away the only useful part.
_SECRET_KINDS = frozenset({"token", "cookie", "csrf", "header"})


def _normalize_host(value: str | None) -> str:
    """Bare, lowercased hostname from a host, authority, or URL. '' if none.

    `scope_host` and a query host may each arrive as a bare host (`t.local`), a
    host:port (`t.local:3000`), or a full URL (`http://user@t.local:3000/x`).
    Comparison is on the hostname alone — a port or scheme difference is still
    the same host, matching primitives.inject_credentials, which compares
    `host.split(":")[0]`. An IPv6 literal keeps its brackets' contents.
    """
    if not value:
        return ""
    v = value.strip()
    if "://" in v:
        v = v.split("://", 1)[1]
    v = v.split("/", 1)[0].split("?", 1)[0]
    if "@" in v:
        v = v.rsplit("@", 1)[1]
    if v.startswith("["):                      # [::1]:443 -> ::1
        v = v[1:].split("]", 1)[0]
    else:
        v = v.split(":", 1)[0]
    return v.lower()


def _in_scope(primitive: "Primitive", host: str | None) -> bool:
    """Whether `primitive` may be returned for a read scoped to `host`.

    `host is None` means the caller asked for no host filtering, so everything is
    in scope (backward compatible, and the right answer when the target host is
    already fixed by the caller). With a host given, the rule is DEFAULT-DENY: the
    primitive's scope_host must normalize to the same hostname. A primitive with
    no scope_host does NOT match a specific host — the store will not guess that
    an unscoped credential is safe to send somewhere — and a host that normalizes
    to nothing (garbage in) matches nothing, mirroring inject_credentials refusing
    when it cannot identify an explicit target.
    """
    if host is None:
        return True
    want = _normalize_host(host)
    if not want:
        return False
    return _normalize_host(primitive.scope_host) == want


@dataclass
class Primitive:
    """One reusable fact captured during a run.

    `kind`       one of PRIMITIVE_KINDS.
    `name`       the handle a later step asks for it by (a cookie name, a header
                 name, a parameter). May be None for an unnamed bearer token.
    `value`      the secret or location itself.
    `source`     where it came from (a tool name, a step id) — provenance for the
                 operator, never used for matching.
    `scope_host` the host this primitive belongs to. The store ENFORCES it: a
                 host-scoped read (`get`/`all`/`auth_headers`/`cookies`/
                 `csrf_tokens` given a `host`) returns a primitive only when its
                 scope_host is that same host, so a session cookie captured from
                 one origin is never handed to a request aimed at another — the
                 credential-exfiltration guard primitives.inject_credentials
                 already applies, made structural here. None means "no host
                 recorded", which is excluded from every host-scoped read (see
                 SessionStore).
    """

    kind: str
    name: str | None
    value: str
    source: str
    scope_host: str | None

    def __post_init__(self) -> None:
        if self.kind not in PRIMITIVE_KINDS:
            raise ValueError(
                f"unknown primitive kind {self.kind!r}; "
                f"expected one of {sorted(PRIMITIVE_KINDS)}")


class SessionStore:
    """An ordered, in-memory set of primitives for a single session.

    Insertion order is preserved and is meaningful: `get()` returns the most
    recent match, because a token captured later in a run supersedes an earlier
    one (a refreshed session, a re-login). Exact duplicates (same kind, name and
    value) are collapsed so replaying the same output twice does not inflate the
    store.
    """

    def __init__(self, session_id: str | None = None) -> None:
        self.session_id = session_id
        self._items: list[Primitive] = []

    def __len__(self) -> int:
        return len(self._items)

    # -- mutation -----------------------------------------------------------
    def add(self, primitive: Primitive) -> Primitive:
        """Store a primitive and return it. Idempotent on an exact duplicate."""
        if not isinstance(primitive, Primitive):
            raise TypeError(f"expected Primitive, got {type(primitive).__name__}")
        for existing in self._items:
            if (existing.kind == primitive.kind
                    and existing.name == primitive.name
                    and existing.value == primitive.value):
                return existing
        self._items.append(primitive)
        return primitive

    # -- retrieval ----------------------------------------------------------
    # Every read takes an optional `host`. With it, only primitives captured from
    # that host come back (default-deny; see _in_scope). The safe call for
    # building a request is the host-scoped one; the no-host form returns the
    # whole session and is for when the caller has already fixed the target.
    def get(self, kind: str, name: str | None = None,
            host: str | None = None) -> Primitive | None:
        """The most recently added primitive of `kind` (and `name`, if given).

        Scoped to `host` when one is passed, so a stale credential from another
        origin is never returned as the current one for this host.
        """
        match = [p for p in self._items
                 if p.kind == kind and (name is None or p.name == name)
                 and _in_scope(p, host)]
        return match[-1] if match else None

    def all(self, kind: str | None = None,
            host: str | None = None) -> list[Primitive]:
        """Every stored primitive, in insertion order, optionally filtered by
        `kind` and/or `host`."""
        return [p for p in self._items
                if (kind is None or p.kind == kind) and _in_scope(p, host)]

    # -- request-side views (RAW values; callers build real requests) -------
    def auth_headers(self, host: str | None = None) -> dict[str, str]:
        """HTTP headers to send on an authenticated request.

        Explicit `header` primitives win, since the agent named them on purpose.
        A `token` primitive becomes `Authorization: Bearer <value>` only if no
        explicit Authorization header is already present — a header the model set
        deliberately must never be silently overwritten by a scraped token.

        Pass `host` to get only credentials captured from that host; this is the
        safe form when building a request, as a token scoped to another origin is
        then excluded rather than attached.
        """
        headers: dict[str, str] = {}
        for p in self.all("header", host=host):
            if p.name and p.value:
                headers[p.name] = p.value
        token = self.get("token", host=host)
        if token and token.value and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {token.value}"
        return headers

    def cookies(self, host: str | None = None) -> dict[str, str]:
        """Captured cookies as {name: value}, newest value per name; scoped to
        `host` when one is given."""
        out: dict[str, str] = {}
        for p in self.all("cookie", host=host):
            if p.name and p.value:
                out[p.name] = p.value
        return out

    def csrf_tokens(self, host: str | None = None) -> dict[str, str]:
        """Captured CSRF tokens as {name: value}, newest value per name; scoped
        to `host` when one is given."""
        out: dict[str, str] = {}
        for p in self.all("csrf", host=host):
            if p.name and p.value:
                out[p.name] = p.value
        return out

    # -- safe surfaces (for logs and LLM context) ---------------------------
    def redact(self, text: str | None) -> str | None:
        """Mask every stored SECRET value found in `text`. None-preserving.

        The store knows its own secrets exactly, so it masks by value rather than
        by pattern: anything it is holding that appears in the text is replaced,
        whether or not a generic extractor would have recognised it. Longest
        values first, so a secret that contains a shorter one is masked whole
        instead of being split around the inner match. `injection_point` values
        are locations, not secrets, and are left untouched.
        """
        if not text:
            return text
        out = text
        secrets = sorted(
            ((p.kind, p.value) for p in self._items
             if p.kind in _SECRET_KINDS and p.value and len(p.value) >= MIN_SECRET_LEN),
            key=lambda kv: len(kv[1]), reverse=True)
        for kind, value in secrets:
            out = out.replace(value, f"<{kind}:redacted:{_digest(value)}>")
        return out

    def summary_facts(self, host: str | None = None) -> list[str]:
        """Short "you now hold <kind> <name>" lines, secret values masked.

        This is what the loop will fold into the model's context: a standing
        reminder of what the session is carrying, with no secret in the clear. A
        secret kind shows its masked value; `injection_point` shows its location,
        which is the whole point of surfacing it.

        Pass `host` to list only what is in scope for that host, so a per-host
        reminder does not advertise a credential that would never be sent there.
        """
        facts: list[str] = []
        for p in self.all(host=host):
            label = p.name if p.name else "(unnamed)"
            article = "an" if p.kind[:1].lower() in "aeiou" else "a"
            if p.kind in _SECRET_KINDS:
                shown = self.redact(p.value) or ""
                facts.append(f"you now hold {article} {p.kind} {label} ({shown})")
            else:
                where = f" at {p.value}" if p.value else ""
                facts.append(f"you now hold {article} {p.kind} {label}{where}")
        return facts
