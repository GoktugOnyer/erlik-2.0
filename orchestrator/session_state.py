"""Stateful session store — the primitives captured during a run and the
handles that re-attach them to later requests.

MINIMAL STUB. The authoritative version of this module is introduced by a
sibling PR (P2-10, the attach + loop wiring). This file exists so the
extraction PR (P2-11, `orchestrator/primitive_extract.py`) is self-contained
and testable on its own: it pins down the `Primitive` dataclass and the
`SessionStore` surface that extraction produces into, nothing more. When the
sibling lands it replaces this file; the contract below is what both sides were
written against.

THE CONTRACT
------------
`Primitive` is one reusable fact lifted from a tool/HTTP response:

    kind          one of token | cookie | csrf | header | injection_point
    value         the credential / token / cookie pair / param name
    source_host   the host the response came from (scope boundary for reuse)
    name          cookie name, header name, or parameter name ("" when n/a)
    hint          how a later step reuses it (prose, for the agent)

`SessionStore` is the per-session collection, gated OFF by default — a run only
accumulates state when the `stateful_session` run-config flag is set, which is
the sibling PR's job to wire. The store itself simply refuses to hold anything
while disabled, so an unwired caller cannot leak captured credentials into a
run that did not opt in.

Nothing here parses HTTP or extracts primitives — that is
`orchestrator/primitive_extract.py`. This module only holds what extraction
produced.
"""

from __future__ import annotations

from dataclasses import dataclass

# The closed set the sibling and the extractor both agree on. A kind outside it
# is a programming error, not target data, so it is rejected loudly.
KINDS = ("token", "cookie", "csrf", "header", "injection_point")


@dataclass(frozen=True)
class Primitive:
    """One reusable fact captured from a response. Immutable: a primitive is
    evidence, and evidence is not edited after it is recorded."""

    kind: str
    value: str
    source_host: str = ""
    name: str = ""
    hint: str = ""

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(
                f"Primitive.kind {self.kind!r} is not one of {KINDS}")


class SessionStore:
    """The primitives captured during one session.

    OFF BY DEFAULT. `enabled` mirrors the `stateful_session` run-config flag.
    While disabled every `add` is a no-op and every accessor is empty, so a
    caller that forgot to gate itself cannot accumulate or replay credentials.
    """

    def __init__(self, enabled: bool = False) -> None:
        self.enabled = bool(enabled)
        self._items: list[Primitive] = []

    # -- writes -----------------------------------------------------------
    def add(self, prim: Primitive) -> bool:
        """Record one primitive. Returns True if it was new and kept.

        Exact (kind, name, value, source_host) duplicates are dropped so a
        value seen on every turn is held once.
        """
        if not self.enabled or prim is None:
            return False
        key = (prim.kind, prim.name, prim.value, prim.source_host)
        if any((p.kind, p.name, p.value, p.source_host) == key for p in self._items):
            return False
        self._items.append(prim)
        return True

    def extend(self, prims) -> int:
        """Record many; returns how many were new."""
        return sum(1 for p in (prims or []) if self.add(p))

    # -- reads ------------------------------------------------------------
    def get(self, kind: str) -> list[Primitive]:
        """Every primitive of one kind, insertion order preserved."""
        return [p for p in self._items if p.kind == kind]

    def all(self) -> list[Primitive]:
        return list(self._items)

    def auth_headers(self) -> dict[str, str]:
        """Request headers that re-authenticate a later step.

        A `header` primitive is replayed verbatim under its name; a `token`
        primitive becomes an `Authorization: Bearer` header. Newest value of a
        given header name wins.
        """
        out: dict[str, str] = {}
        for p in self._items:
            if p.kind == "header" and p.name:
                out[p.name] = p.value
            elif p.kind == "token":
                out["Authorization"] = f"Bearer {p.value}"
        return out

    def cookies(self) -> dict[str, str]:
        """{cookie-name: value} for the session cookies captured. The newest
        value of a repeated name wins (re-login rotates a session)."""
        out: dict[str, str] = {}
        for p in self.get("cookie"):
            name, _, value = p.value.partition("=")
            if name:
                out[name.strip()] = value.strip()
        return out

    def csrf_tokens(self) -> list[str]:
        """Distinct CSRF token values, newest last."""
        seen: list[str] = []
        for p in self.get("csrf"):
            if p.value not in seen:
                seen.append(p.value)
        return seen

    def redact(self, text: str) -> str:
        """Mask every stored secret value where it appears in `text`.

        Default-deny in spirit: a captured credential must not survive into an
        export or a log line just because it was echoed back. Longest values
        first so a short value that is a substring of a longer one does not
        leave the longer one half-masked.
        """
        if not text:
            return text
        secrets = sorted(
            {p.value for p in self._items if p.kind in ("token", "cookie", "csrf", "header")},
            key=len, reverse=True)
        for value in secrets:
            if value:
                text = text.replace(value, "[REDACTED]")
        return text

    def summary_facts(self) -> list[str]:
        """One human-readable line per primitive, for the agent's context."""
        lines: list[str] = []
        for p in self._items:
            disp = p.value if len(p.value) <= 48 else p.value[:45] + "…"
            where = f" from {p.source_host}" if p.source_host else ""
            label = f"{p.name}=" if p.name and not p.value.startswith(f"{p.name}=") else ""
            lines.append(f"{p.kind}: {label}{disp}{where}"
                         + (f"  ({p.hint})" if p.hint else ""))
        return lines

    def __len__(self) -> int:
        return len(self._items)
