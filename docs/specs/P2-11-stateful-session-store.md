# P2-11 — Stateful primitive store + session manager

Status: **design / roadmap**. This spec describes code that does not yet exist
(`orchestrator/session_state.py`, `orchestrator/primitive_extract.py`) and a
runconfig flag (`stateful_session`) that is not yet wired. Every claim about
those names is a proposed contract, not a statement about current `develop`.
Claims about already-shipped code (`orchestrator/primitives.py`,
`orchestrator/testcase/runner.py`, `orchestrator/http_capture.py`,
`orchestrator/engagement.py`, `orchestrator/runconfig.py`) are written to be
true against the tree this spec was committed on and carry file/line anchors.

Per CLAUDE.md #7, docs are tested. If a later change makes one of the
current-code anchors below stale, update the anchor rather than the code's
behaviour — or demote the sentence to roadmap.

## Problem

The agent lane has no memory of the primitives it has already won.

- Each turn the model re-derives auth state, CSRF tokens and injection points
  from raw tool output in its context window. When context is trimmed
  (`_trim_messages`, `orchestrator/main.py:5072`) that derivation is lost and
  the model re-discovers — or fails to re-discover — the same session cookie.
- A partial fix already ships: `orchestrator/primitives.py` extracts
  credentials from tool output (`extract_primitives`, line 39) and re-attaches
  the strongest one to a later command (`inject_credentials`, line 100), gated
  by the `primitives` runconfig flag / `ERLIK_PRIMITIVES`. It is a flat
  `list[dict]` of `{kind, value, hint, tool}`, persisted to the
  `session_primitives` table (`orchestrator/database.py:385`). It covers
  `jwt`, `bearer`, `cookie`, `token`, `basic_auth`, `csrf`
  (`_PATTERNS`, `orchestrator/primitives.py:15`).
- What `primitives.py` does **not** have, and what the deterministic lane does:
  a typed, scope-bound, chainable notion of a captured value.

### The idiom the deterministic lane already has

`orchestrator/testcase/runner.py` turns one case's output into another case's
input through a small, disciplined value-extraction-and-chaining idiom. The
new store mirrors it rather than inventing a second one:

| Concern | Deterministic lane (`runner.py`) | What the store reuses |
|---|---|---|
| Declared outputs | `RunResult.produced: dict[str,list[str]]` (line 88) | A primitive is a named, typed produced value |
| Harvest from output | `_harvest()` (line 253) — every match, deduped, capped at `MAX_PRODUCED_PER_FIELD=200` (line 218) | Same "every occurrence, deduped, bounded" rule |
| Injection gate | each harvested value dropped (never escaped) if `looks_injectable(value)` is non-empty (line 285) | Identical gate at capture time |
| Template fill | `_TEMPLATE_RX` (line 105) + `_render()` (line 108), dotted lookups | The `{{token}}`-style reuse hints |
| Same-host binding | `_resolve_url()` (line 221) — a produced `url` is absolutised and **refused if it leaves the target host/port** | The store's `scope_host` invariant |

The deterministic lane's lesson is encoded in `_resolve_url`'s docstring: a
target file is attacker-controlled, so a value harvested from it must never
retarget a later step at a third party. The agent lane needs the same rule for
a captured bearer token: it may only ever be re-attached to the host it was
harvested from.

## Contract

### `orchestrator/session_state.py` (roadmap)

Gated by a new runconfig flag `stateful_session`, **off by default**. OFF must
be an exact no-op: the agent loop builds byte-identical prompts and commands,
so none of the three frozen `TOOLSET_PRESETS` arms (CLAUDE.md, *Thesis vs
product*) is perturbed and no recorded campaign becomes incomparable. This is
the same discipline `native_argv` and `agent_auth` already document in
`orchestrator/runconfig.py:48-55`.

```python
@dataclass(frozen=True)
class Primitive:
    kind: str          # one of PRIMITIVE_KINDS
    name: str          # logical name, e.g. "session", "XSRF-TOKEN", "id"
    value: str         # the captured value (never rendered to export unmasked)
    source: str        # tool/step that produced it, e.g. "curl", "ATHN-01:login"
    scope_host: str    # bare hostname this primitive is bound to

PRIMITIVE_KINDS = ("token", "cookie", "csrf", "header", "injection_point")
```

`class SessionStore`:

| Method | Returns | Contract |
|---|---|---|
| `add(primitive)` | `None` | Reject if `looks_injectable(primitive.value)` is non-empty (reuse `orchestrator.engagement.looks_injectable`, line 55) **and** the kind is one that renders into a command. Dedupe on `(kind, name, value, scope_host)`. Bound total entries (mirror `MAX_PRODUCED_PER_FIELD`). |
| `get(kind, name=None)` | `Primitive \| None` | Newest matching primitive; `name=None` returns the newest of that kind. |
| `all(kind=None)` | `list[Primitive]` | All, or all of one kind, newest first. |
| `auth_headers()` | `dict[str,str]` | Header lines ready to attach, e.g. `{"Authorization": "Bearer …"}`, built only from `token`/`header` kinds. |
| `cookies()` | `dict[str,str]` | name→value for `cookie` kind. |
| `csrf_tokens()` | `dict[str,str]` | name→value for `csrf` kind. |
| `redact(text)` | `str` | Replace every stored `value` in `text` with a stable mask before the text reaches logs, the agent context replay, or export. |
| `summary_facts()` | `list[str]` | Short, **value-free** lines for the agent prompt, e.g. `"have session cookie for juice-sh.op (from ATHN-01)"` — kinds/names/sources only, never the secret. This mirrors how the export already reports `session_primitives` as **kinds and counts only** (`orchestrator/main.py:1934`). |

`auth_headers()`, `cookies()` and `csrf_tokens()` are the typed successors to
`primitives.best_credentials()` (`orchestrator/primitives.py:81`) and
`format_for_agent()` (line 144). `summary_facts()` is what gets injected into
context; the live values are attached by the executor (slice 11c), never shown
to the model — the same split `primitives.py` already enforces between the
reuse reminder and `inject_credentials`.

### `orchestrator/primitive_extract.py` (roadmap)

The capture sibling. It pulls `Primitive`s out of a tool result and feeds the
store. It composes two existing modules rather than re-parsing:

- **`orchestrator/http_capture.py`** for structure. `csrf`/`cookie`/`header`
  primitives come from the response's header block, read through
  `http_capture.headers()` (line 107) and `http_capture.status()` (line 41),
  never from the body. This matters: `http_capture` exists precisely because
  two lanes each grew a status parser the **target could forge from its own
  response body** (module docstring, lines 1-32). A `Set-Cookie` harvested out
  of a reflected body is a value the target chose; harvested out of the header
  block it is the server's. `body()` (line 113) is used only for
  `injection_point` reflection evidence.
- **`orchestrator/engagement.py: looks_injectable`** (line 55) as the capture
  gate, exactly as `runner._harvest` uses it (line 271). A value carrying a
  shell metacharacter from `_SHELL_META` (line 52) is **dropped, not escaped** —
  it is about to become a command argument.

`injection_point` reuses `engagement.looks_injectable` inverted in spirit: a
parameter is a candidate injection point when a probe value is **reflected**
in `http_capture.body()` and the surrounding context suggests it is
interpolated. The extractor records the parameter name and location as the
primitive `value`/`name`; it does **not** itself decide exploitability.

Extraction kinds map onto today's `primitives._PATTERNS` so nothing regresses:
`jwt`/`bearer`/`token` → `token`; `cookie` → `cookie`; `csrf` → `csrf`;
`basic_auth` → `header`. The new `injection_point` kind has no predecessor in
`primitives.py`.

## Slices being built in parallel

Four slices land independently. Each must keep OFF an exact no-op.

| Slice | Scope | Composes with |
|---|---|---|
| **11a** core + flag | `session_state.py` (`Primitive`, `SessionStore`), add `stateful_session` to `runconfig._BOOL_KEYS`, the override tuple and `_known` set in `resolve()`, and the return dict (`orchestrator/runconfig.py:33,164,178,294`). Default OFF. | nothing — pure data structure + flag |
| **11b** extraction | `primitive_extract.py`; call it after each tool result, feeding 11a's store. | 11a store; `http_capture`; `engagement.looks_injectable` |
| **11c** auto-attach | In the executor path, attach `auth_headers()`/`cookies()` to a command that has none, **host-checked**. | 11a store; supersedes `primitives.inject_credentials` (`orchestrator/main.py:5251`) under the new flag |
| **11d** login provider | A configurable login step that mints the first `token`/`cookie` primitive from credentials, built on `orchestrator/login.py` (`authenticate`, line 352; `Jar`, line 132; `login_form`, line 313; `extract_token`, line 79). | 11a store (writes the seed primitive); engagement credentials (`orchestrator/secrets.py`, encrypted at rest) |

How they compose end to end, with the flag on:

1. **11d** authenticates once (or the agent's own login does), writing a
   `token`/`cookie` `Primitive` bound to `scope_host`.
2. The agent runs a tool. **11b** extracts any new primitives from the result
   via `http_capture` + `looks_injectable` and calls `store.add(...)`.
3. On the next command, **11c** reads `store.auth_headers()`/`cookies()` and
   attaches them **only if** the command's host matches `scope_host`.
4. **11a**'s `summary_facts()` (value-free) is replayed into the agent's
   context instead of raw captures, surviving trim.

Relationship to the shipped `primitives.py`: the typed store is its successor.
During the transition the two must not double-attach — the flags are mutually
exclusive in practice (a run sets `primitives` **or** `stateful_session`), and
11c's attach refuses when a command is already authenticated, the same guard
`primitives._ALREADY_AUTHED` (`orchestrator/primitives.py:76`) applies today.
Retiring `primitives.py` is out of scope for P2-11; it stays until the typed
store has equivalent recorded behaviour.

## Scope and redaction invariants

These are not optimisations; each has a non-recoverable failure mode, so they
are stated as invariants a test must defend (CLAUDE.md #4, #5).

- **A primitive is never attached to a host it was not harvested for.** `add`
  records `scope_host` at capture time; 11c compares the command's host against
  it and refuses on mismatch. This is `inject_credentials`'s existing
  host-check (`orchestrator/primitives.py:126-134`) and `_resolve_url`'s
  same-host rule (`orchestrator/testcase/runner.py:245`) generalised to the
  typed store. The failure mode it prevents is credential exfiltration
  performed by our own tool — a captured session token sent to a third-party
  host because a URL appeared in a command.
- **Scope binding respects the engagement boundary, not just string equality.**
  `scope_host` is a bare hostname; comparison uses label-wise logic, never a
  string suffix (`engagement._is_subdomain_of`, line 77, documents why
  `notacme.com` must not match `acme.com`). A primitive harvested for an
  in-scope host is still subject to the engagement's deny rules
  (`engagement.evaluate_scope`, line 118) before any attach.
- **Redaction stays default-deny.** The export allowlist `_EXPORT_STRUCTURAL`
  (`orchestrator/main.py:8043`) masks every string column not explicitly
  declared structural (CLAUDE.md #8). The `value` field of a `Primitive` is a
  secret and must **never** be added to that allowlist. Any new column or
  export surface that carries primitive values is masked until someone declares
  it structural — and a primitive value is by definition not structural.
  `SessionStore.redact()` and the kinds-and-counts-only export
  (`orchestrator/main.py:1934`) are the two places a live value is allowed near
  output, and both remove it.
- **The model sees facts, not secrets.** `summary_facts()` is the only thing
  injected into the agent's context. A live token reaches a command through
  11c's attach, which the model never reads back verbatim.

## Testing obligations (CLAUDE.md #1,#3,#4,#5,#7)

A test asserts against the real store, never a re-implementation of it.

- Flag OFF is a byte-identical no-op: same prompt, same command, no store
  writes. (Pattern: `native_argv`'s "exact no-op" claim.)
- `add` drops an injectable value (mutation-test: feed a value containing `"`
  from `_SHELL_META`, confirm it is refused, restore).
- Cross-host attach is refused (mutation-test the host comparison).
- `redact()` removes every stored value from a sample log line, including a
  value straddling a truncation boundary — the bug `SECRET_MARGIN`
  (`orchestrator/testcase/runner.py:374`) exists to prevent.
- `summary_facts()` contains no substring of any stored `value` (guard-the-guard:
  the assertion fails if a future change starts leaking the secret into facts).
- A `cookie`/`csrf` primitive extracted from a forged status line in the
  response **body** is not captured — `http_capture` reads the header block
  only (its module docstring is the record of why).
