# Security posture

erlik is an offensive security tool. It executes attacker-supplied commands
against a target, stores credentials it captures, and produces reports that can
contain live secrets. This document states what it protects, what it does not,
and what you are responsible for.

Every claim below is asserted against live code by `tests/test_security_doc.py`,
so a default that drifts fails the suite rather than quietly making this file
wrong.

## Reporting a vulnerability in erlik itself

Open a GitHub issue for anything that does not itself expose a secret. For
something sensitive, contact the maintainer directly rather than filing
publicly. There is no bug bounty.

## What erlik stores

`data/pentest.db` (SQLite, unencrypted, gitignored) holds:

| Table | Sensitive content |
|---|---|
| `steps.tool_input` | Full commands — including any credential `primitives.inject_credentials` added |
| `steps.tool_output` | Full tool output, including `Set-Cookie`, tokens, dumped rows |
| `steps.model_response` | The model's own text, which may quote a captured token |
| `session_primitives.value` | Captured credentials, stored as plain `TEXT` — **not encrypted** |
| `findings.evidence` | Proof text, which for a credential finding is the credential |
| `steps.model_response` | The model's own text, which may quote a token it just captured |
| `sessions.system_prompt` | Your mission text |

`data/reports/*.md` contains the full untruncated step log for each session.

**Treat `data/` as credential material.** It is gitignored, not protected.

## Controls that exist

| Control | Default | Where |
|---|---|---|
| Scope enforcement — refuse commands naming an unrelated public host | **on** | `orchestrator/tool_executor.py` (`_scope_enforced`, `_scope_violation`) |
| Safe mode — refuse destructive actions against an in-scope host | **on** | `orchestrator/tool_executor.py` (`_safe_mode_violation`) |
| Per-segment toolset check — every chained/piped program is checked | on | `orchestrator/tool_executor.py` (`_segment_violation`) |
| Export redaction — mask credentials leaving the system | on | `orchestrator/redaction.py` |
| Submission policy — demote informational classes in reports | on | `orchestrator/submission_policy.py`, `policy_catalog/never_submit.yaml` |
| Scope audit — flag findings naming a host outside the snapshot | on | `orchestrator/main.py` (`_scope_audit`) |
| API token on every `/api/*` request, reads included | **off** | `orchestrator/main.py` (`_api_token_guard`) |
| Refuse `/api/*` off-loopback when no token is set | on | `orchestrator/main.py` (`_api_token_guard`) |
| Skill authoring (writes files into the agent prompt) | **off** | `orchestrator/skills_authoring.py` |
| Bind address | `127.0.0.1` | `run.sh` (`ERLIK_HOST`) |

### Environment variables

| Variable | Default | Effect |
|---|---|---|
| `ERLIK_SCOPE_ENFORCE` | `1` | `0` disables scope refusal entirely |
| `ERLIK_SCOPE_EXTRA_HOSTS` | empty | Comma-separated globs added to scope; snapshotted per session |
| `ERLIK_SAFE_MODE` | `1` | `0` permits destructive commands |
| `ERLIK_API_TOKEN` | unset | When set, **every** `/api/*` request requires it, reads included. `/api/health` stays open for liveness checks |
| `ERLIK_HOST` | `127.0.0.1` | `0.0.0.0` exposes the API to the network; with no `ERLIK_API_TOKEN` set, `/api/*` then refuses every request |
| `ERLIK_ALLOW_UNAUTHENTICATED` | unset | `1` waives that refusal, for an instance behind an authenticating proxy. It does **not** waive a configured `ERLIK_API_TOKEN` |
| `ERLIK_NATIVE` | unset | When set, commands run **on the host as your user**, not in the container |
| `ERLIK_LLM_PROVIDER` | `ollama` | `openai` sends prompts to a third party (`orchestrator/llm_client.py`) |
| `ERLIK_SKILL_AUTHORING` | unset | `1` enables writing skill sheets from the dashboard. Requires `ERLIK_API_TOKEN`, loopback, and non-native mode |

## What erlik does NOT protect

- **The API is unauthenticated on loopback.** With no `ERLIK_API_TOKEN`,
  anything that can reach `127.0.0.1` can read every session, finding and
  stored credential. That is the local development and thesis workflow and it
  is deliberate.

  It no longer extends off-loopback. An unconfigured instance that looks
  network-reachable refuses `/api/*` with a 401 naming the variable that fixes
  it. Two signals decide it, because each alone has a blind spot: `ERLIK_HOST`
  (which `run.sh` sets and which several scripts under `scripts/` set to
  `0.0.0.0`) and the peer address of the request itself, since
  `uvicorn --host 0.0.0.0` typed by hand sets nothing. A forwarded header
  counts as remote on its own — behind a proxy the peer address is loopback
  and therefore no evidence at all. `ERLIK_ALLOW_UNAUTHENTICATED=1` waives it.

  Until recently there was no such fallback: an install that set nothing served
  every route to whoever could reach the port. And when a token *was* set the
  guard ran only on `POST/PUT/PATCH/DELETE`, so a deployment that configured
  one still served 52 `GET` routes — `/api/engagements`,
  `/api/v2/targets/credentials`, `/api/findings`, every report format, and
  `/api/thesis/export`, which returns nine tables. Setting a token bought
  protection against writes while every secret stayed readable. Both are
  closed.

- **Operators, and what they are not.** `ERLIK_API_TOKEN` still identifies
  nobody, but it is no longer the only identity. An operator is a named row
  with their own token (`POST /api/operators`, shown once, stored as a
  SHA-256 — these are 256-bit random secrets, not passwords, so a password
  hash buys nothing here). Their id is stamped on sessions, v2 runs and
  engagement revisions, so "who ran this test and who changed the
  authorisation record" is answerable from the data. Access can be withdrawn
  from one person without rotating anyone else's token, and the row is never
  deleted — deleting it would turn an attributable run into one that reads as
  unattributed.

  Requests that authenticate with the shared secret carry
  `opr_shared_token`, and unauthenticated loopback requests carry
  `opr_unauthenticated`. Both are real rows named for what they are, flagged
  `attributable: false`, so nothing renders them as a person.

  **Minting is privileged.** Only an `admin` operator may create, revoke or
  promote another — before that, a stolen operator token was enough to mint a
  second identity and attribute work to a name nobody recognises. `created_by`
  and `role_changed_by` record which admin did it. New operators are
  `operator` by default, and rows that existed before the role column stay
  `operator`, so an upgrade never hands out privileges nobody granted.

  `opr_shared_token` is admin, because `ERLIK_API_TOKEN` is the deployment's
  root secret and has to be able to mint the *first* admin — once one exists
  the variable can be unset and that bootstrap path closes. It does **not**
  count toward the admin quorum: the last human admin cannot demote or revoke
  themselves even while the shared secret is still set, because a guard that
  relaxed there would be weakest exactly where a deployment has locked itself
  down most. `opr_unauthenticated` is admin too, and only exists on the
  loopback path where no token is configured and nothing is enforced anyway.

  What this is **not**: there is no login, no password, no session and no
  rotation policy. A token is bearer material — whoever holds it is that
  operator, with that operator's role. Anyone holding `ERLIK_API_TOKEN` still
  has admin, which is inherent to it being the root secret; the way to close
  that is to create an admin operator and unset the variable.

  Rows written before this existed have a NULL `operator_id` and read as
  unattributed, which is the truth about them.
- **Stored credentials are not encrypted.** `session_primitives.value` is plain
  `TEXT`.
- **The scope guard is not a sandbox.** It refuses commands that *name* an
  unrelated public host. It cannot stop a tool from following a redirect, and
  it is not a network control. Put erlik on a network that cannot reach what it
  must not touch.

  Because it refuses on the *name*, three WSTG cases could not run at all:
  their probes have to name a host that is not the target — CLNT-07 sends an
  attacker `Origin:`, AUTHZ-05 offers an unregistered `redirect_uri`, INPV-19
  asks the target to fetch the cloud metadata address. In each, erlik's own
  socket goes only to the in-scope target and the host is a header or
  parameter *value*.

  A case may now declare those in `payload_hosts:`. The declaration lives in
  committed, reviewed YAML and is deliberately narrow: exact hostnames only —
  a glob is rejected by the schema — matching the declared name and names
  under it, never a sibling or a different TLD; it applies to that case alone;
  it never covers the case's own target, which is checked against the
  engagement scope exactly as before; a declared host no step actually names
  is a test failure, so unused permissions cannot accumulate; and
  **`deny_hosts` always wins**, so an operator's explicit exclusion cannot be
  reversed by a case file.

  What it does not do is prove the host is unreachable. A case author who
  wrote `curl http://declared-host/` would connect there — the same trust
  already placed in the step's command itself. Nothing in the agent lane
  changed; that lane has its own guard and its own OAST allowlist.
- **`ERLIK_NATIVE=1` removes the container boundary.** Commands run as your
  user on your machine.
- **A remote LLM provider sees your prompts.** With `ERLIK_LLM_PROVIDER=openai`,
  mission text and tool output go to a third party. `redact_secrets`
  (`orchestrator/review.py`) masks credentials on the AI-review path only — it
  has three call sites, all within `review.py`.

## Authoring skills (off by default)

`ERLIK_SKILL_AUTHORING=1` lets an operator write reference sheets from the
dashboard. Those sheets are **injected into the system prompt of an agent that
executes shell commands**, so the endpoint refuses unless all of the following
hold, and says which one failed:

1. `ERLIK_SKILL_AUTHORING=1`
2. `ERLIK_API_TOKEN` is set — stricter than the rest of the API on purpose. A
   guard that is off by default is acceptable for reads and not for a route
   that writes files into an agent's prompt.
3. The request comes from loopback, carries no `X-Forwarded-For`/`Forwarded`/
   `X-Real-IP`, and its `Host` is `127.0.0.1`/`localhost`/`[::1]` (which is
   what blocks DNS rebinding).
4. `ERLIK_NATIVE` is unset — native mode has no container boundary.

**erlik does not filter authored content, and cannot.** An exfiltration
one-liner is textually identical to a legitimate SSRF cheat sheet, because
payload text is what these files are. Instead every URL, host, IP and exec verb
is extracted and shown for you to review before saving. You are the review
step. What does bound the risk: authored files live in `data/skills_local/`,
outside every licensed corpus directory; the scope guard and per-segment tool
allowlist still apply to anything the agent then runs; and the save response
reports whether the router will actually select the sheet, so an inert file is
visible immediately rather than mistaken for a new capability.

## Running it lawfully

erlik is used for real client engagements. Two fields exist to keep that
defensible, and **neither is enforced**:

- `sessions.authorization_ref` — who authorised this test, and under what
  reference. Optional. An operator assertion in a mutable column is an audit
  trail, not audit proof, so erlik does not pretend otherwise by refusing to
  run without it. A report with no reference says
  **`AUTHORIZATION: NOT RECORDED`** in the same place a reader looks for the
  answer.
- `sessions.scope_extra` — the authorised scope, snapshotted at session
  creation so a verdict does not depend on the environment of whichever process
  serves the request later.

You are responsible for having written authorisation before you run this
against anything you do not own.

## Third-party content

Vendored corpora carry different licences, and the licence of a file is
answerable from its path. See [`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md).
HackTricks (CC BY-NC) is referenced by index only and never vendored.
