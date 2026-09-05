# Erlik 2.0 — working notes for Claude

## What this is

An AI pentest orchestrator: an LLM selects and chains Kali tools against a
target, with a scope guard between the model's choice and execution.

**It is becoming a commercial product.** It began as an MSc thesis artifact and
the thesis is still live, so the repository now serves two audiences at once.
That tension is real and shows up in specific places — see *Thesis vs product*
below. When the two conflict, ask rather than assume.

## Two execution lanes

| Lane | Entry | Persists to | Notes |
|---|---|---|---|
| **Agent loop** | `POST /api/sessions/{id}/start` | `sessions`, `findings`, `steps` | LLM plans, orchestrator executes. Every reported thesis result comes from here. |
| **Deterministic** | `/api/v2/*`, `orchestrator/testcase/` | `v2_runs`, `v2_findings` | YAML WSTG cases (29 in `tests_catalog/wstg/`), fixed command sequences with regex/status/llm evaluators. No thesis result uses it. |

The tool interface is a **JSON action protocol over the model's text channel** —
`TOOL_USE_SYSTEM_PROMPT` names tools in prose, the model replies with one JSON
object per turn, `render_system_prompt()` fills placeholders, and
`execute_tool()` admits or refuses. It is **not** MCP and not provider
function-calling. `mcp_servers/cve/server.py` is a real MCP server, but it wraps
NVD enrichment and nothing in `orchestrator/` imports it. METHODOLOGY §3.10
describes this accurately; earlier drafts did not.

## Layout

- `orchestrator/main.py` — ~9.4k lines, routes + agent loop + prompt constants
- `orchestrator/tool_executor.py` — admission control and dispatch
- `orchestrator/testcase/` — the deterministic lane
- `dashboard/templates/index.html` — ~7.5k lines, **single file, all JS inline, no
  build step**. Tailwind via Play CDN. Edit it directly.
- `tests/` — 51 files, 1737 passing + 31 skipped. Run with `.venv/bin/python -m pytest -q`.

## Conventions this codebase actually holds itself to

These are not style preferences; they are why several classes of bug were
caught. Follow them.

1. **The interface may not describe things that do not happen.** A label, log
   line or count that overstates what ran is treated as a defect equal to a
   crash. Most of the 2026-09-04 work was this.
2. **Declare, don't silently drop.** A capability that cannot run stays visible
   and disabled *with the reason* (see the nettacker `brute` scenario, the
   unwired recon tools, skipped WSTG cases). Hiding it is worse than showing it
   broken.
3. **Tests assert against the real thing, never a re-implementation.** A test
   that rebuilds the logic it checks reproduces the same bug and passes. This
   is why `render_system_prompt()` was extracted from the agent loop.
4. **Mutation-test every new guard.** Break the thing, confirm the test fails,
   restore. Several guards passed against the exact bug they were written for
   until this was done — including one that matched JavaScript `continue;`
   because it uppercased the whole dashboard.
5. **Guard the guards.** If a test parses a table or a code block, add one that
   fails when the parse stops matching, or the suite goes green against nothing.
6. **Verify UI changes in a browser**, not by reading. Chromium is at
   `/opt/pw-browsers/chromium`; drive it with Playwright against a local
   uvicorn. Rendering has caught wording that read fine in source.
7. **Docs are tested.** `test_security_doc.py`, `test_reproducibility_doc.py`
   and `test_recon.py` re-assert documented claims against live code. If you
   change a documented fact, expect a test to fail — that is the design.
8. **Redaction is default-deny.** `_EXPORT_STRUCTURAL` is an allowlist; every
   other string column is masked. A column added later is redacted until
   someone declares it structural. Do not invert this.

## Thesis vs product — the live tensions

- **`TOOLSET_PRESETS` (core_10 / standard_20 / full_30) are frozen** and
  `test_the_fixed_size_presets_were_not_grown` enforces it. They are the
  thesis's independent variable; growing them invalidates every recorded arm.
  For product work, add configurable toolsets *alongside* — the dashboard's
  fourth UI-only tier is the precedent. Do not edit the three arms.
- **Reproducibility docs describe a frozen past.** `docs/METHODOLOGY.md`
  reproduces the campaign-era prompt deliberately; `docs/REPRODUCIBILITY.md`
  states per-file which figures are regenerable and which are carried forward.
  Product changes may drift from these — that is fine, but say so rather than
  editing the historical record.
- **What was out of scope for a thesis is now roadmap**: OAST/interactsh,
  per-session rate limiting, PDF and HackerOne export, and WSTG breadth (29 of
  ~90+ cases). Authentication has moved: the token covers reads, an
  unconfigured instance fails closed off-loopback, and `orchestrator/operators.py`
  gives each operator their own token so sessions, v2 runs and engagement
  revisions record who did them, and only an `admin` operator may mint, revoke
  or promote. Still missing there: no login, no sessions, no rotation policy,
  and no multi-tenancy. Anyone holding `ERLIK_API_TOKEN` has admin by
  construction -- it is the bootstrap credential, and the way to close that is
  to create an admin operator and unset it.
- **Licensing matters more now.** `THIRD_PARTY_LICENSES.md` tracks vendored
  corpora — MIT and CC BY 4.0 sheets with different attribution obligations,
  plus GPL tooling in the Kali image. Shipping commercially makes these
  compliance obligations, not courtesies. Check before vendoring anything.
- **Customer data is real now.** The engagement spine (`engagements`,
  `engagement_scope`, credentials encrypted at rest via `orchestrator/secrets.py`)
  stops being lab hygiene and becomes the authorisation record for a paid test.
  Scope enforcement is the contractual boundary — treat weakening it as a
  serious change.

## Environment facts (not defects)

- **No `runs/` corpus and no populated database.** `runs/` and `data/` are
  gitignored; a clean clone has neither. This is the single cause of all **31
  skipped tests** — they are correct behaviour, not failures. It is also why
  the Wilcoxon test is carried forward and why `recompute_gt_coverage.py` and
  `recompute_all_thesis_tables.py` exit with `FileNotFoundError`.
- `scripts/recompute_statistical_tests.py --check` **does** run from a clean
  clone and reproduces the committed file byte-for-byte.
- No GPU; Docker image pulls are blocked by egress policy, so the Kali and
  Juice Shop containers cannot be brought up here.
- The session's GitHub token **cannot delete refs** (403 from GitHub, not the
  proxy — pushing commits works). Branch cleanup is a human step.

## Already fixed — do not re-report

SQLite WAL and `busy_timeout` are set in `get_db()`. Older notes in
`docs/AUDIT_AND_ROADMAP.md` may still list resolved items; section F was
corrected but others may lag.
