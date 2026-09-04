# Erlik 2.0 — Pentest Tool Audit & Improvement Roadmap

*Synthesis of a four-pass code audit — offensive coverage & correctness, engineering/scale/tool-security,
reporting/methodology, and knowledge/continuous-improvement — grounded in the real codebase.*

---

## 1. Executive summary

Erlik 2.0 is a strong **research scaffold** for autonomous web pentesting: a FastAPI orchestrator with two
execution paths (a disciplined deterministic WSTG engine and an LLM agent loop), a real benchmark harness,
and a recently broadened feature set (CVE enrichment, structured `pentest-report.json` + severity
calibration, a skills knowledge corpus, an OWASP Nettacker deterministic pre-scan, a CVE MCP server, a
benchmark SDK, and per-session run-config presets with a GUI).

To cross from *capable research instrument* to *credible pentest tool*, the priorities, in order:

1. **Be safe to deploy and to point at a real target.** The API has **no auth and binds `0.0.0.0`**, scope
   is advisory, commands run through a shell, there's no throttling, and the dashboard has a **stored-XSS** path.
2. **Make findings trustworthy.** Findings are *labeled*, never *re-verified*; false positives can ship.
3. **Make the metrics sound.** The benchmark scoring is a fuzzy point system with mutually inconsistent
   precision/recall — research baselines are currently unsound.
4. **Deepen exploitation** — no stateful chaining or generic auth/session handling.
5. **Broaden coverage** — whole vuln classes are untooled; WSTG coverage is ~10%.
6. **Productize & learn** — single-target/single-run, no real deliverables (HTML/PDF/SARIF), and no
   automated learn-from-your-own-runs loop.

> **One bright spot:** outbound secret handling (OPENAI/NVD keys) is clean — only in request headers, never
> logged, returned, or stored. Keep it that way.

---

## 2. What's already strong (keep / build on)

- **Deterministic WSTG engine** (`orchestrator/testcase/`): scope-checked execution, `when`-conditioned steps,
  regex + LLM-judge evaluators, `chain_to` linking. High quality — just small (9 cases).
- **Dual path**: deterministic probes *plus* an LLM agent with phase-coverage enforcement, min-turns,
  stagnation auto-stop, dedup/failed-command suppression.
- **Robust agent-loop guarding**: LLM calls wrapped in `wait_for(300s)`, malformed JSON never crashes,
  tool failures never raise, every exit path sets a terminal status, fatal-LLM-error sweep abort.
- **Recent additions** (this work): NVD CVE enrichment, structured report + calibration + `report.json`,
  skills RAG (also a Claude Code plugin + model-agnostic CLI), Nettacker deterministic pre-scan, CVE MCP
  server, benchmark SDK, per-session run-config + presets + dashboard.
- **Evaluation harness** (cold/warm/chain, overnight matrix) — genuine research discipline.

---

## 3. Gap analysis (by dimension)

### A. Tool security & safety — **CRITICAL / do first**
- **No authentication, bound to `0.0.0.0:8002`** (`main.py:44` FastAPI has no `dependencies`; `run.sh:15`
  binds all interfaces, with `--reload`). All ~35 endpoints — including `POST /api/sessions` + `/start` and
  `POST /api/benchmarks/run` — are reachable unauthenticated. Anyone who can route to the host gets a
  weaponized attack launcher.
- **Stored XSS in the dashboard**: `marked.parse()` with no DOMPurify, and LLM/target-controlled fields
  (`vuln_type`, `url`, `target_url`, report markdown) interpolated into `innerHTML`
  (`index.html:1668, 2135, 3510`). A malicious target → content recorded as a finding → opening the dashboard
  runs attacker JS against an origin with full unauthenticated API control.
- **Command execution via `docker exec ... bash -c <llm_string>`** (`tool_executor.py:355`). Guard is a thin
  9-regex denylist (`BLOCKED_PATTERNS`) + first-token allowlist — trivially bypassable (pipes/`;`/`$()`).
  With `ERLIK_NATIVE=1` this is **arbitrary host RCE** driven by LLM output.
- **Scope is advisory only in the live loop**: `scope_mode` is interpolated into the prompt and stored, never
  enforced. The real allowlist gate (`testcase/scope.py: check_command/check_url`) is wired **only** into the
  WSTG runner, **not** `execute_tool`. The agent can hit any host.
- **No throttling / rate-limiting** anywhere — noisy and unsafe against production-like targets.

### B. Correctness & trust of findings
- The **"4-check false-positive filter"** is anti-hallucination *string matching* against the transcript.
- Independent verification (`_verify_findings_from_logs`) is **label-only and post-hoc**: re-greps stored
  output, tags `verified/likely/unverified/suspicious`, but **never re-runs a PoC and never drops a finding**.
- **Evidence is lossy** (6 KB exec cap → ~2–4 KB DB truncation).

### C. Evaluation integrity (research-critical)
- Benchmark scoring (`_match_finding_to_ground_truth_scored`, `main.py:5585+`) is a **fuzzy point system, not
  a sound confusion matrix**: precision and recall use **mismatched numerators** (matched findings vs distinct
  GT rows); one finding can satisfy many GTs (recall inflation); weak findings clear the TP threshold on type
  alone via two unconditional `+0.5` credits; `severity_score` sums over TP **and** FP (gameable);
  `owasp_category` is stored but never matched. Ground truth is hardcoded and seeded by row-count only.

### D. Exploitation depth
- **No stateful exploit chaining.** "Chaining" = regex-derived *text hints*; nothing carries a captured
  token/cookie/injection point forward programmatically.
- **Auth is Juice-Shop-hardcoded** (`scripts/login-helper.sh`) and **session context isn't auto-propagated** —
  every `execute_tool` is stateless; re-attaching creds depends on LLM discipline. No CSRF/OAuth/SAML/SSO.

### E. Coverage
- **Whole classes untooled**: GraphQL/API, SSRF (no OAST/collaborator), deserialization/SSTI/XXE (labels
  only), cloud/container, non-HTTP network services, AD/Kerberos, mobile.
- **WSTG deterministic coverage** — 29 cases are committed under `tests_catalog/wstg/`,
  not the 9 this line reported. Coverage of the full WSTG corpus is still partial and
  whole categories remain absent, so the gap is real; the number was not.

### F. Reporting & deliverables — DONE, this section was stale

Every gap listed here has since been closed. Recorded rather than deleted so the
roadmap does not silently drop work that was actually delivered:

- **HTML and SARIF ship**: `GET /api/sessions/{id}/report.html` and
  `report.sarif` (`orchestrator/main.py`). PDF is still absent, deliberately —
  the HTML deliverable prints.
- **Tracker export ships**: `report.defectdojo.json` and `report.jira.csv`.
  HackerOne is still absent.
- **Findings lifecycle is no longer fire-and-forget**: `POST
  /api/findings/{id}/triage` backs an accept / reject / override workflow that
  the dashboard renders, dimming triaged-out findings and filtering on
  `triage_status`.

Remaining in this area: no PDF, no HackerOne export.

### G. Engineering, scale & reliability
- **SQLite has no WAL and no `busy_timeout`** (`database.py`) — single-writer + 0 ms timeout → concurrent
  per-step `INSERT...commit` raises `database is locked` immediately. **#1 failure under parallel sessions.**
- **Process-global state** (`running_tasks`, WS `manager.active`, benchmark abort flag, in-proc NVD cache) →
  not horizontally scalable; a second worker can't see another's tasks.
- **No global concurrency cap**; untracked `create_task` (`_run_benchmark_sequence`) swallows exceptions;
  dead WebSockets aren't pruned on send failure.
- **In-loop DB writes lack try/finally**; `_finish_session`'s own write can raise inside an `except` arm and
  leave a session stuck `running`.
- **LLM retry ignores 5xx** (`llm_client.py` catches only Timeout/ConnectError) — a transient 5xx fails the session.
- **Migrations not versioned** (bare `try/except: pass` swallows real failures); `PRAGMA foreign_keys` never
  enabled; `requirements.txt` loosely pinned; ~30 `ERLIK_*` env vars (config sprawl, partly tamed by run-config).

### H. Continuous improvement
- **No automated learn-from-your-own-runs loop.** Warm/chain memory (`recon_context`) is
  **per-session-lineage, not per-target/global**, and operator-initiated. Fine-tuning is a **manual offline**
  pipeline not wired into the tool. Playbooks are hand-authored Python constants with **no write-back** from
  successful exploits.

---

## 4. Prioritized roadmap

Effort: **S** ≈ hours, **M** ≈ a day or two, **L** ≈ multi-day. All items can ship behind the existing
run-config/flag pattern (off by default), preserving research baselines.

### P0 — Security, safety & trust (required before any non-lab use)
1. **Authenticate the API + bind `127.0.0.1` by default** *(S–M)* — FastAPI bearer/API-key dependency on all
   mutating routes; `run.sh` → `--host 127.0.0.1`, drop `--reload`. *(main.py:44, run.sh:15)*
2. **Enforce scope in `execute_tool`** *(M)* — derive a `Scope` from the session target and call
   `testcase/scope.py:check_command` before every live tool run; refuse out-of-scope hosts. *Highest-value safety fix.*
3. **Sanitize dashboard output** *(S)* — DOMPurify on `marked.parse` output; `textContent` for
   `vuln_type`/`url`/`target_url`. *(index.html:1668, 2135, 3510)*
4. **Harden command execution** *(M–L)* — prefer per-tool argv construction over `bash -c` of an LLM string;
   gate/disable `ERLIK_NATIVE`; keep the denylist only as defense-in-depth. *(tool_executor.py:84-94, 352-355)*
5. **Verify findings, don't just label** *(M)* — record-time evidence-grep gate + automatic PoC re-run for
   high/critical findings before marking `verified`; drop/downgrade unconfirmed instead of shipping `suspicious`.
6. **Per-session throttling / rate-limit** *(S–M)* — configurable RPS/delay surfaced in run-config.

### P1 — Reliability, scale & evaluation integrity
7. **SQLite WAL + busy_timeout** *(S)* — `PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;` per connection
   (or a managed pool). Removes the dominant parallel-session failure. *(database.py)*
8. **DB-write hygiene** *(M)* — wrap hot-loop `get_db()` in try/finally; guard `_finish_session`'s write so
   finalization can't leave a session stuck `running`; retry transient 5xx in `llm_client`.
9. **Rebuild benchmark scoring as a sound confusion matrix** *(M)* — one GT matched once; consistent P/R
   numerators; remove the unconditional `+0.5` credits and the multi-GT inflation; exclude FPs from
   `severity_score`. *Restores research validity.*
10. **Concurrency hygiene** *(M)* — global agent-loop/subprocess semaphore; track all `create_task`s with
    `add_done_callback`; prune dead WebSockets on send failure.

### P2 — Exploitation depth & coverage
11. **Stateful primitive store + generic session manager** *(L)* — extract tokens/cookies/CSRF and injection
    points into a per-session store and auto-attach auth to subsequent tool calls; replace the Juice-Shop login
    hardcode with a configurable login provider. Enables real multi-stage chains.
12. **Fill the biggest blind spots** *(M each)* — OAST/collaborator (interactsh) for blind SSRF/RCE/XXE; a
    GraphQL tool; an SSTI/deserialization tool.
13. **Expand the WSTG catalog** *(M, incremental)* — grow from 9 toward broad coverage (optionally auto-draft
    cases from the skills corpus, human-reviewed).

### P3 — Productization & learning
14. **Engagement model** *(L)* — saved targets/profiles, multi-target campaigns, a rules-of-engagement object
    (scope + throttle + allowed classes), and retest/drift (surface Nettacker's drift detection).
15. **Real reporting & integrations** *(M–L)* — render HTML/PDF/SARIF from the `report.json` source-of-truth;
    DefectDojo/Jira/HackerOne export (Nettacker already emits SARIF/DefectDojo shapes to reuse).
16. **Findings triage workflow** *(M)* — accept/reject/verify/severity-override in the dashboard, persisted and
    reflected in the report.
17. **Per-target knowledge store + closed learning loop** *(L)* — durable memory keyed by target that
    auto-seeds warm-start; turn **verified** exploits into human-approved candidate playbooks/skills; optionally
    a scheduled extract→assemble→fine-tune→redeploy trigger.

---

## 5. The 6 things I'd do first

1. **API auth + bind 127.0.0.1** (P0-1) — the tool is currently an open attack launcher.
2. **Enforce scope in the live tool path** (P0-2) — turn `scope_mode` into a real boundary.
3. **Dashboard XSS sanitization** (P0-3) — a malicious target can pwn the operator.
4. **SQLite WAL + busy_timeout** (P1-7) — the cheapest fix for the biggest reliability failure.
5. **PoC re-run verification for high/critical findings** (P0-5) — stop shipping unverified findings.
6. **Rebuild benchmark scoring** (P1-9) — the current metrics aren't internally consistent.

Items 1, 3, 4 are each ~hours; they remove the most acute risks for very little effort.

---

## 6. North star

A **safe-by-default, evidence-grounded, self-improving autonomous pentester**: authenticated and scoped by
construction, throttled, every finding backed by a re-runnable PoC, capable of real multi-stage exploitation
with maintained auth, producing client-ready deliverables, measured by sound metrics, and getting better —
per target and globally — from its own *verified* successes.
