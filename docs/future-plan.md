# Erlik: future development plan

Planning date: 2026-09-10. Status: proposal for future implementation.

This plan builds on the integration roadmap and the latest working-tree review.
It does not claim that the proposed capabilities are already implemented or
authorize a scan, external deployment, recurring automation, or merge.

> **Corrections folded in, 2026-09-10 (later the same day).** Section 2's baseline
> was measured before that day's work landed, and four of its figures are stale.
> Every correction below names the evidence that establishes it, so a reader can
> check rather than trust. Stale planning facts misallocate effort, and §2 is what
> R0 is scoped from — so the corrections are marked in place rather than quietly
> applied. Sections 11 and 3 also gained clauses that the day's two worst defects
> showed were missing.

## 1. Product direction

Develop Erlik into a dependable, evidence-driven assistant for authorized web and
API penetration tests. An operator should be able to supply a scope, identities,
and application context, see which surfaces were actually tested, reproduce a
finding, and retest its remediation without reconstructing the engagement.

Prioritize improvements in this order:

1. Correct execution, cancellation, authentication, and evidence handling.
2. Authenticated endpoint and operation coverage.
3. Authorization and business-workflow verification.
4. Reproduction, remediation, and change-aware retesting.
5. Bounded AI investigation that measurably adds useful coverage.
6. Additional source/dependency integrations and, later, team deployment.

More alerts, more tools, and more model calls are not success metrics by
themselves. The product should explain what it tested, what it could not test,
and why each finding deserves its confidence level.

## 2. Starting point and known limits

The current tree contains ZAP, Schemathesis, Katana, Interactsh, and DefectDojo
integration code; an isolated proxy-backed execution path; named identities;
structured inventory and evidence; dashboard controls; and local test fixtures.
Endpoint handoff and the catalogue SSRF callback hook now exist. The existing
project also has Nettacker, a technique library, NVD enrichment, target memory,
verification helpers, and a WSTG catalogue. Extend these before creating parallel
implementations of the same features.

The September 10 review observed:

- ~~161 network-free tests passed.~~ **2128 passed, 35 skipped** (the skips are
  Docker- and live-service-gated). Measured on the merged tree.
- The selected acceptance run had 22 passes and one benchmark failure; this
  count includes two network-free checks in the lifecycle file.
- Three temporary focused checks reproduced callback cancellation leakage,
  callback loss after authentication resume, and catalogue writes outside a
  cleanup wrapper. **Still open; see E-001 to E-003 for current status.**
- ~~The benchmark recovered its expected findings but rejected evidence because it
  required every attached artifact, including empty stderr, to be nonempty.~~
  **Closed, in two parts.** `c761b76` stopped `record()` attaching a zero-byte
  stderr to each finding — it was doing so to 22 of them. `e78c257` then found
  that the fix had overshot the clause and that a second clause had never been
  met at all; see E-004.
- ~~14 WSTG catalogue files.~~ **32 catalogue files, 32 cases, 12 of them runnable
  in the assessment lane.** The twenty that are not runnable are not a defect but
  they are untested coverage, and the lane says so per case. Two of the twelve —
  `WSTG-CONF-06` and `WSTG-INPV-07` — carry mutating steps that E-003 now refuses.
- CI runs `pytest tests/ -q`, i.e. every acceptance file, with the Docker and
  live-service suites gated by environment variables — so "CI does not yet run all
  new acceptance files" is **stale**. It has a different and live defect instead:
  see E-005.
- Documentation and the saved benchmark report lag behind the implementation.
  Milestone commits and human review are still outstanding.

### Established the same day, and folded into §11

Two defects found by running the whole lane against the lab
([measurements/2026-09-10-full-lane.md](measurements/2026-09-10-full-lane.md),
fixed in `1046d0a`). Both are closed. They are recorded here because **neither
would have been caught by the metrics in §11 as originally written**, and that is
the lasting lesson rather than the bugs themselves.

- **The lane performed an unauthorized state change.** It set the lab target's
  admin password to `md5("")` while the run declared `state_changing: false`,
  through three separate paths — the crawler seeding itself with a URL synthesised
  from a GET form, per-URL cases fetching that URL, and one step that appended
  guessed parameter names instead of the one it was given, submitting the form
  blank. Every one of those requests was **in scope**. Scope integrity as defined
  in §11 measures request destinations and would have passed.
- **A case that received zero bytes reported `completed`.** 156 of 208 probes in
  the hardened arm of a differential got empty responses — a single-use CSRF token
  baked into the discovered URL had gone stale — and the stage reported no
  findings. "Attempted" was true and meaningless. Known-operation coverage as
  defined in §11 would have counted those as attempted.

### Also closed the same day

- **Findings now carry the bytes they rest on** (`8321ff0`, `aea0898`, `cce6bf6`,
  `6c9b0d9`). This closes E-004's second acceptance clause and a substantial part
  of E-016 — see both entries.
- Error-based SQL injection re-measured against 71 real error bodies and 121
  benign pages (`d2734bb`,
  [measurements/2026-09-09-sql-error-signatures.md](measurements/2026-09-09-sql-error-signatures.md)).
- Blind SQL injection, boolean-differential and time-based (`679becd`,
  [measurements/2026-09-09-blind-injection.md](measurements/2026-09-09-blind-injection.md)).

These are the baseline facts for planning, not a production-readiness claim.
Actual-service fixtures exist for Interactsh and DefectDojo; a release needs a
fresh recorded run against the final code and pinned images. Internet callback
reachability and client-specific authentication still require operator setup.

## 3. Release sequence and effort assumptions

Estimates are preliminary engineering effort, not delivery commitments. They
assume an engineer familiar with the code, occasional frontend help, access to
local Docker, and a separate security reviewer. Review queues, client onboarding,
and infrastructure lead time are additional. Re-estimate after the first gate.

| Release | Outcome | Indicative effort | Dependency / exit gate |
|---|---|---:|---|
| R0 — reliable integration baseline | Close confirmed defects, complete CI and evidence validation | 5–10 engineer-days | All known regressions pass; final local acceptance recorded; **identity isolation demonstrated (moved from R1, see below)** |
| R1 — usable authenticated assessments | Operation inventory, identity matrix, guided configuration, reusable browser journeys | 15–25 days | R0; coverage demonstrated |
| R2 — deeper verification | Role/tenant authorization, selected API workflows, bounded business-logic tests | 20–35 days | R1; positive and negative controls pass |
| R3 — retest and remediation | Evidence bundles, assessment diffs, targeted retests, reliable export UX | 10–20 days | R1 + verified findings from R2 |
| R4 — measured AI follow-up | Shared execution policy, structured hypotheses, bounded investigation, held-out evaluation | 15–25 days | R0–R3 data contracts and evaluation gates |
| R5 — optional expansion | Source/image inputs, additional integrations, team requirements discovery | 10–20 days per selected integration; team platform estimated separately | Demonstrated operator demand and stable core |

R3 reporting work can overlap R2 once the finding/evidence contract is stable.
Do not start every release simultaneously. Maintain at most one execution-boundary
change and one independent product workstream in progress.

> **Identity isolation moves from R1's exit gate to R0's.** A differential run on
> 2026-09-10 reported nine findings at a vulnerable security level and one at a
> hardened one, and the result was not usable: the two arms shared **one of eight**
> `(url, parameter)` pairs, because the hardened target baked a single-use token
> into the URL its forms were discovered from. The arms were not the same surface,
> and the hardened one never reached the injection points at all. Nothing measured
> after an identity boundary means much until that boundary is demonstrably one
> variable — so it gates R0, not R1. R1 keeps the coverage half of its gate.

## 4. R0: finish the current implementation

| ID | Work | Acceptance criterion | Primary code area | Status |
|---|---|---|---|---|
| E-001 | Make collector ownership exception-safe | Cancellation and timeout at every awaited startup/probe boundary close all owned jobs; evidence remains available | `integrations/service.py`, `interactsh.py`, `runtime.py` | **CLOSED** `7723090` + `a1f8c37`. Two leaks first: the `asyncio.TimeoutError` branch did not close, and `CancelledError` is a `BaseException` so `except Exception` never saw it. Then an adversarial pass found the first fix had closed only HALF the clause and introduced a third defect — `close()` releases but never ingests, so a callback that had already arrived was lost, and a failing `close()` replaced the exception it was cleaning up after, swallowing a cancellation entirely |
| E-002 | Restore callback capability after credential replacement | A paused run resumes pending SSRF checks with fresh correlation IDs; previously issued probes are not silently replayed; interrupted collection remains explicitly incomplete | `service.py`, `interactsh.py` | **CLOSED** `639c32e`. The pause erased its own resume marker: the sweep persisted `partial` over the `needs_auth` the stage had just been given, and `run()` only selects `queued`/`needs_auth`. Note the status column was too generous — `issued_payloads` is in-memory and does NOT survive a resume; what prevents reuse is that payloads are minted per client start |
| E-003 | Separate catalogue detection from workflow mutations | V1 catalogue follow-up refuses all mutation steps, or an explicit per-case fixture/cleanup wrapper handles them; no leftover probe artifact in the lab | `deterministic.py`, catalogue runner | **CLOSED** `7f45f06`, taking the plan's first branch: refuse. The gate deferred to the egress policy, which says yes once `state_changing` is selected — measured, `PUT /erlik_put_test.txt` ran. Cost: `WSTG-INPV-07` loses ALL detection (every step is POST) until E-012 builds the wrapper |
| E-004 | Correct evidence completeness validation | Every referenced artifact exists and passes its digest check; each finding has substantive supporting evidence; empty diagnostic files are valid attachments | benchmark, evidence persistence | **CLOSED** `e78c257`, after being marked closed too early. The digest was write-only state — nothing recomputed it, and the benchmark read `size` from the database row, comparing it against itself. An empty diagnostic FILE was also dropped rather than retained. Benchmark now passes against the stricter validator: 17/17 substantive, 80/80 intact |
| E-005 | Expand CI and produce release evidence | Unit and local Docker jobs cover lifecycle, inventory, benchmark and parser tests; dedicated actual-service jobs run on release or manual dispatch with explicit opt-in variables | `.github/workflows/tests.yml` | **CLOSED** `eedb7e3`. The collection defect was the smaller half: CI had also never executed a single one of the 35 Docker-gated tests, so the lane's whole execution boundary was covered only on a developer's machine. Now three jobs — unit on 3.10/3.12/3.14, `-m docker` off-push, actual-services behind a repository variable — plus `ci_assert_suite_ran.py`, because a run where everything skipped is green and worthless. **Still unpushed:** the credential lacks GitHub's `workflow` scope |
| E-006 | Package and document the integration release | Separate reviewable milestone commits, current setup instructions, initial-import/reconcile examples, pinned build manifest, no unrelated operator files included | docs, Git review series | **CLOSED**. Manifest in `eedb7e3`; docs and packaging here. The setup instructions were verified by following them from a fresh clone rather than by reading them, which is how two of my own figures turned out wrong — see below |

Run collector fault-injection tests, real scanner cancellation, actual process
crash recovery, mid-stage credential expiry, redirects, external schema references,
cross-identity isolation, selected mutations, and repeated exports. A passing
mock service test does not substitute for actual pinned-service acceptance.

Add two fault-injection cases the 2026-09-10 run argues for, because both produced
a confident wrong answer rather than a failure: **a target whose state changes
during a run that declared it would not**, and **a probe that receives an empty
response**. Both are now detected, and a regression in either is silent.

Keep R0 focused: avoid adding a sixth scanner while these behaviors are unresolved.

## 5. R1: authenticated coverage and operator experience

### E-007: make the endpoint inventory an operation inventory

Store origin, path template, HTTP method, parameter location/name, content type,
schema operation ID, identity context, discovery source, and whether a request was
actually attempted. Keep concrete URLs as observations beneath the operation.
Preserve raw evidence when normalizing query order, fragments, or path parameters.

Distinguish discovered, inferred from JavaScript/schema, attempted, verified, and
blocked operations. Avoid turning an inferred URL into a claim of tested coverage.
Do not merge different methods, tenant contexts, or authorization identities.

Record **how** an operation was synthesised, not only that it was. A URL built from
a GET form is an action rather than a page, and requesting it performs that form's
action — which is how the 2026-09-10 state change happened. An operation inventory
that cannot express "this URL submits a form" will reproduce it.

Acceptance: overlapping Katana/ZAP/schema discoveries resolve to one operation
where appropriate, while GET/POST and reader/admin evidence remain separate.
The dashboard shows the reason for every untested known operation. A
form-synthesised operation is distinguishable from a crawled one.

### E-008: identity and authorization matrix

Add roles, tenant labels, object ownership, authentication-check status, and
expected permissions to the existing named identities. Start with anonymous,
two ordinary users in different tenants, and one privileged lab identity.
Operators declare which objects each identity may access.

Acceptance: the same operation can be tested under multiple identities without
credential leakage; expected access and unexpected access are distinguishable.
An expired identity pauses only work that depends on it, with a clear retry plan.
**Two identities testing the same operation must produce the same operation set** —
a differential whose arms discovered different URLs is not a differential, and a
run that proves this by comparing arm surfaces is the demonstration R0 needs.

### E-009: reusable browser journeys

Extend the existing Playwright helper into named journeys: login, navigate to a
feature, select a fixture object, and capture network traffic plus trace evidence.
Prefer accessible labels/test IDs, bounded waits, and explicit assertions to
fragile recorded coordinates. Continue operator-assisted MFA first.

Treat clicks that submit forms or change application state as selected workflow
actions. Popup, redirect, download, navigation, and subresource requests must share
the same policy. Do not silently enable WebSocket scanning while HTTP-only
enforcement is the implemented boundary.

Acceptance: a fixed SPA journey reaches an authenticated route reliably across
repeated runs; an out-of-scope redirect receives no unauthorized target request;
session expiry produces a recoverable state instead of a false clean result.

### E-010: guided assessment setup

Replace most raw JSON entry with forms for scope, identities, schemas, callback
services, and per-stage policy. Preserve an advanced JSON view. Show the effective
configuration before launch, including active stages, selected mutations, budgets,
excluded paths, and which credentials each stage will use.

Provide passive discovery, API assessment, authenticated application assessment,
and remediation retest templates. Templates fill configuration; they do not expand
authorization. Add an explicit preview of work to be resumed after an interruption.

The preview should state what the run **will not** do, not only what it will. The
budget arithmetic is the case in point: at the default `max_urls` with every
runnable case selected, the 2026-09-10 run tested one or two parameters per case
out of eight and lost six of nine findings. It said so twelve times, in per-case
observations nobody reads before launch.

Acceptance: an operator can configure the authenticated lab without editing JSON;
the UI and API reject the same invalid settings and produce equivalent saved runs;
the preview shows per-case target budgets before the run starts.

## 6. R2: improve the quality and depth of testing

### E-011: authorization verification — highest-value new capability

Expand the existing IDOR check into object-level and function-level authorization
tests using the identity matrix. Begin with read-only requests and operator-supplied
objects. Compare ownership assertions and sensitive response markers, not merely
HTTP 200, response length, or a changed numeric ID.

Acceptance: recover seeded cross-user, cross-tenant, and privileged-function access
violations; reject public content, generic error pages, and expected shared access
as negative controls. Store both baseline and violating request/response evidence.
Map coverage to relevant WSTG and API Security categories; the OWASP API Security
project supplies the reference taxonomy. [OWASP API Security](https://github.com/OWASP/API-Security)

### E-012: API workflow and schema improvements

Validate and bundle schema references before scanning. Support schema version
diffs, operation exclusions, required fixture data, cleanup receipts, and GraphQL
query-operation inventory. Missing or incompatible schemas should not disappear
into a generic scanner failure.

For selected workflows, model setup → operation sequence → assertions → cleanup.
Persist which mutations actually ran. Reserve cleanup time separately; if the
orchestrator dies, preserve cleanup obligations for operator review rather than
automatically repeating state changes after restart.

Acceptance: a seeded failure reproduces with the same schema digest and seed;
unselected mutations never execute; cleanup success/failure is independently
reported. Schema contract failures remain observations unless security impact is
demonstrated.

### E-013: business-logic and concurrency testing

Extend the existing race-condition case with application-specific invariants:
single-use tokens, duplicate submissions, workflow ordering, and ownership transfer.
Use disposable lab objects and bounded concurrency; retain pre/post state and
cleanup evidence. No generic destructive checkout or real-payment automation.

Acceptance: detect one seeded invariant violation and reject a correctly enforced
control under the same bounded schedule. Confidence records timing variability
and does not infer impact from response counts alone.

### E-014: browser-backed confirmation

Add evidence-based confirmation recipes for existing XSS, CORS, cookie/session,
and authorization observations. For CORS, demonstrate that a browser in the
declared origin context can read the relevant protected response. For client-side
issues, preserve a trace and a narrowly defined assertion.

Do not impose a universal three-replay rule: use repeatability appropriate to the
check, and avoid repeating mutations without an explicit fixture lifecycle.
Scanner and model agreement alone never upgrades confidence to confirmed.

Acceptance: known false-positive fixtures stay unconfirmed; confirmed findings
include the exact assertion, identity, relevant response, and reproduction inputs.

### E-015: versioned methodology coverage

Build a coverage matrix linking implemented checks to versioned WSTG, API Security,
and selected ASVS requirements. ASVS is a verification requirements standard;
mapping scanner output to it does not establish full compliance. The official
ASVS repository provides versioned requirements and identifiers. [OWASP ASVS](https://github.com/OWASP/ASVS)

Acceptance: requirements appear as tested, not tested, not applicable, or manually
reviewed with a reason. Reports never label the application compliant because
automated checks returned no alerts.

## 7. R3: evidence, remediation, and retesting

### E-016: reproducible finding bundles

Package each finding with rule version, target/operation, authorization context,
evidence digests, relevant request/response pairs, tool/image version, and sanitized
reproduction instructions. Use secret placeholders resolved only at execution time.
Keep optional diagnostics separate from substantive evidence.

**Substantially started** (`8321ff0`, `aea0898`, `cce6bf6`, `6c9b0d9`). A finding
now carries the bytes it rests on, separately from the lane's own account of why
the claim was made, because one is lane-authored and the other is chosen by the
application under test. That distinction drove most of the work: the evidence
arrives redacted and bounded, cannot act as markup in a client's tracker, names
any character that would change what it displays, contains its own match rather
than the head of the response, and reaches report.json, the HTML report, SARIF, the
Jira CSV and the DefectDojo description. A time-based blind SQL injection exports
as its four requests with their payloads and measured durations.

Remaining for E-016: rule and image versions on the finding, a digest check at read
time rather than only at write time, and the archive-level "no credential values"
assertion.

Acceptance: a reviewer can trace a finding to its supporting evidence and reproduce
a lab finding with replacement credentials. A changed or missing artifact is
detectable. An exported archive contains no credential values.

### E-017: assessment comparison and targeted retest

Add new, unchanged, changed, fixed, regressed, and not-retested states. Compare
stable fingerprints while considering schema, identity, rule, and scope changes.
Run the minimum relevant checks under the new explicit run policy.

Acceptance: a fixed lab vulnerability becomes fixed only after its verification
check succeeds; authentication failures, omitted endpoints, and partial scans
produce not-retested/unknown outcomes rather than automatic closure. **A probe that
received no bytes is not-retested, never fixed** — the 2026-09-10 run shows how
readily an empty response reads as a clean one.

### E-018: remediation workflow and exports

Finish the existing DefectDojo mapping/reconciliation UX and add remediation
ownership, notes, and explicit export previews. Consider issue-tracker draft
exports after operators demonstrate a need. Keep external sending explicit.

Acceptance: repeated exports do not duplicate records, changed findings update the
same record, and uncertainty after a network failure is reconciled without blind
replay. Reports separate local triage from external synchronization status.

### E-019: retention, backup, and operational diagnostics

Add configurable evidence retention, disk limits, secure deletion policy,
encrypted backups where appropriate, and a tested restore procedure. Define which
metadata survives evidence expiry. Expose scanner health, job ownership, redacted
diagnostics, stage latency, and budget consumption.

Acceptance: restore a historical run with valid evidence links; a disk-full event
causes an explicit incomplete outcome; telemetry cannot contain credentials or
captured response bodies by default. Retention never silently deletes evidence
needed by an active assessment.

## 8. R4: bounded AI investigation

### E-020: consolidate execution and audit policy

Refactor the existing agent flow in `main.py` — **9,468 lines** — into smaller
services without changing historical report contracts. Align the legacy tool path,
deterministic runner, browser journeys, and integration adapters behind typed
requests and the same scope/budget decisions. Do not assume the new integration
proxy already governs every historical execution path.

Acceptance: each execution path passes the same refusal, cancellation, credential,
and audit tests. Unsupported tools fail explicitly. Policy decisions are visible
in the action log and are not delegated to the model.

### E-021: structured hypotheses and evidence review

Extend existing technique selection, target memory, and verification helpers.
Have the model propose a hypothesis with supporting evidence IDs, a bounded next
check, prerequisites, expected signal, and stopping condition. A deterministic
policy layer validates every proposed action.

Treat scanner output, target content, and retrieved technique text as untrusted
input. Separate a proposed investigation from an authorized execution. Store model
and prompt versions, selected references, rationale, and token/action/time usage.

Acceptance: injected instructions in a target response cannot expand scope, access
credentials, or launch an unselected mutation. Missing model availability leaves
deterministic results usable. Rejected hypotheses remain audit entries, not findings.

### E-022: prove AI adds value

Compare deterministic-only and deterministic-plus-AI arms on the same fixed labs,
scopes, identities, schemas, and total budgets. Use multiple runs for stochastic
components. Keep a held-out fixture set separate from the cases used to tune prompts
or technique retrieval; split by vulnerability implementation, not just URL.

Acceptance: publish incremental verified findings, false positives, cost, requests,
and duration. Adopt AI behavior only when measured benefit justifies overhead.
Do not automatically train or persist raw client evidence into shared memory.

## 9. R5: optional integrations and later platform work

These are candidates, not commitments. Confirm operator demand before implementation.

| Candidate | What it adds | Boundary and acceptance | Priority |
|---|---|---|---|
| OpenAPI + HAR / recorded request import | Better inventory when crawling misses authenticated operations | Validate input, redact secrets, preserve origin/identity, never replay state changes by default | High, alongside R1/R2 |
| Semgrep result import | Link source findings to routes and runtime evidence when source is supplied | Begin with JSON/SARIF ingestion; source findings remain unverified runtime hypotheses | Medium |
| Trivy artifact/image analysis | Dependency and image context for supplied deployment artifacts | Scan only supplied artifacts; package presence is not proof of reachable exploitation | Medium |
| Gitleaks repository analysis | Find exposed credential material in authorized supplied source/history | Store redacted locations; do not try discovered credentials against services automatically | Medium |
| Existing NVD enrichment improvements | Better prioritization with cached, timestamped vulnerability metadata | Preserve source/version-match uncertainty; no automatic severity based only on a banner | Medium |
| Issue tracker / SARIF automation | Put reviewed findings into engineering workflows | Stable IDs, explicit sending, preview and repeat-export tests | After R3 |
| Browser proxy session import | Reuse operator-captured testing sessions | Import bounded, redacted artifacts first; live proxy control is a separate execution-policy review | Later |
| WebSocket-specific testing | Coverage for real-time application protocols | Requires a new enforceable transport policy and protocol fixtures; unsupported in current HTTP-only boundary | Later, demand-driven |
| Cloud/Kubernetes assessment | Broader infrastructure coverage | Separate threat model, credentials, scope types, adapters, and fixtures; do not graft it onto web host scope | Separate product decision |

Semgrep documents machine-readable JSON and SARIF output suitable for an ingestion
adapter. [Semgrep output reference](https://docs.semgrep.dev/semgrep-appsec-platform/json-and-sarif/)
Trivy documents container-image analysis as an artifact-oriented input surface.
[Trivy image documentation](https://trivy.dev/docs/latest/target/container_image/)
Gitleaks supports secret detection in repositories and other supplied inputs.
[Gitleaks project](https://github.com/gitleaks/gitleaks)

Select one source/artifact integration first, measure incremental value on a fixed
lab, then decide whether the next is worth maintaining. Review binary and rule-set
licenses separately, pin tested versions/digests, and account for update maintenance.

Before adding a sixth discovery source, note where the 2026-09-10 measurement put
the bottleneck: the lane found 136 endpoints on a target and four parameters, and
missed a reachable error-based SQL injection because the injectable call is an XHR
rather than a link — while the string naming it sat in a JavaScript bundle the lane
had already fetched and recorded as an endpoint. Extracting operations from bodies
already in evidence is cheaper than another crawler, and is the same work as E-007.

### E-023: multi-user operation — only after the single-operator release

Add engagement ownership, roles, separate project secrets, audit identity, and
access checks for every evidence/API/WebSocket route before sharing the app between
operators. Test cross-project isolation directly. Replace the shared operator token
with an appropriate account/session model while retaining a documented local mode.

### E-024: distributed workers — only after measured capacity pressure

Introduce a durable queue, worker leases, heartbeat/reconciliation, and explicit
job ownership only if one host cannot meet measured needs. Move to PostgreSQL and
object storage when concurrency and retention justify them, not preemptively.
Design delivery as at-least-once: side-effecting scan stages must not be blindly
retried after lease loss. A remotely lost worker means interrupted/unknown until
its execution has been accounted for.

### E-025: an uncertain export could block a destination never written to — CLOSED

`export()` marked the row `uncertain` from a blanket
`except (Exception, CancelledError)`, which fires for failures raised before a single
byte leaves the machine — the sandbox not starting because Docker is down, a cancelled
run, a connection reset during the inventory read. An uncertain row blocks its
destination, and reconciliation cannot clear one with no remote write to verify
against: it answers `Remote state differs from intended export` for ever. So every
later export to that destination was a permanent no-op, and an operator whose Docker
daemon hiccuped was locked out of exporting that assessment with no way back.

`wrote` already drew the distinction, and the `RemoteError` branch directly above
already consulted it — only this branch hardcoded uncertainty. The premise was checked
rather than assumed: `wrote = True` is set immediately before each of the two write
requests (the import POST and a finding PATCH), and the only requests that can precede
it are the inventory GETs, which are reads. So "nothing was sent" is knowable, and
`failed` is the honest status — with `Failed before any request was issued; nothing was
written and this destination is not blocked`, so the operator knows to retry.

Pinned from both sides, because widening the `failed` branch too far would be worse
than the original defect: a local failure before any request is `failed` and retryable;
a cancellation *during* a write is still `uncertain` and still blocks; a read that fails
locally is `failed`, which is the test that holds the premise about `wrote`.

One existing test had to be rewritten, and it was mis-scoped rather than merely stale.
`test_defectdojo_uncertain_write_is_not_retried` set up a sandbox that failed to open —
which sends nothing at all — so its name and its scenario disagreed. It now makes the
write leave and then kills the connection, which is what the name describes, with a
sibling covering the other half.

### E-026: the uncertainty block missed the case it existed for — CLOSED

The block matched an export by DESTINATION, or by REMOTE TEST ID on that server. A
first `import` whose response was lost — a 202, a timeout, a cancellation — never
learns a test ID, so its row carries `remote_test_id = NULL`, `remote_test_id = ?`
cannot match, and only a repeat of the byte-identical body was blocked. An operator who
did what the documentation advises — find the test in the DefectDojo UI, then reimport
into it by ID — sailed past the guard and wrote a changed report over a write nobody had
established. That is the exact papering-over the guard prevents, in the exact scenario
it was written for.

A third clause now blocks on an unresolved export **for this session, to this server,
whose destination is not yet known**. Narrow on three counts, because my own note
warned that a wider block would lock out more operators rather than fewer: scoped to
the session that made it, scoped to the server, and lifting the moment the row is
resolved, since reconciling fills in the test ID it verified. Tests cover all three
boundaries — the block does not reach another server, it lifts after reconciliation,
and a `failed` export does not trigger it.

**The two were only safe to fix together, and in this order.** Widening the block while
every local failure still produced an `uncertain` row would have locked out exactly the
operators E-025 freed: one Docker hiccup would have blocked the whole server for that
session instead of one destination hash. The note recording E-026 said so, and it was
right.

### E-027: the shipped AUTHZ-04 check reported findings on clean endpoints — CLOSED

Its verdict was a body-hash differential: normalise three responses, strip 32-hex
and whitespace, and conclude `low == high` is an IDOR. That fires on anything two
identities legitimately see the same, which on a real API is a large class.

**Measured before and after**, over 3 seeded violations and 11 negative controls on
Juice Shop v17.1.1 — the second figure from the rewritten case driven through the
real `run_test_case`, not a reimplementation of its logic:

    the shipped body hash          5 false positives, 0 false negatives
    the rewritten case             0 false positives, 0 false negatives
    the rewritten case, anonymous
      clause removed               3 false positives, 0 false negatives

The five it reported on clean endpoints:

    GET /rest/basket/99999        200 {"data":null} to both     — absent object
    GET /api/Users/99999          404 Not Found to both         — absent object
    GET /rest/basket/2            the low identity's OWN basket — expected access
    GET /rest/products/1/reviews  public, identical to everyone — published content
    GET /api/Addresss/1           400 "Malicious activity" to both

The last is the sharpest, and it is the one reading the code would not predict: a
hash comparison cannot tell **"both identities were refused"** from "both identities
got the object", because both are `low == high`. Two identical denials were reported
as a shared secret.

**The verdict is now the typed `idor` evaluator**, which had existed, unwired, since
it was written. It asks a different question: did the privileged object — named by a
marker the OPERATOR supplies — reach the low-privilege arm while not reaching an
anonymous one? The asymmetry is the safety property, the same one the `ownership`
evaluator rests on: the marker is ours and the responses are the target's, so a
target can cost itself a finding and cannot manufacture one.

The evaluator was missing the anonymous arm entirely, which the ablation above shows
is worth three of the five. A case that declares no `anonymous_step` keeps the old
behaviour, so the clause is additive; a case that declares one whose step is missing
gets no finding, because a clause nobody ran is not a clause that passed.

**Three gates had to be reconciled, and they are not the same gate.** `private_object_marker`
was absent from `declared.DECLARABLE`, so nothing could supply it — and
`looks_injectable` refuses `"`, so every marker that identifies an object in a JSON
API (`"UserId":1`, `"email":"admin@juice-sh.op"`) would have been refused even once
listed. That rule exists because a declared value is **rendered into a command**,
where a quote closes an argument. A marker is compared in Python as a substring and
reaches no command line, so it is now held to the rule that does apply: bounded
length, no control characters. `declared.EVALUATOR_ONLY` is the single list, consulted
by both `declared.validate` and the sweep's own gate so the two cannot drift, and a
catalogue-wide test asserts the premise — that no step interpolates the field —
rather than assuming it.

The third gate was left alone deliberately, and then tightened. `_harvest` applies
`looks_injectable` to values lifted out of a TARGET'S OWN OUTPUT, and that must stay:
a marker the target chose is a finding the target chose. `Evaluator.produces` now
**refuses** an evaluator-only field outright, so the forgery is structurally
impossible rather than left to whoever writes the next case.

**What the rewrite does not do.** The case is still not runnable in the assessment
lane: its `required_any` credential alternatives are something the lane has nothing
to choose between (see `inventory.LANE_TARGET_FIELDS`), and the fetches are still
`bash -c` because a conditional `${HT:+-H ...}` is what lets one command carry either
a bearer token or a cookie. Making it lane-runnable needs per-role credential
plumbing the lane does not have, and is not what a precision fix is for. It runs in
the sweep and the CLI, where it previously produced five false positives.

Supplying credentials alone no longer makes the case run — the operator must also
name the private object, and the skip says so. That is the contract change: the old
verdict needed no operator input, and needing none is where the false positives came
from.

The 0-and-0 above is on Juice Shop, which keeps no application state in a cookie. On
DVWA the rewritten case was still wrong until E-028 was fixed with it, because there
the security level travels in the cookie and the control arm was running against a
different application. The two were entangled, and closing one without the other
would have left a measured false positive in place.

### E-028: the control arm ran at a different application configuration — CLOSED

The same defect as the 2026-09-10 arm divergence, inside the case meant to be the
control. A differential is only about identity if identity is the only thing that
varies, and AUTHZ-04's anonymous arm was `curl -s "$U"` carrying nothing at all —
while on DVWA the application's SECURITY LEVEL travels in a cookie, with
`dvwaSecurityLevelGet` falling back to `impossible` when it is absent. So "anonymous"
was not the authenticated arms' application with nobody logged in. It was a
different, hardened application with nobody logged in.

Measured on `/vulnerabilities/authbypass/get_user_data.php`:

    admin (high), security=low      273 bytes — the full user table
    gordonb (low), security=low     273 bytes — the full user table
    anonymous WITH security=low     273 bytes — the full user table
    anonymous, NO cookie             41 bytes — {"result":"fail","error":"Access denied"}

The endpoint has no access control at that level, so the honest verdict is "public,
not an identity boundary" — and with a bare anonymous arm the marker was absent from
it for the wrong reason, every clause passed, and the case reported HIGH on data DVWA
hands to anyone who asks.

`config_cookie` is the fix: a non-secret, operator-declared cookie carried by EVERY
arm including the anonymous one. curl merges multiple `-b` options (`-b "a=1" -b
"b=2"` sends `a=1;b=2` — verified), so it rides alongside an identity cookie instead
of replacing it, and `${CC:+-b "$CC"}` expands to nothing for an application that
needs none, which is why Juice Shop is unaffected.

Measured through the real runner, all four arrangements, every arm returning real
bytes:

    security=low,        anonymous arm CONFIGURED   no finding   correct (public here)
    security=low,        anonymous arm bare (old)   FINDING      FALSE POSITIVE
    security=impossible, anonymous arm CONFIGURED   no finding   correct (enforced)
    security=impossible, anonymous arm bare (old)   no finding   correct (enforced)

The distinction this introduces is worth more than the one case. Identity material is
per-arm and secret; configuration material is shared by every arm and is not. They
were the same field, and a differential cannot be one variable while they are.

### E-029: an identity with plain cookies got no form discovery at all — CLOSED

`adapters.py` gated the entire browser pass — the only producer of `source="form"`
and `source="playwright"` endpoints — on
`ctx.config.headless or (ctx.identity or {}).get("storage_state")`, while the proxy
injects `identity.headers`, `identity.cookies` AND `storage_state.cookies` on every
in-scope request. So an identity authenticated by plain cookies was fully
authenticated and discovered nothing.

**The premise had to be measured first**, because the browser context is created
with `storage_state=None` for such an identity — Chromium itself holds no cookies,
and only the proxy makes the requests authenticated. If that were not enough, the
fix would have enabled a pass that renders LOGGED-OUT pages while labelling the
endpoints with an authenticated identity, which is worse than not running it.
Measured against real DVWA, real worker image, real proxy, `storage_state=None` in
both arms and only the identity differing:

    anonymous             1342 bytes (the login page)   1 link    1 form
    cookie-only identity  6436 bytes                   31 links  13 forms

and the 13 are DVWA's own module forms. So proxy-injected cookies do authenticate
the rendered pass; it simply was not being run.

**The decision is now asked of the ASSESSMENT, not the arm** —
`adapters.wants_rendered_pass(config)`, which takes the config alone and therefore
cannot branch on an identity. The obvious repair ("run it when THIS identity carries
material") is itself a fork generator: E-008's matrix starts at "anonymous, two
ordinary users in different tenants, and one privileged lab identity", an operator
may name `anonymous` alongside real handles, and under a per-arm test that arm alone
would have no rendered surface — so the arms could never agree and `compare_arms`
would refuse every differential on the assessment. An assessment that selected no
identity and did not ask for a rendered crawl still gets none, because the pass
launches Chromium.

End to end through the real lane against real DVWA, `headless=False`, cookie-only
identity, changing only whether the assessment names an identity:

    before   60 endpoints, all katana,              0 form (module, parameter) pairs
    after   127 endpoints, 5 form + 122 playwright, 7 form (module, parameter) pairs
             brute/username, brute/password, csrf/password_new, csrf/password_conf,
             sqli/id, sqli_blind/id, xss_r/name

Three harness errors of mine were caught on the way there, and all three were the
same kind — a detector that could only say "no": a link check written with a leading
slash that DVWA's relative hrefs never match; a header lookup written
case-sensitively when the proxy writes `cookie` in lower case; and a login through
Python's `http.cookiejar`, which silently drops cookies for dotless hosts like
`localhost` and left every "unauthenticated" reading unauthenticated for the wrong
reason. The verified precondition in the final script — assert the session is live
before trusting anything downstream of it — is what turned the result over.

### E-030: fork points an operation-level identity does not absorb — CLOSED

The eight findings were not one defect. Some are genuine application differences
that must stay VISIBLE — E-008 asks for differences to be distinguishable, not
normalised away — and some are artifacts the lane manufactures, where a difference
the tool invented is not a finding about anything. They need opposite treatment, and
conflating them is what made this item read as a single problem.

**Artifacts, fixed.**

- **A companion-free form URL collided with the crawled page URL.** DVWA's xss_r
  form declares its submit control with no `name`, so at `security=low` it has no
  named companions at all, `form_endpoint` yields the page's own URL with an empty
  query, and the row key merges it with the page row — `sources` became
  `["form","playwright"]` and withholding on "form in sources" hid a real PAGE from
  every read-only case. At `impossible` the hidden `user_token` IS named, so the
  action is its own row and the page survives: the token's ABSENCE forked the
  reading arms in the opposite direction from its presence. `form_urls` now requires
  a QUERY, which is what makes a form URL an action — its own measured table already
  said so (`GET /vulnerabilities/csrf/` changed nothing; the same URL with
  `?Change=Change` changed the password). With no named companion there is no
  submission signal for a handler to fire on.
- **`MAX_FORM_PARAMETERS` was applied in DOM order**, so a control the target
  renders first in one arm — DVWA's csrf form puts `password_current` first at
  `impossible` — pushed a different control off the end. Sorted before the cap, so
  the kept set depends on the NAMES both arms agree about.
- **Nothing refused a session-destroying link.** Measured against the default
  `["/logout","/signout"]`: `/logout`, `/logout.php` and `/signout` refused;
  `/users/sign_out` (Rails), `/accounts/logout/` (Django), `/Account/LogOff`
  (ASP.NET), `/auth/logout`, `/api/v1/logout`, `/logoff` and `/sign-out` all
  **visited**. An arm whose session dies mid-crawl then sees only login forms and
  reports nothing, because every request still succeeds. `egress_policy` now has a
  whole-segment, case-insensitive guard, as the lane's own rule rather than a
  default in the operator's list — an operator replaces `excluded_paths` to ADD an
  exclusion, and that must not be how they silently remove the rule protecting the
  run from itself. ZAP's plan is given the same segment list so it does not spend
  requests discovering what the proxy will refuse; both layers match per whole
  segment, so `/blog/how-to-logout-safely` and `/docs/signout-api` stay crawlable.

**Genuine differences, now named instead of listed.** `compare_arms` returns a
`divergence` entry per one-sided operation, classified from the data: `method_changed`
when both arms reached the endpoint by different methods, `parameters_changed` with
the inputs that appeared or vanished, and `not_reached_by_other_arm` when there is
genuinely nothing there — which must not be dressed up as either of the others,
because that would imply the arm reached it.

**Measured after the fixes**, both DVWA security levels driven through the real lane
in one session, changing only the `security` cookie:

    33 of 40 operations seen by both        (originally 1 of 8 (url, parameter) pairs)
    withheld: 4 in each arm, structurally parallel — the csrf, sqli, sqli_blind and
              brute/xss_r actions, with the hardened arm's copies carrying a token
    offered to reading cases: 30 against 31, and the single extra is
              /vulnerabilities/csp/source/impossible.js — a genuinely
              state-dependent file, not an artifact

    divergence, each named:
      parameters_changed        /vulnerabilities/brute/, /csrf/, /cryptography/, /xss_r/
      not_reached_by_other_arm  /vulnerabilities/csp/source/impossible.js

**The remaining four, and two of them were my own wrong diagnoses.**

- **The row key's missing `source` column was not data loss.** I recorded that "a
  page row and a form row for one URL cannot coexist — `INSERT OR REPLACE` keeps the
  last writer". `persist_result` in fact UNIONS both `sources` and `parameters`, and
  nothing is lost in either arrival order — measured, and now pinned by
  `test_a_page_row_and_a_form_row_at_one_url_both_survive`. The claim was plausible
  from the SQL statement alone and wrong once the code around it was read.

  What genuinely remains at `/vulnerabilities/xss_r/` is an operation-identity
  question, not a storage one. The vulnerable arm merges page and form into one row
  (that form adds no named companion, so the two URLs coincide) while the hardened arm
  has two (its form URL carries a token), so the hardened arm holds one extra
  parameter-free operation. **Absorbing that would reintroduce the page/action merge
  an adversarial pass called blocking** — `/vulnerabilities/csrf/` and
  `/vulnerabilities/csrf/?Change=Change` differ only in their parameter sets, and
  merging them puts a request that changes the admin password under the same identity
  as the page that displays the form. It is reported as `parameters_changed`, which is
  what it is, and that is the right answer rather than a deferral.

- **The state-dependent path is not templatable.** I recorded
  `/vulnerabilities/csp/source/impossible.js` as wanting path templating, on the
  assumption that the vulnerable arm had a counterpart to template against. Measured:
  at `security=low` that page loads **no** `source/*.js` at all — the hardened level
  genuinely loads an extra script. There is nothing to absorb, and
  `not_reached_by_other_arm` is the complete and correct answer. Path templating is
  still E-007's work for locale and tenant prefixes; it was never what this
  particular divergence needed.

- **The page-visit cap now reports itself. FIXED.** The cap was silent, and silence is
  the wrong default in both directions: two arms publishing different menus truncate
  at different places, so the cap MANUFACTURES a difference, and two publishing the
  same menu truncate identically so the cap HIDES one. `adapters.crawl_truncation`
  emits a `crawl_truncated` observation naming how many same-origin links were left
  and why a truncated arm cannot be compared, and stays silent when the cap did not
  fire — an observation on every run is how an observation stops being read. Verified
  end to end against real DVWA with the rebuilt worker image:

        form_pages=5    31 links published, 6 visited, 20 unvisited  -> observation
        form_pages=60   31 links published, 26 visited, 0 unvisited  -> none

  Note the default is 20 and DVWA publishes 31 links, so the default truncates there.
  That was the hidden asymmetry; it is now stated. Raising the cap remains an
  execution-policy decision and is not made here.

- **A schema fetched by URL is identity-dependent. DETECTED.** `SchemaInput` accepts a
  URL, and `schema_file` fetches it through the proxy, which injects the identity's
  headers and cookies — so a target serving a different OpenAPI per role forks the
  schema-derived operations. The information to catch it already existed and nothing
  compared it: both the ZAP and Schemathesis adapters record `schema_sha256` in their
  stage metadata. `compare_arms` now refuses with `different_schema` when the two arms'
  digests disagree, and an absent digest on ONE side counts as disagreement — a target
  that serves the document to one identity and refuses it to another has given the arms
  different surfaces.

  Detection rather than prevention, deliberately. Refusing a per-identity fetch would
  break a schema that is itself behind authentication; fetching it once anonymously
  would break it differently. Which of those an operator wants is their decision, and
  they could not make it while the fork was invisible.

## 10. Shared technical contracts

Prefer additive schema migrations and small services with explicit interfaces.
Suggested concepts are:

- `AssessmentPolicy`: target and service scopes, stage modes, identity references,
  budgets, exclusions, selected operations, effective configuration version.
- `Operation`: method/path template, parameters, schema references, discovery
  provenance, per-identity attempted and verified states.
- `Action`: actor, typed request, policy decision, stage/job IDs, timestamps, result,
  evidence references, and interruption reason.
- `VerificationRecipe`: prerequisites, fixtures, assertion, cleanup, reproducibility
  inputs, and permission requirements.
- `Finding`: stable identity, confidence and basis, evidence links, verification
  state, review history, and external mappings. **Keep the lane's account of the
  claim and the application's own bytes as separate fields** — they have different
  provenance, and a consumer that renders one as trusted text and the other as
  untrusted can only do that if they arrive apart.
- `AssessmentDiff`: comparable context, changed operations/findings, coverage gaps,
  and retest outcomes.

Migrate existing rows incrementally. Keep historical reports readable, never
change saved-run defaults retroactively, and test migration from a populated old
database. Imported archives and reports must use bounded parsers and reject path
traversal, executable content, and unexpected remote references.

## 11. Evaluation and release gates

| Metric | Definition | Proposed release rule |
|---|---|---|
| Scope integrity | Requests observed by recording out-of-scope services, **and target state compared before and after a run** | Zero unauthorized requests across supported execution paths, **and zero state changes while `state_changing` is false** |
| Known-operation coverage | Attempted method/path/identity combinations divided by declared applicable combinations, **counting only probes that received a response** | Every known combination has an attempted result or an explicit reason for exclusion; **a probe that received no bytes is untested coverage, not an attempt** |
| Finding recall | Recovered expected findings / declared expected findings | All release-critical fixture findings recovered; publish broader and held-out results separately |
| Precision | Adjudicated true positives / all adjudicated positives | No known false confirmations; report suspected-alert precision by rule family |
| Evidence integrity | Referenced artifacts resolve and digest checks succeed | 100% references valid; each finding has substantive supporting evidence, **and cites its own rather than the whole stage's** |
| Differential validity | For any comparison between two identities or configurations, the share of `(operation, parameter)` pairs both arms actually reached | **Every pair compared must be reached by both arms**; a differential whose arms tested different surfaces is reported as inconclusive |
| Lifecycle reliability | Fault-injection cases with correct stop/resume/outcome behavior | All cancellation, crash, auth-expiry, cleanup, and uncertain-export cases pass |
| Reproducibility | Same inputs recover the same expected deterministic behavior | Record tool/rule/schema versions and seeds; publish observed exceptions |
| Efficiency | Requests, wall time, model tokens/cost, and verified findings | No budget overruns; justify regressions against the previous fixed baseline |

Three of the clauses above are additions, each from a defect that produced a
confident wrong answer rather than a failure: scope integrity missed an
in-scope request that changed the target's credentials, known-operation coverage
counted 156 empty responses as attempts, and evidence integrity passed while all
nine findings of a run cited the same 772 artifacts. The differential-validity row
is new for the reason given in §3.

Do not calculate coverage against an assumed complete internet-facing surface.
Schema inventory and discovered inventory are separate denominators. Do not count
unadjudicated scanner alerts as either true positives or false positives. Empty
diagnostic files, missing evidence, and insufficient evidence are distinct cases.

Run fast tests on every change; isolated scanner tests on relevant pull requests;
actual-service suites and reproducible benchmarks before release. Client evidence
must not be placed in public CI artifacts. Record host architecture and hardware
when comparing durations. Publish raw metric definitions beside summarized charts.

## 12. First three implementation increments

**Increment 1 — close the review defects: DONE** (`7723090`, `639c32e`, `7f45f06`,
`e78c257`). E-001 through E-003 each got a failing regression first and then the
smallest fix. E-004 did NOT survive confirmation: re-running the benchmark end to
end showed two of its three clauses unmet, so it was reopened and closed properly
— which is the outcome this increment was for. The scope/lifecycle suite passed
against the real scanners after each execution change (22 passed), and the
benchmark — the one failing acceptance check in §2 — now passes against a
stricter validator.

Method note worth keeping: three of the four items were reproduced by agents
working only from the code, and two of their analyses needed correcting on
material points. E-003's recommendation understated the cost (it called
`WSTG-INPV-07`'s mutating steps "four of nine" without noting they are the whole
of that case's detection), and E-002's status in this plan credited
`issued_payloads` with a guarantee it does not provide. Reproductions are worth
delegating; conclusions are worth checking.

**Increment 2 — make the release repeatable: DONE** (`eedb7e3`, plus the docs and
packaging commit). The CI collection defect was one line, as expected, and it was
not the important one: CI had never executed a single Docker-gated test, so the
lane's entire execution boundary — the sandbox, the egress proxy, the container
lifecycle — was verified only on one developer's machine. A one-line fix to a job
that was never going to run the tests anyway would have looked like progress.

E-006 produced the same lesson from the other direction. Every stale figure in it
had been written by someone who read the code instead of running it, so the
instructions were checked by following them from a **fresh clone with a fresh
virtualenv**, and two of my own new numbers were wrong within the hour:

- I quoted "a clean checkout reports 2167 passed, 35 skipped" from my working
  tree. A genuine fresh clone reports **2134 / 68** — the working tree has the
  gitignored `runs/` corpus and Docker, and a new operator has neither. The CI
  ratio guard had been calibrated against the wrong figure for the same reason.
- I then broke the skip breakdown down into categories summing to 44 under a
  total of 68, having counted distinct skip *locations* instead of summing the
  `SKIPPED [n]` counts pytest prints.

Both are now guarded by tests rather than by care: `tests/test_release_tooling.py`
asserts the README's breakdown sums to its own total, that its lane coverage
figure matches what `executable_test_cases` answers, and that no case marked
runnable in the catalogue table is one the parser refuses. The stale numbers this
increment corrected — `9 of the 29`, `1674 passed` — went stale precisely because
nothing ever asked them a question.

One further gap closed under "no unrelated operator files": the release evidence
E-005 introduced was untracked but **not ignored**, and `ERLIK_COVERAGE_REPORT`
given a bare filename lands next to the checkout. A local `pytest -m docker`
pointed at a client rather than the lab would have left a report carrying finding
metadata one `git add -A` from being published.

The audit found no operator or client data, no secrets, and nothing sensitive
anywhere in history. It did find ~36 tracked research artifacts (fine-tuning
scripts, training logs, recomputed statistics) that are evidence for the
evaluation rather than product; whether they ship is a decision for the owner,
not a packaging defect, and nothing was removed.

The repository requires human review and merge for scope/execution changes; no
automated self-merge is part of this plan.

**Increment 3 — demonstrate the next product benefit:** a vertical slice of E-007,
E-008, E-010, and E-011. An operator selects two lab identities, discovers a hidden
API operation, sees its coverage, reproduces a seeded authorization flaw, and opens
its evidence. The identity-isolation half of E-008 belongs in Increment 1 or 2
instead — §3 explains why it gates R0. Expand browser journeys and business
workflows after this works.

**Increment 6 — the identity matrix, and the boundary it does not cross.** The slice
sentence opens with "an operator selects two lab identities", and by now every later
clause was built: the hidden API operation is discovered (Increment 4), its coverage is
visible (Increment 5), a seeded authorization flaw reproduces (the `ownership`
evaluator), and its evidence opens. What was missing is the declaration that makes the
rest mean something.

`Identity` gained `role`, `tenant`, `subject_id` and `may_access` — all
operator-declared, none a secret, each validated as text that reaches a command template
and an evidence quote. `contracts.identity_target_fields` carries the non-secret ones
into a case's target dict, and `compare_arms` reports the roles and tenants so
`cross_tenant` is something a reader sees rather than infers from two opaque handles.

`subject_id` is the one the authorization checks rest on, and putting it on the identity
rather than in a per-run target dict is the point: it travels with the ARM, so two arms
cannot share one by accident, and the asymmetry that makes the `ownership` evaluator safe
— the caller's identity from the operator, the asserted owner from the target — is
expressed where an operator can see it. A check worth confirming before building on it:
`secret_values` is an explicit allow-list rather than a sweep, so the declarations survive
into a finding's evidence. Had it swept every string, the ownership finding's own
comparison would have been redacted out of the evidence that quotes it.

**And the increment stopped at a measured boundary rather than shipping past it.** A lane
stage carries exactly ONE identity — it resolves it from its own row, and the proxy
authenticates that stage as it — while the `ownership` evaluator needs three arms in one
case execution. I wrote a lane-runnable `WSTG-AUTHZ-04.2` to prove the matrix out, then
deleted it: it named an `owner_step` and an `anonymous_step` it had no way to have, so it
could never fire. A case that always reports nothing is worse than no case, and it is the
exact unwired shape E-027 had just been fixed for.

So `subject_id` reaching a case is groundwork, not a working lane check, and two tests pin
that so a future reader does not assume otherwise. The lane-native shape is a comparison
ACROSS stages, which `compare_arms` already does for surfaces and does not yet do for
responses — **that is what Increment 7 should build**, and it is the remaining half of
E-011.

**Increment 5 — make coverage answerable, before and after.** The slice sentence asks
that an operator "sees its coverage", and §E-010 gives the cost of not being able to: at
the default budget the 2026-09-10 run tested one or two parameters per case out of eight
and lost six of nine findings, saying so only in per-case observations nobody reads
before launching. Everything needed was already recorded — `test_case`,
`test_case_not_run`, `test_case_truncated`, `test_case_unreachable`, `parameter_refused`,
`form_url_withheld` — and scattered across stage results, so the question an operator
actually has had no answer. The same shape as the schema digest in E-030: recorded, never
read.

`inventory.coverage` aggregates it per (pair, identity) with a state and a reason, and
`inventory.preview` answers the same question before the run using
`deterministic.target_budget` — the runner's own arithmetic, extracted to module level so
there is one definition rather than two claims. Both are exposed as
`/sessions/{id}/coverage` and `/sessions/{id}/preview`.

**There is no `tested` state, and that is the point.** `answered` means bytes came back;
it is not proof the check exercised anything, because a DVWA probe missing its CSRF token
answers HTTP 200 with 389 bytes of PHP warnings. `verified` — a finding came out of it —
is the only state the lane can stand behind. `not_run` and `not_attempted` are likewise
kept apart: the first says a bigger `max_urls` covers it, the second says nothing
selected tests it and no budget changes that.

**Three of my own errors were caught by making the two views agree**, which is the whole
argument for building them as a pair:

- Matching observations to endpoint rows literally credited **2 of 13** probes that
  actually ran — because `parameters_by_url` hands a case the query-stripped URL while
  the row keeps its query. A report claiming six times less coverage than the run
  delivered sends an operator chasing gaps that are not there. The preview predicted 13
  correctly, which is how the disagreement surfaced.
- Normalising both sides without grouping then credited **57**, because twenty crawled
  variants of one path each claimed the same probe. The unit of work is the probeable
  pair, not the endpoint row; `inventory.probe_key` defines it once for both views.
- A case-wide budget truncation was being applied to every pair in the inventory,
  labelling 41 pairs `not_run` on a run where no selected case was eligible for them at
  all. A case-wide record now applies only to pairs that case could have tested.

And one label of mine was misleading rather than wrong: `not_reached` sums per-case
shortfalls, so it counts case-targets rather than distinct pairs — several cases usually
share a pair. It now says so, and reports `distinct_pairs` beside it.

**Increment 4 — reach the surface the crawler was missing.** No fourth increment was
written down; this is the work §12's own measurements call the binding constraint:
*detection works and discovery does not reach*. On Juice Shop the lane reported 136
endpoints, 4 parameters and 2 findings, both informational, while the application's
error-based SQL injection sat one request away.

**The plan's diagnosis of why was wrong, and measuring it is what found that.** §2
said "the parameter is one JS-body extractor away from being in the inventory". It was
not. The route was out of reach because **the rendered pass was failing outright**: its
landing navigation waited for `networkidle` with a fatal timeout, and an Angular front
end that polls never goes idle — `Page.goto: Timeout 30000ms exceeded`. Worse, `rpc`
raises, so the exception left the adapter and took the whole katana stage with it,
discarding a crawl that would have reported 133 endpoints. E-029 had just made that
path run for every authenticated assessment rather than on request, so the blast radius
had grown.

Idle is now an optimisation rather than a requirement — `domcontentloaded` is the floor,
with a bounded extra wait so late XHRs still fire — and a rendered pass that fails
anyway becomes a `rendered_pass_failed` observation with the stage marked `partial`,
leaving the fetched crawl intact. On Juice Shop that took the pass from **0 to 122
observed endpoints**, and the browser then saw the search XHR itself.

**What that bought, measured end to end:**

    before   136 endpoints, 4 parameters, 2 findings (robots.txt, security.txt)
    after    145 endpoints, 7 parameters, and

             [high] WSTG-INPV-05.2  /rest/products/search (q)
                    982 bytes of evidence carrying the application's own
                    `SQLITE_ERROR: near "probe": syntax error`

**The JavaScript extractor is still worth having, and for a smaller reason than the
plan claimed.** `contracts.infer_endpoints` reads routes out of a script body and
resolves relative ones against the script's own URL, which is how Juice Shop spells its
open redirect (`url:"./redirect?to=..."`). Of the five routes it recovers from
`main.js`, two are found by nothing else — `/rest/user/change-password?current=` and
`/rest/user/security-question?email=` — because the application never calls them on the
landing page. Katana finds neither, and does not find the search route either.

**Every route it returns is target-controlled text about to become a URL the lane
requests and a parameter name it injects into**, so the refusals are the substance: one
leading slash and never two (the same bundle names `//w.soundcloud.com/player/?url=`,
which resolves to a different host); no scheme, no `..`, and a path charset that cannot
carry a `${id}` placeholder or open an argv; parameter names held to `PARAMETER_NAME`;
a fragment refuses the whole candidate rather than truncating it, because `?ok=1&a#b=2`
cut at the `#` yields the name `a` the application never had.

And **an inferred route is a proposal, never a target.** It is recorded as
`source="javascript"` and withheld from `seeds()` and `parameters_by_url()`, so nothing
fetches or probes it until an operator selects it. The reason is in the same five rows:
`/rest/products/search?q=` and `/rest/user/change-password?current=` are syntactically
indistinguishable, and the second is a real mutating endpoint — it answers 401
anonymously, so authentication is the only thing between the lane and a changed
credential while it enumerates. Surfacing a route no crawler reaches is the value;
requesting it unasked is how a tool changes a password by accident.

**Increment 3, first part — the R0 isolation gate and object-level authorization.**

`contracts.operation_key` keys an operation on **what can be injected into it** —
origin, path, method and the testable parameter names — and deliberately not on the
companion query. That query is where DVWA's single-use `user_token` lived, and it
was the whole of the measured divergence. `inventory.operations()` groups the
endpoint rows beneath their operation without discarding any, and
`inventory.compare_arms()` is the comparison E-008 asks for.

**The gate is not met by normalisation, and an independent pass is why this
paragraph does not say it is.** Making the arms agree about the operation set was
my first answer and it is only half of one: agreeing about what exists is not
having tested it. A live run was measured scoring a perfect shared-surface fraction
of **1.0 while all eight probe sets received zero bytes** — the arms agreed
completely and neither reached anything. So `compare_arms` refuses four things
rather than reporting set equality, each because a run gave a wrong answer without
it: the two arms being one identity; an operation only one arm saw; an operation
both arms saw **at different concrete URLs**; and no shared operations at all.

That third clause is the one the operation key itself introduces, and it refuses
the historical DVWA pair: the arms now agree about the operation and still issued
different requests, because the hardened arm carried a token. Companion values are
withheld from the output — the divergence is reported as the differing query
FIELDS, since a value is target-controlled text.

`comparable` therefore means "these two arms describe the same surface", and the
returned record says so in as many words. Reach is a property of execution that
this function cannot see, and §E-030 records that the lane's own emptiness detector
does not fire on a refusal either: a DVWA probe refused for want of a token answers
HTTP 200 with 389 bytes of PHP warnings, which is not empty and is not an answer.

Measured independently, with real Chromium in the worker image against real DVWA
under two logged-in sessions differing only in the `security` cookie: the arms move
from **1 of 8 shared (url, parameter) pairs to 6 of 8**, and both residuals are
genuine application differences rather than artifacts (§E-030).

Three measurements decided the design, and none of them is what reading the code
would suggest:

- DVWA's token is **single-use, and a consumed one is answered with zero bytes** —
  4757 bytes on first use, 0 on the second. That is the cause of the 156-of-208
  empty steps on the hardened arm, and it means the fix is not "refresh the token"
  but "do not put the value in the identity at all".
- **No token at all returns 389 bytes of PHP warning**, not zero. So omitting a
  volatile companion makes the failure visible rather than invisible — a real
  improvement, because the lane can then report `test_case_unreachable` instead of
  clean — but it does NOT make the hardened arm testable. Neither request reaches
  the SQL.
- Therefore **DVWA's `security` cookie is the wrong second identity for an
  authorization differential**, whatever it is worth for a surface comparison: the
  hardened arm's zero findings are vacuous, because it never executed the code
  being compared. Two principals at one level are the right pair — measured, admin
  and gordonb both at `security=low` produce `/vulnerabilities/sqli/?Submit=Submit`
  byte for byte, so the only variable is who made the request.

E-011's object-level half is a new `ownership` evaluator, built on that last point.
It asks whether the application ITSELF attributes the object to somebody other than
the caller, which is a sharper question than the existing `idor` evaluator's body
comparison can ask of an API — every JSON response carries ids and timestamps, so
two identities never produce identical bytes and a hash differential is noise.

Four clauses, each verified load-bearing by removing it and watching its own tests
fail: the caller gets the object and an owner IS asserted; that owner is not the
caller's **operator-declared** id; the declared owner can read it too; and an
anonymous request is refused. The asymmetry is the safety property — who the caller
is comes from the operator, the asserted owner comes from the target, so a target
can cost itself coverage and cannot manufacture a finding.

Validated against Juice Shop v17.1.1 with two seeded principals, and against a
fixture written to forge ownership:

    jim (2) reads admin's basket 1     FINDING     anon refused 401
    admin (1) reads jim's basket 2     FINDING     anon refused 401
    each reading their OWN basket      no finding  caller owns it
    GET /rest/basket/99999             no finding  200 + {"data":null}
    GET /api/Products                  no finding  asserts no owner
    a fixture asserting UserId 1 to
      everyone, anonymous included     no finding  published, not leaked

That last row is the clause that stops a target choosing its own finding. Without
it the lane reports a critical authorization leak on content the application
publishes deliberately.

**Two live defects fixed on the way, both the same shape as ones already fixed:**

- `inventory.seeds()` applied no source filter, and `ZapAdapter.run` passes its
  output into a ZAP **requestor** job — a list of URLs ZAP is told to GET. So
  `/vulnerabilities/csrf/?Change=Change`, which sets DVWA's admin password to the
  md5 of an empty string, was still reachable. It had been fixed twice, at the two
  call sites known about; the guard now lives in the producer, so a fourth caller
  is safe by default and has to ask to be unsafe.
- The typed `idor` evaluator compared `low_priv_token != high_priv_token`. On a
  cookie-authenticated application both are None, `None != None` is False, and the
  evaluator could never fire on the one lab target the project measures against.
  Same bearer-only assumption AUTHZ-04's YAML case was already corrected for — the
  fix had reached the case and not the code beside it.
- `form_endpoint` bounded its companion query with a character slice, which cut the
  last pair mid-value and dropped the submit control entirely. A 700-byte hidden
  field produced a probe carrying a value the application never emitted, unable to
  reach the handler. Bounded by whole pairs now, submit control first.

**Not done, and deliberately:** E-007's full schema (operations, observations and
coverage tables with attempted/verified/blocked states), E-010's preview, and the
function-level half of E-011. E-027 to E-030 record what the audit found and did
not fix, with the measurements.

## 13. Decisions to revisit before expansion

Planning defaults: web/API assessments first; self-hosted services; single operator;
operator-assisted login; local processing of sensitive inputs; explicit external
exports. Automated SSO refresh, team access, distributed workers, bidirectional
DefectDojo triage, and infrastructure-wide testing remain deferred decisions.

Before committing to later releases, establish which user segment matters most
(internal application team, consultancy, or research lab), available engineering
capacity, typical application/authentication patterns, evidence retention needs,
and whether source repositories are normally available. Use those answers and the
measured coverage gaps to choose the next integration rather than tool popularity.
