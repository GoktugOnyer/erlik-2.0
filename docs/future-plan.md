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

### E-025: an uncertain export can block a destination that was never written to

Found while writing the E-006 export documentation, and pinned by
`test_a_local_failure_before_any_request_is_uncertain_and_blocks`.

`export()` marks the row `uncertain` from `except (Exception, CancelledError)`,
which fires for failures raised before a single request leaves the machine — the
sandbox not starting because Docker is down, a cancelled run. The row then blocks
that destination like any other uncertain write, and reconciliation cannot clear
it: reconcile verifies the intended findings against the remote test, and a remote
that never received them answers `Remote state differs`. Every later export to
that destination is a permanent no-op, so an operator whose Docker daemon hiccuped
is locked out of exporting that assessment with no documented way back.

The narrow fix is to distinguish "no request was ever issued" from "a write may
have landed" — `export()` already tracks `wrote`, and the local-failure branch
does not consult it. `failed` is the honest status when nothing was sent. Worth
confirming there is no path where a request escapes without `wrote` being set
before changing it; the conservative default exists for a reason.

### E-026: the uncertainty block misses the case it most needs to cover

Found alongside E-025, pinned by
`test_a_lost_first_import_does_not_block_a_direct_reimport`.

The block matches an export by destination, or by `remote_test_id` on that
server. A first `import` whose response was lost — the 202, the timeout, the
cancellation — never learns a test ID, so its row carries `remote_test_id = NULL`
and only the byte-identical body is blocked. The operator who does what the
documentation advises (find the test in the DefectDojo UI, then reimport into it
by ID) is not blocked, and writes a changed report over a write whose outcome
nobody established. That is the exact papering-over the block exists to prevent,
in the exact scenario it was written for.

A destination-level guard would cover it: an uncertain row for engagement E should
block exports to any test under E for that session, not only to the destination
hash. Note this interacts with E-025 — fix that first, or the wider block will
lock out more operators, not fewer.

### E-027: the shipped AUTHZ-04 check has measured false positives

Found while starting Increment 3, by running the case's own bash command against
the live lab rather than reading it. Scored over 26 requests on Juice Shop and
DVWA: **7 false positives out of 19 negative controls, and 1 false negative out of
7 real violations.** A four-clause marker differential scored 1 and 0 on the same
requests.

The check hashes a normalised whole body for three arms and concludes
`low == high` is an IDOR. That fires on anything two identities legitimately see
the same: `GET /api/Cards` returns `{"data":[]}` to both, `/rest/wallet/balance`
returns `{"data":0}`, `/rest/basket/99999` returns `{"data":null}`. It misses
DVWA's real function-level flaw at `security=low`, because DVWA prints the
username in the page chrome so the two arms' hashes differ and it reports OK.

Four clauses were proposed. An adversarial pass reproduced the 7/1 scoring
independently and then ablated them, which the original scoring script never did:
**only two of the four are supported by the corpus.** Dropping the anonymous clause
costs 7 more false positives (1 -> 8); dropping the liveness clause and dropping
the denial-marker half both leave the score unchanged at 1 and 0. So the
load-bearing pair is: the owner arm must carry the declared marker, and the
anonymous arm must not.

The other two are still probably right and are simply not yet *measured* — the
corpus passes `live` on only 7 of 26 rows, so it cannot exercise that clause. The
denial marker is real regardless: DVWA denies with **HTTP 200** and
`{"result":"fail","error":"Access denied"}`, measured as gordonb at `impossible`,
so a 2xx gate is not enough for any check that relies on status.

Two implementation blockers the same pass found, both of which change the shape of
the fix: WSTG-AUTHZ-04 **cannot run in the assessment lane at all** — its step is
`bash -c`, which the curl dialect refuses — and every JSON marker the proposal uses
is rejected by the declaration gate, because `"` is a shell metacharacter and
declared values are validated for safe rendering into a `bash -c` template. A
marker-based fix therefore needs a non-shell step shape first.

The `ownership` evaluator added in Increment 3 covers the object-level half for
APIs that assert an owner, and by construction refuses four of those seven false
positives. It does not replace the body-hash case for applications that assert no
ownership anywhere, which is what this item is for.

### E-028: AUTHZ-04's anonymous control arm runs at a different configuration

The same defect as the 2026-09-10 arm divergence, inside the case meant to be the
control. DVWA's security level travels in a cookie, and the case's anonymous fetch
is `curl -s "$U"` with no `-b` — so on DVWA the anonymous arm is evaluated at a
different application configuration from the two authenticated arms. Measured:
same PHPSESSID, `security=low` returns the full user table, `security` absent
returns `Access denied`.

Every arm of a differential has to carry the same configuration material, with the
identity as the only variable. Fixing this is a prerequisite for E-027's scoring
to mean anything.

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

### E-030: fork points an operation-level identity does not absorb

From the same audit, and recorded because each is a measured string rather than a
worry. The operation key added in Increment 3 absorbs the
companion-value family entirely — the arms move from **1 of 8 shared
(url, parameter) pairs to 6 of 8**, and both residuals are genuine application
differences. These are what remains:

- **The form's method changes with state.** `/vulnerabilities/brute/` is a GET form
  at `low` and a POST form at `impossible`, so `form_endpoint` returns None in one
  arm and the brute-force surface does not exist there. A genuine difference, but
  the inventory cannot yet say "same operation, the method moved".
- **The control set changes with state.** `/vulnerabilities/csrf/` gains a
  `password_current` input at `impossible`; `/vulnerabilities/csp/` loses its only
  named input. Genuine, and E-008 asks that expected and unexpected differences be
  distinguishable rather than normalised away.
- **`MAX_FORM_PARAMETERS` is applied in DOM order**, so a control inserted at the
  front in one arm pushes a different one off the end. No DVWA form has 11
  testable controls, so this did not fire; it is a cap interacting with render
  order, not a property of the application.
- **A companion-free form URL collides with the crawled page URL**, and the row
  key has no `source` column, so the two merge and `sources` becomes a union — in
  one arm only. The token's ABSENCE forks the reading arms in the opposite
  direction from its presence.
- **A state-dependent PATH survives normalisation.** Measured:
  `/vulnerabilities/csp/source/impossible.js` exists in one arm only, and
  `base_url` strips only the query. Locale prefixes, tenant prefixes and per-user
  ids are the general class.
- **Nothing refuses a session-destroying link** except the proxy's
  `excluded_paths` prefix match, default `['/logout','/signout']`. `/users/sign_out`
  and `/Account/LogOff` are visited, and an arm whose session dies mid-crawl
  discovers only login forms afterwards.
- **The page-visit cap hides arm asymmetry rather than merely truncating.** The
  first audit concluded the 20-page cap "did not fire on DVWA" because both arms
  publish identical menus. An adversarial pass measured the opposite with the
  ordinary crawl root `/` rather than `/index.php`: the cap lands one link later,
  `/vulnerabilities/cryptography/` IS visited, and at `impossible` it is a GET form
  whose only control is a `token` textarea — a second impossible-only operation
  that the first measurement's root spelling hid. The cap firing identically in
  both arms is the worse case, not the benign one, because the asymmetry it
  conceals is real.
- **Schema-derived operations are not fork-free either.** `SchemaInput` accepts a
  URL as well as inline content, and `schema_file` fetches that document through
  the egress proxy — which injects the identity's headers and cookies on every
  request to the target origin. A target serving a different OpenAPI document per
  role forks the schema-derived operations exactly as a rendered form does. Only
  an operator-supplied inline `content` is genuinely identity-independent.

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
