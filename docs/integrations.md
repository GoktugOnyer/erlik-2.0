# Integration assessments

Erlik's optional integration pipeline runs locally in Docker. Existing sessions
and toolset presets do not enable these integrations automatically.

## Installation

```sh
pip install -r requirements-dev.txt
docker compose -f docker-compose.integrations.yml --profile integrations build
docker pull ghcr.io/zaproxy/zaproxy:2.16.1
export ERLIK_API_TOKEN='replace-with-a-long-random-token'
./run.sh
```

Open `/integrations` and authenticate with that token. HTTP data routes and
WebSockets share the same authentication boundary. The browser receives a
SameSite Strict, HttpOnly session cookie; API clients can use `X-API-Token` or
`Authorization: Bearer ...`. Keep the application on loopback or behind TLS.

Scanner workers join a unique **internal** network with no direct egress. A
separate MITM proxy joins that network and the configured target/egress network;
only the proxy can reach target hosts. Its CA is generated per job and mounted
into the worker. CONNECT destinations, HTTP requests, redirects and schema
references are checked. Non-HTTP and WebSocket scanning are unsupported.

For a Docker lab, set `ERLIK_INTEGRATION_EGRESS_NETWORK` to the existing target
network name (inspect with `docker network ls`). Use container DNS names in both
the target and scope; `localhost` inside the proxy is not the host machine.
For external targets the default egress network is `bridge`.
For an internal PKI, `ERLIK_INTEGRATION_CA_FILE` may point to an explicitly trusted
PEM CA bundle. Upstream TLS verification remains enabled.

## Assessment configuration

POST `/api/sessions` with `target_url` and `integration_config`; then POST
`/api/sessions/{id}/start`. Example:

```json
{
  "target_url": "https://app.example.com",
  "integration_config": {
    "scope": {"allow_hosts": ["app.example.com"], "allow_ports": [443]},
    "stages": ["katana", "zap"],
    "active": false,
    "state_changing": false,
    "budget": {"requests_per_second": 5, "concurrency": 2,
               "stage_seconds": 600, "assessment_seconds": 1800}
  }
}
```

Discovery excludes `/logout` and `/signout` by default. Configure additional
excluded paths for application-specific side effects. An allowed GET can still
change state in a poorly designed application; discovery is not a guarantee of
zero side effects.

Add `schemathesis` with `active: true` and `schema_input` containing `kind`
(`openapi` or `graphql`) and exactly one of `url` or `content`. Remote schema
references must remain in scope. Local filesystem references are refused.
State-changing OpenAPI workflows require `state_changing: true` and a `workflow`
with exact `operations` IDs, `fixtures`, and `cleanup` request lists. Each request
contains URL, method, optional JSON body, expected status, and optional body
substring assertion. Cleanup failures and interrupted workflows require inspection;
Erlik never silently replays them on restart.

Schemathesis contract failures are observations. Optional `security_assertions`
establish specific authorization violations using an identity, GET request,
description, and forbidden-content marker. Ordinary scanner alerts remain
suspected; correlated callbacks are likely; confirmed findings require an explicit
reproduced security assertion.

## Authentication

POST `/api/integrations/identities` with a named profile:

```json
{
  "name": "reader",
  "target_origin": "https://app.example.com",
  "headers": {"Authorization": "Bearer YOUR_TOKEN"},
  "check": {"url": "https://app.example.com/me", "expected_status": 200,
            "body_contains": "reader"}
}
```

Use its returned opaque ID in `identity_ids`. Cookie lists and Playwright
`storage_state` are accepted. Profiles live in mode-0600 files beneath
`ERLIK_INTEGRATION_DATA` (default `data/integrations`), never in SQLite. API tokens
for callback/reporting services use POST `/api/integrations/secrets`; there is no
secret-read endpoint. Protect and back up this runtime directory as sensitive data.

For operator-assisted login, install `requirements-browser-login.txt` and run:

```sh
python -m playwright install chromium
python -m orchestrator.integrations.cli login --config assessment.json \
  --identity identity.json --output authenticated-profile.json \
  --login-origin https://login.example.com
```

Complete login/MFA in the headed browser and press Enter. Upload the resulting
profile through the integration dashboard. Additional login origins are allowed
only for this login browser, not for assessment scanning. The helper saves a
redacted audit alongside the profile. Keep both files outside Git.

If a stage reports `needs_auth`, replace the profile with PUT
`/api/integrations/identities/{id}` and start the session again. Completed stages
are not replayed. No unattended SSO/refresh automation is included.

## Self-hosted Interactsh

Operate an Interactsh server with valid HTTPS and an authoritative callback
domain reachable from the assessed target. Supply its explicit HTTPS origin,
optional secret reference, callback grace period, and probes:

```json
{"server":"https://oast.example.com","secret_id":"OPAQUE_ID",
 "grace_seconds":60,
 "probes":[{"url":"https://app.example.com/fetch","parameter":"url"}]}
```

Select `interactsh` and active testing. The collector registers before discovery;
Nuclei sends generated GET probes using per-probe payloads, with its automatic
Interactsh registration disabled. No public-service fallback is permitted. A DNS
callback establishes interaction, not access to sensitive internal resources.

## Operations, and comparing two identities

The lane records the concrete URLs it discovered, and groups them into
**operations**. An operation is identified by what can be injected into it — origin,
path, method and the testable parameter names — and *not* by the rest of the query.

That distinction is not cosmetic. DVWA puts a single-use `user_token` in its forms
at `security=impossible`, and discovery bakes companion fields into the URL, so the
same form produced a different URL string on every observation. Two identities
therefore produced two unrelated rows for one form, and a differential between them
compared two surfaces rather than one variable. Keyed on the injectable surface,
both arms resolve to one operation while `GET` and `POST`, two paths, and two
different input sets all stay separate.

Nothing is discarded: every concrete URL stays as an observation beneath its
operation, tagged with the identity that saw it, so the token one arm was served is
still visible.

### Comparing two arms

`inventory.compare_arms(session_id, first, second)` answers whether two identities
describe the same surface. It reports the operations only one arm saw, and refuses
four situations outright:

| Refusal | Meaning |
|---|---|
| `arms_share_one_identity` | an identity compared with itself agrees perfectly and proves nothing |
| `different_operations` | one arm reached something the other never did |
| `per_arm_value_in_operation` | both arms reached the operation, at **different URLs** — each issued its own request |
| `no_shared_operations` | two arms that discovered nothing agree vacuously |

**What a pass establishes, and what it does not.** `comparable: true` means the two
arms describe the same surface. It says nothing about whether either arm *reached*
it. A live run was measured scoring a perfect shared-surface fraction while all
eight of its probe sets received zero bytes, so treating surface agreement as
differential validity reproduces the defect this comparison exists to catch. The
returned record states this in its `establishes` field.

Relatedly: a refused probe is not an empty one. DVWA answers a request missing its
token with HTTP 200 and 389 bytes of PHP warnings, so the lane's
`test_case_unreachable` observation — which fires when every executed step came back
empty — does not fire on a refusal.

### Choosing a second identity

Two principals at the **same** configuration, not two configurations. DVWA's
`security` cookie is a security level rather than a principal, and at `impossible`
its forms require a single-use token the lane does not refresh, so that arm never
reaches the code being compared and its zero findings are vacuous. Measured: admin
and gordonb, both at `security=low`, produce `/vulnerabilities/sqli/?Submit=Submit`
byte for byte — so the only variable is who made the request.

## Object-level authorization

The `ownership` evaluator asks whether the application itself attributes an object
to somebody other than the caller. On an API that is a sharper question than
comparing response bodies: every JSON response carries ids and timestamps, so two
identities never produce identical bytes and a body differential is noise.

A case declares it like this:

```yaml
evaluators:
  - type: ownership
    owner_field: data.UserId      # where the response names the owner
    owner_step: read_as_owner     # the step that re-reads it as that owner
    anonymous_step: read_anonymously
    emit_finding:
      vuln_type: Broken Object Level Authorization
      severity: high
```

and the operator supplies `subject_id` — who the caller *is* — in the target. All
four clauses must hold for a finding:

1. the caller got the object, and the response **asserts** an owner;
2. that owner is not the caller's declared `subject_id`;
3. the declared owner can read the object too, so the claim is corroborated;
4. an anonymous request is **refused**, so the content is not published.

The asymmetry is the safety property. `subject_id` comes from the operator; the
asserted owner comes from the target. A target can therefore push the lane towards
"this is not yours" and never towards "this is yours" — it can cost itself coverage
and cannot manufacture a finding. Clause 4 closes the remaining gap: a page that
asserts one owner to every caller, anonymous included, is published content however
it is attributed, and without that clause the lane would report it as a critical
leak.

Validated against Juice Shop v17.1.1 and against a fixture written to forge
ownership:

| Request | Verdict |
|---|---|
| `GET /rest/basket/1` as user 2 | **finding** — attributed to user 1, anonymous refused 401 |
| `GET /rest/basket/2` as user 2 | no finding — the caller owns it |
| `GET /rest/basket/99999` | no finding — HTTP 200 with `{"data":null}`, no object |
| `GET /api/Products` | no finding — asserts no owner |
| a fixture asserting one owner to everyone | no finding — published, not leaked |

The third row is why E-011 says "not merely HTTP 200": a nonexistent object answers
200, and a status-code check calls that a critical flaw.

**Limits.** It needs the application to name an owner in the response. Indirect
ownership — Juice Shop's `/api/BasketItems/9` names a `BasketId` and no user — is
not covered, nor is function-level authorization, where there is no object to
attribute. A caller whose session has expired asserts no owner either, so it
produces no finding rather than an explicit "could not test".

## DefectDojo

Export is always explicit — no stage writes to DefectDojo on its own. Findings are
matched by a stable fingerprint rather than a report-local ID, so a second export
updates what it already sent instead of duplicating it. `close_old_findings` is
always false in v1, including for complete scans, and Erlik never imports remote
triage: the local review state is authoritative and is pushed outward, never read
back.

The server must be an explicit HTTPS **origin** — scheme, host and optional port,
nothing else. A `http://` URL, a path (`https://dojo.example.com/dojo`), a query,
or credentials in the URL are all refused at validation. `:443` is accepted and
normalised away; any other port is kept, so a DefectDojo on `https://dojo:8443`
needs no fronting (that is what the project's own live acceptance test uses).

### Registering the API token

The token never travels in the export body. Store it once and refer to it by
handle:

```sh
curl -sX POST http://127.0.0.1:8002/api/integrations/secrets \
  -H "X-API-Token: $ERLIK_API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"token":"<DefectDojo API v2 key>"}'
# -> {"id":"e9082a26d4a1e8d1b923316f2e884ccb"}   a 32-character handle
#    Use it as secret_id below. The token itself is never echoed back, never
#    stored in the export record, and is redacted from the audit evidence.
```

### First import

A first import creates the test inside an engagement that already exists. It needs
`engagement_id` and `test_title`, and must **not** carry a `test_id`:

```json
{
  "server": "https://dojo.lab.internal",
  "secret_id": "e9082a26d4a1e8d1b923316f2e884ccb",
  "action": "import",
  "engagement_id": 7,
  "test_title": "Erlik assessment 2026-09-10"
}
```

```sh
curl -sX POST http://127.0.0.1:8002/api/integrations/sessions/$SESSION/defectdojo \
  -H "X-API-Token: $ERLIK_API_TOKEN" -H 'Content-Type: application/json' \
  --data @first-import.json
```

`action` defaults to `reimport`, so **omitting it on a first import is refused**,
not silently treated as one:

| Body | Result |
|------|--------|
| `action: "import"` + `engagement_id` + `test_title` | accepted |
| `engagement_id` + `test_title`, no `action` | `reimport requires an existing test_id, without engagement_id or test_title` |
| `action: "import"` + `engagement_id` + `test_title` + `test_id` | `initial import requires an existing engagement_id and test_title, without test_id` |
| `action: "reimport"` + `test_id` | accepted |
| `action: "reimport"` + `test_id` + `engagement_id` | `reimport requires an existing test_id, without engagement_id or test_title` |

The engagement must already exist: `auto_create_context` is sent as `false`, so
Erlik will not conjure a product or engagement to import into.

### Re-exporting the same session

**The same body works again.** A successful import records the destination it
reached together with the remote test ID, so a repeat export of that destination
resolves the remote test from that record and reimports into it — the operator
does not have to rewrite the configuration after the first run. Only fingerprints
the remote test does not already hold are sent to the importer; everything else is
compared field by field and PATCHed by remote ID only where it actually differs.

If the report is byte-identical to the last completed export to that destination,
nothing is sent at all and the previous export record is returned.

To reimport into a test whose ID you know — one created by hand, or one from a
different session — address it directly:

```json
{
  "server": "https://dojo.lab.internal",
  "secret_id": "e9082a26d4a1e8d1b923316f2e884ccb",
  "action": "reimport",
  "test_id": 42
}
```

### Reconciling an uncertain export

What the status means:

| Status | Meaning | What to do |
|--------|---------|------------|
| `completed` | Every field Erlik reads back is present remotely | nothing |
| `failed` | Nothing was written, and the destination is not blocked | fix the body or the token and export again |
| `uncertain` | The outcome of a write is unknown — **or the export failed locally before sending anything** | reconcile, or see below |

`completed` is about the fields that are read back, which is not all of them: a
finding's `endpoints` are never compared after the import, and `title` is matched
case-insensitively against its first 511 characters because DefectDojo titlecases
and truncates it. So `completed` does not by itself tell you the URL a finding is
about arrived intact.

`uncertain` also covers a failure that sent **nothing** — the sandbox not starting
because Docker is down, or a cancelled run. The row records
`Check the remote test before retrying`, and it blocks that destination like any
other uncertain row. Reconciliation cannot clear it: there is no remote write to
verify, so it answers `Remote state differs from intended export` and the row
stays blocked. Such a row has to be inspected and cleared directly. This is a
known sharp edge rather than intended design — it is recorded in
`docs/future-plan.md`.

A 202 is uncertain, not successful: the import was queued, and nothing has
confirmed it landed. Treating it as a failure would invite a retry that silently
imports twice.

#### What "blocks" actually covers

An uncertain write is never retried automatically, and it blocks further exports —
but the block is narrower than it sounds, and the gap is in the case this section
exists for.

It matches an export whose destination is the same, or whose remote test ID is the
same on that server. **An import whose response was lost never learned a test ID**,
so its row carries `remote_test_id = NULL` and only a repeat of the identical body
is blocked. Do what the rest of this section advises — find the test in the
DefectDojo UI and address it directly with `action: "reimport"` and its `test_id` —
and that export is *not* blocked. It will write, over a write nobody established.

**Reconcile the uncertain row before addressing the test directly.** Measured, not
inferred: `test_a_lost_first_import_does_not_block_a_direct_reimport` in
`tests/test_defectdojo_completion.py` pins it, and `docs/future-plan.md` carries it
as E-026.

`failed` is narrower than "the remote said no", and the difference is worth
knowing before you wait on a reconcile you do not need:

- A **read** that fails — the inventory GET, say — wrote nothing, so the export
  is `failed` and you can simply export again.
- A **first import** whose POST is rejected 4xx is also `failed`: that POST was
  the first request made, so nothing preceded it.
- A **reimport** whose POST is rejected 4xx is `uncertain`, even though a 4xx
  means nothing was written. A reimport reads the remote inventory before
  writing, and once any request has gone out the lane stops inferring from a
  status code the remote chose that no partial processing happened. It blocks
  until someone looks. This asymmetry is deliberate; both sides are pinned in
  `tests/test_defectdojo_completion.py`.

Reconciliation is **read-only**. It lists the remote test's findings, compares
them against the evidence recorded for that export, and marks the export completed
only if every intended finding is present and matching. No request is replayed.

It requires the remote test ID explicitly, even when the original export was an
`import` — supply the ID you can see in the DefectDojo UI:

```sh
curl -sX POST http://127.0.0.1:8002/api/integrations/exports/$EXPORT_ID/reconcile \
  -H "X-API-Token: $ERLIK_API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"server":"https://dojo.lab.internal","secret_id":"e9082a26d4a1e8d1b923316f2e884ccb",
       "action":"reimport","test_id":42}'
```

The server must match the original export's, and if the export record already
knows a remote test ID, the one supplied must equal it. Two outcomes:

- `Remote state verified; no requests replayed` — status becomes `completed`, the
  fingerprint→remote-ID map is filled in, and exports to that test are unblocked.
- `Remote state differs from intended export; no requests replayed` — the status
  stays `uncertain`. Inspect the remote test yourself; reconciliation will not
  guess which side is right.

Two remote findings sharing one fingerprint is refused —
`Multiple remote findings share one fingerprint; reconcile the remote test`. On
export that lands as the row's `detail`; reconciling returns **502** with the same
message, because the remote is what did not cooperate. It usually means the
importer's own deduplication merged or split findings, and it has to be settled in
DefectDojo before Erlik can map them.

Every export and every reconciliation writes an audit record to the session's
evidence store, with the API token redacted.

## Results and validation

The dashboard provides stages, endpoints, evidence and export records. Existing
JSON, HTML, SARIF and Generic Findings report routes support integration sessions.
Evidence is untruncated but credential-redacted. Temporary raw files are removed
when jobs close. Historical results are unchanged.
After a run, findings can be reviewed as open, false positive, or fixed with a
required note. Reports include open findings; explicit exports carry the local
review state. Review actions are retained as evidence.

```sh
pytest -m 'not docker'                              # network-free, no containers
ERLIK_DOCKER_TESTS=1 pytest -m docker               # every container-backed suite
ERLIK_DOCKER_TESTS=1 ERLIK_BENCHMARK_OUTPUT=/tmp/discovery-comparison.json \
  pytest tests/test_integration_docker.py -k baseline_comparison
```

`-m docker` is the marker, not a filename: the container-backed suites live in
several files, and selecting them by path is how a new one ends up never running.

### Opt-in variables

Every one of these defaults to off. A suite that cannot reach what it needs skips
with a reason rather than failing — missing coverage is not a defect in the code,
and must not be reported as one.

| Variable | Effect |
|----------|--------|
| `ERLIK_DOCKER_TESTS=1` | Run the local container suites. Needs the lane images built. |
| `ERLIK_REAL_INTERACTSH_TESTS=1` | Register against a real self-hosted Interactsh server instead of the protocol fixture. Set it **together with** `ERLIK_DOCKER_TESTS=1` — on its own it skips. Build the lab first: `docker build -t erlik-interactsh-lab:1 docker/interactsh-lab`. |
| `ERLIK_DEFECTDOJO_LIVE_TESTS=1` | Run the export flow against a real DefectDojo, brought up from `docker/defectdojo-lab/`. Sufficient on its own — unlike the Interactsh gate above, it does not also need `ERLIK_DOCKER_TESTS`. No credentials either: the fixture mints the lab's own database password, secret key, AES key and admin password per run and writes them to a compose env-file. It also needs `openssl` on PATH, for the lab's TLS certificate. |
| `ERLIK_COVERAGE_REPORT=<path>` | Write the baseline-vs-integrated benchmark report. Written before the *metric* assertions, so a run that regresses still leaves its numbers behind — but the report is assembled from both arms, so a run that fails because a stage never completed produces none. |
| `ERLIK_BENCHMARK_OUTPUT=<path>` | Write the Katana-vs-browser-crawler discovery comparison. |
| `ERLIK_ACTUAL_SERVICE_TESTS` | Repository **variable** (not an env var) gating the CI job that starts real services. Must be `true`, and the run must be a release or a manual dispatch. |

### Runtime variables

| Variable | Effect |
|----------|--------|
| `ERLIK_API_TOKEN` | Required to reach `/api/integrations/*` at all — these routes are refused without it whether or not the rest of the API is protected. |
| `ERLIK_INTEGRATION_EGRESS_NETWORK` | The Docker network the MITM proxy joins to reach the target. Defaults to `bridge`. |
| `ERLIK_INTEGRATION_CA_FILE` | A PEM bundle to trust for an internal PKI. Upstream TLS verification stays on. |
| `ERLIK_INTEGRATION_DATA` | Where the lane keeps secrets, proxy CAs and evidence. Gitignored; never put it in a tracked path. |

### Pinning a build

`scripts/release_manifest.py` records the image IDs, the versions of the tools
*inside* the worker image, and the commit — the things a benchmark report is
meaningless without six months later:

```sh
python scripts/release_manifest.py --out build-manifest.json
python scripts/release_manifest.py --skip-tools   # skip the in-image probe
```

It reads no configuration, contacts no service, and never touches the evidence
store. An image it cannot find is recorded as absent rather than omitted.

The Docker tests create and remove their own target and recording server. They
check redirect refusal, direct-egress denial, authentication isolation, actual
container cancellation, JS discovery, seeded API failures and authenticated ZAP.
They do not contact client targets. Unit tests cover callback association,
DefectDojo replay behavior, migrations, secrets, HTTP/WebSocket authentication,
and evaluator regressions.
The discovery comparison executes the original `pw-crawl.js` with transport-only
proxy/driver shims against the same fixed fixture as Katana. It compares reported
endpoint inventories, not all requests the browser could reach, and does not
measure vulnerability precision or recall. Client-target and public callback
acceptance are not implied by the local HTTPS protocol fixtures.
