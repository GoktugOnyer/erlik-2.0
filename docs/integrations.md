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

## DefectDojo

Create a test in your self-hosted DefectDojo engagement using Generic Findings
Import. POST `/api/integrations/sessions/{id}/defectdojo` with `server`, `secret_id`
and `test_id`. Export is always explicit. Stable fingerprints replace report-local
IDs; unchanged successful exports are not resent. `close_old_findings` is always
false in v1, including for complete scans. Erlik does not import remote triage.

An uncertain remote write is never automatically retried: inspect the remote test
and the export record before deciding how to reconcile it. A 202 response is
uncertain until the external import has been checked, not claimed successful.

## Results and validation

The dashboard provides stages, endpoints, evidence and export records. Existing
JSON, HTML, SARIF and Generic Findings report routes support integration sessions.
Evidence is untruncated but credential-redacted. Temporary raw files are removed
when jobs close. Historical results are unchanged.
After a run, findings can be reviewed as open, false positive, or fixed with a
required note. Reports include open findings; explicit exports carry the local
review state. Review actions are retained as evidence.

```sh
pytest -m 'not docker'
ERLIK_DOCKER_TESTS=1 pytest tests/test_integration_docker.py
ERLIK_DOCKER_TESTS=1 ERLIK_BENCHMARK_OUTPUT=/tmp/discovery-comparison.json \
  pytest tests/test_integration_docker.py -k baseline_comparison
```

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
