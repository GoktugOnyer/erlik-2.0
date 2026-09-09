# Integration implementation and review map

The approved roadmap is implemented as optional assessment stages, independent of
the historical LLM toolset presets. Review in this order:

1. **Foundation:** contracts, egress policy/proxy, Docker job lifecycle, secrets,
   storage, access middleware, and runner evaluator regressions.
2. **ZAP:** generated Automation Framework plans, proxy configuration, JSON alerts.
3. **Schemathesis:** schemas, seeded reproduction, workflows, explicit assertions.
4. **Interactsh:** private service registration, unique probe payloads, Nuclei
   templates, callback collection and correlation.
5. **Katana:** bounded discovery and shared endpoint inventory.
6. **DefectDojo:** stable IDs, explicit reimport, uncertain-write handling.
7. **Application:** REST lifecycle, credentials, dashboard, CLI, acceptance suite.

Scope and execution changes require human review before merge. No merge or
external service configuration is performed by the implementation itself.

## Acceptance tracking

### Local validation — 2026-09-07

After rebuilding both integration images, the complete suite passed:
`ERLIK_DOCKER_TESTS=1 python -m pytest -q` — **138 passed in 109.30 seconds**
(122 network-free tests and 16 Docker acceptance tests). Two upstream
Starlette/AnyIO deprecation warnings remain. Python compilation and
`git diff --check` also passed. The dashboard was inspected in a local browser.

The final regression includes origin-bound workflow operations, target base
paths, and single-segment path parameters. An earlier test run overlapped this
signature change and failed; the fresh complete run above supersedes it.

The [discovery comparison](integration-discovery-comparison.json) records five
Katana endpoints versus two from the existing crawler on the fixed local fixture,
including the seeded JavaScript-only route. This measures reported discovery
coverage, not vulnerability precision or recall. Interactsh and DefectDojo use
local HTTPS protocol fixtures in acceptance tests; validation against deployed
self-hosted installations and authorized client environments remains outstanding.

Run `pytest -m 'not docker'` for network-free tests. Run the optional Docker suite
as documented in `integrations.md`. A scanner's availability is not its acceptance:
its parser, observed traffic, cancellation, and evidence must all pass.

Historic benchmark outputs are not rewritten. New baseline measurements belong
to a separate report and include the pinned scanner/image versions, schema and
template hashes, endpoint inventory, expected findings, request counts, runtime,
and false positives. Missing client credentials or public callback infrastructure
must appear as untested coverage, never as a passing security result.

### Lab baseline — 2026-09-09

The first such report is
[measurements/2026-09-09-lab-baseline.md](measurements/2026-09-09-lab-baseline.md):
the lane run against Juice Shop v17.1.1 and DVWA, both local lab containers.

Headline: the plumbing works end to end and produced **no false positives**,
but recall is the weak side and the limit is not the scanners. On Juice Shop it
discovered 120 endpoints and 3 parameters, sent 69 probes with none blocked,
and every zero that was checked by hand was a true negative — while missing a
KNOWN open redirect on a parameter it did probe, for want of an
allow-list-bypass payload shape. On DVWA it discovered nothing at all, because
katana emits no output there and neither crawler submits a form; that run is
recorded as untested coverage, not as a clean result.

Measuring against real applications found four defects a fixture could not: a
timing-out stage discarded everything it had found, the first broad case
consumed the whole URL budget and starved the targeted probes, an empty
discovery stage reported `completed`, and the catalogue's per-request cost is a
container start. All four are fixed in the same branch.

### Blind injection — 2026-09-09

[measurements/2026-09-09-blind-injection.md](measurements/2026-09-09-blind-injection.md)
covers the two cases added for the gap the baseline named: an injection that
emits no error was invisible to a lane whose evaluators all read one response.
`WSTG-INPV-05.3` decides from a boolean differential and `WSTG-INPV-05.4` from
a caused delay, both against a control pair that says when the comparison is
admissible at all.

That control is not ceremony. Juice Shop's 404 handler renders the request path
into the page, so any two probes differ — a differential without a validity
control reports SQL injection on every unmatched route of the application.
Measured: DVWA's `sqli_blind` fires both cases at `security=low` and neither at
`impossible`; ninety requests across five Juice Shop endpoints produced nothing.

The payload set is bounded by what could be run against a real engine. There is
no `OR` payload because one was measured sleeping once per row — five sleeps
for a five-row table — which against a real table is a denial of service
delivered by a scanner. There is no MSSQL or Oracle payload because the lab has
neither to validate against.
