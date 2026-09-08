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
