# Integration assessments

Approved input: the integration roadmap supplied in this task on 2026-09-06.

## Outcome

Add optional ZAP, Schemathesis, Interactsh and Katana assessment stages plus
explicit DefectDojo export to the existing single-operator Erlik application.
Expose one validated pipeline to REST and deterministic callers. Preserve
historical sessions and toolset presets.

## Decisions

- Target lab and authorized client applications; self-hosted services only.
- Require explicit scan hosts and ports; login/callback/reporting service access
  never expands scanner scope. HTTP(S) workers use an enforcing proxy on an
  internal Docker network; unsupported traffic fails closed.
- Discovery/passive checks default on; active and selected state-changing API
  workflows require per-assessment selection.
- Named credentials and browser state live in restricted files. Authentication
  checks pause stages on expiry; replacement resumes only uncompleted work.
- Preserve full redacted evidence, stable finding IDs, confidence and basis.
- Treat ordinary scanner alerts as suspected, callbacks as likely, and explicit
  reproduced security assertions as confirmed.
- Use bounded sequential scanner execution, restart interruption handling, and
  real job cancellation. Optional model summaries cannot independently run tools.
- DefectDojo export is explicit, retains stable IDs, never closes absent findings,
  and refuses blind retry after an uncertain remote write.

## Review and validation

Implementation/review map: `docs/integration-roadmap.md`.
Operator setup and API contracts: `docs/integrations.md`.
Run network-free tests and the opt-in Docker acceptance suite before review.
Scope and execution boundary changes require human review before merge; no
self-merge is authorized. Real client environments and Internet callback routing
require operator-provided infrastructure and are distinct from local acceptance.
