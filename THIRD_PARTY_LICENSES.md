# Third-Party Code & Attribution

erlik-2.0 incorporates code adapted from third-party open-source projects.
Each is listed below with its license and the local files derived from it.

## transilienceai/communitytools (MIT)

- Source: https://github.com/transilienceai/communitytools
- License: MIT — full text in [`licenses/communitytools-MIT.txt`](licenses/communitytools-MIT.txt)
- Copyright (c) 2025 Transilience AI

Code in erlik-2.0 adapted from this project:

| erlik-2.0 file | Adapted from | Notes |
|----------------|--------------|-------|
| `orchestrator/enrichment/nvd.py` | `tools/nvd-lookup.py` | NVD CVE lookup reworked into an async, importable `lookup_cve()` using `httpx` with an in-process TTL cache. CVSS/CWE/severity extraction logic retained. |
| `orchestrator/models.py` (`ReportFinding`, `PentestReport`) + report calibration prose in `orchestrator/main.py` | `formats/data.md`, `formats/transilience-report-style/pentest-report.md` (§5, §7) | Pragmatic subset of the `pentest-report.json` schema and a condensed version of the Severity-Calibration rubric. |
| `skills_catalog/**/*.md` | `skills/*/reference/*.md` | Vendored verbatim as a knowledge corpus (injection, server-side, client-side, api-security, authentication, web-app-logic, reconnaissance). See `skills_catalog/NOTICE.md`. |
| `mcp_servers/cve/server.py` | `mcp/transilience-vuln/server.py` | MCP server shell (Server / list_tools / call_tool / stdio bootstrap, the sliding-window RateLimiter, and the disk cache) adapted; the hosted-SaaS backend replaced with erlik's NVD core. |
| `orchestrator/bench/result_types.py`, `orchestrator/bench/results_io.py` | `benchmarks/_shared/result_types.py`, `results_io.py` | Vendored result dataclass + JSON writer (stable schema). |
| `orchestrator/bench/agent_errors.py` | `benchmarks/_shared/agent_errors.py` | Fatal-error classification adapted from subprocess stderr parsing to erlik's httpx LLM error surface (HTTP 429/401/403 + quota/auth text). |

The MIT license requires that the copyright notice and permission notice be
retained in copies or substantial portions. Adapted source files carry an
attribution header pointing here.

## Runtime tools (invoked, not vendored)

erlik can shell out to external scanners it does not bundle. Their code is not
included or redistributed here; you install them yourself.

| Tool | License | Used by | Notes |
|------|---------|---------|-------|
| [OWASP Nettacker](https://github.com/OWASP/Nettacker) | Apache-2.0 | `orchestrator/integrations/nettacker.py` | Optional deterministic pre-scan. erlik builds a CLI invocation and parses Nettacker's JSON output; no Nettacker source is vendored. Enable with `ERLIK_NETTACKER=1`. |
