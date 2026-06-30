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

The MIT license requires that the copyright notice and permission notice be
retained in copies or substantial portions. Adapted source files carry an
attribution header pointing here.
