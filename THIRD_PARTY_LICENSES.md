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

The MIT license requires that the copyright notice and permission notice be
retained in copies or substantial portions. Adapted source files carry an
attribution header pointing here.
