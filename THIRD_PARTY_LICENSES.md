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

## elementalsouls/Claude-BugHunter (CC BY 4.0 content, MIT code)

- Source: https://github.com/elementalsouls/Claude-BugHunter
- Author: Sachin Sharma
- Content licence: **CC BY 4.0** — https://creativecommons.org/licenses/by/4.0/
- Code licence: MIT, Copyright (c) 2026 Sachin Sharma

| erlik-2.0 path | Vendored from | Notes |
|----------------|---------------|-------|
| `skills_catalog/skills/bughunter/*.md` (100 files) | `skills/**/ *.md` | Every skill in the upstream repo — 57 `hunt-<class>` methodologies plus reporting, triage, methodology, OSINT and platform-chain skills. Text unmodified; only the layout was flattened (`<name>/SKILL.md` → `<name>.md`) so `orchestrator/skills.py` indexes them. See [`skills_catalog/skills/bughunter/NOTICE.md`](skills_catalog/skills/bughunter/NOTICE.md). |

CC BY 4.0 permits commercial use and redistribution inside an MIT project
provided attribution is given and modifications are indicated — both are
satisfied by this entry and the NOTICE file. This differs from HackTricks
(CC BY-**NC**), whose NonCommercial clause is incompatible with erlik's MIT
grant and which is therefore referenced by index only, never vendored.

These files are a corpus the router SELECTS from, not text injected wholesale:
any session receives a few excerpts under a character budget. Growing the pool
does not grow what a run receives.

## Runtime tools (invoked, not vendored)

erlik can shell out to external scanners it does not bundle. Their code is not
included or redistributed here; you install them yourself.

| Tool | License | Used by | Notes |
|------|---------|---------|-------|
| [OWASP Nettacker](https://github.com/OWASP/Nettacker) | Apache-2.0 | `orchestrator/integrations/nettacker.py` | Optional deterministic pre-scan. erlik builds a CLI invocation and parses Nettacker's JSON output; no Nettacker source is vendored. Enable with `ERLIK_NETTACKER=1`. |

## HackTricks (referenced, deliberately NOT vendored)

- Source: https://github.com/carlospolop/hacktricks — Carlos Polop
- License: **CC BY-NC 4.0** (Attribution-**NonCommercial**) —
  https://creativecommons.org/licenses/by-nc/4.0/

erlik is MIT. HackTricks is NonCommercial. Those terms are incompatible: copying
HackTricks prose into this repository would publish NC-restricted material under
an MIT grant and silently bind anyone using erlik commercially to terms this
project did not choose. So **no HackTricks text is vendored here**, and none ever
should be — that is a licensing constraint, not a stylistic preference.

What *is* committed is a derived index of **facts** about each technique:

| erlik-2.0 file | Contains | Why this is not the licensed work |
|----------------|----------|-----------------------------------|
| `techniques_catalog/index.yaml` | environment, TCP/UDP ports, page title, routing tags, citation URL | Facts and citations. Ports and section names are not authored expression; titles are short factual headings. No sentence of HackTricks prose appears. |
| `scripts/build_techniques_index.py` | the generator | erlik's own code. Re-derives the index from any clone; records the upstream commit so a result ties to an exact corpus revision. |
| `orchestrator/techniques.py` | the router | erlik's own code. Reads body text at run time from the operator's own clone. |

Technique **body text** is read at run time from a clone the operator obtains
themselves, located via `ERLIK_HACKTRICKS_PATH`. It is never copied into the
repository, never committed, and never redistributed. With no clone configured
the router degrades to titles plus citation URLs — the MIT-safe subset —
and `tests/test_techniques.py` pins that behaviour so the separation cannot
regress unnoticed.

Attribution is carried into every injected block (author, licence, upstream URL)
as CC BY-NC requires of any use.

Regenerate the index after pulling a newer corpus:

```bash
python scripts/build_techniques_index.py --hacktricks /path/to/hacktricks
```

Deterministic test cases under `tests_catalog/wstg/` that were informed by a
HackTricks technique cite the page in their `references:` field. Their probe
logic is erlik's own expression of a publicly documented technique; the
underlying techniques (a header name, a protocol behaviour, a well-known payload
string) are facts, not the licensed text.
