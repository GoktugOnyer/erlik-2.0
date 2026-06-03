# Erlik 2.0

**An automated, methodology-driven web application penetration-testing framework.**

Erlik 2.0 orchestrates industry-standard security tools (the Kali Linux toolset
and OWASP ZAP) against a target web application inside an isolated Docker
network. Test cases are mapped to the **OWASP Web Security Testing Guide
(WSTG)**, so coverage is explicit and reproducible.

---

## Architecture

The framework has two layers:

1. **Deterministic test-case engine (core).**
   Each test case is a YAML file keyed to a WSTG identifier (e.g. `WSTG-INPV-05`
   for SQL injection). It defines a fixed sequence of tool probes and pass/fail
   evaluators (regex / status-code / model-judged). This layer is fully
   reproducible and is what produces findings.

2. **Optional model-reasoning layer.**
   A language model — running locally via **Ollama**, or through any
   **OpenAI-compatible** API endpoint — is used only as a narrow evaluator:
   to judge ambiguous tool output, mutate payloads when a deterministic probe
   misses, and decide which follow-up test case to chain to. The provider is
   selected at run-time.

A **scope guard** enforces an explicit host allow-list before any tool runs — a
command targeting a host outside the authorised scope is refused. This is the
framework's safety floor.

```
orchestrator/
  main.py            FastAPI app + REST API + dashboard
  llm_client.py      Pluggable model backend (Ollama / OpenAI-compatible)
  tool_executor.py   Sandboxed tool execution in the Kali container
  database.py        SQLite persistence
  testcase/          The test-case automation engine
    schema.py        YAML test-case data model
    loader.py        Catalogue loader + validator
    runner.py        Executes a test case, applies evaluators, emits findings
    scope.py         Authorisation scope guard (safety floor)
    chain.py         Chains follow-up test cases (depth/run capped)
    persistence.py   Saves runs + findings
    cli.py           Command-line runner
tests_catalog/wstg/  One YAML test case per WSTG identifier
dashboard/           Web UI
docs/                Methodology + evaluation documentation
```

## Test catalogue (WSTG coverage)

| ID | Test |
|----|------|
| WSTG-INFO-02 | Fingerprint web server |
| WSTG-INFO-03 | Review webserver metafiles |
| WSTG-CONF-07 | Transport-layer security / HSTS |
| WSTG-ATHN-01 | Credentials over encrypted channel |
| WSTG-SESS-10 | JSON Web Token flaws |
| WSTG-AUTHZ-04 | Insecure Direct Object Reference |
| WSTG-INPV-05 | SQL injection |
| WSTG-INPV-19 | Server-Side Request Forgery |
| WSTG-BUSL-04 | Process timing / race condition |

## Quick start

```bash
# 1. Bring up the lab (target + ZAP + Kali tools + orchestrator)
docker compose up -d

# 2. List the test catalogue
python -m orchestrator.testcase.cli list

# 3. Run a single test case against an authorised target
python -m orchestrator.testcase.cli run WSTG-INPV-05 \
    --target url=http://localhost:3000/rest/products/search \
    --target parameter=q \
    --scope localhost

# 4. Run a test case and auto-follow its chain
python -m orchestrator.testcase.cli chain WSTG-INPV-05 \
    --target url=http://localhost:3000/rest/products/search \
    --target parameter=q \
    --scope localhost
```

### Selecting a model provider

```bash
# Local inference (default)
export ERLIK_LLM_PROVIDER=ollama

# Remote / OpenAI-compatible endpoint
export ERLIK_LLM_PROVIDER=openai
export OPENAI_API_KEY=...
export OPENAI_BASE_URL=https://api.openai.com/v1   # or any compatible gateway
export ERLIK_LLM_MODEL=gpt-4o
```

## Authorisation & scope

Every run requires an explicit `--scope` allow-list. The framework refuses to
execute any tool against a host that is not on that list. **Only test systems
you are authorised to assess.**

## Status

Active development. The deterministic engine and WSTG catalogue are
operational; the catalogue is being expanded toward broader WSTG coverage.
