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

## WSTG test-case catalogue

32 cases. The **Lane** column is not maintained by hand — it is what
`inventory.executable_test_cases` answers when asked, and a case earns a `yes`
only if *every* one of its steps runs inside the assessment lane's sandbox (see
[Status](#status) for why a partly-runnable case is excluded outright). A case
without one still runs through the agent lane and the CLI.

| ID | Test | Lane |
|----|------|------|
| WSTG-ATHN-01 | Credentials Transported over Encrypted Channel | — |
| WSTG-AUTHZ-01 | Directory Traversal / Local File Include | — |
| WSTG-AUTHZ-04 | Insecure Direct Object References | — |
| WSTG-AUTHZ-05 | OAuth Authorisation Flow Weaknesses | — |
| WSTG-BUSL-04 | Process Timing / Race Condition | — |
| WSTG-BUSL-09 | Unrestricted File Upload | — |
| WSTG-CLNT-04 | Client-side URL Redirect (Open Redirect) | yes |
| WSTG-CLNT-07 | Cross Origin Resource Sharing | yes |
| WSTG-CLNT-07b | CORS null Origin Trust (GET and preflight) | yes |
| WSTG-CLNT-09 | Clickjacking Protection Headers | — |
| WSTG-CONF-02 | Platform Debug and Diagnostic Endpoint Exposure | — |
| WSTG-CONF-04 | Unreferenced Backup, VCS and Build Artifacts | — |
| WSTG-CONF-06 | HTTP Methods | yes |
| WSTG-CONF-07 | Transport Layer Security | — |
| WSTG-ERRH-01 | Improper Error Handling | — |
| WSTG-INFO-02 | Fingerprint Web Server | — |
| WSTG-INFO-03 | Review Webserver Metafiles | yes |
| WSTG-INPV-01 | Reflected Cross-Site Scripting | — |
| WSTG-INPV-05 | SQL Injection | — |
| WSTG-INPV-05.2 | SQL Injection (error-based, single request) | yes |
| WSTG-INPV-05.3 | SQL Injection (blind, boolean differential) | yes |
| WSTG-INPV-05.4 | SQL Injection (blind, time-based) | yes |
| WSTG-INPV-05.6 | NoSQL Operator Injection | — |
| WSTG-INPV-06 | LDAP Injection | — |
| WSTG-INPV-07 | XML External Entity | yes |
| WSTG-INPV-11 | Insecure Deserialization | — |
| WSTG-INPV-11.2 | Injection — unclassified (interpreter error signatures) | yes |
| WSTG-INPV-15 | Hop-by-Hop Header Handling | — |
| WSTG-INPV-18 | Server-Side Template Injection | yes |
| WSTG-INPV-19 | Server-Side Request Forgery | via collector |
| WSTG-SESS-02 | Cookie Attributes | yes |
| WSTG-SESS-10 | JSON Web Token Flaws | — |

## Prerequisites

- **Docker** — runs the lab (target application, OWASP ZAP, and the Kali tools container)
- **Python 3.10+** — runs the orchestrator
- **Ollama** *(optional)* — local LLM for the model-judge steps. The deterministic
  checks work without it. Install from [ollama.com](https://ollama.com), then pull a
  model: `ollama pull qwen2.5-coder:7b`

## Setup

```bash
git clone https://github.com/GoktugOnyer/erlik-2.0.git
cd erlik-2.0

# Scripted (Linux/macOS): virtualenv + dependencies + containers
./setup.sh

# ...or manually:
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
docker compose up -d        # first run builds the Kali tools image (~10–20 min)

# Start the orchestrator — dashboard at http://localhost:8002
./run.sh                    # or: uvicorn orchestrator.main:app --host 127.0.0.1 --port 8002
```

> **Binding:** `run.sh` listens on `127.0.0.1:8002` — the API launches attacks, so it
> is not exposed on the network by default. Override the host and port with
> `ERLIK_HOST` and `ERLIK_PORT`; `ERLIK_RELOAD=1` enables auto-reload for
> development.

Setting `ERLIK_API_TOKEN` protects every `/api/` and `/ws/` path, reads and
WebSocket streams included — the guard is by path, not by method, because GET
stopped being a safe exemption once reports and findings are customer data. The
dashboard exchanges the token for an HttpOnly cookie at `POST /api/auth`, and API
clients send `X-API-Token` or a bearer token; `/api/auth` and `/api/health` are
exempt. Leaving the token unset keeps the base API open, as it has always been —
pair that with the default loopback bind. Integration assessments are the
exception: `/api/integrations/*` and `/ws/integrations/*` are refused whether or
not a token is set, because they expose credential handles and client evidence.
See [SECURITY.md](SECURITY.md).

> **Note:** the first `docker compose up` builds the Kali tools container — it pulls
> the Kali base image and installs the toolset (nmap, sqlmap, nuclei, dalfox,
> jwt_tool, …). This needs internet and takes a while; later runs start instantly.

### The assessment lane (optional)

The steps above do **not** build it. The assessment lane is a second execution
path that runs ZAP, Schemathesis, Katana, Interactsh and a DefectDojo export as
isolated Docker jobs behind a scope-checking egress proxy. It has its own compose
profile and its own images:

```bash
docker compose -f docker-compose.integrations.yml --profile integrations build
docker pull ghcr.io/zaproxy/zaproxy:2.16.1
export ERLIK_API_TOKEN='replace-with-a-long-random-token'
./run.sh                    # dashboard at /integrations
```

`/api/integrations/*` and `/ws/integrations/*` are refused **whether or not**
`ERLIK_API_TOKEN` is set — unlike the base API there is no unauthenticated mode,
because these routes expose credential handles and client evidence. So setting the
token is necessary but not sufficient: every call must also carry it, as
`X-API-Token`, as a bearer token, or as the cookie the dashboard gets from
`POST /api/auth`.

See **[docs/integrations.md](docs/integrations.md)** for scope configuration,
identities, the DefectDojo import and reconcile examples, and every `ERLIK_*`
variable the lane reads.

## Tests

`pytest` is **not** in `requirements.txt` — the runtime install stays lean. The test
dependencies live in `requirements-dev.txt`, which also pulls in the runtime ones:

```bash
pip install -r requirements-dev.txt
pytest                      # must be run from the repo root
```

Neither Docker nor Ollama is needed to run it; it exercises the Python layer
directly, in about a minute.

What it covers has shifted as the project has. A core of it still pins the
functions the published evaluation's numbers derive from — the finding detector,
the finding↔ground-truth matcher, the scope guard — so a refactor that would move
a number in those results turns a test red first. The bulk of it now pins product
behaviour instead: the curl dialect the assessment lane will and will not execute,
the redaction boundary between a target's bytes and a finding's evidence, the
credential store, and the authorisation gates. Those exist because this codebase's
characteristic defect is not a crash but a confident result from a path that did
nothing — so most of these tests are written to fail if the thing they check stops
happening silently.

Run it from the repository root: `conftest.py` anchors the working directory
there, and `orchestrator.main` builds its Jinja2 template path relative to the
CWD.

A **fresh clone** reports **2705 passed, 68 skipped** on its first run, and
2707 passed / 66 skipped on every run after — measured 2026-09-11 against this
commit by cloning and running it, not quoted from a developer's tree.

> Re-measure this after any change under `tests/`. The first draft of this
> paragraph was taken before the same commit finished adding tests, which is
> exactly the staleness it was written to correct.

Every skip is structural rather than broken, and the 68 account for themselves:

| Count | Reason |
|-------|--------|
| 33 | need `data/pentest.db`, the recorded corpus — `.gitignore` excludes `data/` because it holds real client findings (see `docs/REPRODUCIBILITY.md` and `tests/corpus.py`) |
| 32 | container suites, behind `ERLIK_DOCKER_TESTS=1` |
| 3 | need a real external service (Interactsh, DefectDojo) |

A developer's tree reports **2738 passed, 35 skipped** instead, and the 33-test
gap is entirely that corpus: 31 tests report `corpus present but empty`, and 2
more inspect the live database directly — one for a plaintext credential on disk,
the other for leftover fixture rows. Those two are hygiene checks on a real machine, so skipping
where there is no live database is the right answer; it is also why they stop
skipping from the second run onward, once the suite has created one.

The 32 container suites skip on a developer's machine too. They gate on
`ERLIK_DOCKER_TESTS=1` being set, **not** on whether Docker is available — having
the daemon running does not opt you in.

The Docker-gated suites are selected by a marker rather than by filename:

```bash
ERLIK_DOCKER_TESTS=1 pytest -m docker          # the assessment lane's container tests
pytest -m 'not docker'                         # everything else
```

CI runs the network-free suite on 3.10, 3.12 and 3.14, and the `-m docker` suites
on everything except a plain push — pull requests, manual dispatches and releases. `scripts/ci_assert_suite_ran.py` fails a run in
which the suite collapsed to a handful of tests or silently skipped itself — a
green run where nothing executed is the one failure mode a test suite cannot
report on its own.

See `tests/README.md` for what each module covers and for the coverage command.

## Usage

```bash
# List the WSTG test-case catalogue
python -m orchestrator.testcase.cli list

# Run a single test case against an authorised target
python -m orchestrator.testcase.cli run WSTG-INPV-05 \
    --target url=http://localhost:3000/rest/products/search \
    --target parameter=q \
    --scope localhost

# Run a test case and auto-follow its chain
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

## Reproducing the evaluation

The evaluation campaigns were run with local Ollama inference against two
Dockerised targets, scored against a fixed ground-truth catalogue.

```bash
# 1. Bring up the lab and pull the evaluation model
docker compose up -d
ollama pull qwen2.5-coder:7b      # also 14b / 32b

# 2. Point tool execution at the in-network target container
export ERLIK_DOCKER_TARGET_HOST=juice-shop        # reproduces the lab wiring

# 3. Launch the orchestrator
uvicorn orchestrator.main:app --host 127.0.0.1 --port 8002
```

- Targets: OWASP Juice Shop (ground truth = 35) and DVWA (ground truth = 19).
- Models: `qwen2.5-coder` 7B / 14B / 32B (baseline and LoRA fine-tuned variants).
- Findings are scored by the canonical programmatic ground-truth matcher.

Because inference runs at non-zero temperature, individual session findings vary
between runs; aggregate coverage is stable across repeats.

## Status

The optional [integration assessment pipeline](docs/integrations.md) adds
isolated ZAP, Schemathesis, Interactsh and Katana stages plus explicit
DefectDojo export, each running as a Docker job behind a scope-checking egress
proxy. It does not change the existing toolset presets; the dashboard is at
`/integrations`.

The sandboxed executor runs **12 of the 32** catalogue cases, and a thirteenth
(`WSTG-INPV-19`) through the Interactsh collector instead. Which twelve is
derived from the parser itself (`inventory.executable_test_cases`), not written
down: a case qualifies only when every one of its steps parses as a single
curl request AND interpolates nothing the lane cannot supply, so a case that
would half-run is excluded rather than reported as having passed.

The lane supplies two target fields. `url` comes from discovery; `parameter`
comes from two places: the query strings of the endpoints katana, the browser
crawler, Schemathesis and ZAP report, and — where one was supplied — the
OpenAPI document, which names every parameter and states `in: query` outright
instead of leaving it to be inferred. They are merged per endpoint and kept per
identity, so a parameter learned as an admin is never replayed anonymously.
ZAP's own `param` field is deliberately NOT used: it names the input vector an
alert fired on, which is a cookie or a header at least as often as a query
parameter.

A discovered name is text the TARGET chose, and so is the response, so a name
is refused for any case whose own evidence pattern it matches — otherwise a
planted `<a href="/search?219359=1">` makes an application that merely echoes
unknown field names report critical template injection. The schema is the one
source without that property, because the operator supplied it. A case that tests
a parameter runs once per (endpoint, parameter) pair and only against a URL the
parameter was actually observed on. That field is what **half the runnable
catalogue** depends on: 6 of the 12 interpolate `{{parameter}}` — WSTG-CLNT-04,
the three WSTG-INPV-05.x injection cases, WSTG-INPV-11.2 and WSTG-INPV-18.
Before it, discovery produced endpoints and every injection case sat idle for
want of somewhere to inject.

Of the 20 cases still out of reach: 6 run a shell pipeline or a tool that is not
curl, 4 need a target field discovery does not produce (`login_url`, `host`,
`jwt`, `request_template`/`success_marker` — one case each), 4 interpolate a
field nothing supplies (three want a form `submit` control, and all three are
shell cases regardless), 4 hit a dialect refusal, 1 needs credentials the lane
cannot choose between — WSTG-AUTHZ-04, whose `required_any` names a
high-privilege and a low-privilege identity, and which also wants a
`url_template` nothing supplies — and 1 runs through the Interactsh collector
instead. There is no longer a single change worth several cases — the remaining
blockers are one-offs.

The dialect is deliberately narrower than "safe": `-w` and `-e` were allowed
and then removed because ablation showed they bought zero runnable cases while
`-w` let a case write its own evaluator input. A parameter NAME is held to a
stricter rule than "not shell-injectable" for the same reason — `a#b` would
silently truncate the probe to `?a`, and reporting on a request you did not
make is worse than not making it (see `tests/test_parameter_discovery.py`).

Active development. The deterministic engine and WSTG catalogue are
operational; the catalogue is being expanded toward broader WSTG coverage.

## Deterministic pre-scan (OWASP Nettacker)

To reduce reliance on the LLM, erlik can run a **deterministic** OWASP Nettacker
scan before the agent loop and inject the verified results (open ports, detected
tech, exposed paths, header/TLS/CVE hits) as a starting point — so the model
confirms/exploits rather than blindly re-discovers.

```bash
pip install nettacker            # or use the owasp/nettacker Docker image
export ERLIK_NETTACKER=1         # enable the pre-scan (default off)
export ERLIK_NETTACKER_SCENARIO=recon   # run mode (default: recon)
# optional:
#   ERLIK_NETTACKER_CMD="python -m nettacker.main"   # custom launcher / docker wrapper
#   ERLIK_NETTACKER_PROFILE="scan,info"              # raw Nettacker --profile (overrides scenario)
#   ERLIK_NETTACKER_MODULES="port_scan,dir_scan"     # raw -m module list (advanced)
#   ERLIK_NETTACKER_FINDINGS=1                        # also persist deterministic findings
```

**Scenarios (run modes)** map to Nettacker's stable scan *profiles*:

| Scenario | Covers |
|----------|--------|
| `recon` *(default)* | ports, dirs, tech, subdomains, versions, WAF — fast & safe |
| `info` | recon + information gathering |
| `web` | all HTTP/HTTPS checks |
| `tls` | TLS/SSL certificate, cipher, version |
| `cves` | all CVE checks (~61 modules) |
| `kev` | CISA Known-Exploited-Vulnerabilities subset |
| `critical` | only critical-severity modules |
| `wordpress` | WordPress core/plugin/theme |
| `brute` | credential brute-force (needs `-u/-p`; can lock accounts) |
| `full` | every module (slow & noisy) |

```bash
python -m orchestrator.integrations.nettacker --scenarios          # list them
python -m orchestrator.integrations.nettacker http://target --scenario tls
```

Standalone (any pipeline/model, no erlik session needed):

```bash
python -m orchestrator.integrations.nettacker http://target        # prints recon block
python -m orchestrator.integrations.nettacker http://target --json # parsed buckets
```

Nettacker is Apache-2.0 and is **invoked, not bundled** — see
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

## Environment-specific techniques (HackTricks)

Where the skill library routes on the *mission*, this routes on what the target
actually **is**. The Nettacker pre-scan reports open ports and detected
technologies; a detected `27017` pulls MongoDB techniques, a `6379` pulls Redis.
With the pre-scan off, the target URL's own port still drives routing.

```bash
export ERLIK_TECHNIQUES=1                              # enable injection (default off)
export ERLIK_HACKTRICKS_PATH=~/Projects/hacktricks     # optional: full technique text
```

Two tiers, and the split is a **licensing** requirement rather than a
convenience. HackTricks is CC BY-NC 4.0; erlik is MIT. Its prose is therefore
never vendored here:

- **Committed** — `techniques_catalog/index.yaml`: environment, ports, title,
  routing tags and a citation URL for 814 techniques (175 port-keyed). Facts
  only.
- **Runtime, never committed** — with `ERLIK_HACKTRICKS_PATH` set, the router
  reads body text from *your own* clone. Without it, you still get titles and
  citation URLs.

Inspect routing without running a session:

```bash
python -m orchestrator.techniques --ports 27017 6379 --list
python -m orchestrator.techniques --tech nginx --hint ssrf
```

Regenerate the index after pulling a newer corpus:

```bash
python scripts/build_techniques_index.py --hacktricks /path/to/hacktricks
```

The index records the upstream commit it was built from, so a result ties to an
exact corpus revision. See [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md)
for why the text is referenced rather than bundled.

## Post-run AI review

When a run finishes, a second AI pass critiques **the run, not the target**:
what attack surface was never touched, which tools kept failing, and which
settings to change next time. It is advisory — it writes only to
`session_reviews` and never creates findings or moves a metric.

```bash
export ERLIK_AI_REVIEW=1                  # enable (on in every preset but ai_only)
export ERLIK_REVIEW_MODEL=qwen3:27b       # optional: pin the reviewer
export ERLIK_REVIEW_MODEL_MAX_B=40        # optional: auto-pick cap, default 40B
```

**The reviewer can be a bigger model than the one under test.** It never touches
the attack and runs once, after the session, so it is not part of the
measurement and does not affect experimental control. Left unset, erlik picks
the largest installed chat model at or below the cap; on a remote provider it
uses the configured API model. The reviewer actually used is recorded with the
critique so a result can be traced to it.

The cap exists because the choice should be predictable — without it a 70B
sitting on the machine would be selected silently and take minutes for one
critique. Pin `ERLIK_REVIEW_MODEL` for full control.

Why it matters, measured on the same input: a 7B reviewer invented preset names
in 3 of 4 samples and once claimed no SQL injection was attempted when sqlmap
had run three times and a SQLi finding was in its input. A 35B reviewer named a
real preset and correctly diagnosed the failures as a database-protocol probe
against an HTTP-only service. The recommendation is now also validated against
the real preset list, and a fabricated name is flagged rather than dropped.

Read it back with:

```bash
curl -s localhost:8002/api/sessions/<session_id>/review
```

## License & third-party code

Erlik 2.0 is released under the [MIT License](LICENSE).

Some components are adapted from other open-source projects (e.g. NVD CVE
enrichment from the MIT-licensed
[transilienceai/communitytools](https://github.com/transilienceai/communitytools)).
See [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) for attribution and the
bundled license texts under [`licenses/`](licenses/).
