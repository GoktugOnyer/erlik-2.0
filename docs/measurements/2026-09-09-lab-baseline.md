# Integration lane baseline — local lab, 2026-09-09

The first measurement of the integration assessment lane against real
applications rather than a fixture. Both targets are the repository's own lab
containers (`docker-compose.yml`); **nothing outside the local lab was
contacted**, and no client environment has been assessed.

`docs/integration-roadmap.md` specifies what a baseline must carry: pinned
scanner and image versions, endpoint inventory, expected findings, request
counts, runtime, and false positives. Those follow. It also says that missing
coverage "must appear as untested coverage, never as a passing security
result" — which is the main thing this run has to say.

## Pinned versions

| Component | Version | Image id |
|---|---|---|
| egress proxy | `erlik-egress:1` (mitmproxy 11.0.2) | `sha256:1b31278ca4fb` |
| worker | `erlik-integrations:1` (curl 7.88.1, katana 1.2.2) | `sha256:419bad061083` |
| ZAP | `ghcr.io/zaproxy/zaproxy:2.16.1` | `sha256:124241c1bfac` |
| target A | `bkimminich/juice-shop:v17.1.1` | — |
| target B | `ghcr.io/digininja/dvwa:latest` | — |

Catalogue: 29 cases, 9 executable in this lane. Selected for both runs:
`WSTG-SESS-02`, `WSTG-CLNT-04`, `WSTG-INPV-11.2`, `WSTG-INPV-18`.
Crawl depth 3, `max_urls` 120, 20 rps, concurrency 4. No OpenAPI schema was
supplied, so the schema parameter source contributed nothing here.

## Target A — Juice Shop

| | |
|---|---|
| discovery | katana, **partial** (URL inventory limit), 20.6s |
| endpoints | **120** (all katana), 12 carrying a query parameter |
| parameters | **3**, on 3 query-free URLs |
| testing | **completed**, 26.9s, **69 requests, 0 blocked**, 69 checks executed |
| findings | **0** |
| false positives | **0** |

Parameters discovered: `/api/Challenges/?key`, `/redirect?to`,
`/rest/user/change-password?current`.

### Are the zeros correct?

Checked by hand against the running application:

| Probe | Application's actual response | Verdict |
|---|---|---|
| `/redirect?to=//erlik-redir.oast.test/` | `406`, no `Location` | true negative |
| `/api/Challenges/?key=erlikprobe` | `200`, no interpreter error | true negative |
| `/rest/user/change-password?current=erlikprobe` | `401` | true negative |
| session cookie attributes | no session cookie set unauthenticated | true negative |

So zero findings, zero false positives, and the zeros are correct **for the
probes that were sent**.

### The recall miss, stated plainly

Juice Shop's `/redirect` **is** an open redirect. It is exploitable by putting
an allow-listed string in the query rather than at the start:

```
/redirect?to=http://evil.test/?x=https://github.com/juice-shop/juice-shop
  -> 302 Location: http://evil.test/?x=https://github.com/juice-shop/juice-shop
```

`WSTG-CLNT-04` sent `//erlik-redir.oast.test/` and an encoded variant, and
neither has that shape. A genuine miss of a known vulnerability on a parameter
the lane **did** discover and **did** probe — a case-payload gap, not a
discovery or plumbing gap.

**Addressed, but not for Juice Shop.** Two allow-listed-string payloads were
added and measured against `tests/fixtures/open_redirect_validators.py`, which
implements one naive validator per route, written independently of the
payloads:

| payload | startswith | contains | scheme-block | leading-`//` |
|---|---|---|---|---|
| `//marker/` (existing) | – | – | **bypass** | – |
| `//marker/?x=<origin>` (new) | – | **bypass** | **bypass** | – |
| `//<origin host>@marker/` (new) | – | **bypass** | **bypass** | – |

So the case now covers a validator class it could not reach before. Two classes
stay out of reach on purpose: `startswith` and leading-`//` need a payload
beginning with a scheme'd URL or a backslash, and `check_command` refuses any
step naming an out-of-scope host in a shape it recognises. The guard is right —
it cannot tell a payload from a destination, and `.test` resolves to localhost
in many development setups, so widening it for a marker would be an SSRF hole.
Reaching those classes is a scope-model decision, not a payload one.

And Juice Shop's own shape — "contains one of a hardcoded REMOTE allowlist" —
is defeated by none of them and cannot be: only its
`https://github.com/juice-shop/juice-shop` entry is accepted, and neither the
app's own origin nor any of the three off-site links it publishes
(`owasp-juice.shop`, `owasp.org`, a YouTube URL) is on the list. A scanner
cannot guess it. Re-measured after the change: still **0 findings on Juice
Shop, and no false positive**, which is the correct result.

`WSTG-SESS-02` was truncated to its 30-URL share of the budget and said so.

## Target B — DVWA, first pass (before form extraction)

| | |
|---|---|
| discovery (katana) | **0 endpoints**, 1 request, exit 0, no output at all |
| discovery (browser crawler) | **6 endpoints** — `index.php` and five static assets |
| parameters | **0** |
| findings | 0 at `security=low`, 0 at `security=impossible` |

**This is untested coverage, not a clean result.** The differential control
itself is sound — verified by hand, the same SQLi payload returns one row at
`security=low` and none at `impossible` — but the lane never reached the
vulnerable pages, so the two runs are identical for a reason that has nothing
to do with the application's security.

Two causes, both reproduced outside the lane:

1. **katana finds nothing on DVWA.** `katana -u http://dvwa/login.php` — a 200
   page carrying links — emits no output and exits 0, with `-v` and without.
   The same invocation against Juice Shop crawls normally. Not a lane defect;
   a crawler/target incompatibility that the lane must not hide.
2. **Neither crawler submits forms.** DVWA's injectable inputs
   (`/vulnerabilities/sqli/?id=…&Submit=Submit`) are reachable only by
   submitting a GET form. katana is not passed `-fx`, and the browser action
   collects links and requests but not form controls — `scripts/pw-crawl.js`
   already extracts `form.inputs[].name`, but its output feeds only a benchmark
   baseline, not any adapter.

Note DVWA sets `HttpOnly; SameSite=Strict` on both `PHPSESSID` and `security`,
so `WSTG-SESS-02` reporting nothing there is a correct negative on the one
endpoint it did reach.

## Target B — DVWA, second pass (with form extraction)

Form-control extraction was added to the browser crawler in response to the
first pass, along with one bounded level of depth for forms only. Same target,
same cases, same identity but for one cookie:

| | first pass | second pass |
|---|---|---|
| endpoints | 6 | **36–37** |
| parameters | **0** | **7–8** |
| findings at `security=low` | 0 | **2** |
| findings at `security=impossible` | 0 | **0** |

Parameters found are DVWA's actual attack surface: `id` on `sqli` and
`sqli_blind`, `name` on `xss_r`, `username` on `brute`, the password fields on
`csrf`, and `page` on `fi`.

### The two findings, and why they are real

Both are `WSTG-INPV-11.2`, HIGH, `suspected`:

| Finding | Ground truth at `low` | at `impossible` |
|---|---|---|
| `/vulnerabilities/sqli/?Submit=Submit`, param `id` | `Fatal error: Uncaught mysqli_sql_exception` | no error |
| `/vulnerabilities/brute/?Login=Login`, param `username` | `Fatal error: Uncaught mysqli_sql_exception` | no error |

Same session, same endpoints, same case — the only difference is the `security`
cookie. Both findings vanish at `impossible`, so they track the vulnerability
rather than the application. That is the differential this lab exists to
provide, and it is the first time the lane has produced a true positive under
it.

Precision held: `sqli_blind` was discovered and probed and **not** reported —
blind SQL injection emits no error, and this case looks for interpreter errors
— and `xss_r`, `csrf` and `fi` were discovered but not reported by a case that
does not test for their classes. No false positives.

### Third pass — a SQL error detector

The two findings above were reported by `WSTG-INPV-11.2`, the *generic*
interpreter case, which matched them only because PHP wrapped the database
error in `Fatal error`. Right answer, wrong reason, and only on a PHP target:
nothing in the runnable set was looking for a database error, because the
catalogue's SQL injection case (`WSTG-INPV-05`) runs `bash -c` and sqlmap and
the lane cannot execute it.

`WSTG-INPV-05.2` is that detector — one request per payload, no shell. Same
target, same identity, same control:

| security | parameters probed | findings |
|---|---|---|
| `low` | 8 | **2**, both `SQL Injection (error-based)`, HIGH |
| `impossible` | 7 | **0** |

| endpoint | parameter | verdict |
|---|---|---|
| `/vulnerabilities/sqli/?Submit=Submit` | `id` | **found** |
| `/vulnerabilities/brute/?Login=Login` | `username` | **found** |
| `/vulnerabilities/sqli_blind/?Submit=Submit` | `id` | clean — blind SQLi emits no error |
| `csrf`, `fi`, `xss_r` (4 parameters) | — | clean — not SQL |

Correct classification now rather than "unclassified injection", and the blind
module is the precision control: discovered, probed, and reporting nothing,
which is the honest answer for an error-based detector.

### The pattern, and what it cost to make it safe

The existing set in `INPV-05` was measured against the **902 real response
documents** captured across every run in this report. `SQLITE_ERROR` fired
**eleven times on Juice Shop's own JavaScript bundle**, which contains the
string inside a challenge description — "Did you spot the error message with
the `SQLITE_ERROR` …". A `.js` file is a discovered endpoint like any other, so
that would be a HIGH-severity finding for a request that proved nothing.

Three tightenings, each forced by a control that failed:

| alternative | fired on | tightened to |
|---|---|---|
| `SQLITE_ERROR`, `SQL syntax`, `SQLSTATE` | a JS bundle, a tutorial, a JSON field | full sentences, `SQLSTATE[…]` with its brackets |
| `pg_query()` | a changelog: "pg_query() calls are now parameterised" | requires `Query failed` on the same line |
| `ORA-\d{5}` | a docs page: "See ORA-01756 in the Oracle reference" | requires Oracle's `code: message` form |

`.*` appears nowhere: an evaluator reads a whole response, so `Warning.*mysqli_`
can join a warning in one place to a driver name in another and call the pair
an error. Where context is needed it is bounded and line-scoped.

Final pattern against the same 902 documents: **4 matches, all of them DVWA's
genuine error, nothing else.** Against `tests/fixtures/sql_error_pages.py` —
14 real error strings across MySQL, PostgreSQL, Oracle, MSSQL, SQLite, PDO,
JDBC and Hibernate, plus 11 benign lookalikes — **14 detected, 0 false
positives.**

### What made the difference

**The companion fields.** DVWA answers `?id=<payload>` with nothing and
`?id=<payload>&Submit=Submit` with the rows, so a discovery that reported `id`
alone would have handed every case a probe that cannot reach the handler. Form
endpoints therefore carry the form's submit button and hidden token in their
query, and the testable controls are kept out of it so a case appending its own
value cannot collide.

**One catalogue pattern was dead.** `WSTG-INPV-11.2` looked for
`PHP (Parse|Fatal) error`, which is PHP's *log* format. Its HTTP output is
`<b>Fatal error</b>:` with no `PHP ` prefix, and every case in this lane reads
the HTTP response — so that alternative could never match. Widened to
`(?:PHP )?(Parse|Fatal) error`, which matched **0 of 796** evidence documents
collected across every measurement run in this report, and matches DVWA's
actual response. Without it the lane reached the vulnerability and did not
report it.

## What measuring found that the fixture could not

Five defects, each invisible on a one- or two-URL fixture and each fixed in
this branch:

1. **A stage that ran out of time discarded everything it had found.**
   `service.py` catches the timeout and replaces the accumulated `StageResult`
   with an empty one, so the first Juice Shop run reported "partial, budget
   exhausted" with no findings after 12 minutes of work. The catalogue adapter
   now stops short of the deadline and returns what it has, naming the checks
   it did not reach.
2. **The first broad case consumed the whole URL budget.** `WSTG-SESS-02` swept
   120 discovered URLs, and **29 of the 60 parameter probes that followed were
   refused "URL budget exhausted"** — including
   `/redirect?to=//erlik-redir.oast.test/`, the probe for the one known
   vulnerability on the one interesting parameter. Zero findings meant
   *untested*. Each selected case now gets an equal share, denominated in
   requests; after the fix the same run blocked **0 of 72** probes.
3. **An empty discovery stage reported `completed`.** For DVWA that reads as
   "this application has no attack surface". An empty inventory is now
   `partial`, with a reason, because everything downstream is sized by it.
4. **Catalogue cost is one container per request** — measured at 0.29s, so
   120 URLs × 5 cases × 3 steps ≈ 1800 requests ≈ 8.8 minutes against a default
   180s stage budget. The share-based cap keeps a run inside its budget, but
   the per-request cost is the reason breadth is expensive here.
5. **The lane asked katana to launch a browser its own sandbox forbids.** With
   `headless`, katana extracts a `leakless` helper into `/tmp` and execs it;
   the job tmpfs is `noexec`, so katana exits 1 and the whole stage failed,
   discarding a crawl that had otherwise worked. A non-executable `/tmp` is
   correct for a sandbox running scanners against a hostile target, so the
   flag went rather than the hardening — Playwright already provides the
   rendered pass and seeds katana with what it found.

## Honest summary

- The plumbing works end to end on a real application: discovery, parameter
  extraction, identity, proxy enforcement, evidence, budgets, reporting.
- **Precision on this run: no false positives.** Every zero that was checked
  was a true negative.
- **Recall is the weak side, and it is not the plumbing.** One known
  vulnerability was reached and missed on payload shape; a whole target was
  never reached at all.
- **Form extraction closed the largest gap.** DVWA went from 0 parameters and
  an untestable surface to 2 true positives under a working control.
- The ranked next steps this measurement now supports:
  1. katana's silence on DVWA, or accepting the browser crawler as the fallback
     and giving it depth beyond forms,
  2. whether the catalogue scope guard should be able to tell a payload from a
     destination — the only thing now standing between WSTG-CLNT-04 and two
     more validator classes,
  3. blind injection of any kind. This lane has no timing and no
     boolean-differential capability, so DVWA's `sqli_blind` — discovered,
     probed, and correctly silent — stays out of reach until it does. That is
     the largest remaining category of real SQL injection.

None of these is a scanner integration. The five integrations are in and
verified; what limits findings now is discovery reach and detection technique.

## Reproducing this

`docker compose up -d juice-shop dvwa dvwa-db`, then point the lane at
`http://juice-shop:3000` or `http://dvwa/index.php` with
`ERLIK_INTEGRATION_EGRESS_NETWORK=erlik-20_pentest-net`. DVWA needs
`setup.php` run once, a login, and BOTH cookies in the identity — its security
level comes from the `security` cookie and defaults to `impossible` when that
cookie is absent, which silently turns the vulnerable target into a hardened
one.

One caveat on this run: the worker image could not be rebuilt from
`Dockerfile.worker` here, because the build stalls fetching registry metadata
for its base images and this environment has no registry access. The updated
`worker.py` was applied to the existing image with `docker cp` + `docker
commit`, and verified byte-identical to the source file in the repository. CI
should build it the normal way.
