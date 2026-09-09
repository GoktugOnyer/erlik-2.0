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

`WSTG-CLNT-04` sends `//erlik-redir.oast.test/` and an encoded variant, and
neither has that shape. This is a genuine miss of a known vulnerability on a
parameter the lane **did** discover and **did** probe — a case-payload gap, not
a discovery or plumbing gap. It is the clearest single improvement available.

`WSTG-SESS-02` was truncated to its 30-URL share of the budget and said so.

## Target B — DVWA

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

## What measuring found that the fixture could not

Four defects, each invisible on a one- or two-URL fixture and each fixed in
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

## Honest summary

- The plumbing works end to end on a real application: discovery, parameter
  extraction, identity, proxy enforcement, evidence, budgets, reporting.
- **Precision on this run: no false positives.** Every zero that was checked
  was a true negative.
- **Recall is the weak side, and it is not the plumbing.** One known
  vulnerability was reached and missed on payload shape; a whole target was
  never reached at all.
- The ranked next steps this measurement supports, in order of expected value:
  1. form-control extraction in the browser crawler (unblocks DVWA-shaped apps
     entirely — the code already exists in `scripts/pw-crawl.js`),
  2. an allow-list-bypass payload for `WSTG-CLNT-04`,
  3. diagnosing katana's silence on DVWA, or accepting the browser crawler as
     the fallback and giving it depth.

None of these is a scanner integration. The five integrations are in and
verified; what limits findings now is discovery reach and payload breadth.
