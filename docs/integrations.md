# Integration assessments

Erlik's optional integration pipeline runs locally in Docker. Existing sessions
and toolset presets do not enable these integrations automatically.

## Installation

```sh
pip install -r requirements-dev.txt
docker compose -f docker-compose.integrations.yml --profile integrations build
docker pull ghcr.io/zaproxy/zaproxy:2.16.1
export ERLIK_API_TOKEN='replace-with-a-long-random-token'
./run.sh
```

Open `/integrations` and authenticate with that token. HTTP data routes and
WebSockets share the same authentication boundary. The browser receives a
SameSite Strict, HttpOnly session cookie; API clients can use `X-API-Token` or
`Authorization: Bearer ...`. Keep the application on loopback or behind TLS.

Scanner workers join a unique **internal** network with no direct egress. A
separate MITM proxy joins that network and the configured target/egress network;
only the proxy can reach target hosts. Its CA is generated per job and mounted
into the worker. CONNECT destinations, HTTP requests, redirects and schema
references are checked. Non-HTTP and WebSocket scanning are unsupported.

For a Docker lab, set `ERLIK_INTEGRATION_EGRESS_NETWORK` to the existing target
network name (inspect with `docker network ls`). Use container DNS names in both
the target and scope; `localhost` inside the proxy is not the host machine.
For external targets the default egress network is `bridge`.
For an internal PKI, `ERLIK_INTEGRATION_CA_FILE` may point to an explicitly trusted
PEM CA bundle. Upstream TLS verification remains enabled.

## Assessment configuration

POST `/api/sessions` with `target_url` and `integration_config`; then POST
`/api/sessions/{id}/start`. Example:

```json
{
  "target_url": "https://app.example.com",
  "integration_config": {
    "scope": {"allow_hosts": ["app.example.com"], "allow_ports": [443]},
    "stages": ["katana", "zap"],
    "active": false,
    "state_changing": false,
    "budget": {"requests_per_second": 5, "concurrency": 2,
               "stage_seconds": 600, "assessment_seconds": 1800}
  }
}
```

Discovery excludes `/logout` and `/signout` by default. Configure additional
excluded paths for application-specific side effects. An allowed GET can still
change state in a poorly designed application; discovery is not a guarantee of
zero side effects.

Add `schemathesis` with `active: true` and `schema_input` containing `kind`
(`openapi` or `graphql`) and exactly one of `url` or `content`. Remote schema
references must remain in scope. Local filesystem references are refused.
State-changing OpenAPI workflows require `state_changing: true` and a `workflow`
with exact `operations` IDs, `fixtures`, and `cleanup` request lists. Each request
contains URL, method, optional JSON body, expected status, and optional body
substring assertion. Cleanup failures and interrupted workflows require inspection;
Erlik never silently replays them on restart.

Schemathesis contract failures are observations. Optional `security_assertions`
establish specific authorization violations using an identity, GET request,
description, and forbidden-content marker. Ordinary scanner alerts remain
suspected; correlated callbacks are likely; confirmed findings require an explicit
reproduced security assertion.

## Authentication

POST `/api/integrations/identities` with a named profile:

```json
{
  "name": "reader",
  "target_origin": "https://app.example.com",
  "headers": {"Authorization": "Bearer YOUR_TOKEN"},
  "check": {"url": "https://app.example.com/me", "expected_status": 200,
            "body_contains": "reader"}
}
```

Use its returned opaque ID in `identity_ids`. Cookie lists and Playwright
`storage_state` are accepted. Profiles live in mode-0600 files beneath
`ERLIK_INTEGRATION_DATA` (default `data/integrations`), never in SQLite. API tokens
for callback/reporting services use POST `/api/integrations/secrets`; there is no
secret-read endpoint. Protect and back up this runtime directory as sensitive data.

For operator-assisted login, install `requirements-browser-login.txt` and run:

```sh
python -m playwright install chromium
python -m orchestrator.integrations.cli login --config assessment.json \
  --identity identity.json --output authenticated-profile.json \
  --login-origin https://login.example.com
```

Complete login/MFA in the headed browser and press Enter. Upload the resulting
profile through the integration dashboard. Additional login origins are allowed
only for this login browser, not for assessment scanning. The helper saves a
redacted audit alongside the profile. Keep both files outside Git.

If a stage reports `needs_auth`, replace the profile with PUT
`/api/integrations/identities/{id}` and start the session again. Completed stages
are not replayed. No unattended SSO/refresh automation is included.

## Self-hosted Interactsh

Operate an Interactsh server with valid HTTPS and an authoritative callback
domain reachable from the assessed target. Supply its explicit HTTPS origin,
optional secret reference, callback grace period, and probes:

```json
{"server":"https://oast.example.com","secret_id":"OPAQUE_ID",
 "grace_seconds":60,
 "probes":[{"url":"https://app.example.com/fetch","parameter":"url"}]}
```

Select `interactsh` and active testing. The collector registers before discovery;
Nuclei sends generated GET probes using per-probe payloads, with its automatic
Interactsh registration disabled. No public-service fallback is permitted. A DNS
callback establishes interaction, not access to sensitive internal resources.

## Operations, and comparing two identities

The lane records the concrete URLs it discovered, and groups them into
**operations**. An operation is identified by what can be injected into it — origin,
path, method and the testable parameter names — and *not* by the rest of the query.

That distinction is not cosmetic. DVWA puts a single-use `user_token` in its forms
at `security=impossible`, and discovery bakes companion fields into the URL, so the
same form produced a different URL string on every observation. Two identities
therefore produced two unrelated rows for one form, and a differential between them
compared two surfaces rather than one variable. Keyed on the injectable surface,
both arms resolve to one operation while `GET` and `POST`, two paths, and two
different input sets all stay separate.

Nothing is discarded: every concrete URL stays as an observation beneath its
operation, tagged with the identity that saw it, so the token one arm was served is
still visible.

### Comparing two arms

`inventory.compare_arms(session_id, first, second)` answers whether two identities
describe the same surface. It reports the operations only one arm saw, and refuses
four situations outright:

| Refusal | Meaning |
|---|---|
| `arms_share_one_identity` | an identity compared with itself agrees perfectly and proves nothing |
| `different_operations` | one arm reached something the other never did |
| `per_arm_value_in_operation` | both arms reached the operation, at **different URLs** — each issued its own request |
| `no_shared_operations` | two arms that discovered nothing agree vacuously |
| `different_schema` | the arms were assessed against different API documents |

`different_schema` catches something a schema URL makes easy to miss. `schema_input`
accepts a `url` as well as inline `content`, and that document is fetched through the
egress proxy — which injects the identity's headers and cookies. A target serving a
different OpenAPI per role therefore forks the schema-derived operations exactly as a
rendered form does. The recorded `schema_sha256` of each arm is compared, and a digest
present for one arm and absent for the other counts as disagreement: a document served
to one identity and refused to another is not a shared surface. Supply inline
`content` when you need the arms to be certain of sharing it.

Every one-sided operation also comes back classified, under `divergence`, because
"an operation only one arm saw" is the same sentence whether the crawl missed a page
or the application moved the surface — and an operator cannot act on those the same
way:

| `kind` | What it means |
|---|---|
| `method_changed` | both arms reached the endpoint, by different methods — a form that is GET for one identity and POST for another |
| `parameters_changed` | both reached it with a different injectable surface; the entry names the inputs that appeared or vanished |
| `not_reached_by_other_arm` | there is genuinely nothing at that endpoint in the other arm |

### Routes read out of JavaScript

A single-page application calls its API from JavaScript, so the routes that matter are
often in a bundle rather than behind a link. The lane reads them out of the script
bodies the rendered pass already fetched and records them as `source="javascript"`,
with relative routes resolved against the script's own URL — which is how Juice Shop
spells its open redirect, `url:"./redirect?to=..."`.

**These are proposals, and nothing probes them.** An inferred route is withheld from
everything that fetches or injects until you select it. That is not caution for its own
sake: the same Juice Shop bundle names `/rest/products/search?q=` and
`/rest/user/change-password?current=`, nothing syntactic separates them, and a probe of
the second as an authenticated identity is the password change. Surfacing a route no
crawler reaches is the value; requesting it unasked is how a tool changes a credential
while enumerating.

Everything the reader returns is target-controlled text on its way to becoming a URL,
so it refuses: more than one leading slash (`//w.soundcloud.com/player/?url=` is in the
same bundle and is a different host), any scheme, `..`, a path that could carry a
template placeholder or a shell metacharacter, parameter names the lane would not
accept anywhere else, and any candidate whose query contains a `#` — cutting
`?ok=1&a#b=2` at the fragment would yield a parameter the application never had.

A `inferred_from_javascript` observation names what was read and from how many scripts.

### When the crawl stops early

The rendered pass visits one level past the landing page, bounded by `form_pages`
(default 20). When that bound is reached the stage records a `crawl_truncated`
observation naming how many same-origin links were left unvisited.

It is worth reading rather than skipping. A cap is normally just lost coverage, but
this one distorts a differential in both directions: two identities whose menus differ
truncate at different places, so the cap manufactures a surface difference — and two
whose menus match truncate identically, so the cap hides a real one beyond its
boundary. Measured on DVWA, which publishes 31 links from its landing page: at the
default the crawl stops at 20 and says so, and moving the boundary by a single link
reveals a form that exists at one security level and not the other.

Raise `form_pages` to cover them. The observation appears only when the cap actually
fired.

### Links the crawler refuses

A crawler that follows a sign-out link ends its own session, and everything it
visits afterwards is a login form — so that arm's surface silently shrinks while
every request still succeeds. Nothing reports it.

Any URL with a path segment that spells logging out — `logout`, `logoff`,
`sign_out`, `sign-out`, `signoff` and their variants, case-insensitively — is
refused, and ZAP is told the same list so it does not spend requests discovering
that. This is the lane's own rule, not a default in `excluded_paths`: replacing that
list is how you ADD an exclusion, and it must not be how you silently remove the
rule that protects a run from itself.

Matching is per whole segment, so `/users/sign_out` and `/Account/LogOff` are
refused while `/blog/how-to-logout-safely` and `/docs/signout-api` are still
crawled. `excluded_paths` remains yours, matched as a prefix.

**What a pass establishes, and what it does not.** `comparable: true` means the two
arms describe the same surface. It says nothing about whether either arm *reached*
it. A live run was measured scoring a perfect shared-surface fraction while all
eight of its probe sets received zero bytes, so treating surface agreement as
differential validity reproduces the defect this comparison exists to catch. The
returned record states this in its `establishes` field.

Relatedly: a refused probe is not an empty one. DVWA answers a request missing its
token with HTTP 200 and 389 bytes of PHP warnings, so the lane's
`test_case_unreachable` observation — which fires when every executed step came back
empty — does not fire on a refusal.

### When the rendered pass runs

Discovery has two halves: katana, which fetches, and a Playwright pass, which
renders. The rendered pass is the only thing that finds **forms**, and therefore the
only thing that finds the parameters a case can inject into — on DVWA every one of
the injectable pairs comes from it.

It runs when the assessment **names any identity**, or when `headless: true` is set.
An anonymous assessment that asked for neither gets neither, because the pass starts
Chromium and nobody should pay for that unasked.

The decision is made per **assessment**, never per identity. That is deliberate: if
it depended on what each identity carries, an anonymous arm would have no rendered
surface while its authenticated siblings did, the arms would disagree about what
exists, and `compare_arms` would refuse every differential drawn from the run. A
gate on discovery has to answer the same for every arm or it becomes the thing it
was guarding against.

You do **not** need a `storage_state` for this. The egress proxy injects an
identity's headers and cookies on every in-scope request, so a plain cookie session
is enough — measured on DVWA, a cookie-only identity renders 31 links and 13 forms
where an anonymous one gets the login page. Supply `storage_state` when the
application needs client-side state the proxy cannot inject, such as a token in
`localStorage`.

### Choosing a second identity

Two principals at the **same** configuration, not two configurations. DVWA's
`security` cookie is a security level rather than a principal, and at `impossible`
its forms require a single-use token the lane does not refresh, so that arm never
reaches the code being compared and its zero findings are vacuous. Measured: admin
and gordonb, both at `security=low`, produce `/vulnerabilities/sqli/?Submit=Submit`
byte for byte — so the only variable is who made the request.

## The identity matrix

An identity carries what authenticates it and, optionally, what the operator declares
about it:

| Field | Kind | Used for |
|---|---|---|
| `headers`, `cookies`, `storage_state` | secret, injected by the proxy | authenticating every in-scope request |
| `role` | operator label | reporting — the lane does not interpret it |
| `tenant` | operator label | reporting, and `cross_tenant` on an arm comparison |
| `subject_id` | operator declaration | **who this identity IS in the application** |
| `may_access` | operator declaration | which object paths this identity is expected to reach |

`subject_id` is the one the authorization checks rest on, and the asymmetry is the safety
property: who the caller is comes from **you**, the asserted owner comes from the
**target**. A target can therefore cost itself a finding and can never manufacture one.
It lives on the identity rather than being typed per run so that it travels with the arm —
two arms cannot accidentally share one.

None of the four is a secret, and `secret_values` is an explicit allow-list rather than a
sweep, so they survive into a finding's evidence. That matters: the ownership finding
quotes "the caller is declared to be '2'", and a comparison whose own terms were redacted
could not be checked by whoever reads it.

### Checking authorization across two arms

`POST /api/integrations/sessions/{id}/authorization` compares what two arms of a finished
assessment received for the same object:

```json
{ "caller": "<identity handle>", "owner": "<identity handle>",
  "owner_field": "data.UserId", "anonymous": "anonymous" }
```

A finding needs all four clauses, the same ones the `ownership` evaluator applies — the
caller received the object and an owner is asserted; that owner is not the caller's
declared `subject_id`; the declared owner corroborates it; and an anonymous arm was
refused.

**Read `refused_because` before `findings`.** A refusal means the comparison did not run,
and an empty `findings` list is then not a clean result. It refuses when the two arms did
not describe the same surface — it calls `compare_arms` first, so an operation both arms
reached at *different* URLs is refused rather than compared — when an identity declared no
`subject_id`, and when there is no anonymous arm, because a clause nobody ran is not a
clause that passed.

Measured end to end on Juice Shop with three stages, three identities and the real proxy:

    arm jim        HTTP 200   asserted owner 1       (declared subject_id 2)
    arm admin      HTTP 200   asserted owner 1       (declared subject_id 1 — corroborates)
    arm anonymous  HTTP 401                          (refused, so not published)

    -> 1 finding, refused_because [], and no bearer token anywhere in the verdict

### Checking access to a privileged function

`POST /api/integrations/sessions/{id}/privileged-function` asks the other half of the
same question. Object-level authorization reads an owner out of the response, so the
target itself says who a record belongs to. A **function** has no owner to read:
`GET /api/Users` returns every user and nothing in the payload says "only an
administrator may ask this".

So the operator supplies the one thing that cannot be inferred — a marker identifying
privileged **data** — and the lane supplies what happened:

```json
{ "privileged": "<identity handle>", "unprivileged": "<identity handle>",
  "marker": "\"email\":\"admin@juice-sh.op\"", "anonymous": "anonymous" }
```

Three clauses, all of which must hold: the marked data reached the **privileged** arm, so
there is a privileged function here at all; it also reached the **unprivileged** arm, which
is the crossing; and an anonymous arm **asked for it and did not receive it**, so it is not
published content.

**Why not compare statuses.** "Both authenticated arms got 200, the anonymous arm did not"
describes every ordinary authenticated endpoint. Measured over 16 Juice Shop endpoints with
three real arms, a status-shaped rule reports **6 and is wrong about 3** of them:

    endpoint                              admin  cust  anon   status rule   marker rule
    /api/Users                             200    200   401    report       report
    /api/Users/1                           200    200   401    report       report
    /rest/user/authentication-details      200    200   401    report       report
    /rest/basket/1                         200    200   401    report  FP   -
    /api/Complaints                        200    200   401    report  FP   -
    /rest/order-history                    200    200   500    report  FP   -

    -> marker rule: 3 findings of 16 checked, 0 false positives

`/rest/order-history` is the clearest one: each arm received its **own** orders, and no
rule that only looks at status codes can tell that apart from a crossing.

**Why the anonymous arm carries the weight.** Three of the first four candidates measured
turned out to be public, and two of them have `admin` in the path —
`/rest/admin/application-configuration`, `/rest/admin/application-version`,
`/api/Feedbacks`, `/api/Recycles` all answer **200 to nobody in particular**. A path-name
heuristic reports all four.

**A denial is not always a 4xx**, so there is no denial list to keep current. Juice Shop
refuses the wrong customer's card with HTTP **400**
`{"status":"error","data":"Malicious activity detected"}`; DVWA refuses with HTTP **200**
`{"result":"fail","error":"Access denied"}`. Neither body contains the privileged data, so
clause 2 rejects both. The same clause rejects an arm whose session has expired, because a
dead session receives the anonymous response.

The marker is matched against the response **body** of a **2xx** only. A marker reflected
into a `Location:` header, or echoed back by a 400, is the application repeating the
question rather than answering it.

**Read `refused_because` before `findings`**, as with the sibling route. It refuses when
either identity declares no `role`, when both declare the **same** role (a privilege
crossing needs two privilege levels, and guessing which of two handles is privileged would
let the lane report its own assumption), when there is no anonymous arm, and when the
marker is not a usable comparison — it is held to `declared.validate`, the same rule that
governs `private_object_marker` in the catalogue, rather than to a second rule invented
here.

**Entitlement is the one thing no response can express**, so the operator declares it.
`Identity.may_access` — a field that until now was validated and read by nothing — lists
paths an identity is entitled to reach, and a declared path removes a finding. It is read
as an OPEN-WORLD suppression: an empty declaration suppresses nothing, so it can only ever
remove a finding, never manufacture one. Read the other way, as "anything not declared is a
violation", it invents them — worst of all for the anonymous arm, whose list is empty and
for whom every public endpoint would then read as forbidden.

The measured case that makes it necessary: `GET /rest/basket/2` is **jim's own basket**,
and the administrator can read it too —

    admin  200 {"status":"success","data":{"id":2,...,"UserId":2,...}}
    jim    200 byte-identical
    anon   401

— so a marker naming jim's own data satisfies every clause with nothing wrong. Declaring
`may_access: ["/rest/basket/2"]` on that identity is how the operator says so, and
`suppressed_declared_access` in the payload lists what was removed, because a suppression
nobody can see is indistinguishable from a check that never looked.

**Two measured limits, both outside this check and both real.**

*The anonymous arm cannot carry application configuration.* `service.register` builds a
stage's identity as `SecretStore().get(...) if identity_id != "anonymous" else None`, and
the proxy injects nothing when that is `None` — so on an application whose configuration
lives in a cookie, the anonymous arm is evaluated against a **different application**.
Measured on DVWA, whose security level is a caller-supplied cookie
(`dvwaPage.inc.php:200`): `/vulnerabilities/authbypass/get_user_data.php` returns the
273-byte user table to an anonymous caller carrying `security=low`, and 41 bytes
`{"result":"fail","error":"Access denied"}` with no cookie at all. The anonymous clause
compares against whichever of those the lane happened to produce. Until a stage can carry
non-credential configuration, **trust the anonymous clause only on applications that do not
keep configuration in a cookie.**

*Liveness is not differential.* `service.authenticate` returns
`not blocked and status == expected_status and (optional body_contains)`, and
`RequestSpec.expected_status` defaults to 200 — so an identity whose check URL is the
target origin passes while carrying no credential at all, and its arm is then effectively
anonymous. In the other direction, `GET /rest/user/whoami` with a header-only Juice Shop
token answers 200 `{"user":{}}`, byte-identical to the anonymous answer, so that URL as a
check reports a working session as dead. This is the same defect `login._verify` already
documents for the other lane, and the fix is the same: compare against a control request
that drops the identity.

**The marker is never echoed into a finding.** It describes the application's private
data — a real address, an internal identifier — and a finding travels into a DefectDojo
export. The payload carries a short digest instead, and says so.

### Every arm tests the same application, and proves it is the arm it claims to be

Both cross-arm checks above rest on an anonymous arm, and two things were wrong with the
arms themselves. Neither was a missing feature; both were measured false positives.

**`AssessmentConfig.application_cookies` — configuration every arm carries.** DVWA's
security level is a value the CALLER chooses (`dvwaPage.inc.php:200` returns
`$_COOKIE['security']` when set and `impossible` otherwise), and a stage's identity is
`None` for the anonymous arm, so the proxy injected nothing into it. Measured through the
real proxy on `/vulnerabilities/authbypass/get_user_data.php`:

    identity arm carrying security=low     200, 273 bytes, the full user table
    anonymous arm as the lane built it     200,  41 bytes, {"result":"fail",...}

So the anonymous arm was not the authenticated arms' application with nobody logged in —
it was a different, hardened application. Measured end to end with real admin and gordonb
sessions: **1 false positive** before, **0** after, on data DVWA hands to anybody who sets
a cookie.

```json
{ "application_cookies": [
    { "name": "security", "value": "low", "target_origin": "http://dvwa" } ] }
```

`target_origin` is required, and it is the whole origin — scheme, host *and* port. A first
draft reused the identity cookie plumbing, which is fenced by
`origin(url) == origin(identity.target_origin)`, without that fence: a cookie declared for
`localhost:8081` was measured landing on a request to `localhost:3000`, and no cookie
`domain` can express a port. Juice Shop treats a bare `token` cookie as a full identity, so
on a two-host scope that handed a credential to a second application.

**The declaration outranks the identity**, and cookies are merged rather than replaced. DVWA
answers *every* request with `Set-Cookie: security=impossible`, and `login.py`'s jar is a
flat name→value dict that absorbs it — so an identity captured by erlik's own credential
flow carries `security=impossible`, a cookie the operator never declared and has no reason
to know is there. With the identity winning, declaring `security=low` silently did nothing.
The override is recorded in the proxy audit, never silent. (The old code ended with
`headers["cookie"] = "; ".join(accepted)`; ablating the merge back to that flips the same
declared configuration between 5070 bytes with five usernames and 389 bytes with nothing,
purely on join order, because PHP takes the **first** of duplicate cookie names.)

**What this guarantees is UNIFORMITY, not that the values are not credentials.** Anything
every arm carries cannot distinguish one arm from another, so it cannot manufacture a
differential. It can change the application under test, which is the point. On a run with
**no identities** there is only one arm and therefore no differential at all, so an operator
who puts a session cookie here would get a post-authentication finding labelled anonymous
with nothing to contradict it — which is why every stage records
`metadata.application_configuration`, and why the published configuration keeps the cookie
names and origins and redacts only the values.

**`service.authenticate` is now differential.** It was
`status == check["expected_status"] and (optional body_contains)`, and
`RequestSpec.expected_status` defaults to 200 — so an identity whose check URL was the target
origin passed while carrying nothing, and its arm was then effectively anonymous while every
comparison believed it was a distinct identity. Two arms that are the same caller is the
worst possible input to a differential.

The rule: the identity's response satisfies the operator's assertion **and** a control — the
same request with the identity dropped, the application's configuration kept — does not.
Four verdicts, and only the first is resumable:

| verdict | stage | meaning |
|---|---|---|
| `needs_auth` | `needs_auth` | the credential is dead or wrong — replace it and resume |
| `indiscriminate` | `failed` | the assertion holds without the credential, so it establishes nothing |
| `check_is_unstable` | `failed` | two identical anonymous requests disagreed about the assertion |
| `control_unavailable` | `failed` | the control was never obtained, or the proxy refused it |

Scored over 11 rows captured through the real proxy across both lab apps, the old rule is
wrong on 3 and the new rule on 0; an independent 41-row corpus put the old rule at fp=11 and
the new at fp=1, and ablating the differential took it straight back to 11. Every verdict the
differential changed was `authenticated → indiscriminate` — it cannot produce a silent false
dead — and each refused check had a discriminating alternative in the same corpus.

Three things it does **not** fix, all measured:

* **A control the egress proxy refused** used to read as a discriminating control, because
  `satisfies` opens with `not response["blocked"]` and a blocked control fails every
  assertion. That certified an arm carrying nothing — the defect the rule exists to remove,
  resurrected by its own guard. A blocked or errored control is now `control_unavailable`.
* **A non-deterministic assertion.** On Juice Shop's public `/metrics`, whose body varies
  between consecutive identical requests, an arm carrying nothing was certified in 18–24% of
  trials, and re-sampling plateaus rather than converging (24%, 6%, 10%, 8% for k=1,2,3,5).
  Two control samples now refuse a check whose own assertion they disagree about, which names
  the problem instead of trying to out-sample it. A residual remains for an assertion that is
  *mostly* stable.
* **The target supplying the discriminator.** Juice Shop answers `/api/Users` 401 `"Invalid
  token: no header in signature"` to a garbage bearer token and 401 `"No Authorization header
  was found"` to none, so an assertion keyed on the former passes both clauses with material
  the target explicitly rejected. `Identity.check` must now assert a **2xx**: a rejection
  cannot prove a credential works. That also removes an unreachable assertion — the worker
  follows redirects, so a live DVWA session asserting 302 on `/index.php` was reported 200 and
  failed as dead.

On DVWA the control is degenerate and worth knowing about: following redirects as the worker
does, anonymous GETs of `/index.php`, `/vulnerabilities/sqli/`, `/vulnerabilities/exec/`,
`/security.php` and `/phpinfo.php` all return the identical 1342-byte login page. So the
differential there reduces to "is your assertion absent from login.php" — and that page
contains both `DVWA` and `Damn Vulnerable Web Application`. `Welcome`, `Logout` and the
username discriminate.

**The anonymous arm is now actually registered.** `register` built its arms as
`config.identity_ids or ["anonymous"]`, so an anonymous arm existed only when *no* identity
was configured — and `preflight` rejects `"anonymous"` as an identity handle. Measured on a
two-identity registration: 4 stages, 2 arms, no anonymous one, and both cross-arm checks
refusing with `anonymous_arm_did_not_run`. **The authorization work could not run on any
assessment the product accepts**; the three-arm sessions its tests exercise were written into
the database by the tests. `anonymous_arm` now defaults to true and costs one more pass of
each selected stage.

### What a real assessment revealed

Increment 9 made the cross-arm checks reachable. Increment 10 ran one — `service.run()`,
three arms, against both lab applications — and found three reasons they still produced
nothing, none of which any unit test could have shown.

**A refusal by erlik's own proxy was read as an expired credential, and halted the run.** The
admin arm crawled 63 Juice Shop endpoints under `max_urls=60`; the stage's CLOSING liveness
check was then the 61st distinct URL, so the proxy refused it, `satisfies` opens with
`not response["blocked"]`, and the stage was recorded:

    katana, admin arm   needs_auth   "authentication expired during stage; results are
                                      incomplete"
    every other stage   queued

The evidence says it plainly — `authentication-check blocked=True status=403 body='X-Erlik-
Blocked: true\nURL budget exhausted'`. The credential was fine. One arm's budget then cost
the other identity **and the anonymous arm**, which has no credential that can expire. Two
fixes: a blocked or errored probe is its own verdict (`probe_refused` — `failed` pre-stage,
`partial` post-stage, never `needs_auth`), and **erlik's own liveness traffic no longer
spends the operator's URL budget.** `max_urls` bounds how much of the *target* an assessment
explores; a probe of one declared, already scope-checked URL is not exploration. It still
counts against `max_requests` and is still scope-checked.

**One incomparable operation discarded every comparable one.** `compare_arms` warns that an
operation both arms reached at different concrete URLs cannot be compared — and that warning
refused the whole session. Measured: 37 of 37 Juice Shop operations seen by both arms, roles
declared correctly, and both checks returning nothing, because **three `/socket.io/`
operations carry a per-connection `sid` and a cache-busting `t`**. Thirty-four comparable
operations thrown away for three websocket handshakes. Those two conditions are per-operation,
so they are now counted (`not_comparable`) rather than refusing the session.

A first attempt at that returned the concrete excluded URLs, which carry the companion
*values* `compare_arms` deliberately withholds — a single-use `user_token` went straight into
the payload, and an existing test caught it. It then turned out the subtraction was
unnecessary at all: `arm_responses` keys evidence by the request, URL included, so two arms
are only ever compared on the *identical* URL and the danger the warning describes cannot
arise through this path. Verified by removing it and re-running both real sessions —
identical results. So it is reported, not subtracted; code that cannot fire implies a
protection that is not there.

**The evidence key omitted the parameter.** `WSTG-INPV-05.2` runs once per (endpoint,
parameter) pair, so on DVWA one URL legitimately carries several captures:

    key WSTG-INPV-05.2:single_quote on /vulnerabilities/brute/?Login=Login
        parameters behind that ONE key: ['password', 'username']

Two genuinely different probes collapsed into one key, their differing captures read as
self-contradiction, and `ambiguous_evidence` refused all 29 comparable operations. Every test
fixture had used `parameter: ""`, so only a real run could show it. The parameter is part of
the request and is now part of the key; ambiguity drops the key and is counted rather than
refusing the session.

**After the three fixes**, both real sessions run clean: Juice Shop 34 operations checked,
DVWA 37 and 38, `refused_because` empty on all four checks.

**Zero findings was the honest answer, and that was verified rather than assumed.** A check
that cannot fire also returns zero. On DVWA two real keys have a finding's exact structure —
admin 2xx, low-privilege 2xx, anonymous *answered* non-2xx — and running the shipped check
over the real lane evidence with a marker actually present in those captures produces a
finding, while a marker absent from them produces none. So the machinery fires on real
evidence and the marker is what decides. (That diagnostic used a discovered marker, which is
target-controlled, so it is not a reportable finding — only proof of non-vacuity.)

It also exposed one duplicate: `WSTG-CONF-06:options` and `WSTG-SESS-02:fetch_headers` both
fetched `http://dvwa/`, and the check emitted two byte-identical findings. Which case did the
fetching is not part of the claim, so one finding per operation now.

**Two structural limits, both measured, neither a defect.** On DVWA the anonymous arm
discovered **4** endpoints against the identity arms' 31 and 32, because DVWA redirects an
unauthenticated caller away from its whole surface — so the anonymous clause cannot be
evaluated for the authenticated surface at all, and the checks correctly skip rather than
conclude. And the cross-arm checks read whatever the selected catalogue cases happened to
fetch: the four used here (`SESS-02`, `INPV-05.2`, `CONF-06`, `INFO-03`) probe for injection
and information, and **none of them reads a privileged object as each identity.** Until a case
does that systematically, the authorization checks are opportunistic — they work, on whatever
evidence the run happens to leave them.

### Reading the surface as each identity

The cross-arm checks above compare what each arm received for the same request. They read the
evidence catalogue cases leave behind — and **not one runnable case simply reads a discovered
endpoint.** So on a real three-arm run both checks ran clean, compared 34 operations, refused
nothing, and found nothing: the zero was honest and useless. They were a capability with no
input.

`ERLIK-SURFACE-READ` is one plain GET of each discovered endpoint, per arm, recorded as run
evidence and **evaluating nothing**. It is deliberately not a WSTG case: one read by one
identity cannot tell privileged data from published data — that is the whole reason the
comparison is cross-arm — and a catalogue entry whose evaluator can never fire is the
vacuous-case shape this project keeps deleting. It uses the same id and step name on every
arm, because the checks key evidence on `(url, test_case, step, parameter)`.

**It closes the arc.** On a real three-arm assessment of Juice Shop, through `service.run()`:

    privileged-function   findings=1   checked=213   refused_because=[]
      FINDING http://juice-shop:3000/api/Users  [customer -> admin]

213 operations compared where the same run without the read compared 34, and the finding is
the violation first measured by hand two increments earlier — a customer reading the
administrator's record out of `/api/Users`. It is the lane's first authorization finding
produced end to end, from discovery to verdict.

**Where it spends a budget it cannot finish matters more than the probe itself.** `seeds()`
returns `ORDER BY url`, and alphabetical wasted the share. Measured on a real 63-URL inventory
at `max_urls=60` with four cases, where the share is twelve: the twelve were the homepage,
`MaterialIcons-Regular.woff2`, two JSON APIs, `favicon_js.ico`, `assets/i18n/en.json` and six
product JPEGs — and the first `/rest/` URL sat at rank 24. A static asset cannot differ by
identity, so it cannot carry a differential; sorting those last took the share from 3 of 12
API URLs to 10 of 12. It is a **reordering, not a filter** — a generous budget still reads
everything, and `surface_read_truncated` says what was left.

**Two declarations are the floor, not a tuning choice.** An independent pass scored the shipped
checks over three arms of the full violation set and recovered all four with zero false
positives across ten negative controls — but only as the union of `cross_arm_privileged_function`
with marker `"role":"admin"` (`/api/Users`, `/api/Users/1`,
`/rest/user/authentication-details`) and `cross_arm_authorization` with `owner_field
data.UserId` (`/rest/basket/1`). No single marker reaches 4/4: an exhaustive sweep of 15,001
substrings of the admin user record found 826 that score 4/4, and every one is a seed-data
timestamp fragment or JSON punctuation. The reason is structural — three of the four are one
dataset a function marker can name, and the BOLA is an object whose body carries no privileged
attribute at all, only an owner field.

The marker is genuinely load-bearing: a shape-only marker `"status":"success"` reports 7, of
which 3 are declared negative controls (`/api/Cards` per-identity scoping, `/rest/basket/99999`
absent record, `/rest/order-history` each arm's own orders).

**A PLAIN GET IS NOT ALWAYS A READ**, and the probe does not pretend otherwise. Measured on
Juice Shop: a bare `GET /rest/captcha/` runs `CaptchaModel.build().save()` and rotates the live
captcha (`captchaId` 51 then 52 on two consecutive reads); `GET /rest/saveLoginIp` updates the
user row; retrieving five static PNGs under `/assets/public/images/padding/` flips challenges
to solved; and `GET /rest/web3/nftMintListen` makes the **target** open a websocket to a public
host. `state_changing: false` cannot express any of that, because it is about the method.

What bounds the exposure is where the URLs come from. `seeds()` returns only this arm's own
endpoint rows, minus script-inferred routes (never requested by anything) and minus
form-synthesised actions, fragments collapsed — so **every URL read was already requested by
this arm's own crawler during discovery.** Verified: 0 of the 86 URLs read on a real run were
absent from that arm's rows, and `/rest/captcha/` was discovered by the browser pass, so its
write had already happened before this probe existed. The read changes the volume of requests,
not the class of side effect the lane already causes. On an application that must not be
touched that way, set `surface_read: false` and the cross-arm checks go back to having no
input.

**Two further limits worth knowing.** The lane's own redaction rewrites secret-shaped values,
so stored evidence for `/rest/user/authentication-details` reads
`"password":"[REDACTED]"` — a password-shaped marker can never be found, however natural it
looks. And `owner_field: data.id` appears to find both object-level violations, but on
`/rest/basket/1` it is reading the basket's own primary key as a principal id; it matches
admin's `subject_id` only because Juice Shop seeds basket *n* to user *n*. `data.UserId` is the
sound declaration.

### Deriving object instances from collections

The lane discovered **collections** and never **instances**, and object-level authorization
lives on instances. Measured on a real three-arm Juice Shop run: `/api/Users` and `/api/Cards`
had endpoint rows, `/api/Users/1` and `/rest/basket/1` had none, and only 5 of 234 discovered
URLs contained a numeric path segment.

The surface read's own evidence already named them: 15 collections in that run carried integer
row ids, `/api/Users` among them. So pass two of the read derives instance URLs from the
collection bodies pass one captured, and reads those.

**The hazard this raises is the sharpest one in the threat model** — "a discovered value fed
back into a probe lets the target choose the evidence", the rule a planted
`<a href="/search?219359=1">` earned by turning a discovered parameter name into a CRITICAL
template-injection finding against an application with no template engine. An id read out of a
response body is the same kind of text.

So `inventory.safe_object_id` is a whitelist of **shapes**: a bounded run of ASCII digits, or a
canonical UUID. Explicit `[0-9]`, never `\d`, because `\d` matches Arabic-Indic `١` and
fullwidth `１`. A traversal, a slash, a percent escape, a space, a sign, a float, a URL and a
Python `bool` all fail it. The URL is then **rebuilt** — scheme and netloc copied from the
collection, query and fragment dropped, the id appended as one path segment — so no id can move
the request to another host or above the collection's path. Dropping the query matters: an
independent implementation that concatenated produced
`/api/Challenges/?name=Score%20Board/74`, which is still the list route with a nonsense filter
and answers 200 to everybody.

**Say plainly what the gate is for.** Measured across all 15 collection bodies in a real run:
889 rows, every `id` an integer, **0 rejected**. It is a safety gate against a hostile target,
not a precision filter — it is what makes the feature safe to have, not what makes it useful.

**Unlike pass one, this issues requests nothing crawled.** Pass one can say every URL it
fetches was already fetched during discovery; a derived instance was not. So it additionally
requires `active` — the operator's existing declaration that this run may probe — and has its
own `derive_instances` switch. The share is **split, not doubled**: pass two takes a third of
the read's budget, so `max_urls` keeps meaning what the operator set.

Candidates are taken **breadth before depth** — every collection's first instance before any
collection's second. Depth-first spent a tight budget on whichever collections sorted first:
measured, 30 candidates against a share of 28 dropped exactly `/api/Users/2` and
`/api/Users/3`, because `/api/Users` comes last alphabetically.

**Derived URLs are excluded from the object-level check, and this is the important part.** On a
derived instance the asserted owner IS the path segment the lane chose: `GET /api/Users/1`
answers `{"data":{"id":1,…}}`, so `owner_field: data.id` reads back the `1` the lane put in the
URL. An adversarial pass scored it on real captures across four `owner_field` declarations —
derivation took `cross_arm_authorization` from 0 findings to **1 true positive and 7 false
positives**, precision over all declarations falling from 1.00 to 0.42 — and porting the
reflection clause removed all seven *along with the only true positive*. There is nothing for
that check to keep on a URL the lane invented.

The worst of those false positives is worth naming: `/api/Feedbacks` answers **200 to anonymous**
and its row id 1 carries `UserId 1` with the full comment, while `/api/Feedbacks/1` is 401 to
anonymous because only the instance route is guarded. Every clause is then satisfied for a
customer "reading the administrator's feedback" — content the anonymous arm's own evidence for
the *collection* shows is published.

`cross_arm_privileged_function` is unaffected and gains, because its marker is the **operator's**
and no choice of URL satisfies it. That is the safety asymmetry one level down: who the caller is
comes from the operator, and so does what privileged data looks like — but an *owner* is read
from the response, and here the lane wrote it.

**Measured end to end** on a three-arm Juice Shop assessment through `service.run()` with
`derive_instances` enabled:

    privileged-function   findings=2   checked=225   refused_because=[]
      FINDING http://juice-shop:3000/api/Users     [customer -> admin]
      FINDING http://juice-shop:3000/api/Users/1   [customer -> admin]
    object-level          findings=0   checked=206

Two of the four known violations, zero false positives over 225 compared operations — the
collection from Increment 11 and now the instance. The object-level check reports nothing, which
is correct: derived URLs are withheld from it and no other object-level violation was reached.

**What this does not reach, measured.** `/rest/basket/1` is not recoverable this way at all: no
collection lists baskets, and `/api/BasketItems` carries `BasketId` as a foreign key rather than
as its rows' `id`. Classic BOLA — each arm seeing only its own ids — is also out of reach,
because an arm derives from its own listing and never names another principal's object.
`/api/Users/3` (a customer reading a third user's record) is a real violation the check declines
on purpose: `asserted != owner_subject` drops it, so BOLA recall is bounded by the number of
**declared identities**, not by the number of instances read.

And one of the three "unreachable" violations never was: `/rest/user/authentication-details/`
(with the trailing slash) was in every arm's endpoint rows, non-static, at position 105 of 200
in the read order — lost to the **URL budget**, not to the collection/instance gap. Raise
`max_urls` and it is read.

**DVWA has no derivable collections.** Of 50 2xx responses in a real DVWA run exactly 2 are
JSON, both bare arrays, and the one carrying per-user records has no `id` key at all (only
`user_id`) and is served as `text/html`. Worse, its derived instance URL is not an instance
route: Apache accepts the extra segment as `PATH_INFO`, the script ignores it, and
`get_user_data.php/1` returns the **entire collection**, byte-identical. The feature is API-only
in practice.

**The anonymous arm is handed the instances the other arms derived, and without that the
feature produces nothing.** An arm derives from collections *it* can read, and the anonymous arm
is refused exactly the interesting ones. Measured on a clean three-arm run: the only derived
instances all three arms shared were of **public** collections — Challenges, Products, Feedbacks,
SecurityQuestions — while `/api/Users/1` was derived by both identity arms and by neither the
anonymous one. The function-level check then skipped it, correctly: clause 3 requires the
anonymous arm to have **asked**, and an arm that never requested a URL proves nothing about
whether that URL is public.

So the arm whose whole job is to establish "not published" is given the URLs it must ask about.
The anonymous stage is registered last, so those rows exist when it runs. This cannot invent a
finding — an anonymous 2xx *suppresses* one — so the only thing asking can do is remove findings
the lane would otherwise have reported.

It also corrects what looked like the obvious economy. 10 of the 15 collections are readable
anonymously and nearly a third of derived probes hit routes `denyAll()` or `isAccounting()`
refuses to everyone, so about two thirds of the derived budget appears to buy nothing — and
gating derivation on "was the **collection** refused to the anonymous arm" was measured to cut 36
probes to 10 while keeping the true positive. But that gate is backwards once the anonymous arm
needs the instances: the collections it cannot read are precisely the ones worth deriving from.
The other candidate signal, "does the collection body differ between the arms", is **unsound** for
a different reason — `/api/Users` is byte-identical between admin and jim and is exactly where
the real violation is.

### The same response twice is not two observations

Everything the lane does is rationed by `max_urls`, and half a real run's read budget bought the
same document twice. Measured on a three-arm Juice Shop assessment: of 86 surface reads, **37
returned a response the lane had already seen**, absorbed into three survivors — `/`,
`/api/Feedbacks` and `/api/Quantitys`. The 36-strong group is the single-page application's
shell, which its server returns for any route it does not know:

    /   /%5C/index.html   /.json   /2fa/enter   /Edge/   /Trident/   /about
    /accounting   /address/create   ...and 27 more

`/Edge/` and `/Trident/` are browser-detection regex fragments katana mined out of a JavaScript
bundle. A catalogue case probing those for injection cannot find anything, and a coverage report
listing them as untested reads as outstanding work when there is none — that report said 461 of
566 rows were `not_run`.

**The rule is a comparison, not a guess.** `inventory.indistinct_urls` maps each URL that
answered with a response an earlier URL had already given to the URL that gave it first. "The
same response" is `inventory.response_signature`: the **status**, the **stable headers** and the
**body**. One rule also folds in the ordinary case — `/api/Feedbacks` and `/api/Feedbacks/` are
separate endpoint rows with identical bodies.

**The headers are compared, and that was free.** `WSTG-SESS-02` decides entirely on
`Set-Cookie` and `WSTG-CONF-06` on `Allow`, so a body-only rule could prune the one URL whose
finding lives in a header. Only genuinely volatile headers are excluded — `Date`,
`Content-Length`, `ETag`, `Age`, `Expires`, `Last-Modified`, `Keep-Alive`, `Connection` and a
few request-id headers. Measured on the real captures, comparing the stable headers as well as
the body changed nothing: 35 groups and 37 pruned either way. The blind spot closed for free.

**An empty body is never evidence**, and a real measurement forced that clause. On DVWA six
genuinely different static files — `detail.png`, `overview.png`, `main.css`, `logo.png` —
grouped together because the captures came from an `OPTIONS` probe and every body was 0 bytes.
Pruning them would have discarded four real assets. Only 2xx is compared for the same reason in
reverse: every refusal looks alike, and on DVWA an unauthenticated arm is redirected away from
the whole surface.

**Only the no-parameter cases are pruned.** A parameter probe is a different request from the
bare read that grouped, so a URL whose base response is the shell could still answer differently
to `?id=1'`. Measured, no pruned URL carried a discovered parameter at all — but the safety is
structural rather than resting on that: `parameters_by_url` pairs are never consulted against
the pruned set.

**What it buys is better targets, not fewer probes** — and the first framing of this was wrong,
so it is worth being exact. A case takes its *share* of the budget (`case_targets =
eligible[:case_budget(tc)]`), so a shorter eligible list changes *which* URLs it picks, not how
many. Measured on two otherwise identical three-arm runs:

    before   WSTG-INFO-03 probed 21 urls, 11 of them a response already seen  (52%)
    after    WSTG-INFO-03 probed 21 urls,  0 of them a response already seen

Same 21 probes; every one now lands on a distinct response instead of fetching the application
shell eleven times.

It does *not* free the surface read's own budget — the read cannot know a URL is a repeat until
it has read it. The other half of the win is the **report**: `coverage()` has an `indistinct`
state, so a URL with nothing left to test no longer reads as `not_run`. Endpoint rows are
untouched, so the cross-arm authorization comparison sees exactly what it saw before.

### What the matrix does not unlock

A lane stage carries exactly **one** identity — it resolves it from its own row, and the
proxy authenticates that stage's requests as it. The `ownership` evaluator needs three
arms in one case execution (the caller, the declared owner, anonymous), so no single stage
can satisfy it however the identity is declared. `subject_id` reaching a case is
groundwork, not a working lane check.

The lane-native shape is a comparison **across** stages, which is what
`POST /sessions/{id}/authorization` above does. Run a stage per identity, then compare. The
three-arm checks that live inside a single case — WSTG-AUTHZ-04 — still belong to the sweep
or the CLI, where per-role credentials can be supplied to one execution.

## Coverage: what ran, what did not, and why

Two routes answer the same question from either side of a run.

`GET /api/integrations/sessions/{id}/preview` — **before** it starts, what will not be
reached. `GET /api/integrations/sessions/{id}/coverage` — **after**, what happened to
every known (endpoint, parameter) pair. Both accept `identity_id` to narrow to one arm.

The reason they exist is measured. At the default budget the 2026-09-10 run tested one
or two parameters per case out of eight and **lost six of nine findings** — and said so
only in per-case observations nobody reads before launching. Everything needed was
already recorded; nothing aggregated it, so the question an operator actually has ("was
this endpoint tested?") had no answer.

### The states, and what they refuse to claim

| State | Meaning |
|---|---|
| `verified` | a finding came out of the probe |
| `answered` | the probe ran and bytes came back, and nothing matched |
| `unreachable` | every executed step received an empty response |
| `refused` | the lane declined it — a forgeable parameter name, a withheld form action |
| `not_run` | a selected case was eligible and the budget or the clock ran out |
| `inferred` | read out of a JavaScript body; nothing has requested it |
| `not_attempted` | in the inventory, and no selected case tests it |

**There is no `tested`.** `answered` means something answered, which is not proof the
check exercised the application: measured on DVWA, a probe missing its CSRF token
answers HTTP 200 with 389 bytes of PHP warnings, so the emptiness detector stays quiet
and nothing was tested all the same. `verified` is the only state the lane can stand
behind, and adding `answered` to it does not produce a coverage figure.

`not_run` and `not_attempted` are deliberately different answers. The first says a
bigger `max_urls` would have covered it; the second says nothing you selected tests it,
and no budget changes that.

### One unit of work, shared

Both routes count **probeable pairs**, not endpoint rows. Twenty crawled variants of
`/api/Challenges/` are one pair per parameter, because a crawled URL's query holds a
sample value rather than the name under test — while a form action keeps its query,
which its handler requires. `inventory.probe_key` defines that once and both sides use
it, so the preview cannot promise work the coverage report will not account for.

Getting this wrong in either direction was measured: matching endpoint rows literally
credited 2 of 13 probes that ran, and normalising without grouping credited 57.

## Authorization differentials: identity against configuration

An authorization differential only says something about identity if identity is the
only thing that varies. Two fields keep that true, and they are not the same kind of
thing:

| Field | Kind | Carried by |
|---|---|---|
| `high_priv_token` / `high_priv_cookie`, `low_priv_token` / `low_priv_cookie` | identity — secret, resolved from the credential store at execution | the arm it belongs to |
| `config_cookie` | application configuration — not secret, operator-declared | **every** arm, the anonymous one included |

They used to be one field, and a differential cannot be one variable while that is
so. DVWA's security level travels in a cookie and its
`dvwaSecurityLevelGet` falls back to `impossible` when the cookie is absent — so an
anonymous control arm that sent nothing was not the same application with nobody
logged in, it was a hardened one. Measured on
`/vulnerabilities/authbypass/get_user_data.php` at `security=low`, where the endpoint
has no access control at all: all three identities and an anonymous caller *carrying
the level* get the full user table, while an anonymous caller sending nothing gets
`Access denied`. With the bare arm the check reported HIGH on data the application
publishes to anyone.

Set `config_cookie` when the application's behaviour depends on a cookie that is not
a credential — a security level, a locale, a feature flag, a tenant selector. Leave
it unset otherwise and nothing changes; Juice Shop needs none.

## Object-level authorization

The `ownership` evaluator asks whether the application itself attributes an object
to somebody other than the caller. On an API that is a sharper question than
comparing response bodies: every JSON response carries ids and timestamps, so two
identities never produce identical bytes and a body differential is noise.

A case declares it like this:

```yaml
evaluators:
  - type: ownership
    owner_field: data.UserId      # where the response names the owner
    owner_step: read_as_owner     # the step that re-reads it as that owner
    anonymous_step: read_anonymously
    emit_finding:
      vuln_type: Broken Object Level Authorization
      severity: high
```

and the operator supplies `subject_id` — who the caller *is* — in the target. All
four clauses must hold for a finding:

1. the caller got the object, and the response **asserts** an owner;
2. that owner is not the caller's declared `subject_id`;
3. the declared owner can read the object too, so the claim is corroborated;
4. an anonymous request is **refused**, so the content is not published.

The asymmetry is the safety property. `subject_id` comes from the operator; the
asserted owner comes from the target. A target can therefore push the lane towards
"this is not yours" and never towards "this is yours" — it can cost itself coverage
and cannot manufacture a finding. Clause 4 closes the remaining gap: a page that
asserts one owner to every caller, anonymous included, is published content however
it is attributed, and without that clause the lane would report it as a critical
leak.

Validated against Juice Shop v17.1.1 and against a fixture written to forge
ownership:

| Request | Verdict |
|---|---|
| `GET /rest/basket/1` as user 2 | **finding** — attributed to user 1, anonymous refused 401 |
| `GET /rest/basket/2` as user 2 | no finding — the caller owns it |
| `GET /rest/basket/99999` | no finding — HTTP 200 with `{"data":null}`, no object |
| `GET /api/Products` | no finding — asserts no owner |
| a fixture asserting one owner to everyone | no finding — published, not leaked |

The third row is why E-011 says "not merely HTTP 200": a nonexistent object answers
200, and a status-code check calls that a critical flaw.

**Limits.** It needs the application to name an owner in the response. Indirect
ownership — Juice Shop's `/api/BasketItems/9` names a `BasketId` and no user — is
not covered, nor is function-level authorization, where there is no object to
attribute. A caller whose session has expired asserts no owner either, so it
produces no finding rather than an explicit "could not test".

## DefectDojo

Export is always explicit — no stage writes to DefectDojo on its own. Findings are
matched by a stable fingerprint rather than a report-local ID, so a second export
updates what it already sent instead of duplicating it. `close_old_findings` is
always false in v1, including for complete scans, and Erlik never imports remote
triage: the local review state is authoritative and is pushed outward, never read
back.

The server must be an explicit HTTPS **origin** — scheme, host and optional port,
nothing else. A `http://` URL, a path (`https://dojo.example.com/dojo`), a query,
or credentials in the URL are all refused at validation. `:443` is accepted and
normalised away; any other port is kept, so a DefectDojo on `https://dojo:8443`
needs no fronting (that is what the project's own live acceptance test uses).

### Registering the API token

The token never travels in the export body. Store it once and refer to it by
handle:

```sh
curl -sX POST http://127.0.0.1:8002/api/integrations/secrets \
  -H "X-API-Token: $ERLIK_API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"token":"<DefectDojo API v2 key>"}'
# -> {"id":"e9082a26d4a1e8d1b923316f2e884ccb"}   a 32-character handle
#    Use it as secret_id below. The token itself is never echoed back, never
#    stored in the export record, and is redacted from the audit evidence.
```

### First import

A first import creates the test inside an engagement that already exists. It needs
`engagement_id` and `test_title`, and must **not** carry a `test_id`:

```json
{
  "server": "https://dojo.lab.internal",
  "secret_id": "e9082a26d4a1e8d1b923316f2e884ccb",
  "action": "import",
  "engagement_id": 7,
  "test_title": "Erlik assessment 2026-09-10"
}
```

```sh
curl -sX POST http://127.0.0.1:8002/api/integrations/sessions/$SESSION/defectdojo \
  -H "X-API-Token: $ERLIK_API_TOKEN" -H 'Content-Type: application/json' \
  --data @first-import.json
```

`action` defaults to `reimport`, so **omitting it on a first import is refused**,
not silently treated as one:

| Body | Result |
|------|--------|
| `action: "import"` + `engagement_id` + `test_title` | accepted |
| `engagement_id` + `test_title`, no `action` | `reimport requires an existing test_id, without engagement_id or test_title` |
| `action: "import"` + `engagement_id` + `test_title` + `test_id` | `initial import requires an existing engagement_id and test_title, without test_id` |
| `action: "reimport"` + `test_id` | accepted |
| `action: "reimport"` + `test_id` + `engagement_id` | `reimport requires an existing test_id, without engagement_id or test_title` |

The engagement must already exist: `auto_create_context` is sent as `false`, so
Erlik will not conjure a product or engagement to import into.

### Re-exporting the same session

**The same body works again.** A successful import records the destination it
reached together with the remote test ID, so a repeat export of that destination
resolves the remote test from that record and reimports into it — the operator
does not have to rewrite the configuration after the first run. Only fingerprints
the remote test does not already hold are sent to the importer; everything else is
compared field by field and PATCHed by remote ID only where it actually differs.

If the report is byte-identical to the last completed export to that destination,
nothing is sent at all and the previous export record is returned.

To reimport into a test whose ID you know — one created by hand, or one from a
different session — address it directly:

```json
{
  "server": "https://dojo.lab.internal",
  "secret_id": "e9082a26d4a1e8d1b923316f2e884ccb",
  "action": "reimport",
  "test_id": 42
}
```

### Reconciling an uncertain export

What the status means:

| Status | Meaning | What to do |
|--------|---------|------------|
| `completed` | Every field Erlik reads back is present remotely | nothing |
| `failed` | Nothing was written, and the destination is not blocked | fix the body or the token and export again |
| `uncertain` | A write was issued and its outcome is unknown | reconcile |

`completed` is about the fields that are read back, which is not all of them: a
finding's `endpoints` are never compared after the import, and `title` is matched
case-insensitively against its first 511 characters because DefectDojo titlecases
and truncates it. So `completed` does not by itself tell you the URL a finding is
about arrived intact.

**Uncertainty requires a write.** A failure that sent nothing — the sandbox not
starting because Docker is down, a cancelled run, a connection reset during the
inventory read — is `failed`, with `Failed before any request was issued; nothing was
written and this destination is not blocked`. Retry it.

That distinction matters because an uncertain row blocks its destination and
reconciliation cannot clear one that has no remote write to verify against: it would
answer `Remote state differs from intended export` for ever. Marking a local failure
uncertain therefore locked an operator out of exporting the assessment at all, with
no way back. Only the two requests that actually write — the import POST and a
finding PATCH — can produce uncertainty; the inventory GETs that precede them are
reads, and a read changes nothing.

A 202 is uncertain, not successful: the import was queued, and nothing has
confirmed it landed. Treating it as a failure would invite a retry that silently
imports twice.

#### What "blocks" actually covers

An uncertain write is never retried automatically, and it blocks further exports. The
block matches an export by destination, by remote test ID on that server, **and** —
for the session that made it — by the mere existence of an unresolved export to that
server whose destination is not yet known.

That third clause exists because the first two missed the case the guard is for. An
import whose response was lost never learned a test ID, so its row carries
`remote_test_id = NULL` and neither of the first two clauses can match it. Finding the
test in the DefectDojo UI and reimporting into it by ID then sailed straight past the
guard and wrote a changed report over a write nobody had established — the exact
papering-over the guard prevents, in the exact scenario it was written for.

It is narrow on three counts, because a wider block would lock out more operators
rather than fewer: it is scoped to the session that made the unresolved export, scoped
to that server, and lifts as soon as the row is resolved, since reconciling it fills in
the test ID it verified. A `failed` export does not block at all.

**So reconcile the uncertain row before addressing the test directly.** That is now
enforced rather than advised.

Reconciliation is **read-only**. It lists the remote test's findings, compares
them against the evidence recorded for that export, and marks the export completed
only if every intended finding is present and matching. No request is replayed.

It requires the remote test ID explicitly, even when the original export was an
`import` — supply the ID you can see in the DefectDojo UI:

```sh
curl -sX POST http://127.0.0.1:8002/api/integrations/exports/$EXPORT_ID/reconcile \
  -H "X-API-Token: $ERLIK_API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"server":"https://dojo.lab.internal","secret_id":"e9082a26d4a1e8d1b923316f2e884ccb",
       "action":"reimport","test_id":42}'
```

The server must match the original export's, and if the export record already
knows a remote test ID, the one supplied must equal it. Two outcomes:

- `Remote state verified; no requests replayed` — status becomes `completed`, the
  fingerprint→remote-ID map is filled in, and exports to that test are unblocked.
- `Remote state differs from intended export; no requests replayed` — the status
  stays `uncertain`. Inspect the remote test yourself; reconciliation will not
  guess which side is right.

Two remote findings sharing one fingerprint is refused —
`Multiple remote findings share one fingerprint; reconcile the remote test`. On
export that lands as the row's `detail`; reconciling returns **502** with the same
message, because the remote is what did not cooperate. It usually means the
importer's own deduplication merged or split findings, and it has to be settled in
DefectDojo before Erlik can map them.

Every export and every reconciliation writes an audit record to the session's
evidence store, with the API token redacted.

## Results and validation

The dashboard provides stages, endpoints, evidence and export records. Existing
JSON, HTML, SARIF and Generic Findings report routes support integration sessions.
Evidence is untruncated but credential-redacted. Temporary raw files are removed
when jobs close. Historical results are unchanged.
After a run, findings can be reviewed as open, false positive, or fixed with a
required note. Reports include open findings; explicit exports carry the local
review state. Review actions are retained as evidence.

```sh
pytest -m 'not docker'                              # network-free, no containers
ERLIK_DOCKER_TESTS=1 pytest -m docker               # every container-backed suite
ERLIK_DOCKER_TESTS=1 ERLIK_BENCHMARK_OUTPUT=/tmp/discovery-comparison.json \
  pytest tests/test_integration_docker.py -k baseline_comparison
```

`-m docker` is the marker, not a filename: the container-backed suites live in
several files, and selecting them by path is how a new one ends up never running.

### Opt-in variables

Every one of these defaults to off. A suite that cannot reach what it needs skips
with a reason rather than failing — missing coverage is not a defect in the code,
and must not be reported as one.

| Variable | Effect |
|----------|--------|
| `ERLIK_DOCKER_TESTS=1` | Run the local container suites. Needs the lane images built. |
| `ERLIK_REAL_INTERACTSH_TESTS=1` | Register against a real self-hosted Interactsh server instead of the protocol fixture. Set it **together with** `ERLIK_DOCKER_TESTS=1` — on its own it skips. Build the lab first: `docker build -t erlik-interactsh-lab:1 docker/interactsh-lab`. |
| `ERLIK_DEFECTDOJO_LIVE_TESTS=1` | Run the export flow against a real DefectDojo, brought up from `docker/defectdojo-lab/`. Sufficient on its own — unlike the Interactsh gate above, it does not also need `ERLIK_DOCKER_TESTS`. No credentials either: the fixture mints the lab's own database password, secret key, AES key and admin password per run and writes them to a compose env-file. It also needs `openssl` on PATH, for the lab's TLS certificate. |
| `ERLIK_COVERAGE_REPORT=<path>` | Write the baseline-vs-integrated benchmark report. Written before the *metric* assertions, so a run that regresses still leaves its numbers behind — but the report is assembled from both arms, so a run that fails because a stage never completed produces none. |
| `ERLIK_BENCHMARK_OUTPUT=<path>` | Write the Katana-vs-browser-crawler discovery comparison. |
| `ERLIK_ACTUAL_SERVICE_TESTS` | Repository **variable** (not an env var) gating the CI job that starts real services. Must be `true`, and the run must be a release or a manual dispatch. |

### Runtime variables

| Variable | Effect |
|----------|--------|
| `ERLIK_API_TOKEN` | Required to reach `/api/integrations/*` at all — these routes are refused without it whether or not the rest of the API is protected. |
| `ERLIK_INTEGRATION_EGRESS_NETWORK` | The Docker network the MITM proxy joins to reach the target. Defaults to `bridge`. |
| `ERLIK_INTEGRATION_CA_FILE` | A PEM bundle to trust for an internal PKI. Upstream TLS verification stays on. |
| `ERLIK_INTEGRATION_DATA` | Where the lane keeps secrets, proxy CAs and evidence. Gitignored; never put it in a tracked path. |

### Pinning a build

`scripts/release_manifest.py` records the image IDs, the versions of the tools
*inside* the worker image, and the commit — the things a benchmark report is
meaningless without six months later:

```sh
python scripts/release_manifest.py --out build-manifest.json
python scripts/release_manifest.py --skip-tools   # skip the in-image probe
```

It reads no configuration, contacts no service, and never touches the evidence
store. An image it cannot find is recorded as absent rather than omitted.

The Docker tests create and remove their own target and recording server. They
check redirect refusal, direct-egress denial, authentication isolation, actual
container cancellation, JS discovery, seeded API failures and authenticated ZAP.
They do not contact client targets. Unit tests cover callback association,
DefectDojo replay behavior, migrations, secrets, HTTP/WebSocket authentication,
and evaluator regressions.
The discovery comparison executes the original `pw-crawl.js` with transport-only
proxy/driver shims against the same fixed fixture as Katana. It compares reported
endpoint inventories, not all requests the browser could reach, and does not
measure vulnerability precision or recall. Client-target and public callback
acceptance are not implied by the local HTTPS protocol fixtures.
