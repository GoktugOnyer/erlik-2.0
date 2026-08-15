# Validating a test case

A case that loads and runs without error has **not** been shown to detect
anything. Several cases here ran cleanly against Juice Shop and reported nothing,
which is indistinguishable from a case that can never fire. Two controls settle
it:

- **positive** — point the case at a deliberately vulnerable endpoint; it must
  report the finding
- **negative** — point it at the correctly-implemented equivalent; it must report
  nothing

`scripts/vuln_fixture.py` serves both. It needs no MongoDB, LDAP server or git
repository: every case detects through the HTTP response — an error string, a
header, or a body-size differential — so reproducing the response is enough.

## Run it

```bash
docker cp scripts/vuln_fixture.py kali-tools:/tmp/
docker exec -d kali-tools python3 /tmp/vuln_fixture.py
```

Then, for example:

```bash
python -m orchestrator.testcase.cli run WSTG-INPV-06 \
    --target url=http://kali-tools:8098/ldap --target parameter=u \
    --scope kali-tools
```

## Address it as `kali-tools:8098`, never loopback

`tool_executor` rewrites `localhost` / `127.0.0.1` to the session target — see
`_LOOPBACK_HOSTS` and the alias list. A fixture addressed on loopback is never
reached: the probe hits the real target instead, and the run *looks* like a
successful control while describing a different server. That produced a
convincing false pass once, including an apparent false positive that did not
exist. If a control result surprises you, check which server actually answered
before believing it.

## Endpoints

| Endpoint | Vulnerable behaviour | Exercises |
|---|---|---|
| `/nosql` | unknown-operator driver error, `$ne` differential, array cast error | `WSTG-INPV-05.6` |
| `/ldap` | filter syntax error, wildcard and blind boolean differentials | `WSTG-INPV-06` |
| `/hbh` | trusts `X-Forwarded-For` behind a hop honouring `Connection:` nominations | `WSTG-INPV-15` |
| `/actuator`, `/actuator/env` | Spring Actuator index and env dump with a datasource password | `WSTG-CONF-02` |
| `/server-status`, `/server-info`, `/nginx_status`, `/phpinfo.php`, `/console` | exposed platform and debug handlers | `WSTG-CONF-02` |
| `/noframe` | no `X-Frame-Options`, no CSP `frame-ancestors` | `WSTG-CLNT-09` |
| `/allowfrom` | `X-Frame-Options: ALLOW-FROM` (never enforced) | `WSTG-CLNT-09` |
| `/redirect` | honours `?url=` | `WSTG-CLNT-04` |
| `/cors` | reflects any `Origin`, including `null`, with credentials | `WSTG-CLNT-07b` |
| `/.git/HEAD` | exposed VCS working copy | `WSTG-CONF-04` |
| `/nosql-safe`, `/ldap-safe`, `/hbh-safe`, `/safe` | correctly implemented | negative controls |

## Current status — all eight derived cases proven

| Case | Positive | Negative |
|---|---|---|
| `WSTG-INPV-05.6` NoSQL | 2 findings | clean |
| `WSTG-INPV-06` LDAP | 2 findings | clean |
| `WSTG-INPV-15` Hop-by-hop | 1 finding | clean |
| `WSTG-CONF-02` Debug endpoints | 9 findings (every evaluator) | clean |
| `WSTG-CLNT-04` Open Redirect | 1 finding | — |
| `WSTG-CLNT-07b` CORS | 2 findings | — |
| `WSTG-CLNT-09` Clickjacking | 1 finding | clean |
| `WSTG-CONF-04` VCS artifacts | 1 finding | — |

The nine inherited cases (`INFO-02`, `INFO-03`, `CONF-06`, `CONF-07`, `ATHN-01`,
`AUTHZ-04`, `BUSL-04`, `ERRH-01`, `INPV-01`, `INPV-05`, `INPV-19`, `SESS-02`,
`SESS-10`, `CLNT-07`) predate this fixture and are **not** covered by it. They
are exercised against Juice Shop, which genuinely holds several of the
vulnerabilities they look for, but none has been run through a matched
positive/negative pair here.

## Reproducing a control

The hop-by-hop case is the one worth explaining, since its fixture is not just a
canned response. RFC 9110 §7.6.1 lets a client name extra fields in `Connection:`,
and a compliant hop must strip those before forwarding. `/hbh` models an origin
that trusts `X-Forwarded-For` for access control sitting behind such a hop: name
`X-Forwarded-For` in `Connection:` and the origin answers as though it never
arrived, so 200 becomes 403. `/hbh-safe` ignores nominations, so both requests
return 200 and the case correctly reports nothing.
