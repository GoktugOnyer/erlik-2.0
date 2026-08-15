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
| `/noframe` | no `X-Frame-Options`, no CSP `frame-ancestors` | `WSTG-CLNT-09` |
| `/allowfrom` | `X-Frame-Options: ALLOW-FROM` (never enforced) | `WSTG-CLNT-09` |
| `/redirect` | honours `?url=` | `WSTG-CLNT-04` |
| `/cors` | reflects any `Origin`, including `null`, with credentials | `WSTG-CLNT-07b` |
| `/.git/HEAD` | exposed VCS working copy | `WSTG-CONF-04` |
| `/nosql-safe`, `/ldap-safe`, `/safe` | correctly implemented | negative controls |

## Current status

| Case | Positive | Negative |
|---|---|---|
| `WSTG-INPV-05.6` NoSQL | 2 findings | clean |
| `WSTG-INPV-06` LDAP | 2 findings | clean |
| `WSTG-CLNT-04` Open Redirect | 1 finding | — |
| `WSTG-CLNT-07b` CORS | 2 findings | — |
| `WSTG-CLNT-09` Clickjacking | 1 finding | clean |
| `WSTG-CONF-04` VCS artifacts | 1 finding | — |

`WSTG-CONF-02` (debug endpoints) and `WSTG-INPV-15` (hop-by-hop headers) have no
fixture endpoint yet and remain unvalidated — they load and execute, but have not
been observed to fire.
