# Blind SQL injection: what the two new cases were measured against

Date: 2026-09-09. Lab only — DVWA (PHP 8 / MySQL 8.0), Juice Shop v17.1.1
(Node / SQLite), and throwaway MySQL 8.0 and PostgreSQL 16 containers. Nothing
outside this machine was contacted.

Two cases were added because the lane had no way to see an injection that emits
no error. `WSTG-INPV-05.2` says so in its own header, and DVWA's `sqli_blind`
module was being probed and correctly reported as nothing.

- **WSTG-INPV-05.3** — boolean differential. 7 requests, sub-second.
- **WSTG-INPV-05.4** — time-based. 11 requests, ~24s on a clean parameter.

## The positive control

DVWA `sqli_blind`, `security=low`, driven through the real runner:

| case | steps run | findings | grade |
|---|---|---|---|
| INPV-05.3 | 5 (stopped early) | 1 | `confirmed` |
| INPV-05.4 | 5 (stopped early) | 1 | `suspected` |

The boolean finding's evidence quotes the difference it decided on:

```
    control_a          4687 bytes  (control)
    control_b          4687 bytes  (control)
    false_string       4687 bytes  (false condition)
    true_string        4681 bytes  DIFFERS
  first difference:
    false: ... <pre>User ID is MISSING from the database.</pre> ...
    true : ... <pre>User ID exists in the database.</pre> ...
```

The timing finding measured 5021ms against 1014ms for its own short probe — a
4007ms margin over the 3000ms the evaluator requires.

## The negative controls

`security=impossible`, same URL and parameter: 0 findings from both cases.
Honest caveat — DVWA's impossible level demands a CSRF token and short-circuits
before running any query, so this shows the case reports nothing, not that it
reports nothing *against a prepared statement*. The prepared-statement negative
is the `/safe` route of `tests/fixtures/blind_injection_app.py`.

Juice Shop, five endpoints × both cases = 90 requests, **0 findings**. One of
those five is the measurement that justifies the whole control design:

    /rest/track-order?id=erlikprobeaaa
      -> <title>Error: Unexpected path: /rest/track-order?id=erlikprobeaaa</title>

Juice Shop's 404 handler renders the request path into the page, so any two
probes differ. A boolean differential without a validity control reports SQL
injection on **every unmatched route of the application**. Here the controls
disagreed, the case declined, and nothing was reported.

## Payload decisions, and what forced them

**No `OR` payload, ever.** `nosuchid' OR SLEEP(1) AND '1'='1` against DVWA took
5025ms — five sleeps for a five-row table, because MySQL evaluates the WHERE
clause per row and the left side is false for every one. The same shape against
a table of any real size is a denial of service delivered by a scanner. Pinned
by `test_an_or_payload_would_sleep_once_per_row`.

**MySQL needs a seed that matches; PostgreSQL does not.** `1' AND SLEEP(4) AND
'1'='1` took 4012ms on DVWA and 9ms with a seed matching no row — MySQL
short-circuits the AND per row. PostgreSQL ran the same shape in ~6100ms for
both seeds, because `(SELECT 1 FROM pg_sleep(n))` is uncorrelated and evaluated
once before the scan. So the case seeds on `1`, reaches MySQL only through a
parameter whose valid value is guessable, and reaches PostgreSQL regardless.

**A warm-up request, because the first response of a session is different.**
DVWA's first authenticated response carries `You have logged in as 'admin'`
(4774 bytes against 4687 for every one after it). Landing on `control_a`, that
one-shot banner made the controls disagree and a known-vulnerable target report
nothing.

**Equal-length probe pairs.** `SLEEP(1)` and `SLEEP(5)` are the same length, so
an endpoint whose latency tracks input length moves both equally. Pinned by
`test_every_sleep_payload_pair_is_the_same_length` and exercised by the
fixture's `/slow_by_length` route.

## Two false positives the design had to be changed for

Both were found by attacking the evaluator rather than the payloads.

1. **A timed-out step is a confident false positive in both directions.** curl's
   `--max-time` makes `duration_ms` the whole budget, so a hung request looks
   exactly like a successful `SLEEP(20)`; and its empty body differs from every
   control, so it looks exactly like a true condition. Both evaluators now
   decline a step that did not succeed with a body.
2. **The evidence was the wrong document.** A blind finding's proof is the
   comparison, not the response — the true condition on its own is an ordinary
   page. The evaluators now emit the comparison, and the first-difference window
   is taken from the normalised text, because diffing the raw bodies pointed at
   the CSRF token that normalisation exists to ignore.

## Grading

`boolean_differential` is graded `confirmed` — which sets `verified` on the
DefectDojo export — only when the false condition also sits on the baseline,
i.e. both halves of the pair behaved as SQL. When only the true side moved, the
difference is real but the reading of it is a lead: `suspected`.

`timing` is **never** graded `confirmed`. One measurement cannot rule out a
single spike landing on the long probe alone, and that is the residual risk the
design does not close. Both cases chain to `WSTG-INPV-05` (sqlmap), which
retries.

## Coverage this does not have

- No MSSQL (`WAITFOR DELAY`) or Oracle payloads. Both are stacked-query or
  package-call shapes with nothing in the lab to validate against, and shipping
  an unvalidated payload is how a scanner comes to claim things it did not test.
- A parameter whose valid values are not guessable is out of reach on MySQL.
- Second-order injection — where the payload is stored and executed later — is
  invisible to both cases.
