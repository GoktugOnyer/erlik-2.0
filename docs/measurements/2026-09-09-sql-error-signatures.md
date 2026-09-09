# The error-based SQL injection signature, and what it was measured against

Date: 2026-09-09. Lab only. Nothing outside this machine was contacted.

An adversarial round against `WSTG-INPV-05.2`'s pattern reported that the
detector shipped that morning was much weaker than its own tests said. It was
right, and re-measuring it found more than it did.

## The scores

Corpus: **71 real database-error bodies** across 31 engine/driver/ORM
combinations, and **121 benign pages**, most of which exist because they broke a
specific alternative. Both are in `tests/fixtures/sql_error_corpus.py`.

| pattern | recall | false positives |
|---|---|---|
| `WSTG-INPV-05`, as it stood | 31/71 | 38/121 |
| `WSTG-INPV-05.2`, shipped that morning | 60/71 | 31/121 |
| the adversarial round's proposal | 50/71 | 3/121 |
| **what ships now** | **65/71** | **0/121** |

A third set, `PATTERN_CANNOT_SEPARATE`, holds the bodies where no body-only
regex can win — a Stack Overflow title, a changelog quoting a PHP warning. The
pattern matches them and always will. They are not counted as false positives
because they are not the pattern's job: they read the same before and after the
payload, so the comparison drops them. Keeping them in their own set makes the
layering something a test asserts rather than something a comment claims.

The morning's pattern was tuned against **eleven** benign pages. That is the
whole story of its 31 false positives: the corpus could not see them.

## The false positives that mattered

`java.sql.SQLException` cost six false positives and bought **zero** real
errors. `SQLSTATE\[[0-9A-Z]{5}\]` fired on a Laravel blog post, a hidden form
field and a filter message. But the two that matter most were found by
adjudication, not by the original round:

    sqlite3\.\w+Error       fires on  sqlite3.IntegrityError: UNIQUE constraint failed
    SQLSTATE\[[0-9A-Z]{5}\] fires on  SQLSTATE[23000]: Integrity constraint violation

**A duplicate email at signup, on any application with a leaky error page, was
reported as HIGH-severity SQL injection.** Both are now bound to the failure
text; `test_a_constraint_violation_is_not_an_injection` pins it.

Three rules came out of the negatives, and every dropped alternative broke one:

1. **A class or namespace name is not an error.** One `/openapi.json` publishing
   an error-code enum broke seven alternatives at once.
2. **An error code must carry its message.** `ORA-\d+` fired on `Aurora-2024`
   and on `Invalid parameter ORA-00933: expected integer`, which an application
   can be made to render.
3. **Documentation carries the message too.** MySQL's own manual renders
   `near '%s' at line 1`; Microsoft's error table renders `'%.*ls'`.

## Three structural defects, all produced live

These were not missing alternatives. They were the same mistakes repeated.

**Line-scoped spans break on a query written across lines.** MySQL embeds the
rest of the statement in the message, newlines included:

    ... to use near 'probe'
      AND id > 0
    ORDER BY id' at line 2

Every query builder and heredoc does this. No branch anchors on a trailing
` at line N` any more.

**A literal quote is defeated by any framework.** `htmlspecialchars` is what a
framework is *for*. Produced live from PHP 8.5.3 against the lab's MySQL:

    ... to use near &#039;probe&#039;&#039; at line 1

Every delimiter is now an alternation over the raw byte and its entity forms.
JSON's backslash form is added only on the SQLite token branch, where it was
measured to buy two bodies; on the psycopg branch it bought none and cost a
false positive.

**SQLite has two answers to a lone quote, and the case only knew one.**
`erlik'probe` *closes* a string, so SQLite trips on the identifier after it and
emits a parser row rather than `unrecognized token`. That is what the lab's own
Juice Shop returns:

    GET /rest/products/search?q=erlik%27probe   ->  HTTP 500
    <title>Error: SQLITE_ERROR: near &quot;probe&quot;: syntax error</title>

**A genuine, reachable, error-based SQL injection on a target sitting in the
lab, and the case reported nothing for it.** `SQLITE_ERROR` alone cannot be the
fix — it fires on Juice Shop's own 456KB JavaScript bundle, which describes the
challenge in prose. The engine marker plus the parser grammar fires on the 500
and not on the bundle, measured against both live.

## The gate that was not built

The adversarial round recommended a benign baseline step that **stops** when the
error signature is already present. Measured against real MySQL 8.0 on an
unquoted numeric sink — `WHERE id = <raw>`, the easiest SQL injection to exploit
because it needs no quote to escape:

    id=erlikprobebaseline  ->  ERROR 1054  Unknown column 'erlikprobebaseline' in 'where clause'
    id=erlik'probe         ->  ERROR 1064  You have an error in your SQL syntax
    id=1 OR 1=1            ->  admin, gordonb          (exploit proven)

The benign probe already carries a signature, because *any* non-numeric value
does. A presence check drops that parameter — silently, without a finding, and
without even chaining it to sqlmap, since `chain.on_finding` fires only when
there is a finding.

So the baseline step carries no evaluator at all. Each payload step names it in
`differs_from` and reports only when its own response **differs**. A
documentation page, an error-code table, an OpenAPI enum and a Stack Overflow
question answer both requests identically and are dropped; a 1054 turning into a
1064 is reported, which is what it is. `differs_from` on a `regex` evaluator
parsed and did nothing before this — the runner now consults it, and a baseline
that did not run or came back empty is treated as differing, so a failed request
can never silently suppress a finding.

## A live defect the exercise found on the way

Two alternatives in `WSTG-INPV-05` could not match anything at all. The pattern
was written as a folded `>-` YAML scalar across four lines, and a folded scalar
joins wrapped lines with a **space** — so ` SQLITE_ERROR` and
` Microsoft OLE DB Provider for SQL Server` were loaded with a leading space
nobody wrote. `WSTG-ERRH-01` carried three more. The YAML looked right.
`test_no_catalogue_pattern_was_damaged_by_yaml_folding` now fails on the shape
rather than on the consequence, catalogue-wide.

## Two justifications that were wrong, and are now right

**"PHP 8 no longer warns on a SQL error"** is false. Produced live on PHP 8.5.3:
an application calling `mysqli_report(MYSQLI_REPORT_ERROR)` without `STRICT`
still emits `Warning:  mysqli::query(): (42000/1064): You have an error in your
SQL syntax...`. `Warning.*mysqli?_` is rejected for its `.*` — on PHP 8.5.3 it
fires on `Warning: Undefined array key "mysql_id"`, a response with no database
in it, and one this lane manufactures itself by guessing parameter names. A
justification that is factually wrong is a landmine: the next reader finds the
warning and puts the alternative back.

**The case-sensitivity argument** was six bodies; only one of them is real
evidence, and even that one is already handled by the comparison. The two
reasons that survive are an accident (`ERROR:` is satisfied by the tail of
`...SyntaxError: ` under IGNORECASE) and a case the comparison cannot see (a WAF
answering a quote with a canned lowercased signature). The flag is **not** free,
and the corpus by construction cannot price it: an injectable application whose
error rendering lowercases is found with IGNORECASE on and missed silently
without it.

## Live results

| target | engine | rendering | expected | got |
|---|---|---|---|---|
| DVWA `/sqli` security=low | MySQL 8.0 | raw HTML | finding | finding |
| DVWA `/sqli` security=impossible | MySQL 8.0 | — | clean | clean |
| DVWA `/sqli_blind` | MySQL 8.0 | no error at all | clean | clean |
| Juice Shop `/rest/products/search` | SQLite | HTML-escaped | finding | finding |
| Juice Shop `/api/Products` | SQLite | — | clean | clean |
| PostgREST `/rpc/search` | PostgreSQL 16 | JSON | finding | finding |
| an unquoted numeric sink | MySQL 8.0 | raw | finding | finding |

Four real injections across three engines and three rendering styles; three
negatives clean. Every one of the four costs two requests, and each still chains
to sqlmap.

## What this detector still cannot see

- **A non-English deployment.** Every alternative is an English engine sentence
  or a code bound to its English message, and four of the seven Oracle codes are
  server-translated. Only ORA-01756 — the one a single quote provokes — stays
  English, and that is luck.
- **A wrapper that names no engine**: `SQLGrammarException`,
  `BadSqlGrammarException`, a bare `System.Data.SQLite.SQLiteException`. Real
  errors, byte-identical to an issue-tracker line. Kept as fixtures in
  `sql_error_pages.UNREACHABLE_ERRORS` so the blind spot is a test.
- **An injection that emits no error at all** — `WSTG-INPV-05.3` and
  `WSTG-INPV-05.4` are the cases for that.
- **Oracle 23ai/26ai's ORA-03049**, reported by an agent as the answer to a
  closing-paren break. Not added: there is no Oracle in this lab to produce a
  body for, and an alternative with no body behind it is the thing this whole
  exercise was about.

A clean run on this case is not evidence of absence, and it should be reported
as "error-based SQL injection, confirmed" — never as "no SQL injection found".
