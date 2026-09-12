"""WSTG-INPV-05.2 against real database errors, and against text that only reads like one.

Two layers, because they answer different questions.

The HTTP-driven tests run the real case through the real runner against
fixtures/sql_error_pages.py, and answer "does the CASE work" — including the
differential, which a pattern test cannot reach: the fixture only breaks when
the value carries a quote, and `/always_broken` breaks for every request.

The in-process tests run the pattern over fixtures/sql_error_corpus.py — 66 real
error bodies and 113 benign ones — and answer "is the PATTERN any good". They
pin the exact misses and the exact false positive by name, so a change to the
pattern has to say which one it moved.
"""
import re
import shlex
import shutil
import subprocess
import threading
from http.server import HTTPServer

import pytest

from orchestrator.testcase.loader import find_by_id, load_catalog
from orchestrator.testcase.runner import run_test_case

from fixtures import sql_error_corpus, sql_error_pages

pytestmark = pytest.mark.skipif(shutil.which("curl") is None, reason="needs a real curl")

# A KERNEL-CHOSEN PORT, NOT A FIXED ONE. These fixtures bound a hard-coded number, and two
# full-suite runs inside the TIME_WAIT window left it in `TIME_WAIT` from the first — so the
# second errored every test in the file with `OSError: [Errno 48] Address already in use`, and
# a third minutes later passed. Measured three times in one sitting, once on a fresh clone
# where it read as a product regression and was a socket. `SO_REUSEADDR` does not help: the
# listening socket is gone and what remains are the closed connections to it.
#
# Binding 0 asks for a free one; `server.server_address[1]` is what was given.
CASE = "WSTG-INPV-05.2"


def signature():
    """The evaluator as the runner will apply it — pattern AND flags."""
    ev = next(e for s in find_by_id(CASE).steps for e in s.evaluators if e.pattern)
    return re.compile(ev.pattern, re.MULTILINE | (re.IGNORECASE if ev.case_insensitive else 0))


@pytest.fixture(scope="module")
def pages():
    server = HTTPServer(("127.0.0.1", 0), sql_error_pages.Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://localhost:{port}"
    server.shutdown()


async def real_curl(command, **kwargs):
    result = subprocess.run(shlex.split(command), capture_output=True, text=True, timeout=20)
    return {"success": result.returncode == 0, "exit_code": result.returncode,
            "output": result.stdout, "error": result.stderr or None}


async def probe(route, base):
    return await run_test_case(
        find_by_id(CASE),
        {"url": f"{base}/{route}", "parameter": "id", "scope": {"allow_hosts": ["localhost"]}},
        executor=real_curl, allow_llm=False)


# ------------------------------------------------------------ the case

@pytest.mark.parametrize("engine", sorted(sql_error_pages.DATABASE_ERRORS))
async def test_a_real_database_error_is_detected(engine, pages):
    run = await probe(engine, pages)
    assert run.findings, f"{engine}: a real database error went unreported"
    assert "SQL Injection" in (run.findings[0].vuln_type or "")
    assert run.findings[0].severity == "high"


@pytest.mark.parametrize("page", sorted(sql_error_pages.BENIGN_PAGES))
async def test_a_page_that_merely_mentions_databases_is_not_a_finding(page, pages):
    run = await probe(page, pages)
    assert not run.findings, (
        f"{page}: false positive — a HIGH finding for a request that proved nothing")


async def test_a_page_that_was_already_broken_is_declined_not_reported(pages):
    """`/always_broken` answers every request with the same real PostgreSQL
    error — a debug page left on, a docs page, an error-code table. The pattern
    matches every one of its responses; the payload caused none of them."""
    run = await probe("always_broken", pages)
    assert not run.findings, "reported evidence that was on the page before the payload"
    assert len(run.steps) == 4, "the payloads must still be SENT — only the verdict is withheld"
    assert all(signature().search(s.output) for s in run.steps), (
        "the fixture did not actually leak, so this proves nothing")


async def test_an_unquoted_numeric_sink_is_still_reported(pages):
    """The shape a presence check would have destroyed, and the reason the
    payload steps compare instead of merely matching.

    `WHERE id = <raw>` errors on every non-numeric value, so the benign probe
    already carries a signature — while the parameter is the most exploitable
    kind there is. Reproduced against real MySQL 8.0: 1054 at baseline, 1064
    under the payload, and `1 OR 1=1` returning every row."""
    run = await probe("numeric_sink", pages)
    assert signature().search(run.steps[0].output), "the baseline must itself carry a signature"
    assert run.findings, "an exploitable parameter was suppressed by its own baseline"
    assert run.chain_next == ["WSTG-INPV-05"], "and it must still reach sqlmap"


async def test_a_baseline_that_never_answered_does_not_suppress_a_finding(pages):
    """An unanswerable question is not evidence of innocence. If the reference
    request failed, the comparison cannot be made, and the finding stands on the
    pattern alone rather than vanishing without a trace."""
    from orchestrator.testcase.runner import Evaluator, StepResult, _attributable
    ev = Evaluator(type="regex", pattern="x", differs_from="benign_baseline")
    step = StepResult(step="single_quote", command="curl", success=True,
                      output="You have an error in your SQL syntax", duration_ms=1)
    empty = StepResult(step="benign_baseline", command="curl", success=False,
                       output="", duration_ms=1)
    assert _attributable(ev, step, [empty]) is True
    assert _attributable(ev, step, []) is True
    same = StepResult(step="benign_baseline", command="curl", success=True,
                      output="You  have an error in your SQL syntax", duration_ms=1)
    assert _attributable(ev, step, [same]) is False, "whitespace is not a difference"


@pytest.mark.parametrize("blind_spot", sorted(sql_error_pages.UNREACHABLE_ERRORS))
async def test_the_documented_blind_spots_stay_blind(blind_spot, pages):
    """These are REAL database errors that this detector cannot claim: a wrapper
    class name carrying no engine text, byte-identical to a line in an issue
    tracker, a Javadoc page or an OpenAPI error enum. Every alternative that
    would catch them was measured to cost between one and six false positives
    and to buy at most two. If someone widens the pattern to catch them, this
    test should start failing and the trade should be made explicitly."""
    run = await probe(blind_spot, pages)
    assert not run.findings


async def test_the_differential_costs_one_request_and_stops_at_the_first_answer(pages):
    """A vulnerable parameter costs the baseline plus one payload; a clean one
    costs the baseline plus all three."""
    hit = await probe("mysql_php", pages)
    assert [s.step for s in hit.steps] == ["benign_baseline", "single_quote"]
    clean = await probe("sql_tutorial", pages)
    assert len(clean.steps) == 4


# --------------------------------------------------------- the pattern

# Pinned by name rather than by count, so a pattern change has to say which body
# it moved. Both lists are explained in sql_error_pages.UNREACHABLE_ERRORS and
# in the case header.
EXPECTED_MISSES = {
    "fixture_hibernate", "workflow_hibernate_5_jpa", "workflow_spring_jdbc_spring_data_e",
    "workflow_sequelize_node_behind_expr", "workflow_sqlite_7", "workflow_mysql_mariadb",
}
EXPECTED_FALSE_POSITIVES = set()


def test_the_pattern_scores_what_it_was_measured_to_score():
    rx = signature()
    missed = {k for k, v in sql_error_corpus.POSITIVE_BODIES.items() if not rx.search(v)}
    fp = {k for k, v in sql_error_corpus.BENIGN_BODIES.items() if rx.search(v)}
    assert missed == EXPECTED_MISSES
    assert fp == EXPECTED_FALSE_POSITIVES
    assert len(sql_error_corpus.POSITIVE_BODIES) - len(missed) >= 65
    assert len(sql_error_corpus.BENIGN_BODIES) >= 121, "the negative corpus must stay hard"
    assert sql_error_corpus.PATTERN_CANNOT_SEPARATE, (
        "the bodies only the comparison can drop are documented, not hidden")


def test_a_constraint_violation_is_not_an_injection():
    """The defect this whole exercise was looking for. A bare `sqlite3\\.\\w+Error`
    or a bare `SQLSTATE\\[[0-9A-Z]{5}\\]` reports a duplicate email at signup, on
    any application with a leaky error page, as HIGH-severity SQL injection.
    Both were in the pattern that shipped yesterday."""
    rx = signature()
    assert not rx.search('{"error":"sqlite3.IntegrityError: UNIQUE constraint failed: users.email"}')
    assert not rx.search("SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry "
                         "'a@b.c' for key 'email'")
    assert rx.search("SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error "
                     "in your SQL syntax; check the manual")


def test_case_insensitivity_is_off_and_that_is_load_bearing():
    """Every token is a fixed-case engine sentence or vendor code, so IGNORECASE
    buys no recall — and it costs one: a lowercased digest of the MySQL 1064
    message matches under it."""
    ev = next(e for s in find_by_id(CASE).steps for e in s.evaluators if e.pattern)
    assert ev.case_insensitive is False
    sensitive = re.compile(ev.pattern, re.MULTILINE)
    insensitive = re.compile(ev.pattern, re.MULTILINE | re.IGNORECASE)
    gained = [k for k, v in sql_error_corpus.POSITIVE_BODIES.items()
              if insensitive.search(v) and not sensitive.search(v)]
    cost = [k for k, v in sql_error_corpus.BENIGN_BODIES.items()
            if insensitive.search(v) and not sensitive.search(v)]
    assert gained == [], f"IGNORECASE would buy recall after all: {gained}"
    assert cost, "IGNORECASE no longer costs anything — re-check whether it is still worth off"


def test_no_alternative_is_dead_weight():
    """An alternative that matches no real error is surface with no purpose, and
    an alternative that matches a benign page is worse than nothing."""
    ev = next(e for s in find_by_id(CASE).steps for e in s.evaluators if e.pattern)
    for alt in _top_level_alternatives(ev.pattern):
        rx = re.compile(alt, re.MULTILINE)
        tp = sum(1 for v in sql_error_corpus.POSITIVE_BODIES.values() if rx.search(v))
        fp = [k for k, v in sql_error_corpus.BENIGN_BODIES.items() if rx.search(v)]
        assert tp, f"dead alternative, matches no real error: {alt}"
        assert set(fp) <= EXPECTED_FALSE_POSITIVES, f"{alt} fires on {fp}"


@pytest.mark.parametrize("page", sorted(sql_error_corpus.PATTERN_CANNOT_SEPARATE))
async def test_what_the_pattern_cannot_separate_the_comparison_still_drops(page, pages):
    """The layering, tested rather than assumed.

    These bodies are byte-identical to a real error — a Stack Overflow title, a
    changelog quoting a PHP warning. The pattern matches them and always will;
    no body-only regex separates them. What drops them is that they read the
    same before and after the payload."""
    assert signature().search(sql_error_corpus.PATTERN_CANNOT_SEPARATE[page]), (
        "if the pattern no longer matches this, move it to BENIGN_BODIES")
    run = await probe(page, pages)
    assert not run.findings
    assert len(run.steps) == 4, "the payloads are still sent; only the verdict is withheld"


def test_the_pattern_carries_no_unbounded_wildcard():
    """`Warning.*mysqli_` can join a warning in one place to a driver name in
    another and call the pair an error. The runner applies MULTILINE without
    DOTALL, so `.` does not cross a newline and the join is within ONE line —
    which is every minified bundle, every JSON body, and every HTML page served
    without linebreaks."""
    for step in find_by_id(CASE).steps:
        for evaluator in step.evaluators:
            assert ".*" not in (evaluator.pattern or ""), step.name


# ------------------------------------------------- forging the evidence

def test_no_parameter_name_the_lane_would_accept_completes_the_pattern():
    """The lane feeds DISCOVERED parameter names into this probe, and an
    application chooses both the names it publishes and how it echoes them
    back."""
    from orchestrator.integrations.contracts import PARAMETER_NAME
    rx = signature()
    hostile = ["sqlstate", "SQLSTATE", "ORA-01756", "ORA-00933", "DPY-2041",
               "psycopg2.errors.SyntaxError", "org.sqlite.JDBC", "Unknown_column",
               "mysqli_query", "pg_num", "SQLSTATE[42000]", "Incorrect.syntax.near"]
    for name in filter(PARAMETER_NAME.match, hostile):
        for body in (name, f"Unknown parameter {name}", f"<p>{name}: erlik'probe</p>",
                     f"Invalid parameter {name}: expected integer, got string"):
            assert not rx.search(body), f"forged with parameter name {name!r}: {body!r}"


def test_an_application_that_echoes_the_payload_cannot_forge_the_sqlite_signature():
    """A search DSL and a CSP report endpoint both answered a lone quote with
    `unrecognized token: "'"`, echoing the offending character straight back.
    SQLite reports the whole unterminated token, so a real one carries the REST
    of the payload — which is why the payload is `erlik'probe` and not `'`."""
    rx = signature()
    assert not rx.search('{"error":{"reason":"unrecognized token: \\"\'\\" at position 12"}}')
    assert rx.search("sqlite3.OperationalError: unrecognized token: \"'probe\"")


# --------------------------------------------------- catalogue-wide guards

def _top_level_alternatives(pattern):
    out, depth, cur, esc, cls = [], 0, [], False, False
    for ch in pattern:
        if esc:
            cur.append(ch); esc = False; continue
        if ch == "\\":
            cur.append(ch); esc = True; continue
        if cls:
            cur.append(ch); cls = ch != "]"; continue
        if ch == "[":
            cls = True; cur.append(ch); continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "|" and depth == 0:
            out.append("".join(cur)); cur = []; continue
        cur.append(ch)
    out.append("".join(cur))
    return out


def test_no_catalogue_pattern_was_damaged_by_yaml_folding():
    """A folded `>-` scalar joins wrapped lines with a SPACE. An alternation
    written across several lines therefore loads with a leading space on every
    alternative that started a new one — and the YAML still looks right.

    Measured when this guard was added: WSTG-INPV-05 carried ` SQLITE_ERROR` and
    ` Microsoft OLE DB Provider for SQL Server`, and WSTG-ERRH-01 carried
    ` \\.java:\\d+`, ` Warning:.*on line \\d+` and ` Microsoft \\.NET`. Five checks
    that could only fire on text with a space in front of them.

    A regex alternative genuinely needing a leading space should spell it `\\s`
    or `\\x20`, which this guard does not object to."""
    damaged = []
    for test_id, tc in load_catalog().items():
        for step in tc.steps:
            for ev in step.evaluators:
                for alt in _top_level_alternatives(ev.pattern or ""):
                    if alt.startswith(" "):
                        damaged.append(f"{test_id}/{step.name}: {alt!r}")
    assert not damaged, "folded YAML injected a space into these alternatives:\n" + "\n".join(damaged)


def test_both_sqli_cases_carry_the_identical_signature():
    """WSTG-INPV-05 and WSTG-INPV-05.2 look for the same thing, and YAML anchors
    do not cross files. This is what stops the two copies drifting."""
    full = next(e.pattern for s in find_by_id("WSTG-INPV-05").steps
                if s.name == "error_based_probe" for e in s.evaluators if e.pattern)
    lane = next(e.pattern for s in find_by_id(CASE).steps for e in s.evaluators if e.pattern)
    assert full == lane


def test_the_signature_is_written_once_within_the_lane_case():
    """Four steps, one anchored definition. Three copies of a 1500-character
    regex is three chances to fix one of them."""
    patterns = {e.pattern for s in find_by_id(CASE).steps for e in s.evaluators if e.pattern}
    assert len(patterns) == 1


def test_the_case_runs_where_the_findings_are():
    from orchestrator.integrations.inventory import executable_test_cases
    runnable = executable_test_cases()
    assert CASE in runnable
    assert "WSTG-INPV-05" not in runnable, "unchanged: it still needs a shell"
