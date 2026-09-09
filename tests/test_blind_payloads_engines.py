"""WSTG-INPV-05.4's payloads, run through the engines they name.

The hermetic fixture in test_blind_injection.py proves the EVALUATOR — that a
caused delay is told apart from a slow endpoint — using SQLite with a `SLEEP`
function registered. What it cannot prove is that the payload strings are valid
SQL for MySQL and PostgreSQL, because SQLite parses neither dialect's sleep.

This takes the payloads out of the case as they are written and concatenates
them into the two sink shapes against real engines, which is the only way that
claim can be checked. It is opt-in because it starts containers.

Two properties per payload, and the second matters as much as the first:
  - it delays for the time it asks for, in its own engine and sink shape
  - it costs one fast request in the OTHER engine, rather than hanging it

Also measured here, once, is the reason there is no `OR` payload: on MySQL the
sleep runs once per row the WHERE clause visits.
"""
import os
import re
import shlex
import subprocess
import time

import pytest

from orchestrator.testcase.loader import find_by_id

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(os.environ.get("ERLIK_DOCKER_TESTS") != "1",
                       reason="set ERLIK_DOCKER_TESTS=1 for Docker lab tests"),
]

ENGINES = {
    "postgres": {"image": "postgres:16-alpine", "container": "erlik-test-pg",
                 "env": ["-e", "POSTGRES_PASSWORD=probe"],
                 "sql": lambda q: ["psql", "-U", "postgres", "-tAq", "-c", q]},
    "mysql": {"image": "mysql:8.0", "container": "erlik-test-mysql",
              "env": ["-e", "MYSQL_ROOT_PASSWORD=probe", "-e", "MYSQL_DATABASE=probe"],
              "sql": lambda q: ["mysql", "-uroot", "-pprobe", "-N", "-B", "probe", "-e", q]},


}


def _run(engine, query):
    spec = ENGINES[engine]
    started = time.monotonic()
    done = subprocess.run(["docker", "exec", spec["container"], *spec["sql"](query)],
                          capture_output=True, text=True, timeout=90)
    return int((time.monotonic() - started) * 1000), done


def _up(engine):
    spec = ENGINES[engine]
    subprocess.run(["docker", "rm", "-f", spec["container"]], capture_output=True)
    subprocess.run(["docker", "run", "-d", "--name", spec["container"], *spec["env"],
                    spec["image"]], check=True, capture_output=True)
    # Readiness is the REAL query succeeding, not a ping. MySQL's entrypoint
    # runs a temporary server while it initialises, and `mysqladmin ping`
    # answers from it — so every statement afterwards failed silently and every
    # payload looked fast. A ping that lies is worse than no check.
    for _ in range(90):
        if _run(engine, "SELECT 1")[1].returncode == 0:
            break
        time.sleep(1)
    else:
        pytest.skip(f"{engine} never became ready")
    for statement in ("DROP TABLE IF EXISTS users",
                      "CREATE TABLE users (id varchar(16), uid int, name varchar(16))",
                      "INSERT INTO users VALUES ('1',1,'admin'),('2',2,'gordonb'),('3',3,'pablo')"):
        done = _run(engine, statement)[1]
        assert done.returncode == 0, f"{engine} setup failed: {done.stderr}"
    assert _run(engine, "SELECT COUNT(*) FROM users")[1].stdout.strip().endswith("3")


def _sql(engine, query):
    """Run a statement and return how long the ENGINE took, in milliseconds.

    An erroring statement is FAST, so a test asserting a delay is really
    asserting the statement ran at all — which is why the setup above verifies
    the table exists before any of them.
    """
    return _run(engine, query)[0]


@pytest.fixture(scope="module")
def engines():
    for engine in ENGINES:
        _up(engine)
    yield
    for spec in ENGINES.values():
        subprocess.run(["docker", "rm", "-f", spec["container"]], capture_output=True)


def payload(step_name):
    """The value the case sends, lifted out of the rendered curl command."""
    command = next(s.command for s in find_by_id("WSTG-INPV-05.4").steps
                   if s.name == step_name)
    value = next(a for a in shlex.split(command) if a.startswith("{{parameter}}="))
    return value.split("=", 1)[1]


def inject(value, quoted):
    """The statement a vulnerable application builds from that value."""
    return (f"SELECT name FROM users WHERE id = '{value}'" if quoted
            else f"SELECT name FROM users WHERE uid = {value}")


CASES = [
    # step prefix,          engine,      quoted sink
    ("mysql_quoted",        "mysql",     True),
    ("mysql_numeric",       "mysql",     False),
    ("postgres_quoted",     "postgres",  True),
    ("postgres_numeric",    "postgres",  False),
]


@pytest.mark.parametrize("prefix,engine,quoted", CASES)
def test_the_payload_delays_by_what_it_asked_for(prefix, engine, quoted, engines):
    """The long probe asks for five seconds and the short one for one. The
    evaluator needs a 3000ms margin between them, so this asserts the property
    the evaluator relies on, not merely that something was slow."""
    short = _sql(engine, inject(payload(f"{prefix}_short"), quoted))
    long_ = _sql(engine, inject(payload(f"{prefix}_long"), quoted))
    assert long_ - short >= 3000, f"{prefix}: {long_}ms against {short}ms"


@pytest.mark.parametrize("prefix,engine,quoted", CASES)
def test_the_payload_is_cheap_in_the_engine_it_does_not_name(prefix, engine, quoted, engines):
    """Four families are sent to every parameter, so three of them are always
    wrong. A wrong one has to cost one fast request — if it hung, the case
    would spend the stage budget on targets that have nothing."""
    other = "postgres" if engine == "mysql" else "mysql"
    assert _sql(other, inject(payload(f"{prefix}_long"), quoted)) < 2000


def test_an_or_payload_would_sleep_once_per_row(engines):
    """Why every payload in the case is an AND. The users table has three rows;
    an OR payload visits all of them because the left side is false for each,
    and the sleep runs every time. Against a table of any real size that is a
    denial of service delivered by a scanner."""
    rows = 3
    one_sleep = _sql("mysql", inject("1' AND SLEEP(1) AND '1'='1", quoted=True))
    per_row = _sql("mysql", inject("nosuchid' OR SLEEP(1) AND '1'='1", quoted=True))
    assert per_row >= one_sleep * (rows - 1), (
        f"OR slept {per_row}ms against {one_sleep}ms for a single AND")
    for case in ("WSTG-INPV-05.3", "WSTG-INPV-05.4"):
        for step in find_by_id(case).steps:
            assert " OR " not in step.command.upper(), step.name


def test_the_mysql_payload_needs_a_seed_that_matches(engines):
    """MySQL short-circuits the AND per row, so a seed matching nothing never
    reaches the sleep. This is the documented reason the case seeds on `1` and
    the reason it cannot reach a parameter whose values are unguessable — if it
    ever stops being true, the case's own comment is wrong."""
    matching = _sql("mysql", inject("1' AND SLEEP(4) AND '1'='1", quoted=True))
    missing = _sql("mysql", inject("nosuchid' AND SLEEP(4) AND '1'='1", quoted=True))
    assert matching >= 3500 and missing < 1000


def test_postgres_sleeps_regardless_of_the_seed(engines):
    """And the contrast: the sub-select is uncorrelated, so PostgreSQL runs it
    once before the scan and the seed does not matter."""
    for seed in ("1", "nosuchid"):
        value = payload("postgres_quoted_long").replace("1'", f"{seed}'", 1)
        assert _sql("postgres", inject(value, quoted=True)) >= 4000, seed
