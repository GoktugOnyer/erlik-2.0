"""`produces:` — the half of the type system erlik was missing.

`target_schema.required` declares what a test case CONSUMES. There was no
declaration of what one DISCOVERS, and the reason was one line:

    matched = bool(re.search(ev.pattern, step_result.output, flags))

The Match was destroyed on the line that created it. Cases already located
endpoints, parameters and paths in tool output and threw every capture group
away to keep a yes/no. So the deterministic lane fired all 22 cases at whatever
single URL it was handed — the same "cannot reach the endpoint" bottleneck
measured in the agent lane, arrived at from the other direction.

THREE PROPERTIES, and each has a failure story:

  EVERY OCCURRENCE. A robots.txt has many Disallow lines and a crawl emits many
  paths. `re.search` finds one and discards the rest, which would make a
  producer that technically works and practically finds a single endpoint.

  UNTRUSTED. This text came from the target and is about to become a command
  argument. Values are DROPPED, never escaped, if they fail the same injection
  gate the sweep planner applies.

  ADDITIVE. An evaluator without `produces` must behave byte-identically, or
  every recorded run becomes incomparable.
"""

import re

import pytest

from orchestrator.testcase import runner as R
from orchestrator.testcase.schema import Evaluator

FLAGS = re.MULTILINE | re.IGNORECASE

ROBOTS = """User-agent: *
Disallow: /ftp
Disallow: /admin
Disallow: /api/internal
Disallow: /backup
Allow: /public
"""


def ev(**kw):
    return Evaluator(type="regex", **kw)


class TestEveryOccurrenceIsCaptured:
    def test_all_disallow_lines_not_just_the_first(self):
        e = ev(pattern=r"^Disallow:\s*(\S+)", produces={"endpoint": 1})
        got = R._harvest(e, ROBOTS, FLAGS)
        assert got == {"endpoint": ["/ftp", "/admin", "/api/internal", "/backup"]}

    def test_re_search_would_have_found_one(self):
        """The defect in checkable form: the old code kept a boolean built from
        a single match and discarded the other three."""
        m = re.search(r"^Disallow:\s*(\S+)", ROBOTS, FLAGS)
        assert m.group(1) == "/ftp"
        assert len(R._harvest(ev(pattern=r"^Disallow:\s*(\S+)",
                                 produces={"endpoint": 1}), ROBOTS, FLAGS)["endpoint"]) == 4

    def test_duplicates_collapse_and_order_is_kept(self):
        out = "p=id\np=name\np=id\np=email\n"
        got = R._harvest(ev(pattern=r"^p=(\w+)", produces={"parameter": 1}), out, FLAGS)
        assert got == {"parameter": ["id", "name", "email"]}

    def test_capture_is_bounded(self):
        """A crawl of a large site must not plan an unbounded fan-out."""
        out = "\n".join(f"Disallow: /p{i}" for i in range(500))
        got = R._harvest(ev(pattern=r"^Disallow:\s*(\S+)", produces={"endpoint": 1}),
                         out, FLAGS)
        assert len(got["endpoint"]) == R.MAX_PRODUCED_PER_FIELD

    def test_several_fields_from_one_pattern(self):
        out = "GET /search?q=1\nGET /login?user=2\n"
        e = ev(pattern=r"^GET (\S+?)\?(\w+)=", produces={"endpoint": 1, "parameter": 2})
        got = R._harvest(e, out, FLAGS)
        assert got["endpoint"] == ["/search", "/login"]
        assert got["parameter"] == ["q", "user"]


class TestUntrustedOutputIsDropped:
    """Tool output is target-controlled and these values reach a command line."""

    @pytest.mark.parametrize("evil", [
        "/a$(id)", "/a`id`", '/a"; id; echo "', "/a'; id; echo '", "/a\\x",
    ])
    def test_injectable_values_are_dropped_not_escaped(self, evil):
        out = f"Disallow: {evil}\nDisallow: /safe\n"
        got = R._harvest(ev(pattern=r"^Disallow:\s*(\S+)", produces={"endpoint": 1}),
                         out, FLAGS)
        assert got == {"endpoint": ["/safe"]}, f"kept an injectable value: {evil!r}"

    def test_the_gate_is_the_same_one_the_planner_uses(self):
        """Two gates drift. One does not."""
        import inspect
        assert "looks_injectable" in inspect.getsource(R._harvest)

    def test_a_field_with_nothing_survivable_is_absent_not_empty(self):
        out = "Disallow: /a$(id)\n"
        got = R._harvest(ev(pattern=r"^Disallow:\s*(\S+)", produces={"endpoint": 1}),
                         out, FLAGS)
        assert "endpoint" not in got


class TestMalformedDeclarationsDoNotCrash:
    def test_a_group_index_that_does_not_exist(self):
        got = R._harvest(ev(pattern=r"^Disallow:\s*\S+", produces={"endpoint": 3}),
                         ROBOTS, FLAGS)
        assert got == {}

    def test_group_zero_is_the_whole_match(self):
        got = R._harvest(ev(pattern=r"/admin", produces={"endpoint": 0}), ROBOTS, FLAGS)
        assert got == {"endpoint": ["/admin"]}

    def test_no_produces_harvests_nothing(self):
        assert R._harvest(ev(pattern=r"^Disallow:\s*(\S+)"), ROBOTS, FLAGS) == {}

    def test_empty_captures_are_skipped(self):
        # [ \t] not \s — \s matches a newline, so `\s*(\S*)` on an empty
        # Disallow line walks onto the NEXT line and captures "Disallow:".
        # That is real regex behaviour and worth pinning: a producing pattern
        # that spans lines silently harvests the wrong thing.
        got = R._harvest(ev(pattern=r"^Disallow:[ \t]*(\S*)$", produces={"endpoint": 1}),
                         "Disallow:\nDisallow: /real\n", FLAGS)
        assert got == {"endpoint": ["/real"]}

    def test_a_greedy_whitespace_pattern_walks_onto_the_next_line(self):
        """Pinned deliberately. \s crosses newlines even under MULTILINE, so a
        case author writing `\s*` on a line-oriented format gets values from
        the wrong line rather than an error."""
        got = R._harvest(ev(pattern=r"^Disallow:\s*(\S*)", produces={"endpoint": 1}),
                         "Disallow:\nDisallow: /real\n", FLAGS)
        # It captures the literal text "Disallow:" from the NEXT line, and then
        # finds no further match because that line has been consumed — so the
        # real path is lost entirely. One malformed pattern, one wrong value,
        # zero errors.
        assert got == {"endpoint": ["Disallow:"]}


class TestAdditive:
    """An evaluator without `produces` must behave exactly as before, or every
    recorded run becomes incomparable."""

    def test_matching_is_unchanged_without_produces(self):
        e = ev(pattern=r"^Disallow:")
        assert R._harvest(e, ROBOTS, FLAGS) == {}
        assert bool(re.search(e.pattern, ROBOTS, FLAGS)) is True

    def test_produces_is_optional_in_the_schema(self):
        assert Evaluator(type="regex", pattern="x").produces is None

    def test_a_producing_evaluator_still_matches_when_it_captures(self):
        """`produces` must not change WHETHER a case fires, only what it
        carries out — otherwise it silently rewrites detection."""
        e = ev(pattern=r"^Disallow:\s*(\S+)", produces={"endpoint": 1})
        assert R._harvest(e, ROBOTS, FLAGS)
        assert bool(re.search(e.pattern, ROBOTS, FLAGS)) is True

    def test_a_producing_evaluator_that_captures_nothing_still_matches_the_pattern(self):
        """Harvest failing must not suppress a real match — the case still
        detected something even if nothing survived the gate."""
        out = "Disallow: /a$(id)\n"
        e = ev(pattern=r"^Disallow:\s*(\S+)", produces={"endpoint": 1})
        assert R._harvest(e, out, FLAGS) == {}
        assert bool(re.search(e.pattern, out, FLAGS)) is True

    def test_run_result_defaults_to_empty(self):
        rr = R.RunResult(test_case_id="X", target={})
        assert rr.produced == {}


class TestTheOldDefectIsGone:
    def test_the_match_is_no_longer_discarded_on_creation(self):
        import inspect
        src = inspect.getsource(R._run_evaluator)
        assert "matched = bool(re.search(ev.pattern, step_result.output, flags))" not in src
        assert "_harvest(" in src

    def test_the_runner_accumulates_into_the_result(self):
        import inspect
        src = inspect.getsource(R.run_test_case)
        assert "result.produced" in src, "harvested values never reach the RunResult"
