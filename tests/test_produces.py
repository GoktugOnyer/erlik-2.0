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
        r"""Pinned deliberately. \s crosses newlines even under MULTILINE, so a
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


class TestHarvestIsActuallyCalled:
    """Most tests above call `_harvest` DIRECTLY, so they pass even if nothing
    ever calls it — the producer-with-no-consumer shape this codebase keeps
    producing, reproduced in my own test design.

    Removing the call site from `_run_evaluator` failed exactly ONE test (a
    source-inspection check). These exercise the path behaviourally, so the
    disconnect fails loudly.
    """

    @staticmethod
    def _evaluate(pattern, produces, output):
        import asyncio
        from orchestrator.testcase.schema import TestCase, TargetSchema
        tc = TestCase(id="X", name="x", category="c", severity="info",
                      target_schema=TargetSchema(required=[]), steps=[])
        sr = R.StepResult(step="s", command="c", success=True, output=output,
                          duration_ms=1)
        e = Evaluator(type="regex", pattern=pattern, produces=produces)
        return asyncio.run(R._run_evaluator(e, sr, tc, {}, None, None))

    def test_run_evaluator_returns_what_it_harvested(self):
        _, _, _, produced, _ = self._evaluate(r"^Disallow:\s*(\S+)",
                                              {"endpoint": 1}, ROBOTS)
        assert produced == {"endpoint": ["/ftp", "/admin", "/api/internal", "/backup"]}

    def test_run_evaluator_returns_nothing_without_produces(self):
        _, _, _, produced, _ = self._evaluate(r"^Disallow:", None, ROBOTS)
        assert produced == {}

    def test_a_producing_evaluator_still_reports_a_match(self):
        finding, _, _, produced, _ = self._evaluate(r"^Disallow:\s*(\S+)",
                                                    {"endpoint": 1}, ROBOTS)
        assert produced, "harvest did not run through the evaluator"

    def test_run_test_case_accumulates_across_evaluators(self):
        """The whole path: two evaluators on one step, both producing, merged
        onto the RunResult without duplication."""
        import asyncio
        from unittest.mock import patch
        from orchestrator.testcase.schema import TestCase, TestStep, TargetSchema

        tc = TestCase(
            id="X", name="x", category="c", severity="info",
            target_schema=TargetSchema(required=[]),
            steps=[TestStep(name="s", tool="curl", command="curl x", evaluators=[
                Evaluator(type="regex", pattern=r"^Disallow:\s*(\S+)",
                          produces={"endpoint": 1}),
                Evaluator(type="regex", pattern=r"^Allow:\s*(\S+)",
                          produces={"endpoint": 1}),
            ])])

        async def fake_exec(*a, **k):
            return {"success": True, "output": ROBOTS, "error": None}

        with patch("orchestrator.testcase.runner.execute_tool", fake_exec):
            r = asyncio.run(R.run_test_case(tc, {"scope": {}}))
        assert r.produced["endpoint"] == [
            "/ftp", "/admin", "/api/internal", "/backup", "/public"]


class TestDiscoveredEndpointsPersist:
    """The table existed with zero writers and zero readers. These assert the
    round trip and the properties that keep a stored row from becoming a
    liability."""

    @staticmethod
    def _db(tmp_path, monkeypatch):
        import orchestrator.database as db_mod
        monkeypatch.setattr(db_mod, "DB_PATH", str(tmp_path / "e.db"))
        return db_mod

    def test_round_trip(self, tmp_path, monkeypatch):
        import asyncio
        from orchestrator.testcase import endpoints as EP
        db_mod = self._db(tmp_path, monkeypatch)

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            n = await EP.record(db, "http://t.example", "WSTG-INFO-03",
                                {"url": ["http://t.example/admin",
                                         "http://t.example/backup"]})
            await db.commit()
            rows = await EP.known(db, "http://t.example")
            await db.close()
            return n, rows

        n, rows = asyncio.run(go())
        assert n == 2
        assert sorted(r["path"] for r in rows) == ["/admin", "/backup"]

    def test_recording_is_idempotent(self, tmp_path, monkeypatch):
        """A sweep that revisits a site must not multiply its own inventory."""
        import asyncio
        from orchestrator.testcase import endpoints as EP
        db_mod = self._db(tmp_path, monkeypatch)

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            for _ in range(3):
                await EP.record(db, "http://t.example", "X",
                                {"url": ["http://t.example/a"]})
            await db.commit()
            rows = await EP.known(db, "http://t.example")
            await db.close()
            return rows

        assert len(asyncio.run(go())) == 1

    def test_paths_not_absolute_urls_are_stored(self, tmp_path, monkeypatch):
        """The scheme and authority come from whatever base a later sweep is
        planning against, so a stored row cannot smuggle in a different host."""
        import asyncio
        from orchestrator.testcase import endpoints as EP
        db_mod = self._db(tmp_path, monkeypatch)

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            await EP.record(db, "http://t.example", "X",
                            {"url": ["http://t.example/admin"]})
            await db.commit()
            rows = await EP.known(db, "http://t.example")
            await db.close()
            return rows

        rows = asyncio.run(go())
        assert rows[0]["path"] == "/admin"
        assert "t.example" not in rows[0]["path"]

    def test_a_stored_row_cannot_retarget_another_host(self):
        """as_sweep_inputs rebuilds from the CALLER's base, never from
        anything stored."""
        from orchestrator.testcase import endpoints as EP
        got = EP.as_sweep_inputs([{"path": "/admin", "params": []}],
                                 "http://other.example")
        assert got == {"url": ["http://other.example/admin"]}

    def test_targets_are_keyed_by_host_and_port(self):
        from orchestrator.testcase import endpoints as EP
        assert EP.target_key("http://t.example/x") == "t.example:80"
        assert EP.target_key("https://t.example/x") == "t.example:443"
        assert EP.target_key("http://t.example:8080") == "t.example:8080"

    def test_the_key_matches_the_handoffs(self):
        """recon_context and the handoff already key on host:port. A second
        convention would mean discovery and recon never see each other's work."""
        from orchestrator.testcase import endpoints as EP
        from orchestrator.handoff import target_key as handoff_key
        for u in ("http://a.test", "https://b.test:8443/x", "c.test:99"):
            assert EP.target_key(u) == handoff_key(u)

    def test_injectable_values_never_reach_the_table(self, tmp_path, monkeypatch):
        import asyncio
        from orchestrator.testcase import endpoints as EP
        db_mod = self._db(tmp_path, monkeypatch)

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            n = await EP.record(db, "http://t.example", "X",
                                {"url": ["http://t.example/a$(id)"]})
            await db.commit()
            rows = await EP.known(db, "http://t.example")
            await db.close()
            return n, rows

        n, rows = asyncio.run(go())
        assert n == 0 and rows == []

    def test_the_deterministic_lane_calls_the_writer(self):
        """Wiring guard — the table sat empty because nothing wrote to it."""
        import pathlib
        src = (pathlib.Path(__file__).resolve().parents[1] / "orchestrator"
               / "testcase" / "persistence.py").read_text()
        assert "endpoints as _EP" in src and "_EP.record(" in src
