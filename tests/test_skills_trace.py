"""`sessions.skills_trace`: what the router actually gave a run.

Recorded, never re-derived. The corpus is writable now, so asking the selector
again months later answers a different question than "what did this session
receive" — and the whole point of the trace is that the second question has an
answer at all.

It also separates two things the UI previously conflated:

    reachable         COULD the router ever pick this sheet (probe missions)
    runs_selected_in  did a REAL run actually receive it (the trace)

A sheet can be reachable and have reached nothing, if an operator's missions do
not resemble the probes. Only the second number says whether authoring changed
what erlik does — which is the countermeasure to the BugHunter import, where
100 skills were reachable, listed, and selected by nothing.
"""

import asyncio
import hashlib
import json
import warnings

import pytest

warnings.filterwarnings("ignore", category=DeprecationWarning)

import orchestrator.database as db_mod  # noqa: E402
from orchestrator.skills import (plan_skills, render_plan, render_skills,  # noqa: E402
                                 select_skill_files, MAX_FILE_EXCERPT)


class TestPlannerAgreesWithTheSelector:
    @pytest.mark.parametrize("hint", [
        "sql injection", "xss", "idor access control", "ssrf",
        "authentication weaknesses", "sql injection and broken access control",
    ])
    def test_same_files_as_select_skill_files(self, hint):
        files, _ = plan_skills(hint)
        assert [f.name for f in files] == [f.name for f in select_skill_files(hint)]

    def test_render_plan_matches_render_skills(self):
        """Text and trace must come from ONE selection. Selecting twice — once
        to render, once to explain — is a re-derivation racing a writable
        corpus, and the two can legitimately disagree."""
        for hint in ("sql injection", "xss", "ssrf"):
            files, _ = plan_skills(hint)
            assert render_plan(files) == render_skills(hint)

    def test_budget_zero_still_yields_one_file(self):
        """max_chars=0 does NOT mean 'no skills' — the selector takes the first
        file unconditionally. Pinned so the UI copy stays true."""
        files, plan = plan_skills("sql injection", max_chars=0)
        assert len(files) == 1
        assert plan["injected_total"] == min(files[0].stat().st_size, MAX_FILE_EXCERPT)

    def test_empty_hint_plans_nothing(self):
        files, plan = plan_skills("")
        assert files == [] and plan["selected"] == []
        assert render_plan(files) == ""


class TestPlanContent:
    def test_records_licence_and_injected_size_per_sheet(self):
        _, plan = plan_skills("hunt for xss and idor")
        assert plan["selected"]
        for e in plan["selected"]:
            assert e["licence"]
            assert e["injected_bytes"] <= e["file_bytes"]
            assert e["injected_bytes"] <= MAX_FILE_EXCERPT
            if e["excerpted"]:
                assert e["injected_bytes"] < e["file_bytes"]

    def test_records_the_knobs_that_produced_it(self):
        _, plan = plan_skills("sql injection", max_chars=9000,
                              exclude=["a.md"], pin=["hunt-ssrf.md"])
        assert plan["max_chars"] == 9000
        assert plan["exclude"] == ["a.md"] and plan["pin"] == ["hunt-ssrf.md"]

    def test_records_detected_classes(self):
        _, plan = plan_skills("sql injection and broken access control")
        assert "sqli" in plan["classes"] and "authz" in plan["classes"]

    def test_distinguishes_corpus_from_operator_authored(self):
        _, plan = plan_skills("sql injection")
        assert {e["root"] for e in plan["selected"]} <= {"corpus", "local"}
        assert all(e["root"] == "corpus" for e in plan["selected"])

    def test_injected_total_is_the_sum_of_its_parts(self):
        _, plan = plan_skills("sql injection and access control")
        assert plan["injected_total"] == sum(e["injected_bytes"] for e in plan["selected"])


class TestTraceIsVerifiable:
    def test_hash_identifies_the_exact_block(self):
        """A claim about what a session received can be CHECKED against the
        text that was really appended, rather than trusted."""
        files, plan = plan_skills("sql injection")
        block = render_plan(files)
        plan["rendered_chars"] = len(block)
        plan["sha256"] = hashlib.sha256(block.encode()).hexdigest()
        assert plan["sha256"] == hashlib.sha256(
            render_skills("sql injection").encode()).hexdigest()

    def test_rendered_size_exceeds_the_raw_file_total(self):
        """The block carries a header and a per-sheet provenance marker, so the
        sum of file sizes understates what the prompt receives. Reporting the
        raw total as 'injected' would quietly under-report prompt cost."""
        files, plan = plan_skills("sql injection")
        assert len(render_plan(files)) > plan["injected_total"]


class TestNoDualModuleIdentity:
    def test_import_fallback_is_gone(self):
        """`except ImportError: from skills import render_skills` imported the
        SAME module under a second name, so monkeypatching one identity left
        the other live and every wiring test was blind."""
        import inspect
        import orchestrator.main as M
        src = inspect.getsource(M)
        assert "from skills import render_skills" not in src
        assert "from orchestrator.skills import plan_skills, render_plan" in src


class TestPersistedTrace:
    @pytest.fixture
    def db(self, tmp_path, monkeypatch):
        monkeypatch.setattr(db_mod, "DB_DIR", tmp_path)
        monkeypatch.setattr(db_mod, "DB_PATH", tmp_path / "t.db")
        asyncio.run(db_mod.init_db())
        return tmp_path / "t.db"

    def test_column_exists_and_is_nullable(self, db):
        async def go():
            x = await db_mod.get_db()
            try:
                await x.execute(
                    "INSERT INTO sessions (id,target_url,system_prompt) VALUES (?,?,?)",
                    ("s1", "http://t", "m"))
                await x.commit()
                cur = await x.execute("SELECT skills_trace FROM sessions WHERE id='s1'")
                return (await cur.fetchone())[0]
            finally:
                await x.close()
        assert asyncio.run(go()) is None

    def test_round_trips_a_real_plan(self, db):
        _, plan = plan_skills("sql injection")

        async def go():
            x = await db_mod.get_db()
            try:
                await x.execute(
                    "INSERT INTO sessions (id,target_url,system_prompt,skills_trace) "
                    "VALUES (?,?,?,?)", ("s1", "http://t", "m", json.dumps(plan)))
                await x.commit()
                cur = await x.execute("SELECT skills_trace FROM sessions WHERE id='s1'")
                return json.loads((await cur.fetchone())[0])
            finally:
                await x.close()
        got = asyncio.run(go())
        assert [e["name"] for e in got["selected"]] == [e["name"] for e in plan["selected"]]

    def test_persistence_failure_does_not_break_a_run(self):
        """Telemetry must never take a session down."""
        import inspect
        import orchestrator.main as M
        src = inspect.getsource(M)
        i = src.index("skills_trace = ? WHERE id = ?")
        assert "except Exception" in src[i:i + 500]
        assert "not recorded" in src[i:i + 600]


class TestReachableIsNotTheSameAsUsed:
    """The distinction the counter exists to make."""

    def test_status_reports_both_numbers(self):
        import inspect
        import orchestrator.main as M
        src = inspect.getsource(M.library_authoring_status)
        assert "runs_selected_in" in src
        assert "local_skills_selected_in_last_50_runs" in src
        assert "reachable" in src

    def test_trace_query_is_bounded(self):
        """An unbounded scan over every session would grow with the corpus."""
        import inspect
        import orchestrator.main as M
        src = inspect.getsource(M.library_authoring_status)
        assert "LIMIT 50" in src
        assert "ORDER BY created_at DESC" in src

    def test_ui_states_the_zero_case(self):
        from pathlib import Path
        html = (Path(__file__).resolve().parents[1]
                / "dashboard" / "templates" / "index.html").read_text()
        assert "None of your sheets appeared in the last" in html
        assert "nothing you have written has changed what erlik did" in html
