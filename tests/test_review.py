"""Tests for the post-run AI review.

The review critiques the RUN — what surface was never touched, which tools kept
failing, which levers to change — as distinct from the report's NEXT_STEPS,
which is remediation advice about the target.

The property that matters most is what it must NOT do. A critique that reached
the metrics would let the model grade its own homework, so it writes only to
session_reviews: no findings, no `verified`, and above all no `evidence`, which
is a scoring input to both the verification labeller and ground-truth matching.
"""

import asyncio

import pytest

import orchestrator.database as db_mod
import orchestrator.main as main_mod
import orchestrator.review as R

SAMPLE = """EXECUTIVE fluff that should be ignored

COVERAGE_GAPS:
- No authenticated surface was tested; every request was anonymous
- Port 27017 was open but no MongoDB probe ran

WASTED_EFFORT:
- sqlmap called 6 times against the same parameter, all failing to connect

CONFIG_SUGGESTIONS:
- Enable TECHNIQUES so an open 27017 injects MongoDB context
- none

RECOMMENDED_NEXT_RUN: Re-run with guided_techniques and a longer turn budget.

CONFIDENCE: medium
"""


# --- parsing --------------------------------------------------------------

def test_parses_every_section():
    r = R.parse_review(SAMPLE)
    assert len(r["coverage_gaps"]) == 2
    assert "27017" in r["coverage_gaps"][1]
    assert len(r["wasted_effort"]) == 1
    assert r["recommended_next_run"].startswith("Re-run with guided_techniques")
    assert r["confidence"] == "medium"


def test_none_placeholders_are_dropped():
    """A model told to write 'none' when it has nothing must not produce a
    bullet that reads 'none'."""
    r = R.parse_review(SAMPLE)
    assert len(r["config_suggestions"]) == 1
    assert all(x.lower() != "none" for x in r["config_suggestions"])


def test_missing_sections_degrade_to_empty():
    r = R.parse_review("garbage with no structure at all")
    assert r["coverage_gaps"] == []
    assert r["wasted_effort"] == []
    assert r["config_suggestions"] == []
    assert r["recommended_next_run"] == ""
    assert r["confidence"] == ""


def test_empty_input_is_safe():
    for bad in ("", None):
        r = R.parse_review(bad)
        assert r["coverage_gaps"] == [] and r["confidence"] == ""


def test_confidence_is_constrained():
    assert R.parse_review("CONFIDENCE: banana")["confidence"] == ""
    assert R.parse_review("CONFIDENCE: HIGH")["confidence"] == "high"


# --- prompt ---------------------------------------------------------------

def test_prompt_names_the_enabled_help():
    p = R.build_review_prompt(
        config={"preset": "guided_techniques", "skills": True, "techniques": True,
                "playbooks": "juiceshop", "nettacker_scenario": "recon"},
        activity={"target_url": "http://juice-shop:3000", "steps": 12,
                  "max_turns": 30, "phases": ["recon", "test"], "duration_ms": 60000,
                  "open_ports": [3000, 27017]},
        tools=[{"tool": "curl", "calls": 8, "failures": 0},
               {"tool": "sqlmap", "calls": 4, "failures": 4, "last_error": "Connection refused"}],
        outcome={"findings": 2, "severities": {"high": 1, "low": 1},
                 "unused_tools": ["nmap", "nuclei"]})
    assert "guided_techniques" in p
    assert "skills, techniques" in p
    assert "27017" in p
    assert "sqlmap: 4 call(s), 4 failed" in p
    assert "Connection refused" in p
    assert "nmap, nuclei" in p


def test_prompt_marks_the_unguided_baseline_explicitly():
    p = R.build_review_prompt(config={"preset": "ai_only"},
                              activity={}, tools=[], outcome={})
    assert "NONE (raw model baseline)" in p
    assert "no tools were executed" in p


def test_prompt_asks_for_run_critique_not_remediation():
    p = R.build_review_prompt(config={}, activity={}, tools=[], outcome={})
    assert "Critique the RUN, not the application" in p
    assert "COVERAGE_GAPS" in p and "CONFIG_SUGGESTIONS" in p


# --- markdown -------------------------------------------------------------

def test_markdown_renders_and_declares_itself_advisory():
    md = R.render_review_markdown(R.parse_review(SAMPLE))
    assert "## Run Review" in md
    assert "never creates findings" in md
    assert "Coverage gaps" in md and "Configuration suggestions" in md


def test_markdown_is_empty_when_there_is_nothing_to_say():
    assert R.render_review_markdown(R.parse_review("nothing")) == ""


# --- gating ---------------------------------------------------------------

@pytest.mark.parametrize("value, on", [
    ("1", True), ("true", True), ("ON", True),
    ("0", False), ("", False), ("maybe", False),
])
def test_enable_flag(monkeypatch, value, on):
    monkeypatch.setenv("ERLIK_AI_REVIEW", value)
    assert R.review_enabled() is on


# --- persistence, and what it must never touch ----------------------------

@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db_mod, "DB_PATH", tmp_path / "t.db")
    monkeypatch.setattr(db_mod, "DB_DIR", tmp_path)
    asyncio.run(db_mod.init_db())
    return tmp_path


@pytest.fixture
def fake_llm(monkeypatch):
    async def chat(messages, model=None, **kw):
        return SAMPLE
    monkeypatch.setattr(main_mod.llm_client, "chat", chat)


def _seed_session():
    async def go():
        db = await db_mod.get_db()
        await db.execute("INSERT INTO sessions (id, target_url) VALUES (?, ?)",
                         ("s1", "http://juice-shop:3000"))
        await db.execute(
            "INSERT INTO steps (session_id, phase, step_number, tool_called, tool_output) "
            "VALUES (?, ?, ?, ?, ?)", ("s1", "recon", 1, "curl", "HTTP/1.1 200 OK"))
        await db.execute(
            "INSERT INTO findings (session_id, vuln_type, severity, url, evidence) "
            "VALUES (?, ?, ?, ?, ?)",
            ("s1", "SQL Injection", "high", "http://juice-shop:3000/x", "original evidence"))
        await db.commit()
        await db.close()
    asyncio.run(go())


def _run(force=True):
    return asyncio.run(main_mod.run_ai_review("s1", "test-model", {"preset": "guided_ai"},
                                              ["curl", "nmap"], force=force))


def test_review_is_persisted(temp_db, fake_llm):
    _seed_session()
    out = _run()
    assert out and out["confidence"] == "medium"

    async def read():
        db = await db_mod.get_db()
        row = await (await db.execute(
            "SELECT * FROM session_reviews WHERE session_id = ?", ("s1",))).fetchone()
        await db.close()
        return dict(row)
    row = read.__wrapped__() if hasattr(read, "__wrapped__") else asyncio.run(read())
    assert row["confidence"] == "medium"
    assert "27017" in row["coverage_gaps"]
    assert row["model"] == "test-model"


def test_review_creates_no_findings_and_does_not_touch_evidence(temp_db, fake_llm):
    """The critical property: a critique must not reach anything the metrics read."""
    _seed_session()
    _run()

    async def read():
        db = await db_mod.get_db()
        f = [dict(r) for r in await (await db.execute(
            "SELECT vuln_type, evidence, verified, poc_status FROM findings "
            "WHERE session_id = ?", ("s1",))).fetchall()]
        await db.close()
        return f
    rows = asyncio.run(read())
    assert len(rows) == 1, "the review must not add findings"
    assert rows[0]["evidence"] == "original evidence"
    assert rows[0]["verified"] == 0
    assert rows[0]["poc_status"] is None


def test_disabled_does_nothing(temp_db, fake_llm):
    _seed_session()
    assert _run(force=False) is None


def test_never_raises_on_a_broken_store(monkeypatch, tmp_path, fake_llm):
    monkeypatch.setattr(db_mod, "DB_PATH", tmp_path / "nope" / "x.db")
    assert _run() is None
