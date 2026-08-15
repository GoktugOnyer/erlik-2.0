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


def test_wasted_turns_are_made_visible():
    """A turn that produced no tool step still consumed budget. Reporting only
    the recorded steps hid exactly the turns the review exists to find."""
    p = R.build_review_prompt(
        config={}, activity={"steps": 30, "recorded_steps": 7, "max_turns": 30},
        tools=[], outcome={})
    assert "turns used: 30 of 30" in p
    assert "only 7 produced a tool step" in p
    assert "23 turn(s) yielded nothing" in p


def test_no_gap_reported_when_every_turn_produced_a_step():
    p = R.build_review_prompt(
        config={}, activity={"steps": 7, "recorded_steps": 7, "max_turns": 30},
        tools=[], outcome={})
    assert "yielded nothing" not in p


def test_observed_environment_reaches_the_prompt():
    """open_ports was hardcoded to [], so the reviewer could never comment on
    what the target was actually running."""
    p = R.build_review_prompt(
        config={}, activity={"open_ports": [3000, 27017], "tech": ["Express", "jQuery 2.2.4"]},
        tools=[], outcome={})
    assert "ports observed: 3000, 27017" in p
    assert "Express" in p and "jQuery 2.2.4" in p


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


# --- reviewer model selection ---------------------------------------------
#
# The reviewer may be LARGER than the model under test: it never touches the
# attack and runs once, after the session, so it is not part of the measurement.
# Measured on a 7B the critique invented preset names in 3 of 4 samples and once
# contradicted its own input; on a 35B it named a real preset and diagnosed the
# tool failures correctly.

INSTALLED = ["qwen2.5vl:7b", "llama3.1:70b", "nomic-embed-text:latest",
             "qwen2.5:7b", "qwen2.5-coder:7b", "qwen3.5:35b",
             "hf.co/Trendyol/Trendyol-Cybersecurity-LLM-Qwen3-32B-Q8_0-GGUF:Q8_0"]


@pytest.mark.parametrize("name, size", [
    ("llama3.1:70b", 70),
    ("qwen3.5:35b", 35),
    ("qwen2.5-coder:7b", 7),
    ("qwen3:27b", 27),
    ("hf.co/Trendyol/Trendyol-Cybersecurity-LLM-Qwen3-32B-Q8_0-GGUF:Q8_0", 32),
    ("nomic-embed-text:latest", None),
    ("", None),
])
def test_parse_param_size(name, size):
    assert R.parse_param_size(name) == size


def test_version_number_is_not_read_as_a_size():
    """'qwen2.5-coder:7b' is a 7B model, not a 2.5B one."""
    assert R.parse_param_size("qwen2.5-coder:7b") == 7


def test_picks_the_largest_local_model_under_the_cap():
    assert R.select_review_model(INSTALLED, "qwen2.5-coder:7b") == "qwen3.5:35b"


def test_cap_keeps_a_70b_from_being_chosen_silently():
    """Without the cap one critique would take minutes on a local 70B."""
    assert R.select_review_model(INSTALLED, "qwen2.5-coder:7b", max_b=100) == "llama3.1:70b"


def test_explicit_choice_wins():
    assert R.select_review_model(INSTALLED, "qwen2.5-coder:7b",
                                 explicit="qwen3:27b") == "qwen3:27b"


def test_remote_provider_defers_to_the_api_default():
    assert R.select_review_model(INSTALLED, "gpt-4o", provider="openai") is None


def test_explicit_wins_even_on_a_remote_provider():
    assert R.select_review_model([], "gpt-4o", explicit="o3",
                                 provider="openai") == "o3"


def test_falls_back_to_the_attack_model_when_nothing_is_bigger():
    assert R.select_review_model(["qwen2.5-coder:7b"], "qwen2.5-coder:7b") == "qwen2.5-coder:7b"
    assert R.select_review_model([], "qwen2.5-coder:7b") == "qwen2.5-coder:7b"


def test_embedding_and_vision_models_are_never_chosen():
    picked = R.select_review_model(["nomic-embed-text:latest", "qwen2.5vl:7b"], None)
    assert picked is None


def test_env_can_raise_the_cap(monkeypatch):
    monkeypatch.setenv("ERLIK_REVIEW_MODEL_MAX_B", "100")
    assert R.select_review_model(INSTALLED, "qwen2.5-coder:7b") == "llama3.1:70b"


# --- recommendation grounding ---------------------------------------------

PRESETS = ["ai_only", "guided_ai", "guided_techniques", "recon_first",
           "deterministic_heavy", "full_assessment"]


def test_prompt_lists_the_real_presets():
    p = R.build_review_prompt({}, {}, [], {}, valid_presets=PRESETS)
    assert "SELECTABLE PRESETS" in p
    assert "guided_techniques" in p


def test_invented_preset_is_flagged_not_silently_dropped():
    """A fabricated name is a signal the critique is unreliable, so it stays
    visible to the operator."""
    out = R.validate_recommendation('Try the `pentest_web_service` preset.', PRESETS)
    assert "unverified" in out
    assert "pentest_web_service" in out


def test_real_preset_passes_through_untouched():
    rec = 'Re-run with `full_assessment` for wider tool coverage.'
    assert R.validate_recommendation(rec, PRESETS) == rec


def test_validation_is_a_noop_without_a_preset_list():
    rec = "Try something else."
    assert R.validate_recommendation(rec, None) == rec
    assert R.validate_recommendation("", PRESETS) == ""


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
    """Stub the LLM. list_models is stubbed too — otherwise reviewer selection
    reaches the real Ollama and the test result depends on what happens to be
    installed on the machine."""
    async def chat(messages, model=None, **kw):
        return SAMPLE

    async def list_models():
        return ["qwen2.5-coder:7b", "qwen3.5:35b"]

    monkeypatch.setattr(main_mod.llm_client, "chat", chat)
    monkeypatch.setattr(main_mod.llm_client, "list_models", list_models)
    monkeypatch.delenv("ERLIK_REVIEW_MODEL", raising=False)


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
    row = asyncio.run(read())
    assert row["confidence"] == "medium"
    assert "27017" in row["coverage_gaps"]
    # The REVIEWER model is recorded, not the model under test — otherwise a
    # result could not be traced to what actually produced the critique.
    assert row["model"] == "qwen3.5:35b"


def test_authoritative_turn_count_is_used_not_the_step_row_count(temp_db, fake_llm, monkeypatch):
    """sessions.total_steps counts turns; steps rows count turns that produced a
    tool call. The review must report the former, or it undercounts the waste."""
    _seed_session()

    async def bump():
        db = await db_mod.get_db()
        await db.execute("UPDATE sessions SET total_steps = 25 WHERE id = ?", ("s1",))
        await db.commit()
        await db.close()
    asyncio.run(bump())

    # main.py imports the module inside the function, so patching the module
    # attribute here is what run_ai_review will resolve at call time.
    seen = {}
    real_build = R.build_review_prompt
    monkeypatch.setattr(R, "build_review_prompt",
                        lambda **kw: seen.update(kw) or real_build(**kw))
    _run()
    # one step row was seeded, but the session recorded 25 turns
    assert seen["activity"]["steps"] == 25
    assert seen["activity"]["recorded_steps"] == 1


def test_observed_ports_are_threaded_through(temp_db, fake_llm, monkeypatch):
    _seed_session()
    seen = {}
    real_build = R.build_review_prompt
    monkeypatch.setattr(R, "build_review_prompt",
                        lambda **kw: seen.update(kw) or real_build(**kw))
    asyncio.run(main_mod.run_ai_review(
        "s1", "test-model", {"preset": "guided_ai"}, ["curl"], force=True,
        observed_ports=[3000, 27017, 3000], observed_tech=["Express", "Express"]))
    assert seen["activity"]["open_ports"] == [3000, 27017]   # deduped, sorted
    assert seen["activity"]["tech"] == ["Express"]           # deduped, order kept


def test_explicit_review_model_is_honoured(temp_db, fake_llm, monkeypatch):
    monkeypatch.setenv("ERLIK_REVIEW_MODEL", "qwen3:27b")
    _seed_session()
    _run()

    async def read():
        db = await db_mod.get_db()
        r = await (await db.execute(
            "SELECT model FROM session_reviews WHERE session_id = ?", ("s1",))).fetchone()
        await db.close()
        return dict(r)["model"]
    assert asyncio.run(read()) == "qwen3:27b"


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
