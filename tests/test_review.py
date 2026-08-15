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


# --- ground-truth coverage ------------------------------------------------
#
# "What did this run miss" is MEASURED, not asked of the model: the same
# one-to-one assignment that produces the confusion matrix yields the unmatched
# ground truths, so recall and reported coverage cannot contradict each other.
# The answer key is read post-hoc and must never be visible to the agent.

GT_ROWS = [
    {"target_name": "OWASP Juice Shop", "target_url": "http://juice-shop:3000"},
    {"target_name": "DVWA", "target_url": "http://dvwa"},
]

# How the answer key is ACTUALLY seeded — Juice Shop under localhost, while every
# real run targets the compose service name.
REAL_GT_ROWS = [
    {"target_name": "OWASP Juice Shop", "target_url": "http://localhost:3000"},
    {"target_name": "DVWA", "target_url": "http://dvwa:8080"},
]


@pytest.mark.parametrize("url, expected", [
    ("http://juice-shop:3000", "OWASP Juice Shop"),
    ("http://juice-shop:3000/rest/products", "OWASP Juice Shop"),
    ("https://juice-shop", "OWASP Juice Shop"),
    ("http://dvwa/login.php", "DVWA"),
])
def test_target_resolves_from_the_session_url(url, expected):
    assert R.match_target_name(url, GT_ROWS) == expected


@pytest.mark.parametrize("url", [
    "http://juice-shop:3000",
    "http://juice-shop:3000/rest/user/login",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
])
def test_loopback_and_service_name_are_the_same_target(url):
    """The regression that made this feature silently do nothing: ground truth
    registers Juice Shop under localhost:3000, runs target juice-shop:3000, and
    tool_executor rewrites between them. A strict host match found no answer key
    for the only target that has one."""
    assert R.match_target_name(url, REAL_GT_ROWS) == "OWASP Juice Shop"


def test_alias_matching_does_not_confuse_different_services():
    """The port is what identifies a service inside the lab, so a shared alias
    must not merge two different ones."""
    assert R.match_target_name("http://dvwa:8080", REAL_GT_ROWS) == "DVWA"
    assert R.match_target_name("http://localhost:8080", REAL_GT_ROWS) == "DVWA"
    assert R.match_target_name("http://juice-shop:9999", REAL_GT_ROWS) is None


def test_unknown_target_returns_none_rather_than_guessing():
    """A wrong answer key would report fabricated coverage gaps."""
    assert R.match_target_name("http://example.com", GT_ROWS) is None
    assert R.match_target_name(None, GT_ROWS) is None
    assert R.match_target_name("http://juice-shop:3000", []) is None


def test_missed_vulnerabilities_are_listed_as_measured_fact():
    p = R.build_review_prompt({}, {}, [], {}, coverage={
        "total": 5, "found": 3,
        "missed": [{"vuln_type": "Cross-Site Scripting", "severity": "high",
                    "url_pattern": "/search", "parameter": "q",
                    "owasp_category": "A03:2021"}]})
    assert "3 of 5 known vulnerabilities were found" in p
    assert "[HIGH] Cross-Site Scripting at /search (param: q) [A03:2021]" in p


def test_full_coverage_says_so():
    p = R.build_review_prompt({}, {}, [], {}, coverage={"total": 4, "found": 4, "missed": []})
    assert "all 4 known vulnerabilities for this target were reported" in p


def test_absent_answer_key_forbids_speculation():
    p = R.build_review_prompt({}, {}, [], {}, coverage=None)
    assert "no answer key for this target" in p
    assert "do not speculate" in p


def test_model_is_told_not_to_re_argue_the_measured_list():
    p = R.build_review_prompt({}, {}, [], {}, coverage={"total": 1, "found": 0, "missed": []})
    assert "measured, not your judgement" in p
    assert "do not add classes to it" in p


def test_long_miss_lists_are_truncated():
    missed = [{"vuln_type": f"V{i}", "severity": "low"} for i in range(30)]
    p = R.build_review_prompt({}, {}, [], {}, coverage={"total": 30, "found": 0, "missed": missed})
    assert "…and 10 more" in p


def test_coverage_matches_the_confusion_matrix():
    """The two must be derived from one assignment, or a report can claim recall
    0.33 while listing a different number of misses."""
    from orchestrator.main import _assign_findings_to_ground_truth, _sound_confusion_matrix
    gts = [{"vuln_type": "SQL Injection", "url_pattern": "/login", "parameter": "email", "severity": "critical"},
           {"vuln_type": "Cross-Site Scripting", "url_pattern": "/search", "parameter": "q", "severity": "high"},
           {"vuln_type": "Broken Access Control", "url_pattern": "/basket", "parameter": None, "severity": "high"}]
    fs = [{"vuln_type": "SQL Injection", "url": "http://t/login", "parameter": "email"}]
    a = _assign_findings_to_ground_truth(fs, gts)
    m = _sound_confusion_matrix(fs, gts)
    assert len(a["matched"]) == m["tp"]
    assert len(a["missed_ground_truths"]) == m["fn"]
    assert len(a["unmatched_findings"]) == m["fp"]


def test_assignment_is_deterministic():
    """Feeds research metrics, so it must not reorder between runs."""
    from orchestrator.main import _assign_findings_to_ground_truth
    gts = [{"vuln_type": "XSS", "url_pattern": "/a", "parameter": "q", "severity": "high"},
           {"vuln_type": "XSS", "url_pattern": "/b", "parameter": "q", "severity": "high"}]
    fs = [{"vuln_type": "XSS", "url": "http://t/a", "parameter": "q"}]
    first = _assign_findings_to_ground_truth(fs, gts)
    for _ in range(5):
        again = _assign_findings_to_ground_truth(fs, gts)
        assert [g["url_pattern"] for g in again["missed_ground_truths"]] == \
               [g["url_pattern"] for g in first["missed_ground_truths"]]


# --- credential redaction -------------------------------------------------
#
# primitives.py teaches the agent to reuse captured material, its reuse hints
# being literally '-H "Authorization: Bearer <jwt>"' and '--cookie "<cookie>"',
# so steps.tool_input holds live tokens whenever that lever is on. The reviewer
# may be a REMOTE model, so anything sent to it must be masked first.

JWT_VALUE = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.s3cr3tsignature"


def test_jwt_in_a_command_is_masked():
    cmd = f'curl -H "Authorization: Bearer {JWT_VALUE}" http://juice-shop:3000/rest/user'
    out = R.redact_secrets(cmd)
    assert JWT_VALUE not in out
    assert "redacted" in out
    assert "juice-shop:3000/rest/user" in out      # the useful part survives


def test_cookie_and_basic_auth_are_masked():
    text = ("Set-Cookie: token=abc123def456ghi\n"
            "Authorization: Basic YWRtaW46c3VwZXJzZWNyZXQ=")
    out = R.redact_secrets(text)
    assert "abc123def456ghi" not in out
    assert "YWRtaW46c3VwZXJzZWNyZXQ=" not in out


def test_redaction_is_safe_on_empty_input():
    assert R.redact_secrets("") == ""
    assert R.redact_secrets(None) == ""


def test_no_secret_survives_into_the_prompt():
    """The end-to-end property: whatever the agent ran, the prompt is clean."""
    steps = [{"step_number": 1, "tool_called": "curl",
              "tool_input": f'curl -H "Authorization: Bearer {JWT_VALUE}" http://t/x',
              "prompt_sent": f"reuse the token {JWT_VALUE} against the admin API"}]
    p = R.build_review_prompt({}, {}, [], {}, steps=steps)
    assert JWT_VALUE not in p


def test_primitive_values_are_never_passed_only_kinds():
    """The outcome section reports kinds and counts, never the values."""
    p = R.build_review_prompt({}, {}, [], {"primitive_kinds": {"jwt": 2, "cookie": 1}})
    assert "jwt=2" in p and "cookie=1" in p
    assert JWT_VALUE not in p


def test_absent_credentials_are_called_out():
    p = R.build_review_prompt({}, {}, [], {"primitive_kinds": {}})
    assert "never held an authenticated session" in p


# --- richer evidence ------------------------------------------------------

def test_distinct_commands_are_shown_not_just_counts():
    """4 probes against 4 parameters is not 4 identical retries."""
    steps = [{"step_number": i, "tool_called": "sqlmap",
              "tool_input": f"sqlmap -u http://t/search?q=1&p={i}"} for i in range(1, 5)]
    out = R.summarise_commands(steps)
    assert len(out) == 4
    assert all("sqlmap" in line for line in out)


def test_identical_retries_collapse():
    steps = [{"step_number": i, "tool_called": "sqlmap",
              "tool_input": "sqlmap -u http://t/search?q=1"} for i in range(1, 6)]
    assert len(R.summarise_commands(steps)) == 1


def test_command_list_is_capped_per_tool():
    steps = [{"step_number": i, "tool_called": "curl",
              "tool_input": f"curl http://t/{i}"} for i in range(1, 12)]
    out = R.summarise_commands(steps, per_tool=3)
    assert len([o for o in out if "…and" not in o]) == 3
    assert any("and 8 more distinct command(s)" in o for o in out)


def test_agent_intent_is_surfaced_with_its_turn():
    steps = [{"step_number": 3, "tool_called": "whatweb",
              "prompt_sent": "enumerate authentication endpoints"}]
    out = R.summarise_intents(steps)
    assert out and "turn 3" in out[0] and "enumerate authentication" in out[0]


def test_mission_and_toolset_tier_reach_the_prompt():
    p = R.build_review_prompt(
        config={"toolset_preset": "core_10", "enabled_tools": ["curl", "nmap"]},
        activity={"mission": "Find authentication bypasses only."},
        tools=[], outcome={})
    assert "Find authentication bypasses only." in p
    assert "core_10" in p
    assert "curl, nmap" in p


def test_finding_classes_are_listed_not_just_severities():
    p = R.build_review_prompt({}, {}, [], {
        "findings": 3, "severities": {"low": 3},
        "finding_types": ["Missing Security Header", "Server Banner Disclosure"]})
    assert "Missing Security Header" in p


def test_prompt_requires_citations():
    p = R.build_review_prompt({}, {}, [], {})
    assert "must cite its evidence" in p
    assert "A claim you cannot cite is one you must not make" in p


def test_prompt_guards_against_the_two_known_false_critiques():
    """The 7B faulted the agent for unavailable tools and claimed classes were
    untested when they had been probed."""
    p = R.build_review_prompt({}, {}, [], {})
    assert "not in its enabled list" in p
    assert "if a command above probed it" in p


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


def test_ground_truth_never_reaches_the_agent(temp_db, fake_llm):
    """THE constraint on this feature. The answer key may inform the post-hoc
    critique; if it reached the agent's own context the measurement would be
    worthless. Asserted structurally: nothing that builds the agent's system
    prompt reads ground_truth."""
    import inspect
    import orchestrator.main as M

    agent_src = inspect.getsource(M.agent_loop)
    assert "ground_truth" not in agent_src, \
        "agent_loop must never read the ground-truth answer key"

    # And the only reader is the post-run review.
    for fn in (M._build_report_json, M._persist_derived_references):
        assert "ground_truth" not in inspect.getsource(fn)
    assert "ground_truth" in inspect.getsource(M.run_ai_review)


def test_measured_coverage_is_persisted_and_returned(temp_db, fake_llm):
    """The miss list must survive without a model — it is computed, not authored."""
    _seed_session()

    async def seed_gt():
        db = await db_mod.get_db()
        # /x matches the finding seeded by _seed_session, so this exercises a
        # genuine hit alongside two genuine misses.
        for vt, sev, pat in [("SQL Injection", "critical", "/x"),
                             ("Cross-Site Scripting", "high", "/search"),
                             ("Broken Access Control", "high", "/rest/basket")]:
            await db.execute(
                "INSERT INTO ground_truth (target_name, target_url, vuln_type, severity, "
                "url_pattern, parameter, owasp_category) VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("OWASP Juice Shop", "http://juice-shop:3000", vt, sev, pat, None, "A03:2021"))
        await db.commit()
        await db.close()
    asyncio.run(seed_gt())

    out = _run()
    cov = out["coverage"]
    assert cov["target_name"] == "OWASP Juice Shop"
    assert cov["total"] == 3
    # the seeded finding matches the SQLi entry, so two remain unmatched
    missed = {m["vuln_type"] for m in cov["missed"]}
    assert "Cross-Site Scripting" in missed
    assert "SQL Injection" not in missed

    async def read():
        db = await db_mod.get_db()
        r = await (await db.execute(
            "SELECT coverage FROM session_reviews WHERE session_id = ?", ("s1",))).fetchone()
        await db.close()
        return dict(r)["coverage"]
    import json as _json
    assert _json.loads(asyncio.run(read()))["total"] == 3


def test_unknown_target_yields_no_coverage_claim(temp_db, fake_llm):
    _seed_session()
    out = _run()
    assert out["coverage"] is None      # no ground truth seeded for this target


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
