"""Tests for run-config presets — especially the AI-solo baseline, which must
stay clean (no injected help) even if help-enabling env vars are set, so the
'raw model capability' measurement is not contaminated."""

import orchestrator.runconfig as rc


def test_ai_solo_is_clean_even_with_env_help_set(monkeypatch):
    # Env vars that would otherwise enable help must NOT leak into the baseline.
    monkeypatch.setenv("ERLIK_PLAYBOOKS", "juiceshop")
    monkeypatch.setenv("ERLIK_SKILLS", "true")
    monkeypatch.setenv("ERLIK_ENRICH_CVE", "true")
    monkeypatch.setenv("ERLIK_PRIMITIVES", "true")
    r = rc.resolve({"preset": "ai_only"})
    assert r["skills"] is False
    assert r["cve_enrich"] is False
    assert r["nettacker"] is False
    assert r["primitives"] is False
    assert r["target_memory"] is False
    assert r["playbooks"] in ("", None)   # no target playbook


def test_comparison_arms_are_env_proof(monkeypatch):
    """Both arms of the baseline-vs-guided comparison must pin every help lever,
    or a stray env var silently changes what is being measured."""
    monkeypatch.setenv("ERLIK_TECHNIQUES", "true")
    monkeypatch.setenv("ERLIK_NETTACKER", "true")
    for preset in ("ai_only", "guided_ai"):
        r = rc.resolve({"preset": preset})
        assert r["techniques"] is False, preset
        assert r["nettacker"] is False, preset


def test_client_facing_presets_reverify_their_findings():
    """A finding that reaches a report is something someone may act on. The
    presets meant for real use must re-test high/critical findings rather than
    ship them unverified."""
    for preset in ("guided_techniques", "deterministic_heavy", "full_assessment"):
        assert rc.resolve({"preset": preset})["poc_verify"] is True, preset


def test_prescan_presets_enable_environment_techniques():
    """Technique routing keys off observed ports, so it belongs with the presets
    that actually run a pre-scan."""
    for preset in ("recon_first", "deterministic_heavy", "full_assessment"):
        assert rc.resolve({"preset": preset})["techniques"] is True, preset


def test_guided_injects_skills_and_playbook():
    r = rc.resolve({"preset": "guided_ai"})
    assert r["skills"] is True
    assert r["cve_enrich"] is True
    assert r["primitives"] is True
    # "auto" = generic playbooks routed to the mission's vuln classes. It used
    # to be "juiceshop" here — the default preset shipped one app's endpoints to
    # every target. Juice Shop's endpoints are still selectable by name.
    assert r["playbooks"] == "auto"
    assert r["nettacker"] is False         # no external scanner in guided


def test_explicit_toggle_overrides_preset():
    # Ticking a toggle (custom) overrides the preset's value.
    r = rc.resolve({"preset": "guided_ai", "skills": False})
    assert r["skills"] is False
    assert r["playbooks"] == "auto"        # untouched keys keep preset value


def test_custom_preset_uses_env_fallback(monkeypatch):
    monkeypatch.setenv("ERLIK_SKILLS", "true")
    r = rc.resolve({"preset": "custom"})
    assert r["skills"] is True              # tri-state falls back to env


def test_all_presets_expose_label_and_config():
    for p in rc.presets_for_api():
        assert p["name"] and p["label"] and isinstance(p["config"], dict)


class TestProviderIsPinnablePerRun:
    """Every recorded experiment ran on local Ollama with qwen2.5-coder:7b.

    The process default is now a hosted provider, and a hosted model is a
    DIFFERENT model. An arm compared against archived rows has to take the same
    inference path, or the comparison is between two things at once — the
    treatment AND the model. Hence a per-run pin rather than a process-wide
    setting.
    """

    def test_unpinned_falls_back_to_the_process_default(self):
        assert rc.resolve({"preset": "custom"})["provider"] is None

    def test_a_run_can_pin_ollama(self):
        assert rc.resolve({"preset": "custom", "provider": "ollama"})["provider"] == "ollama"

    def test_an_unknown_provider_warns_and_falls_back(self):
        """Silently honouring a typo would route a run to a backend nobody
        chose, and the row would still claim the arm ran."""
        r = rc.resolve({"preset": "custom", "provider": "gpt5-turbo-ultra"})
        assert r["provider"] is None
        assert any("provider" in w for w in r["run_config_warnings"])

    def test_the_experiment_harness_pins_ollama(self):
        """The reason this feature exists. If the harness ever stops pinning,
        the next experiment silently changes model AND provider."""
        import importlib.util
        import pathlib
        path = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "context_test.py"
        spec = importlib.util.spec_from_file_location("ct", path)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        assert m.BASE.get("provider") == "ollama"

    def test_the_agent_loop_actually_uses_the_pin(self):
        """Wiring guard: a run_config key nothing reads is this codebase's
        signature defect — the tunables shipped that way for months."""
        import pathlib
        src = (pathlib.Path(__file__).resolve().parents[1]
               / "orchestrator" / "main.py").read_text()
        assert 'runcfg.get("provider")' in src
        assert "provider=_provider" in src
        assert src.count("provider=_provider") >= 2, (
            "the pin must reach BOTH the model-availability check and the "
            "generation call")

    def test_chat_json_forwards_the_provider(self):
        """It accepted `provider` and dropped it — the deterministic lane's
        LLM-judged cases would have ignored the pin entirely."""
        import inspect
        import orchestrator.llm_client as L
        assert "provider=provider" in inspect.getsource(L.chat_json)

    def test_default_model_follows_the_resolved_provider(self):
        """Pinning ollama while the process default is hosted must not hand
        Ollama a hosted model id — that fails at request time as an opaque 404
        rather than an obvious configuration error."""
        import orchestrator.llm_client as L
        assert L.default_model_for("ollama") == L.OLLAMA_DEFAULT_MODEL
        assert ":" in L.default_model_for("ollama"), "not an Ollama-style tag"
