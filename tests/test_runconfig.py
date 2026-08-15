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
    assert r["playbooks"] == "juiceshop"   # real endpoints for the target
    assert r["nettacker"] is False         # no external scanner in guided


def test_explicit_toggle_overrides_preset():
    # Ticking a toggle (custom) overrides the preset's value.
    r = rc.resolve({"preset": "guided_ai", "skills": False})
    assert r["skills"] is False
    assert r["playbooks"] == "juiceshop"   # untouched keys keep preset value


def test_custom_preset_uses_env_fallback(monkeypatch):
    monkeypatch.setenv("ERLIK_SKILLS", "true")
    r = rc.resolve({"preset": "custom"})
    assert r["skills"] is True              # tri-state falls back to env


def test_all_presets_expose_label_and_config():
    for p in rc.presets_for_api():
        assert p["name"] and p["label"] and isinstance(p["config"], dict)
