"""Per-session run configuration: which deterministic / AI stages run, plus a
few sensible pre-selectable setups ("presets").

This sits on top of the existing per-session **prompt** (`system_prompt`) and
**scope** (`scope_mode`), and lets the dashboard offer either one-click presets
or full custom control over the automation *flow*:

  - cve_enrich          NVD CVE enrichment of findings        (ERLIK_ENRICH_CVE)
  - skills              inject relevant skill knowledge        (ERLIK_SKILLS)
  - nettacker           deterministic OWASP Nettacker pre-scan (ERLIK_NETTACKER)
  - nettacker_scenario  which Nettacker run mode               (ERLIK_NETTACKER_SCENARIO)
  - nettacker_findings  persist Nettacker findings             (ERLIK_NETTACKER_FINDINGS)
  - playbooks           Juice-Shop exploit playbooks           (ERLIK_PLAYBOOKS)

A session may carry a `run_config` JSON object. Each boolean flag is TRI-STATE:
True/False forces it; null/absent falls back to the process env default. This
keeps existing env-driven behavior intact when no per-session config is given.
"""

from __future__ import annotations

import json
import os

from orchestrator.integrations.nettacker import DEFAULT_SCENARIO, SCENARIOS


def _env_bool(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


_BOOL_KEYS = {
    "cve_enrich": "ERLIK_ENRICH_CVE",
    "skills": "ERLIK_SKILLS",
    "nettacker": "ERLIK_NETTACKER",
    "nettacker_findings": "ERLIK_NETTACKER_FINDINGS",
    "poc_verify": "ERLIK_POC_VERIFY",
    "primitives": "ERLIK_PRIMITIVES",
    "target_memory": "ERLIK_TARGET_MEMORY",
    "techniques": "ERLIK_TECHNIQUES",
    "ai_review": "ERLIK_AI_REVIEW",
}

# Sensible pre-selectable setups. Keys map to the flag bundle a preset turns on;
# anything a preset omits falls back to env. `custom` = no preset, user decides.
RUN_PRESETS: dict[str, dict] = {
    "ai_only": {
        "label": "AI Solo — raw model, no help (baseline)",
        "desc": "Pure LLM agent. No skill injection, no target playbook, no pre-scan, "
                "no memory, no primitive reuse. Measures the model's OWN capability — "
                "use this as the unguided baseline. Everything is forced OFF, so a "
                "stray env var can't leak help into the measurement.",
        # Every knowledge/help lever explicitly False so the baseline is clean.
        "config": {"cve_enrich": False, "skills": False, "nettacker": False,
                   "playbooks": "", "primitives": False, "target_memory": False,
                   "poc_verify": False, "techniques": False,
                   "ai_review": False},
    },
    "guided_ai": {
        "label": "Guided AI — skills + target playbook (most effective)",
        "desc": "LLM agent + injected skill knowledge + the target's exploit playbook "
                "(real endpoints & payloads) + primitive reuse + CVE enrichment. No "
                "external scanner. The most effective setup for finding the most vulns.",
        # techniques is pinned False for the same reason nettacker is: this arm is
        # compared against ai_only, so no help lever may drift in from the env.
        "config": {"skills": True, "cve_enrich": True, "nettacker": False,
                   "playbooks": "juiceshop", "primitives": True,
                   "techniques": False, "ai_review": True},
    },
    "guided_techniques": {
        "label": "Guided Attack — environment-specific techniques",
        "desc": "Skills + target playbook + techniques matched to what the target "
                "actually runs (ports/tech observed by a light pre-scan), then an AI "
                "review of the run at the end. Set ERLIK_HACKTRICKS_PATH for full "
                "technique text; without it you still get titles and reference links.",
        "config": {"skills": True, "cve_enrich": True, "nettacker": True,
                   "nettacker_scenario": "recon", "techniques": True,
                   "playbooks": "juiceshop", "primitives": True,
                   "ai_review": True},
    },
    "recon_first": {
        "label": "Recon-first — Nettacker seeds the agent",
        "desc": "Deterministic Nettacker recon seeds the agent, then skills + target "
                "playbook + CVE enrichment. Reuses durable per-target memory.",
        "config": {"nettacker": True, "nettacker_scenario": "recon",
                   "skills": True, "cve_enrich": True, "playbooks": "juiceshop",
                   "primitives": True, "target_memory": True,
                   "techniques": True, "ai_review": True},
    },
    "deterministic_heavy": {
        "label": "Deterministic-heavy — broad pre-scan",
        "desc": "Broad Nettacker web/vuln pre-scan with findings persisted; skills + "
                "target playbook; lighter AI reliance.",
        "config": {"nettacker": True, "nettacker_scenario": "web",
                   "nettacker_findings": True, "skills": True, "cve_enrich": True,
                   "playbooks": "juiceshop", "poc_verify": True,
                   "techniques": True, "ai_review": True},
    },
    "full_assessment": {
        "label": "Full assessment — everything on (slow)",
        "desc": "Everything: Nettacker full scan, skills, target playbook, PoC "
                "re-verification, primitive reuse and per-target memory. Slow & thorough.",
        "config": {"nettacker": True, "nettacker_scenario": "full",
                   "nettacker_findings": True, "skills": True, "cve_enrich": True,
                   "playbooks": "juiceshop", "poc_verify": True, "primitives": True,
                   "target_memory": True, "techniques": True, "ai_review": True},
    },
}

DEFAULT_PRESET = "guided_ai"


def _coerce(run_config) -> dict:
    if isinstance(run_config, str):
        try:
            return json.loads(run_config) if run_config.strip() else {}
        except (json.JSONDecodeError, ValueError):
            return {}
    return dict(run_config) if isinstance(run_config, dict) else {}


def resolve(run_config=None) -> dict:
    """Collapse (preset + explicit overrides + env) into effective settings.

    Returns: {cve_enrich, skills, nettacker, nettacker_findings,
              nettacker_scenario, playbooks, preset}.
    """
    cfg = _coerce(run_config)

    preset = cfg.get("preset")
    base: dict = dict(RUN_PRESETS.get(preset, {}).get("config", {})) if preset and preset != "custom" else {}

    # Explicit per-key values in the session config override the preset.
    for k in ("cve_enrich", "skills", "nettacker", "nettacker_findings",
              "nettacker_scenario", "playbooks", "poc_verify", "primitives",
              "target_memory", "techniques", "ai_review", "review_model"):
        if k in cfg and cfg[k] is not None:
            base[k] = cfg[k]

    def tri(key: str) -> bool:
        v = base.get(key)
        return _env_bool(_BOOL_KEYS[key]) if v is None else bool(v)

    scenario = (base.get("nettacker_scenario")
                or os.environ.get("ERLIK_NETTACKER_SCENARIO", "").strip()
                or DEFAULT_SCENARIO)
    if scenario not in SCENARIOS:
        scenario = DEFAULT_SCENARIO

    # Which model writes the post-run critique. Not a help lever — the reviewer
    # is not part of the measurement — so it is a free-form string, not tri-state.
    review_model = (base.get("review_model")
                    or os.environ.get("ERLIK_REVIEW_MODEL", "").strip() or None)

    playbooks = base.get("playbooks")
    if playbooks is None:
        playbooks = os.environ.get("ERLIK_PLAYBOOKS", "") or None

    return {
        "preset": preset or "custom",
        "cve_enrich": tri("cve_enrich"),
        "skills": tri("skills"),
        "nettacker": tri("nettacker"),
        "nettacker_findings": tri("nettacker_findings"),
        "poc_verify": tri("poc_verify"),
        "primitives": tri("primitives"),
        "target_memory": tri("target_memory"),
        "techniques": tri("techniques"),
        "ai_review": tri("ai_review"),
        "review_model": review_model,
        "nettacker_scenario": scenario,
        "playbooks": playbooks,
    }


def presets_for_api() -> list[dict]:
    """Preset catalogue for the dashboard (name, label, desc, config)."""
    return [
        {"name": name, "label": p["label"], "desc": p["desc"], "config": p["config"]}
        for name, p in RUN_PRESETS.items()
    ]
