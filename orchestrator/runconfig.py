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
}

# Sensible pre-selectable setups. Keys map to the flag bundle a preset turns on;
# anything a preset omits falls back to env. `custom` = no preset, user decides.
RUN_PRESETS: dict[str, dict] = {
    "ai_only": {
        "label": "AI only",
        "desc": "Pure LLM agent — no deterministic pre-scan or knowledge injection.",
        "config": {"cve_enrich": False, "skills": False, "nettacker": False},
    },
    "guided_ai": {
        "label": "Guided AI",
        "desc": "LLM agent + injected skill knowledge + CVE enrichment. No external scanner.",
        "config": {"skills": True, "cve_enrich": True, "nettacker": False},
    },
    "recon_first": {
        "label": "Recon-first (recommended)",
        "desc": "Deterministic Nettacker recon seeds the agent, then skills + CVE enrichment.",
        "config": {"nettacker": True, "nettacker_scenario": "recon",
                   "skills": True, "cve_enrich": True},
    },
    "deterministic_heavy": {
        "label": "Deterministic-heavy",
        "desc": "Broad Nettacker web/vuln pre-scan with findings persisted; lighter AI reliance.",
        "config": {"nettacker": True, "nettacker_scenario": "web",
                   "nettacker_findings": True, "skills": True, "cve_enrich": True},
    },
    "full_assessment": {
        "label": "Full assessment",
        "desc": "Everything on; Nettacker full scan. Slow & thorough.",
        "config": {"nettacker": True, "nettacker_scenario": "full",
                   "nettacker_findings": True, "skills": True, "cve_enrich": True},
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
              "nettacker_scenario", "playbooks"):
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

    playbooks = base.get("playbooks")
    if playbooks is None:
        playbooks = os.environ.get("ERLIK_PLAYBOOKS", "") or None

    return {
        "preset": preset or "custom",
        "cve_enrich": tri("cve_enrich"),
        "skills": tri("skills"),
        "nettacker": tri("nettacker"),
        "nettacker_findings": tri("nettacker_findings"),
        "nettacker_scenario": scenario,
        "playbooks": playbooks,
    }


def presets_for_api() -> list[dict]:
    """Preset catalogue for the dashboard (name, label, desc, config)."""
    return [
        {"name": name, "label": p["label"], "desc": p["desc"], "config": p["config"]}
        for name, p in RUN_PRESETS.items()
    ]
