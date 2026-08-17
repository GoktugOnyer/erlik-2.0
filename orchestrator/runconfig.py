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
        # poc_verify is on because this preset is meant for real engagements, not
        # just measurement: an unverified finding that reaches a client report is
        # something they may act on that nobody re-tested. It only examines
        # high/critical findings with a usable URL, so the cost is small.
        "config": {"skills": True, "cve_enrich": True, "nettacker": True,
                   "nettacker_scenario": "recon", "techniques": True,
                   "playbooks": "juiceshop", "primitives": True,
                   "poc_verify": True, "ai_review": True},
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
              "target_memory", "techniques", "ai_review", "review_model",
              "skills_exclude", "skills_pin", "skills_max_chars",
              "safe_mode", "safe_mode_ack"):
        if k in cfg and cfg[k] is not None:
            base[k] = cfg[k]

    # A key that is not in the tuple above VANISHES SILENTLY — the operator
    # sets it, the UI shows it, and the run ignores it. Name the ones we can
    # recognise as intended-but-wrong rather than dropping them without a word.
    warnings: list[str] = []
    _known = {"cve_enrich", "skills", "nettacker", "nettacker_findings",
              "nettacker_scenario", "playbooks", "poc_verify", "primitives",
              "target_memory", "techniques", "ai_review", "review_model",
              "skills_exclude", "skills_pin", "skills_max_chars",
              "safe_mode", "safe_mode_ack", "preset"}
    for k in cfg:
        if k not in _known:
            warnings.append(f"run_config key {k!r} is not recognised and was ignored")

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

    # Budget: clamped, not trusted. 0 does NOT mean "off" — the selector takes
    # the first file unconditionally — so a 0 here would be a knob whose label
    # lies. Values outside the sane band fall back to the default and warn.
    from orchestrator.skills import DEFAULT_SKILLS_BUDGET
    _mc = base.get("skills_max_chars")
    skills_max_chars = DEFAULT_SKILLS_BUDGET
    if _mc is not None:
        try:
            _mc = int(_mc)
            if 2000 <= _mc <= 40000:
                skills_max_chars = _mc
            else:
                warnings.append(
                    f"skills_max_chars {_mc} is outside 2000-40000; "
                    f"using {DEFAULT_SKILLS_BUDGET}")
        except (TypeError, ValueError):
            warnings.append(f"skills_max_chars {_mc!r} is not a number; "
                            f"using {DEFAULT_SKILLS_BUDGET}")

    def _as_list(v):
        if v is None:
            return []
        if isinstance(v, str):
            return [x.strip() for x in v.split(",") if x.strip()]
        return [str(x).strip() for x in v if str(x).strip()]

    # Safe mode: ON unless the operator BOTH turns it off AND names the
    # engagement authorising destructive testing.
    #
    # A bare `safe_mode: false` is not honoured. The dashboard's
    # applyRunPreset() blanket-assigns every control from the chosen preset, so
    # a checkbox wired the ordinary way would post `safe_mode: false` the moment
    # someone touched the preset dropdown — silently disarming a guard nobody
    # meant to disarm. Requiring a non-empty ack makes that impossible to do by
    # accident, and leaves a record of who claimed the authorisation.
    _ack = (base.get("safe_mode_ack") or "").strip() if isinstance(
        base.get("safe_mode_ack"), str) else ""
    safe_mode = True
    if base.get("safe_mode") is False:
        if _ack:
            safe_mode = False
        else:
            warnings.append(
                "safe_mode: false ignored — destructive testing requires "
                "safe_mode_ack naming the engagement that authorises it")
    elif base.get("safe_mode") is None:
        safe_mode = _env_bool("ERLIK_SAFE_MODE") if os.environ.get("ERLIK_SAFE_MODE") else True

    return {
        "preset": preset or "custom",
        "safe_mode": safe_mode,
        "safe_mode_ack": _ack or None,
        "skills_exclude": _as_list(base.get("skills_exclude")),
        "skills_pin": _as_list(base.get("skills_pin")),
        "skills_max_chars": skills_max_chars,
        "run_config_warnings": warnings,
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
