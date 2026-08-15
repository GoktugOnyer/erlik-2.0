"""Post-run AI review — a critique of the ATTACK, not of the target.

The end-of-session report already asks the model for NEXT_STEPS, but those are
remediation advice about the application. This is a different question: given
what the run actually did, what did it MISS, what did it WASTE effort on, and
which run-config levers would have helped?

Deliberately advisory only. It never writes a finding, never sets `verified`,
and never touches `evidence` — a critique that fed the metrics would let the
model grade its own homework, and evidence in particular is a scoring input to
both the verification labeller and ground-truth matching.

Pure prompt construction and parsing here; the DB reads and the LLM call live in
main.py. Gated by the per-session run config (`ai_review`) / ERLIK_AI_REVIEW.
"""

from __future__ import annotations

import os
import re

REVIEW_PROMPT = """You are a senior penetration tester reviewing a colleague's \
automated scan of ONE web application. Critique the RUN, not the application. \
Do not restate findings and do not give remediation advice — a separate report \
covers that.

RUN CONFIGURATION (what help the agent had)
{config_text}

WHAT THE RUN DID
{activity_text}

TOOL USAGE
{tools_text}

OUTCOME
{outcome_text}

Judge only from the evidence above. If something was not attempted, say so \
plainly; do not assume it succeeded. Be specific and concrete — name endpoints, \
tools and settings, not generalities.

Respond in this EXACT format (nothing else):

COVERAGE_GAPS:
- <attack surface or vuln class this run never touched, and why it matters here>
- <another, or "none" if coverage was genuinely complete>

WASTED_EFFORT:
- <a tool that repeatedly failed, a loop, or turns spent with no progress>
- <another, or "none">

CONFIG_SUGGESTIONS:
- <a concrete run-config change and the reason, e.g. "enable TECHNIQUES: port \
27017 was open but no MongoDB technique context was injected">
- <another, or "none">

RECOMMENDED_NEXT_RUN: <one sentence naming ONE preset from the list above and why>

CONFIDENCE: <high|medium|low — how much the evidence above supports this critique>
"""

# The recommendation was free text, so the model invented plausible preset names
# ("pentest_web_service", "aggressive") in 3 of 4 measured samples. The valid set
# is known, so it goes in the prompt and is checked on the way back out.
_PRESET_LINE = "\nSELECTABLE PRESETS (use one of these names verbatim, nothing else):\n{presets}\n"


def review_enabled() -> bool:
    """True when post-run review is opted in via ERLIK_AI_REVIEW."""
    return os.environ.get("ERLIK_AI_REVIEW", "").strip().lower() in ("1", "true", "yes", "on")


# The reviewer may be a LARGER model than the one under test. It is not part of
# the measurement — it never touches the attack, and runs once after the session
# — so using a stronger model costs seconds and does not affect experimental
# control. Measured on a 7B: the critique invented preset names in 3 of 4 samples
# and once contradicted the facts it was given.
DEFAULT_REVIEW_MAX_B = 40.0

# Not chat models, or not useful as a reviewer.
_NOT_A_REVIEWER = ("embed", "-vl", "vl:", "vision", "whisper", "rerank")

_PARAM_RX = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d)?)\s*[bB](?![a-zA-Z0-9])")


def parse_param_size(model_name: str) -> float | None:
    """Billions of parameters advertised in a model tag, if any.

    Handles 'llama3.1:70b' -> 70, 'qwen3.5:35b' -> 35, 'qwen2.5-coder:7b' -> 7,
    and 'hf.co/…-Qwen3-32B-Q8_0-GGUF:Q8_0' -> 32. The lookbehind stops a version
    number ('qwen2.5') being read as a size.
    """
    if not model_name:
        return None
    sizes = [float(m) for m in _PARAM_RX.findall(str(model_name))]
    return max(sizes) if sizes else None


def select_review_model(installed: list[str] | None = None,
                        attack_model: str | None = None,
                        explicit: str | None = None,
                        provider: str = "ollama",
                        max_b: float | None = None) -> str | None:
    """Which model should write the critique.

    Precedence:
      1. an explicit choice (run config `review_model` / ERLIK_REVIEW_MODEL)
      2. a remote provider — return None so llm_client uses its configured
         default, which is already the strong hosted model
      3. locally, the largest installed chat model at or below `max_b`

    The cap keeps the default predictable and quick: without it a 70B present on
    the machine would silently be chosen and take minutes for one critique. Pin
    ERLIK_REVIEW_MODEL to override, or raise ERLIK_REVIEW_MODEL_MAX_B.

    Falls back to `attack_model` when nothing better is available, so the review
    still runs on a machine with only the small model installed.
    """
    if explicit and explicit.strip():
        return explicit.strip()
    if (provider or "").lower() != "ollama":
        return None

    if max_b is None:
        try:
            max_b = float(os.environ.get("ERLIK_REVIEW_MODEL_MAX_B", "") or DEFAULT_REVIEW_MAX_B)
        except ValueError:
            max_b = DEFAULT_REVIEW_MAX_B

    best_name, best_size = None, -1.0
    for name in (installed or []):
        low = str(name).lower()
        if any(bad in low for bad in _NOT_A_REVIEWER):
            continue
        size = parse_param_size(name)
        if size is None or size > max_b:
            continue
        if size > best_size:
            best_name, best_size = name, size

    if best_name and (attack_model is None
                      or best_size > (parse_param_size(attack_model) or 0)):
        return best_name
    return attack_model or None


def _bullets(block: str | None) -> list[str]:
    out: list[str] = []
    for line in (block or "").strip().splitlines():
        line = line.strip().lstrip("-•* ").strip()
        if not line or line.lower() in ("none", "none.", "n/a"):
            continue
        out.append(line)
    return out


def build_review_prompt(config: dict, activity: dict, tools: list[dict],
                        outcome: dict, valid_presets: list[str] | None = None) -> str:
    """Compose the critique prompt from facts already recorded for the session."""
    helps = [k for k in ("skills", "nettacker", "techniques", "primitives",
                         "target_memory", "cve_enrich", "poc_verify")
             if config.get(k)]
    config_text = (
        f"- preset: {config.get('preset') or 'custom'}\n"
        f"- help enabled: {', '.join(helps) if helps else 'NONE (raw model baseline)'}\n"
        f"- target playbook: {config.get('playbooks') or 'none'}\n"
        f"- pre-scan scenario: {config.get('nettacker_scenario') or 'n/a'}"
    )

    ports = activity.get("open_ports") or []
    activity_text = (
        f"- target: {activity.get('target_url')}\n"
        f"- turns used: {activity.get('steps', 0)} of {activity.get('max_turns', '?')} allowed\n"
        f"- phases reached: {', '.join(activity.get('phases') or []) or 'none recorded'}\n"
        f"- duration: {round((activity.get('duration_ms') or 0) / 1000)}s\n"
        f"- ports observed: {', '.join(str(p) for p in ports) if ports else 'none recorded'}"
    )

    if tools:
        rows = [f"- {t['tool']}: {t['calls']} call(s), {t['failures']} failed"
                + (f" — last error: {t['last_error'][:120]}" if t.get("last_error") else "")
                for t in tools]
        tools_text = "\n".join(rows)
    else:
        tools_text = "- no tools were executed"

    sev = outcome.get("severities") or {}
    sev_text = ", ".join(f"{k}={v}" for k, v in sev.items() if v) or "none"
    outcome_text = (
        f"- findings: {outcome.get('findings', 0)} ({sev_text})\n"
        f"- tools available but never used: "
        f"{', '.join(outcome.get('unused_tools') or []) or 'none'}"
    )

    if valid_presets:
        config_text += _PRESET_LINE.format(
            presets="\n".join(f"  - {p}" for p in valid_presets))

    return REVIEW_PROMPT.format(config_text=config_text, activity_text=activity_text,
                                tools_text=tools_text, outcome_text=outcome_text)


def validate_recommendation(recommendation: str, valid_presets: list[str] | None) -> str:
    """Flag a recommendation that names a preset which does not exist.

    Left visible rather than silently dropped: an operator should see that the
    reviewer invented a name, since it is a signal the critique is unreliable.
    """
    if not recommendation or not valid_presets:
        return recommendation or ""
    named = set(re.findall(r"[`\"']([A-Za-z_][A-Za-z0-9_]{3,})[`\"']", recommendation))
    invented = sorted(n for n in named if n not in set(valid_presets))
    if invented:
        return (f"{recommendation}  [unverified: no preset named "
                f"{', '.join(invented)} — reviewer may be unreliable]")
    return recommendation


def parse_review(text: str) -> dict:
    """Structure the model's critique. Missing sections degrade to empty."""
    def section(name: str, stop: str) -> str | None:
        m = re.search(rf"{name}:\s*(.+?)(?={stop}|\Z)", text or "", re.DOTALL)
        return m.group(1) if m else None

    nxt = section("RECOMMENDED_NEXT_RUN", r"\nCONFIDENCE:")
    conf = section("CONFIDENCE", r"\Z")
    confidence = (conf or "").strip().split()[0].lower() if conf else ""

    return {
        "coverage_gaps": _bullets(section("COVERAGE_GAPS", r"\nWASTED_EFFORT:")),
        "wasted_effort": _bullets(section("WASTED_EFFORT", r"\nCONFIG_SUGGESTIONS:")),
        "config_suggestions": _bullets(section("CONFIG_SUGGESTIONS", r"\nRECOMMENDED_NEXT_RUN:")),
        "recommended_next_run": (nxt or "").strip(),
        "confidence": confidence if confidence in ("high", "medium", "low") else "",
    }


def render_review_markdown(review: dict) -> str:
    """The critique as a report section. "" when the model returned nothing usable."""
    if not any(review.get(k) for k in
               ("coverage_gaps", "wasted_effort", "config_suggestions",
                "recommended_next_run")):
        return ""
    L = ["## Run Review (AI critique of this scan)", "",
         "*Advisory only — this section never creates findings or changes metrics.*", ""]
    for title, key in (("Coverage gaps", "coverage_gaps"),
                       ("Wasted effort", "wasted_effort"),
                       ("Configuration suggestions", "config_suggestions")):
        items = review.get(key) or []
        if items:
            L.append(f"**{title}**")
            L.extend(f"- {i}" for i in items)
            L.append("")
    if review.get("recommended_next_run"):
        L.append(f"**Recommended next run:** {review['recommended_next_run']}")
        L.append("")
    if review.get("confidence"):
        L.append(f"*Reviewer confidence: {review['confidence']}.*")
        L.append("")
    return "\n".join(L)
