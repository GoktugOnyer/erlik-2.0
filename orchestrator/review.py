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

RECOMMENDED_NEXT_RUN: <one sentence: which preset/settings to try next and why>

CONFIDENCE: <high|medium|low — how much the evidence above supports this critique>
"""


def review_enabled() -> bool:
    """True when post-run review is opted in via ERLIK_AI_REVIEW."""
    return os.environ.get("ERLIK_AI_REVIEW", "").strip().lower() in ("1", "true", "yes", "on")


def _bullets(block: str | None) -> list[str]:
    out: list[str] = []
    for line in (block or "").strip().splitlines():
        line = line.strip().lstrip("-•* ").strip()
        if not line or line.lower() in ("none", "none.", "n/a"):
            continue
        out.append(line)
    return out


def build_review_prompt(config: dict, activity: dict, tools: list[dict],
                        outcome: dict) -> str:
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

    return REVIEW_PROMPT.format(config_text=config_text, activity_text=activity_text,
                                tools_text=tools_text, outcome_text=outcome_text)


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
