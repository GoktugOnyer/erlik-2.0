"""Skill knowledge-library selector (Phase 3).

Loads the vendored pentest knowledge corpus under ``skills_catalog/`` and
selects 1-3 of the most relevant reference files for a session — by its
``vuln_category`` preset + mission text — to inject into the agent loop's
system prompt. This generalises erlik off the Juice-Shop-only
``playbooks.py``: it works against any target and any vuln class in the corpus.

Discipline mirrors the upstream "router picks 1-2, never load all": selection
is keyword-scored and hard-capped by a character budget.

Inside erlik this is gated by ``ERLIK_SKILLS`` (default off). The selection +
composition logic is provider-agnostic, though: ``render_skills()`` and the
``python -m orchestrator.skills`` CLI return plain text usable with ANY model
or API (Ollama, OpenAI-compatible gateways, Anthropic, …), not just erlik.

Corpus vendored from transilienceai/communitytools (MIT); see
``skills_catalog/NOTICE.md`` and ``THIRD_PARTY_LICENSES.md``.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

SKILLS_ROOT = Path(__file__).resolve().parents[1] / "skills_catalog" / "skills"

# Expand erlik's short vuln-category / jargon tokens into the corpus vocabulary
# so a preset like "sqli_focused" matches the sql-injection references.
ALIASES = {
    "sqli": ["sql", "injection"],
    "sql": ["injection"],
    "nosql": ["injection"],
    "xss": ["dom", "client"],
    "csrf": ["client"],
    "idor": ["access", "control", "logic"],
    "auth": ["authentication", "jwt", "oauth"],
    "authn": ["authentication"],
    "authz": ["access", "control"],
    "jwt": ["authentication"],
    "oauth": ["authentication"],
    "ssrf": ["server", "side"],
    "xxe": ["injection"],
    "rce": ["command", "injection", "ssti"],
    "ssti": ["injection"],
    "lfi": ["file", "server"],
    "upload": ["file", "server"],
    "cors": ["client"],
    "recon": ["reconnaissance"],
    "api": ["graphql", "websockets"],
    "logic": ["access", "business"],
    "owasp": ["injection", "authentication", "access"],
}

# Action-oriented reference files are preferred, but ONLY as a tie-breaker
# between files of equal topical relevance — never as a way to outrank a file
# that matched more query tokens. Category directories share tokens ("client-side"
# and "server-side" both yield "side"), so letting a filename-shape bonus
# outweigh real overlap made e.g. an "ssrf" hint select client-side quickstarts.
_BOOST = (("quickstart", 3), ("cheat-sheet", 2), ("advanced", 1), ("principles", 1))

_STOP = {
    "the", "and", "for", "with", "mission", "test", "testing", "focused",
    "suite", "all", "types", "general", "assessment", "top", "guided", "lab",
    "hunt", "control", "access",  # kept as expansions, too noisy as raw query terms
}


def skills_enabled() -> bool:
    """True when skill-library injection is opted in via ERLIK_SKILLS."""
    return os.environ.get("ERLIK_SKILLS", "").strip().lower() in ("1", "true", "yes", "on")


def _tokens(text: str) -> set[str]:
    out: set[str] = set()
    for t in re.split(r"[^a-z0-9]+", (text or "").lower()):
        if not t or len(t) < 2:
            continue
        for exp in ALIASES.get(t, []):
            out.add(exp)
        if t in _STOP:
            continue
        out.add(t)
    return out


def _catalog() -> list[tuple[Path, set[str]]]:
    """All corpus files with the tokens derived from their skill + filename."""
    if not SKILLS_ROOT.exists():
        return []
    files: list[tuple[Path, set[str]]] = []
    for p in sorted(SKILLS_ROOT.rglob("*.md")):
        if p.name in ("NOTICE.md", "INDEX.md", "SKILL.md"):
            continue
        rel = p.relative_to(SKILLS_ROOT)
        files.append((p, _tokens(f"{rel.parent.name} {p.stem}")))
    return files


def select_skill_files(hint: str, max_files: int = 3, max_chars: int = 14000) -> list[Path]:
    """Return the highest-scoring reference files for a hint, budget-capped.

    Empty list when the hint matches nothing — we never dump unrelated skills.
    """
    q = _tokens(hint)
    if not q:
        return []
    scored: list[tuple[int, int, Path]] = []
    for path, toks in _catalog():
        overlap = len(q & toks)
        if overlap == 0:
            continue
        name = path.name.lower()
        boost = sum(b for kw, b in _BOOST if kw in name)
        scored.append((overlap, boost, path))
    # Rank on topical overlap first; the action-oriented boost only orders files
    # that are equally relevant. Sorting on a combined sum let a +3 filename
    # bonus beat a genuinely better match.
    scored.sort(key=lambda x: (-x[0], -x[1], str(x[2])))

    chosen: list[Path] = []
    used = 0
    for _overlap, _boost, path in scored:
        size = path.stat().st_size
        if chosen and used + size > max_chars:
            # Skip this one — a later, smaller file may still fit. Breaking here
            # abandoned the remaining budget entirely (an oversized rank-2 file
            # truncated the selection to a single skill).
            continue
        chosen.append(path)
        used += size
        if len(chosen) >= max_files:
            break
    return chosen


def render_skills(hint: str, max_chars: int = 14000) -> str:
    """Compose the selected knowledge block for a hint — WITHOUT the
    ``ERLIK_SKILLS`` gate. Provider-agnostic: the result is plain text you can
    drop into the system prompt of ANY model or API (local Ollama, an
    OpenAI-compatible gateway, Anthropic, etc.). Returns "" when nothing matches.
    """
    files = select_skill_files(hint, max_chars=max_chars)
    if not files:
        return ""
    header = (
        "═══════════════════════════════════════════════════════════════\n"
        "RELEVANT PENTEST KNOWLEDGE (auto-selected for this mission)\n"
        "═══════════════════════════════════════════════════════════════\n"
        "Reference material for the vulnerability classes most relevant here.\n"
        "Use the payloads/techniques as a guide; adapt them to the real target.\n"
        "Source: transilienceai/communitytools (MIT).\n"
    )
    parts = [header]
    for p in files:
        rel = p.relative_to(SKILLS_ROOT)
        body = p.read_text(encoding="utf-8", errors="replace").strip()
        parts.append(f"\n----- skill: {rel.parent.name} / {p.stem} -----\n{body}")
    return "\n".join(parts) + "\n"


def get_skills_context(target_url: str, hint: str, max_chars: int = 14000) -> str:
    """Composed knowledge block to inject into erlik's agent loop, or "" when
    disabled (ERLIK_SKILLS) / no match. Thin gate over ``render_skills``.
    """
    if not skills_enabled():
        return ""
    return render_skills(hint, max_chars=max_chars)


def _cli(argv: list[str] | None = None) -> int:
    """Standalone selector so the corpus is usable outside erlik, with any model.

        python -m orchestrator.skills "sql injection"        # print context
        python -m orchestrator.skills --files "jwt auth"     # just the paths
    """
    import argparse

    ap = argparse.ArgumentParser(
        prog="orchestrator.skills",
        description="Select and print relevant pentest skill knowledge for a hint "
                    "(model-agnostic — pipe into any model/API system prompt).",
    )
    ap.add_argument("hint", nargs="+", help="vuln class / mission keywords, e.g. 'sql injection'")
    ap.add_argument("--max-chars", type=int, default=14000)
    ap.add_argument("--files", action="store_true", help="print only the selected file paths")
    ns = ap.parse_args(argv)
    hint = " ".join(ns.hint)
    if ns.files:
        for p in select_skill_files(hint, max_files=3, max_chars=ns.max_chars):
            print(p.relative_to(SKILLS_ROOT))
        return 0
    out = render_skills(hint, max_chars=ns.max_chars)
    if out:
        print(out)
        return 0
    print(f"(no skill matched hint: {hint!r})")
    return 1


if __name__ == "__main__":
    raise SystemExit(_cli())
