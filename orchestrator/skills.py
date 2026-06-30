"""Skill knowledge-library selector (Phase 3).

Loads the vendored pentest knowledge corpus under ``skills_catalog/`` and
selects 1-3 of the most relevant reference files for a session — by its
``vuln_category`` preset + mission text — to inject into the agent loop's
system prompt. This generalises erlik off the Juice-Shop-only
``playbooks.py``: it works against any target and any vuln class in the corpus.

Discipline mirrors the upstream "router picks 1-2, never load all": selection
is keyword-scored and hard-capped by a character budget.

Gated by ``ERLIK_SKILLS`` (default off): unset / "" → disabled.

Corpus vendored from transilienceai/communitytools (MIT); see
``skills_catalog/NOTICE.md`` and ``THIRD_PARTY_LICENSES.md``.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

SKILLS_ROOT = Path(__file__).resolve().parents[1] / "skills_catalog"

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

# Action-oriented reference files get a relevance boost.
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
        if p.name in ("NOTICE.md", "INDEX.md"):
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
    scored: list[tuple[int, Path]] = []
    for path, toks in _catalog():
        overlap = len(q & toks)
        if overlap == 0:
            continue
        score = overlap
        name = path.name.lower()
        for kw, boost in _BOOST:
            if kw in name:
                score += boost
        scored.append((score, path))
    scored.sort(key=lambda x: (-x[0], str(x[1])))

    chosen: list[Path] = []
    used = 0
    for _score, path in scored:
        size = path.stat().st_size
        if chosen and used + size > max_chars:
            break
        chosen.append(path)
        used += size
        if len(chosen) >= max_files:
            break
    return chosen


def get_skills_context(target_url: str, hint: str, max_chars: int = 14000) -> str:
    """Composed knowledge block to inject, or "" when disabled / no match."""
    if not skills_enabled():
        return ""
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
