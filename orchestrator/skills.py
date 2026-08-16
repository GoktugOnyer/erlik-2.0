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


# A mission names vulnerability CLASSES, but single-token overlap cannot tell
# them apart: "injection" matches ldap-, nosql-, os-command-, sql-, ssti-, xpath-
# and xxe-injection equally, so every one ties on (overlap, boost) and the winner
# is decided by alphabetical order and file size. A run whose mission asked for
# "injection, authentication and access-control" was handed an API Top-10
# overview and an OS-command-injection quickstart — no SQLi sheet, no XSS sheet,
# nothing on access control.
#
# Phrases are matched against the mission first, and each recognised class then
# contributes its own best file, so every class the operator named is represented.
_CLASS_PATTERNS: list[tuple[str, str, tuple[str, ...]]] = [
    # (class key, regex over the hint, filename tokens that satisfy it)
    ("sqli",        r"\bsql[i\b]|\bsql injection", ("sql-injection",)),
    ("nosql",       r"\bnosql", ("nosql-injection",)),
    ("xss",         r"\bxss\b|cross[- ]site scripting", ("xss", "dom-xss")),
    ("cmdi",        r"command injection|\brce\b|remote code exec", ("os-command-injection",)),
    ("ssti",        r"\bssti\b|template injection", ("ssti",)),
    ("xxe",         r"\bxxe\b|xml external", ("xxe",)),
    ("ldap",        r"\bldap\b", ("ldap-injection",)),
    ("path",        r"path traversal|\blfi\b|file inclusion|directory traversal",
                    ("file-inclusion", "path-traversal", "file-upload")),
    ("upload",      r"file upload|unrestricted upload", ("file-upload",)),
    ("deserialize", r"deserializ", ("deserialization",)),
    ("ssrf",        r"\bssrf\b|server[- ]side request", ("ssrf", "server-side")),
    ("csrf",        r"\bcsrf\b|cross[- ]site request", ("csrf",)),
    ("cors",        r"\bcors\b", ("cors",)),
    ("authn",       r"authentication|\bauthn\b|login|credential|brute[- ]force",
                    ("authentication-quickstart", "authentication-cheat-sheet")),
    ("jwt",         r"\bjwt\b|json web token", ("jwt",)),
    ("oauth",       r"\boauth\b", ("oauth",)),
    ("authz",       r"access[- ]control|\bidor\b|\bauthz\b|privilege|broken access",
                    ("access-control", "idor")),
    ("logic",       r"business logic|race condition", ("business-logic", "race-condition")),
    ("disclosure",  r"information disclosure|sensitive data|data exposure",
                    ("information-disclosure",)),
    ("recon",       r"reconnaissance|fingerprint|enumerat", ("reconnaissance",)),
    # Listed last so a specific class always wins first. A mission that says only
    # "injection" still deserves the canonical injection sheet rather than
    # nothing — previously it fell through to keyword overlap and landed on
    # whichever injection file sorted first alphabetically and happened to fit.
    ("injection_generic", r"\binjection\b", ("sql-injection", "injection-principles")),
]


def detect_classes(hint: str) -> list[str]:
    """Vulnerability classes explicitly named in the mission, in listed order."""
    text = (hint or "").lower()
    return [key for key, rx, _toks in _CLASS_PATTERNS if re.search(rx, text)]


def _class_candidates(cls: str, catalog: list[tuple[Path, set[str]]]) -> list[Path]:
    """Files whose NAME carries one of the class's tokens, action-oriented first."""
    toks = next(t for k, _rx, t in _CLASS_PATTERNS if k == cls)

    def matches(stem: str, tok: str) -> bool:
        # Anchor on a name boundary. A plain substring test made "sql-injection"
        # match "nosql-injection-quickstart", so asking for SQLi returned NoSQL.
        return stem == tok or stem.startswith(tok + "-") or ("-" + tok) in stem

    hits = [p for p, _ in catalog
            if any(matches(p.stem.lower(), tok) for tok in toks)
            # "<topic>-index.md" is navigation, not technique content. _catalog
            # already drops INDEX.md/SKILL.md but not these.
            and not p.stem.lower().endswith("-index")]
    return sorted(hits, key=lambda p: (-sum(b for kw, b in _BOOST if kw in p.name.lower()),
                                       str(p)))


def select_skill_files(hint: str, max_files: int = 3, max_chars: int = 14000,
                       tech: list[str] | None = None) -> list[Path]:
    """Return the highest-scoring reference files for a hint, budget-capped.

    Classes named in the mission are honoured first, one file each in the order
    named, so a three-class mission does not spend its whole budget inside one
    class. Whatever budget remains falls back to keyword overlap.

    `tech` accepts observed technologies (from a pre-scan or fingerprint) and is
    treated as additional query text, so a PHP target biases toward the sheets
    that matter for it.

    Empty list when nothing matches — we never dump unrelated skills.
    """
    query_text = " ".join(filter(None, [hint, " ".join(tech or [])]))
    q = _tokens(query_text)
    if not q:
        return []

    catalog = _catalog()
    chosen: list[Path] = []
    used = 0

    def _take(path: Path) -> bool:
        nonlocal used
        if path in chosen:
            return False
        size = path.stat().st_size
        if chosen and used + size > max_chars:
            return False          # skip; a later, smaller file may still fit
        chosen.append(path)
        used += size
        return True

    # 1. One file per class the mission actually named, in the order named, so a
    #    three-class mission is not answered with three files from one class.
    #    Each class gets a share of the budget: taking the best file for the
    #    first two classes greedily consumed 11 KB of 14 KB, leaving nothing that
    #    any injection sheet could fit into, so the third named class was dropped
    #    and a small unrelated file took the slot instead.
    classes = detect_classes(query_text)
    if classes:
        # Three classes cannot fit a 14 KB budget at this corpus's file sizes
        # (the smallest useful sheet per class is ~5-6 KB), so a three-class
        # mission always lost one. Widen modestly rather than silently drop a
        # class the operator explicitly asked for; a mission naming three areas
        # genuinely needs more context than one naming a single area.
        if len(classes) >= 3:
            max_chars = int(max_chars * 1.4)
        share = max_chars // min(len(classes), max_files)
        for cls in classes:
            if len(chosen) >= max_files:
                break
            cands = _class_candidates(cls, catalog)
            if not cands:
                continue
            # Best-ranked file within this class's share, else the smallest the
            # class has. Picking one explicitly matters: _take always accepts the
            # very first file regardless of size, so letting it iterate let class
            # one spend most of the budget and starve the rest.
            fits = [c for c in cands if c.stat().st_size <= share]
            _take(fits[0] if fits else min(cands, key=lambda p: p.stat().st_size))

    # 2. Fill any remaining budget by keyword overlap, as before.
    scored: list[tuple[int, int, Path]] = []
    for path, toks in catalog:
        overlap = len(q & toks)
        if overlap == 0:
            continue
        if path.stem.lower().endswith("-index"):
            continue          # navigation, not technique content
        name = path.name.lower()
        boost = sum(b for kw, b in _BOOST if kw in name)
        scored.append((overlap, boost, path))
    # Rank on topical overlap first; the action-oriented boost only orders files
    # that are equally relevant. Sorting on a combined sum let a +3 filename
    # bonus beat a genuinely better match.
    scored.sort(key=lambda x: (-x[0], -x[1], str(x[2])))

    for _overlap, _boost, path in scored:
        if len(chosen) >= max_files:
            break
        _take(path)
    return chosen


def render_skills(hint: str, max_chars: int = 14000,
                  tech: list[str] | None = None) -> str:
    """Compose the selected knowledge block for a hint — WITHOUT the
    ``ERLIK_SKILLS`` gate. Provider-agnostic: the result is plain text you can
    drop into the system prompt of ANY model or API (local Ollama, an
    OpenAI-compatible gateway, Anthropic, etc.). Returns "" when nothing matches.
    """
    files = select_skill_files(hint, max_chars=max_chars, tech=tech)
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


def get_skills_context(target_url: str, hint: str, max_chars: int = 14000,
                       tech: list[str] | None = None) -> str:
    """Composed knowledge block to inject into erlik's agent loop, or "" when
    disabled (ERLIK_SKILLS) / no match. Thin gate over ``render_skills``.
    """
    if not skills_enabled():
        return ""
    return render_skills(hint, max_chars=max_chars, tech=tech)


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
