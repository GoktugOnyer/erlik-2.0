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

# Largest slice of any ONE file that may be injected. The vendored Claude-BugHunter
# sheets have a median size of 16.5 KB and 60 of 101 exceed the whole 14 KB budget
# — hunt-xss alone is 30 KB — so without an excerpt cap the most valuable files are
# never selectable at all, and the budget logic silently prefers small reference
# prose over step-by-step methodology.
#
# Excerpting rather than raising the budget is deliberate: a measured 12-run
# experiment found injected volume is inversely correlated with recall on a local
# 7B (0.171 -> 0.095, r = -0.796). Total injected bytes must NOT grow. These files
# lead with the actionable part (What actually pays -> Crown Jewel Targets ->
# Attack Surface Signals -> Phase 1 …), so the head is the part worth keeping.
MAX_FILE_EXCERPT = 7000

# Default character budget for injected guidance.
#
# Was 14,000. Lowered on measurement: a dose-response run on a 7B varied ONLY
# this value, with the sheets accumulating additively, and recall fell
# monotonically with every sheet added —
#
#     0 chars (none)      recall 0.1429
#     6,452  (1 sheet)           0.0857
#    11,496  (2 sheets)          0.0714
#    18,166  (3 sheets)          0.0428
#
# The dose is reduced by DEFAULT_SKILLS_FILES below, NOT by shrinking this.
# Lowering the budget looked equivalent and is not: the per-class share is
# `max_chars // min(len(classes), max_files)`, so a small budget starves the
# share and the router falls back to a lower-ranked sheet that fits. Measured:
#
#     hint "idor"  budget=2000 -> access-control-resources   (generic)
#                  max_files=1 -> hunt-idor                  (the right sheet)
#     hint "ssrf"  budget=2000 -> server-side-principles
#                  max_files=1 -> hunt-ssrf
#
# Both deliver ~6.5 KB. Capping the FILE COUNT gives the same volume without
# degrading which sheet is chosen, so the budget stays where it was.
DEFAULT_SKILLS_BUDGET = 14000

# Sheets injected per run. Was 3.
#
# A dose-response run on a 7B varied injected volume only, with sheets
# accumulating additively, and recall fell monotonically with every sheet:
#
#     0 chars (none)      recall 0.1429
#     6,452  (1 sheet)           0.0857
#    11,496  (2 sheets)          0.0714
#    18,166  (3 sheets)          0.0428
#
# One sheet halves the damage relative to three. See
# docs/CONTEXT_ALLOCATION_EXPERIMENT.md.
#
# It is NOT a win: every guided arm still scored below injecting nothing. This
# is damage limitation, and the honest default for the lever would arguably be
# off — but that is a behaviour change for operators who rely on it, so the
# dose drops and the on/off decision stays with the run config.
#
# CAVEAT: the measured arm used budget=2000, which selects one sheet BY
# STARVATION and therefore a worse one. This configuration delivers the same
# volume with a better-targeted sheet, so it should be at least as good — but
# that exact inference is not itself measured.
DEFAULT_SKILLS_FILES = 1

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
# "hunt-" ranks with quickstart because those files ARE the action-oriented form
# this boost exists to reward: each is a step-by-step methodology with real
# commands (Attack Surface Signals -> Phase 1 -> Phase 2 …), where "-principles"
# and "-resources" are reference prose. Without an entry here every vendored
# hunt-* file scored boost 0 and lost to the older corpus on every tie, leaving
# 100 newly-vendored files effectively unreachable.
_BOOST = (("quickstart", 3), ("hunt-", 3), ("cheat-sheet", 2),
          ("advanced", 1), ("principles", 1))

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


# Licence by corpus directory. The licence of a file must be answerable from
# its PATH — that is why the vendored corpora live in separate directories in
# the first place (see skills_catalog/skills/bughunter/NOTICE.md).
#
# Before this existed, render_skills stamped one blanket line above every
# selection: "Source: transilienceai/communitytools (MIT)." Since the BugHunter
# import that header sat above 100 CC BY 4.0 sheets, so the text erlik fed the
# model — and anything derived from it — misattributed the work AND asserted a
# licence that does not apply. CC BY 4.0 requires attribution; a blanket MIT
# line is not it.
_LICENCES = {
    "bughunter": "CC BY 4.0 — elementalsouls/Claude-BugHunter",
}
_DEFAULT_LICENCE = "MIT — transilienceai/communitytools"
UNKNOWN_LICENCE = "UNKNOWN — provenance not recorded"


def _roots() -> list[Path]:
    """Corpus roots, in RANK ORDER. Vendored first, operator-authored second.

    Zone rank is structural, not a tiebreak: an authored sheet must never
    displace a vetted one just by sorting earlier. See _catalog().
    """
    from orchestrator import skills_authoring as _sa
    return [SKILLS_ROOT, _sa.local_root()]


def root_of(path: Path) -> Path | None:
    p = Path(path).resolve()
    for r in _roots():
        try:
            if p.is_relative_to(r.resolve()):
                return r
        except OSError:
            continue
    return None


def rel_of(path: Path) -> Path:
    """Path relative to whichever root owns it.

    Replaces bare `relative_to(SKILLS_ROOT)`, which raises for an authored file
    and would 500 every caller the moment the second root has anything in it.
    """
    r = root_of(path)
    return Path(path).resolve().relative_to(r.resolve()) if r else Path(path).name


def license_of(path: Path) -> str:
    """Licence string for a corpus file, keyed on its top-level directory.

    An unrecognised directory returns UNKNOWN rather than the MIT default: a
    new corpus dropped in without a licence entry must be visibly unattributed,
    never silently relabelled as MIT.
    """
    from orchestrator import skills_authoring as _sa
    p = Path(path)
    try:
        if p.resolve().is_relative_to(_sa.local_root().resolve()):
            return "operator-authored — no third-party licence"
    except OSError:
        pass
    try:
        rel = p.resolve().relative_to(SKILLS_ROOT.resolve())
    except (ValueError, OSError):
        return UNKNOWN_LICENCE
    top = rel.parts[0] if rel.parts else ""
    if top in _LICENCES:
        return _LICENCES[top]
    known_mit = {"api-security", "authentication", "client-side", "injection",
                 "reconnaissance", "server-side", "web-app-logic"}
    return _DEFAULT_LICENCE if top in known_mit else UNKNOWN_LICENCE


def _catalog() -> list[tuple[Path, set[str]]]:
    """All corpus files with the tokens derived from their skill + filename."""
    files: list[tuple[Path, set[str]]] = []
    # Rank order matters and is structural: every vendored sheet is appended
    # before any authored one, so an operator file can only ever be chosen when
    # it genuinely out-ranks the corpus, never by sorting earlier in a tie.
    for root in _roots():
        if not root.exists():
            continue
        for p in sorted(root.rglob("*.md")):
            if p.name in ("NOTICE.md", "INDEX.md", "SKILL.md"):
                continue
            rel = p.relative_to(root)
            parent = rel.parent.name if rel.parent.name != "." else "local"
            files.append((p, _tokens(f"{parent} {p.stem}")))
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
    # Tokens must name sheets that EXIST. "file-inclusion" and "path-traversal"
    # named nothing in the corpus, so the only token that ever matched was
    # "file-upload" — borrowed from the class below — and every LFI / traversal
    # mission was answered with hunt-file-upload.md while hunt-lfi.md (16 KB, the
    # canonical sheet: filter-chain RCE, log poisoning, wrappers, RFI) could not
    # be selected by any mission. _class_candidates ranks on (boost, path), NOT on
    # token order, so an aspirational token cannot sit in front of a live one as a
    # preference: hunt-file-upload.md sorts before hunt-lfi.md and would keep
    # winning. test_every_class_token_names_a_real_sheet holds the line.
    ("path",        r"path traversal|\blfi\b|file inclusion|directory traversal",
                    ("lfi",)),
    # Hop-by-hop header handling and request splitting are the same family, and
    # WSTG-INPV-15 was filed under `path` — a class labelled "Path Traversal /
    # File Inclusion" — purely because nothing else claimed it. Two sheets
    # already exist for this, so the routing has somewhere real to go.
    ("smuggling",   r"request smuggl|http splitting|hop[- ]by[- ]hop|desync",
                    ("http-smuggling", "http-request-smuggling")),
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


def catalog_stems() -> set[str]:
    """Every selectable sheet's filename. The allowlist for pin/exclude."""
    return {p.name for p, _ in _catalog()}


def _resolve_refs(refs, kind: str) -> tuple[list[str], list[str]]:
    """Split operator-supplied sheet names into (valid, warnings).

    Constrained to CATALOGUE MEMBERS, never free paths: a pin is a
    guaranteed-injection primitive, so it must not be able to name anything the
    router could not already have chosen. An unknown name WARNS rather than
    failing the run — a stale pin from an old preset should not stop a scan —
    but it is never silently ignored, which is how a knob comes to look like it
    works while doing nothing.
    """
    known = catalog_stems()
    ok, warn = [], []
    for raw in (refs or []):
        name = str(raw).strip()
        if not name:
            continue
        if "/" in name or "\\" in name or ".." in name:
            warn.append(f"{kind} {name!r} rejected: names a path, not a sheet")
            continue
        if not name.endswith(".md"):
            name += ".md"
        if name in known:
            ok.append(name)
        else:
            warn.append(f"{kind} {name!r} matches no sheet in the corpus")
    return ok, warn


def select_skill_files(hint: str, max_files: int = DEFAULT_SKILLS_FILES,
                       max_chars: int = DEFAULT_SKILLS_BUDGET,
                       tech: list[str] | None = None,
                       exclude: list[str] | None = None,
                       pin: list[str] | None = None) -> list[Path]:
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
    excluded, _ = _resolve_refs(exclude, "exclude")
    if excluded:
        catalog = [(p, t) for p, t in catalog if p.name not in set(excluded)]
    chosen: list[Path] = []
    used = 0

    def _take_pins() -> None:
        """Pinned sheets are taken before anything else and DO consume budget.

        Exempting them would let a pin quietly raise injected volume above the
        stated cap, which is the one number an operator must be able to trust.
        """
        pinned, _ = _resolve_refs(pin, "pin")
        by_name = {p.name: p for p, _ in catalog}
        for name in pinned:
            if name in by_name:
                _take(by_name[name])

    def _take(path: Path) -> bool:
        nonlocal used
        if path in chosen:
            return False
        size = min(path.stat().st_size, MAX_FILE_EXCERPT)
        if chosen and used + size > max_chars:
            return False          # skip; a later, smaller file may still fit
        chosen.append(path)
        used += size
        return True

    # 0. Operator pins first — an explicit "always send this" outranks routing.
    _take_pins()

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
            fits = [c for c in cands if min(c.stat().st_size, MAX_FILE_EXCERPT) <= share]
            _take(fits[0] if fits else min(
                cands, key=lambda p: min(p.stat().st_size, MAX_FILE_EXCERPT)))

    # 2. Fill any remaining budget by keyword overlap, as before.
    scored: list[tuple[int, int, int, Path]] = []
    for path, toks in catalog:
        overlap = len(q & toks)
        if overlap == 0:
            continue
        if path.stem.lower().endswith("-index"):
            continue          # navigation, not technique content
        name = path.name.lower()
        boost = sum(b for kw, b in _BOOST if kw in name)
        # Tokens the mission did NOT ask for. A sheet named exactly for the
        # subject carries none; a sub-module of that subject carries one per
        # extra name segment, and is a looser answer to the question asked.
        scored.append((overlap, boost, len(toks) - overlap, path))
    # Rank on topical overlap first; the action-oriented boost only orders files
    # that are equally relevant. Sorting on a combined sum let a +3 filename
    # bonus beat a genuinely better match.
    #
    # Specificity breaks the remaining ties, ahead of the alphabet. It has to:
    # a parent sheet and its sub-modules all match the same tokens with the same
    # boost, and "-" sorts before "." — so every "<subject>-<module>.md" sorted
    # in front of "<subject>.md" and the parent could never be reached. That made
    # bughunter/offensive-osint.md (34 KB, the arsenal itself) rank 17 of 100 for
    # its OWN subject, behind all 16 of its sub-modules, and therefore dead at
    # every realistic file cap. Same defect class as the LFI mis-route above:
    # a sheet in the catalogue that no mission can select.
    scored.sort(key=lambda x: (-x[0], -x[1], x[2], str(x[3])))

    for _overlap, _boost, _extra, path in scored:
        if len(chosen) >= max_files:
            break
        _take(path)
    return chosen


def plan_skills(hint: str, max_chars: int = DEFAULT_SKILLS_BUDGET,
                exclude: list[str] | None = None, pin: list[str] | None = None,
                tech: list[str] | None = None,
                max_files: int = DEFAULT_SKILLS_FILES) -> tuple[list[Path], dict]:
    """Select sheets AND record why, in one pass.

    Returns (files, plan). The plan is what actually happened — not a
    re-derivation. Anything that asks "which sheets did this run receive?"
    later must read this, because calling the selector again answers a
    different question: the corpus is now writable, so a second call can return
    a different answer than the run got.

    The plan carries a sha256 of the rendered block, so a claim about what a
    session received can be checked against the text that was really appended
    to its system prompt rather than trusted.
    """
    files = select_skill_files(hint, max_files=max_files, max_chars=max_chars,
                               tech=tech, exclude=exclude, pin=pin)
    entries = []
    for f in files:
        size = f.stat().st_size
        entries.append({
            "path": str(rel_of(f)),
            "name": f.name,
            "stem": f.stem,
            "licence": license_of(f),
            "root": "local" if root_of(f) != SKILLS_ROOT else "corpus",
            "file_bytes": size,
            "injected_bytes": min(size, MAX_FILE_EXCERPT),
            "excerpted": size > MAX_FILE_EXCERPT,
        })
    plan = {
        "hint": (hint or "")[:400],
        "classes": sorted(detect_classes(hint or "")),
        "max_chars": max_chars,
        "max_files": max_files,
        "exclude": list(exclude or []),
        "pin": list(pin or []),
        "tech": list(tech or []),
        "selected": entries,
        "injected_total": sum(e["injected_bytes"] for e in entries),
    }
    return files, plan


def render_plan(files: list[Path]) -> str:
    """Render an ALREADY-SELECTED list of sheets into the knowledge block.

    Split out of render_skills so the text a run receives and the trace
    recorded about it come from ONE selection. Selecting twice — once to render,
    once to explain — is a re-derivation racing a now-writable corpus, and the
    two can legitimately disagree.
    """
    if not files:
        return ""
    header = (
        "═══════════════════════════════════════════════════════════════\n"
        "RELEVANT PENTEST KNOWLEDGE (auto-selected for this mission)\n"
        "═══════════════════════════════════════════════════════════════\n"
        "Reference material for the vulnerability classes most relevant here.\n"
        "Use the payloads/techniques as a guide; adapt them to the real target.\n"
        "Each sheet below carries its own source and licence.\n"
    )
    parts = [header]
    for p in files:
        rel = rel_of(p)
        body = p.read_text(encoding="utf-8", errors="replace").strip()
        excerpted = len(body) > MAX_FILE_EXCERPT
        if excerpted:
            body = (body[:MAX_FILE_EXCERPT].rsplit("\n", 1)[0]
                    + "\n…(excerpt — this sheet continues beyond what fits the budget)")
        parts.append(
            f"\n----- skill: {rel.parent.name if rel.parent.name != '.' else 'local'} / {p.stem}"
            f"  [{license_of(p)}]{' (EXCERPTED)' if excerpted else ''} -----\n{body}")
    return "\n".join(parts) + "\n"


def render_skills(hint: str, max_chars: int = DEFAULT_SKILLS_BUDGET,
                  exclude: list[str] | None = None, pin: list[str] | None = None,
                  tech: list[str] | None = None) -> str:
    """Compose the selected knowledge block for a hint — WITHOUT the
    ``ERLIK_SKILLS`` gate. Provider-agnostic: the result is plain text you can
    drop into the system prompt of ANY model or API (local Ollama, an
    OpenAI-compatible gateway, Anthropic, etc.). Returns "" when nothing matches.

    Thin wrapper over plan_skills + render_plan, kept for callers that do not
    need the trace.
    """
    files, _plan = plan_skills(hint, max_chars=max_chars, tech=tech,
                               exclude=exclude, pin=pin)
    return render_plan(files)


def get_skills_context(target_url: str, hint: str, max_chars: int = DEFAULT_SKILLS_BUDGET,
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
    ap.add_argument("--max-chars", type=int, default=DEFAULT_SKILLS_BUDGET)
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
