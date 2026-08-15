"""Environment-aware technique router over the HackTricks-derived index.

Where ``skills.py`` routes on a vuln-class hint, this routes on what the target
actually IS: the open ports and technologies a pre-scan found. A detected 27017
pulls MongoDB techniques; a detected 6379 pulls Redis. That makes the injected
knowledge specific to the environment under test rather than to the mission text.

TWO-TIER BY LICENCE
-------------------
``techniques_catalog/index.yaml`` is committed and contains only facts —
environment, ports, title, routing tags, citation URL. HackTricks is CC BY-NC 4.0
and erlik is MIT, so its prose is never vendored here (see
scripts/build_techniques_index.py for the full reasoning).

The body text is read at run time from the reader's OWN clone, located via
``ERLIK_HACKTRICKS_PATH``. With the clone present the agent gets full technique
detail; without it, it still gets titles and citation URLs, which is the
MIT-safe subset and remains useful. Nothing is redistributed either way.

Gated by the per-session run config (``techniques``) / ERLIK_TECHNIQUES.
"""

from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path

INDEX_PATH = Path(__file__).resolve().parents[1] / "techniques_catalog" / "index.yaml"

# mdbook directives and HackTricks' sponsor banners — not technique content.
_STRIP_RX = re.compile(r"\{\{#include[^}]*\}\}|\{\{#ref[^}]*\}\}|\{\{#endref\}\}")

_STOP = {
    "the", "and", "for", "with", "test", "testing", "mission", "target",
    "pentesting", "http", "https", "www", "com", "assessment", "scan",
}


def techniques_enabled() -> bool:
    """True when technique injection is opted in via ERLIK_TECHNIQUES."""
    return os.environ.get("ERLIK_TECHNIQUES", "").strip().lower() in ("1", "true", "yes", "on")


def hacktricks_root() -> Path | None:
    """The reader's local HackTricks clone, or None when unset/absent.

    Never bundled — this is why the index carries no prose.
    """
    raw = os.environ.get("ERLIK_HACKTRICKS_PATH", "").strip()
    if not raw:
        return None
    root = Path(raw).expanduser()
    src = root / "src"
    return src if src.is_dir() else None


@lru_cache(maxsize=1)
def load_index() -> list[dict]:
    """Parse the committed index. Returns [] when it is missing or unreadable."""
    try:
        import yaml
        with INDEX_PATH.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        out = data.get("techniques") or []
        return out if isinstance(out, list) else []
    except Exception as e:  # noqa: BLE001
        print(f"[techniques] index unavailable (non-fatal): {e}", flush=True)
        return []


def _tokens(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9+]+", (text or "").lower())
            if len(t) > 1 and t not in _STOP}


def select_techniques(open_ports: list[int] | None = None,
                      tech: list[str] | None = None,
                      hint: str = "",
                      environments: list[str] | None = None,
                      max_items: int = 6) -> list[dict]:
    """Techniques relevant to an observed environment, strongest signal first.

    Ranked on an ordered tuple (port match, tag overlap) rather than a summed
    score, so a weak tag overlap can never outrank an exact port hit — the same
    defect that made the skills router pick client-side sheets for an SSRF hint.
    """
    index = load_index()
    if not index:
        return []

    ports = {int(p) for p in (open_ports or []) if str(p).isdigit()}
    q = _tokens(" ".join(tech or [])) | _tokens(hint)
    envs = set(environments or [])

    scored: list[tuple[int, int, str, dict]] = []
    for t in index:
        if envs and t.get("env") not in envs:
            continue
        port_hit = 1 if ports and set(t.get("ports") or []) & ports else 0
        overlap = len(q & set(t.get("tags") or [])) if q else 0
        if not port_hit and not overlap:
            continue
        scored.append((port_hit, overlap, str(t.get("id") or ""), t))

    # port hit, then tag overlap, then id for a stable order
    scored.sort(key=lambda x: (-x[0], -x[1], x[2]))
    return [t for _p, _o, _i, t in scored[:max_items]]


def read_technique_body(technique: dict, max_chars: int = 6000) -> str:
    """Body text for one technique from the local clone, or "" without one."""
    root = hacktricks_root()
    if not root or not technique.get("path"):
        return ""
    path = root / str(technique["path"])
    try:
        if not path.is_file():
            return ""
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""
    text = _STRIP_RX.sub("", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    if len(text) > max_chars:
        text = text[:max_chars].rsplit("\n", 1)[0] + "\n…(truncated)"
    return text


def render_techniques(open_ports: list[int] | None = None,
                      tech: list[str] | None = None,
                      hint: str = "",
                      environments: list[str] | None = None,
                      max_items: int = 6,
                      max_chars: int = 12000) -> str:
    """Composed technique block for the agent's system prompt.

    With a local clone: titles plus body text, budget-capped. Without one: the
    citation list alone, which is the MIT-safe subset and still tells the agent
    what is worth trying against this environment.
    """
    picked = select_techniques(open_ports, tech, hint, environments, max_items)
    if not picked:
        return ""

    have_clone = hacktricks_root() is not None
    head = [
        "═══════════════════════════════════════════════════════════════",
        "ENVIRONMENT-SPECIFIC TECHNIQUES (matched to this target)",
        "═══════════════════════════════════════════════════════════════",
        "Selected from the observed ports/technologies of THIS target — not",
        "generic advice. Adapt every payload to what you actually see.",
        "Source: HackTricks by Carlos Polop (CC BY-NC 4.0) — "
        "https://github.com/carlospolop/hacktricks",
    ]
    if not have_clone:
        head.append("(Local corpus not configured — citations only. Set "
                    "ERLIK_HACKTRICKS_PATH for full technique text.)")
    parts = ["\n".join(head)]

    used = 0
    for t in picked:
        ports = ", ".join(str(p) for p in (t.get("ports") or [])) or "—"
        header = (f"\n----- technique: {t.get('title')} "
                  f"[env={t.get('env')} ports={ports}]\n{t.get('source')}")
        body = read_technique_body(t) if have_clone else ""
        chunk = f"{header}\n{body}" if body else header
        # Skip an oversized entry rather than abandoning the rest of the budget.
        if used and used + len(chunk) > max_chars:
            continue
        parts.append(chunk)
        used += len(chunk)
    return "\n".join(parts) + "\n"


def get_techniques_context(open_ports: list[int] | None = None,
                           tech: list[str] | None = None,
                           hint: str = "",
                           environments: list[str] | None = None,
                           max_chars: int = 12000) -> str:
    """Gated entry point for the agent loop. "" when disabled or nothing matches."""
    if not techniques_enabled():
        return ""
    return render_techniques(open_ports, tech, hint, environments,
                             max_chars=max_chars)


def _cli(argv: list[str] | None = None) -> int:
    """Inspect routing without running a session.

        python -m orchestrator.techniques --ports 27017 6379
        python -m orchestrator.techniques --tech nginx --hint ssrf --list
    """
    import argparse

    ap = argparse.ArgumentParser(
        prog="orchestrator.techniques",
        description="Show which techniques an observed environment selects.")
    ap.add_argument("--ports", nargs="*", type=int, default=[])
    ap.add_argument("--tech", nargs="*", default=[])
    ap.add_argument("--hint", default="")
    ap.add_argument("--env", nargs="*", default=None, help="restrict to environments")
    ap.add_argument("--max-items", type=int, default=6)
    ap.add_argument("--list", action="store_true", help="titles only")
    ns = ap.parse_args(argv)

    picked = select_techniques(ns.ports, ns.tech, ns.hint, ns.env, ns.max_items)
    if not picked:
        print("(no technique matched)")
        return 1
    if ns.list:
        for t in picked:
            ports = ",".join(str(p) for p in (t.get("ports") or [])) or "-"
            print(f"{t['env']:<9} {ports:<16} {t['title']}")
            print(f"{'':<26} {t['source']}")
        return 0
    print(render_techniques(ns.ports, ns.tech, ns.hint, ns.env, ns.max_items))
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
