#!/usr/bin/env python3
"""Tool-usage comparison: fine-tuned vs untuned (from the steps table).

Answers 'did fine-tuning make the model run tools less, more, or about the
same — and did it change WHICH tools and HOW it drives them?' — questions the
committed figures cannot, because per-invocation data lives only in the `steps`
table of the (gitignored) pentest.db.

For a baseline and a fine-tuned model it reports, per model:
  * sessions, total tool calls, and CALLS PER SESSION (the decrease/same answer)
  * distinct tools used, and the per-tool call distribution
  * average call duration, and denied-step rate when the schema records it
and, from the `tool_input` command strings (the "approach"):
  * endpoints probed (path, numeric ids folded to /{n})
  * CLI flags used
  * technique markers (idor/object, manual-sqli, xss, traversal, auth, write)
  * command repetition and average command length
Sessions with zero steps still count in the per-session denominator, so an
Instruct-style zero-tool collapse shows as a low calls/session, not as a gap.

Nothing about ground-truth scoring is involved; this reads only `sessions` and
`steps`. Schema (docs/METHODOLOGY.md): steps(session_id, phase, step_number,
tool_called, tool_input, duration_ms, ...); a `denied` column, used by some
builds, is auto-detected.

Usage
-----
    python scripts/tool_usage_ft_vs_base.py data/pentest.db \
        --base qwen2.5-coder:7b --ft qwen2.5-coder:7b-juicy3

    python scripts/tool_usage_ft_vs_base.py \
        --base-db runs/2026-04-17_00-07-23/pentest.db --base qwen2.5-coder:7b \
        --ft-db   runs/2026-04-17_19-24-01/pentest.db --ft   qwen2.5-coder:7b-juicy3

    ... --kind cold      # restrict to one session kind (default: all kinds)
    ... --top 20         # rows in the per-tool / endpoint / flag tables (default 15)
    ... --no-commands    # skip the tool_input (approach) profile
    ... --json out.json  # also write the comparison as JSON
"""
import argparse
import json
import re
import sqlite3
import sys
from collections import Counter
from pathlib import Path

# ── tool_input parsing (heuristic, but identical for both models so comparable) ──
_URL_RE = re.compile(r"https?://[^\s\"'|>]+", re.I)
_FLAG_RE = re.compile(r"(?<![\w-])(--?[A-Za-z][\w-]*)")
_NUM_SEG = re.compile(r"/\d+(?=/|$|\?|\")")
_TECHNIQUES = {
    "idor/object":    re.compile(r"/api/|\?id=|userid=|/rest/basket", re.I),
    "manual-sqli":    re.compile(r"union\s+select|'\s*or\b|\b1=1\b|sleep\(|'\s*--|%27", re.I),
    "xss-payload":    re.compile(r"<script|onerror=|javascript:|alert\(", re.I),
    "path-traversal": re.compile(r"\.\./|\.\.%2f", re.I),
    "auth-probe":     re.compile(r"authorization:|bearer |/login|password", re.I),
    "write/POST":     re.compile(r"-x\s*post|--data|\bput\b|(?<!\w)-d\s", re.I),
}


def _endpoint(cmd: str):
    m = _URL_RE.search(cmd)
    if not m:
        return None
    after = m.group(0).split("://", 1)[-1]
    path = ("/" + after.split("/", 1)[1]) if "/" in after else "/"
    path = path.split("?", 1)[0].split("#", 1)[0].rstrip("\"'`,);")
    return _NUM_SEG.sub("/{n}", path) or "/"


def _profile(inputs: list[str]) -> dict:
    endpoints: Counter = Counter()
    flags: Counter = Counter()
    techniques: Counter = Counter()
    for cmd in inputs:
        ep = _endpoint(cmd)
        if ep:
            endpoints[ep] += 1
        for fl in _FLAG_RE.findall(cmd):
            flags[fl] += 1
        for name, rx in _TECHNIQUES.items():
            if rx.search(cmd):
                techniques[name] += 1
    total = len(inputs)
    return {
        "cmd_total": total,
        "cmd_distinct": len(set(inputs)),
        "cmd_avg_len": (sum(len(c) for c in inputs) / total) if total else None,
        "endpoints": endpoints,
        "flags": flags,
        "techniques": techniques,
    }


def _connect(db_path: str) -> sqlite3.Connection:
    p = Path(db_path)
    if not p.exists():
        sys.exit(
            f"error: database not found: {db_path}\n"
            f"       drop the pentest.db there, or pass --base-db/--ft-db. "
            f"The runs/ and data/ corpora are gitignored and absent from a clean clone."
        )
    db = sqlite3.connect(str(p))
    db.row_factory = sqlite3.Row
    return db


def _has_column(db: sqlite3.Connection, table: str, col: str) -> bool:
    try:
        return any(r["name"] == col for r in db.execute(f"PRAGMA table_info({table})"))
    except sqlite3.OperationalError:
        return False


def _models(db: sqlite3.Connection, kind: str | None) -> list[str]:
    q = "SELECT DISTINCT model FROM sessions WHERE model IS NOT NULL"
    params: list = []
    if kind:
        q += " AND session_type = ?"
        params.append(kind)
    q += " ORDER BY model"
    try:
        return [r["model"] for r in db.execute(q, params).fetchall()]
    except sqlite3.OperationalError as e:
        sys.exit(f"error: cannot read sessions table ({e}). Is this an Erlik pentest.db?")


def _resolve_model(db: sqlite3.Connection, kind: str | None, given: str | None, side: str) -> str:
    present = _models(db, kind)
    scope = f"{kind!r} " if kind else ""
    if given:
        if given not in present:
            sys.exit(f"error: --{side} model {given!r} has no {scope}sessions in its "
                     f"database.\n       available: {', '.join(present) or '(none)'}")
        return given
    if len(present) == 1:
        return present[0]
    if not present:
        sys.exit(f"error: no {scope}sessions in the --{side} database.")
    listed = "\n       ".join(present)
    sys.exit(f"error: --{side} database has several models; pass --{side} <model>:\n       {listed}")


def _usage(db: sqlite3.Connection, model: str, kind: str | None, profile: bool) -> dict:
    where = "s.model = ?"
    params: list = [model]
    if kind:
        where += " AND s.session_type = ?"
        params.append(kind)

    meta = db.execute(
        f"SELECT COUNT(*) n, MIN(created_at) lo, MAX(created_at) hi FROM sessions s WHERE {where}",
        params,
    ).fetchone()
    sessions = meta["n"] or 0

    has_denied = _has_column(db, "steps", "denied")
    cols = "st.tool_called tc, st.tool_input inp, st.duration_ms dur" + (", st.denied den" if has_denied else "")
    rows = db.execute(
        f"SELECT {cols} FROM sessions s JOIN steps st ON st.session_id = s.id WHERE {where}",
        params,
    ).fetchall()

    freq: Counter = Counter()
    durs: list[int] = []
    inputs: list[str] = []
    denied = 0
    for r in rows:
        tc = (r["tc"] or "").strip()
        if tc:
            freq[tc] += 1
        inp = (r["inp"] or "").strip()
        if inp:
            inputs.append(inp)
        if r["dur"] is not None:
            durs.append(r["dur"])
        if has_denied and r["den"]:
            denied += 1

    calls = sum(freq.values())
    out = {
        "model": model,
        "sessions": sessions,
        "steps_rows": len(rows),
        "tool_calls": calls,
        "calls_per_session": (calls / sessions) if sessions else 0.0,
        "distinct_tools": len(freq),
        "avg_duration_ms": (sum(durs) / len(durs)) if durs else None,
        "denied_rate": (denied / len(rows)) if (has_denied and rows) else None,
        "has_denied": has_denied,
        "freq": freq,
        "prov": {"n": sessions, "lo": str(meta["lo"])[:19] if meta["lo"] else None,
                 "hi": str(meta["hi"])[:19] if meta["hi"] else None},
    }
    if profile:
        out["commands"] = _profile(inputs)
    return out


def _fmt(v, suffix=""):
    return "n/a" if v is None else (f"{v:.1f}{suffix}" if isinstance(v, float) else f"{v}{suffix}")


def _side_by_side(title, a: Counter, b: Counter, top: int, keywidth: int = 22):
    allk = a + b
    if not allk:
        return
    print(f"\n=== {title} (baseline | fine-tuned) ===")
    print(f"{'':<{keywidth}} {'base':>6} {'ft':>6}")
    for key, _ in allk.most_common(top):
        print(f"{key[:keywidth]:<{keywidth}} {a.get(key, 0):>6} {b.get(key, 0):>6}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("db", nargs="?", help="shared pentest.db (when both models live in one database)")
    ap.add_argument("--base-db")
    ap.add_argument("--ft-db")
    ap.add_argument("--base", help="baseline model tag, e.g. qwen2.5-coder:7b")
    ap.add_argument("--ft", help="fine-tuned model tag, e.g. qwen2.5-coder:7b-juicy3")
    ap.add_argument("--kind", default=None, help="restrict to one session kind (default: all kinds)")
    ap.add_argument("--top", type=int, default=15, help="rows in the per-tool / endpoint / flag tables (default 15)")
    ap.add_argument("--commands", action=argparse.BooleanOptionalAction, default=True,
                    help="profile tool_input command strings (default: on)")
    ap.add_argument("--json", dest="json_out", default=None)
    args = ap.parse_args()

    base_db_path = args.base_db or args.db
    ft_db_path = args.ft_db or args.db
    if not base_db_path or not ft_db_path:
        ap.error("need a database: give a positional db, or both --base-db and --ft-db")

    base_db = _connect(base_db_path)
    ft_db = _connect(ft_db_path)
    base_model = _resolve_model(base_db, args.kind, args.base, "base")
    ft_model = _resolve_model(ft_db, args.kind, args.ft, "ft")

    base = _usage(base_db, base_model, args.kind, args.commands)
    ft = _usage(ft_db, ft_model, args.kind, args.commands)

    scope = args.kind or "all kinds"
    print(f"Tool usage: baseline vs fine-tuned    (session kind: {scope})\n")
    hdr = f"{'':<12} {'model':<26} {'sess':>5} {'calls':>6} {'calls/sess':>11} {'distinct':>9} {'avg_ms':>8} {'denied%':>8}"
    print(hdr)
    print("-" * len(hdr))
    for label, u in (("BASELINE", base), ("FINE-TUNED", ft)):
        dr = _fmt(u["denied_rate"] * 100, "%") if u["denied_rate"] is not None else "n/a"
        print(f"{label:<12} {u['model']:<26} {u['sessions']:>5} {u['tool_calls']:>6} "
              f"{u['calls_per_session']:>11.2f} {u['distinct_tools']:>9} "
              f"{_fmt(u['avg_duration_ms']):>8} {dr:>8}")
    print(f"\n  baseline   provenance: {base['prov']['n']} sessions, {base['prov']['lo']} … {base['prov']['hi']}")
    print(f"  fine-tuned provenance: {ft['prov']['n']} sessions, {ft['prov']['lo']} … {ft['prov']['hi']}")

    b, f = base["calls_per_session"], ft["calls_per_session"]
    if b == 0:
        verdict = "baseline ran no tools — cannot compare"
    else:
        pct = (f - b) / b * 100
        verdict = (f"about the same ({pct:+.1f}%)" if abs(pct) < 5
                   else f"fine-tuned ran {'FEWER' if pct < 0 else 'MORE'} tools per session ({pct:+.1f}%)")
    print(f"\n=== tool calls per session ===")
    print(f"  baseline ...... {b:.2f}")
    print(f"  fine-tuned .... {f:.2f}")
    print(f"  verdict ....... {verdict}")
    print(f"  distinct tools: baseline {base['distinct_tools']} vs fine-tuned {ft['distinct_tools']}")

    _side_by_side("tools by calls", base["freq"], ft["freq"], args.top)

    if args.commands:
        bc, fc = base["commands"], ft["commands"]
        uniq = lambda c: (f"{c['cmd_distinct']}/{c['cmd_total']} "
                          f"({c['cmd_distinct']/c['cmd_total']*100:.0f}% unique)" if c["cmd_total"] else "n/a")
        print(f"\n=== command-level approach (from tool_input) ===")
        print(f"  unique commands: baseline {uniq(bc)} | fine-tuned {uniq(fc)}")
        print(f"  avg command length: baseline {_fmt(bc['cmd_avg_len'])} | fine-tuned {_fmt(fc['cmd_avg_len'])}")
        _side_by_side("technique markers", bc["techniques"], fc["techniques"], args.top, keywidth=16)
        _side_by_side("endpoints probed", bc["endpoints"], fc["endpoints"], args.top, keywidth=30)
        _side_by_side("CLI flags", bc["flags"], fc["flags"], args.top, keywidth=16)

    if args.json_out:
        def strip(u):
            d = {}
            for k, v in u.items():
                if isinstance(v, Counter):
                    d[k] = dict(v)
                elif isinstance(v, dict):
                    d[k] = {kk: (dict(vv) if isinstance(vv, Counter) else vv) for kk, vv in v.items()}
                else:
                    d[k] = v
            return d
        Path(args.json_out).write_text(json.dumps(
            {"kind": scope, "baseline": strip(base), "fine_tuned": strip(ft), "verdict": verdict},
            indent=2, default=str))
        print(f"\nSaved -> {args.json_out}")


if __name__ == "__main__":
    main()
