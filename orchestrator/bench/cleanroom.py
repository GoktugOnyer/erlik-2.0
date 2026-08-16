"""False-positive cleanroom: the one measurement a client engagement cares about.

Against a deliberately CLEAN target, any finding erlik emits is BY DEFINITION a
false positive. There is no ground-truth matcher, no threshold and no judgement
call in that number.

That matters because erlik's recorded precision (0.73-1.0) is partly matcher
leniency: `_match_finding_to_ground_truth_scored` awards type +1, url:generic
+0.5 and param:generic +0.5, totalling exactly the 2.0 match threshold — so a
finding whose only correct attribute is its class name already scores as a true
positive. The cleanroom number has no such give.

Two corrections that make or break the harness:

1. A fixture is {route, tool, command, response, expected}, NOT a bare response.
   `DetectContext.url` is parsed FROM THE COMMAND. With an empty command — which
   the helper in tests/test_auto_detect.py defaults to — 11 of the 15 curl rules
   are structurally dead, including open-redirect and null-byte, while a CORS
   canary still fires. That combination produces green controls over a silent
   corpus and a headline of "~0 false positives" that measures nothing.

2. Zone A fixtures are EXPECTED to fire. They are deliberate collisions — benign
   behaviour by a clean app that nonetheless looks like a vulnerability — and
   their emissions ARE the false positives being counted. Asserting `== []` over
   them either fails on day one or gets neutered into a test that passes with
   detection.py deleted. The control is per-route expected-set EQUALITY against
   a committed manifest.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

CORPUS_PATH = Path(__file__).resolve().parents[2] / "tests_catalog" / "cleanroom" / "corpus.yaml"

# The cleanroom is a fixture corpus, not a live host. If a deployment has
# ERLIK_DOCKER_TARGET_HOST set, `_sanitize_command` rewrites URLs in commands —
# which would silently change what the detectors see and make the measurement
# describe a different corpus than the committed one.
_HOSTILE_ENV = ("ERLIK_DOCKER_TARGET_HOST",)


class CleanroomError(RuntimeError):
    pass


@dataclass(frozen=True)
class Fixture:
    route: str
    zone: str
    tool: str
    command: str
    response: str
    expected: tuple = ()
    rationale: str = ""
    family: str = ""


@dataclass
class Report:
    fixtures: int = 0
    zone_a: int = 0
    zone_b: int = 0
    false_positives: int = 0          # deduped, matching main.py's rule
    zone_b_findings: int = 0          # any of these is an unambiguous FP
    by_detector: dict = field(default_factory=dict)
    mismatches: list = field(default_factory=list)
    unreachable: list = field(default_factory=list)
    exercised: list = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.mismatches and self.zone_b_findings == 0


def _guard_env() -> None:
    for var in _HOSTILE_ENV:
        if os.environ.get(var):
            raise CleanroomError(
                f"{var} is set. It rewrites URLs inside commands, so the "
                f"detectors would see a different corpus than the committed one. "
                f"Unset it before measuring.")


def load_corpus(path: Path | None = None) -> list[Fixture]:
    p = path or CORPUS_PATH
    if not p.exists():
        return []
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    out = []
    for f in raw.get("fixtures") or []:
        out.append(Fixture(
            route=f["route"], zone=f["zone"], tool=f["tool"],
            command=f["command"], response=f["response"],
            expected=tuple(tuple(sorted(e.items())) for e in (f.get("expected") or ())),
            rationale=f.get("rationale", ""), family=f.get("family", ""),
        ))
    return out


def _emit(fx: Fixture) -> list[dict]:
    """What erlik's detectors actually produce for this fixture."""
    from orchestrator.detection import auto_detect_findings
    return auto_detect_findings(fx.tool, fx.response, fx.command)


def _norm(findings: list[dict]) -> tuple:
    """Comparable, order-independent shape: (vuln_type, severity, detector)."""
    return tuple(sorted(
        tuple(sorted({"vuln_type": f.get("vuln_type"),
                      "severity": f.get("severity"),
                      "detector": f.get("detector")}.items()))
        for f in findings))


def all_rule_names() -> list[str]:
    """Every leaf detector erlik can dispatch, as `tool:rule` names."""
    from orchestrator import detection as D
    names = [f"curl:{r.__name__}" for r in D._CURL_RULES]
    for tool, fn in D._DETECTORS.items():
        if fn.__name__ == "_detect_curl":
            continue
        names.append(f"{tool}:{fn.__name__}")
    return sorted(set(names))


def measure(corpus: list[Fixture] | None = None) -> Report:
    """Run the corpus and report the false-positive count."""
    _guard_env()
    corpus = corpus if corpus is not None else load_corpus()
    rep = Report(fixtures=len(corpus))
    seen: set[tuple] = set()
    fired: set[str] = set()

    for fx in corpus:
        got = _emit(fx)
        if fx.zone == "A":
            rep.zone_a += 1
        else:
            rep.zone_b += 1
            rep.zone_b_findings += len(got)

        if _norm(got) != tuple(sorted(fx.expected)):
            rep.mismatches.append({
                "route": fx.route,
                "expected": [dict(e) for e in fx.expected],
                "got": [dict(x) for x in _norm(got)],
            })

        for f in got:
            det = f.get("detector") or "unattributed"
            fired.add(det)
            # Replicate main.py's persistence dedup exactly, or the headline
            # scales with probe-list length instead of with erlik's behaviour.
            key = (f.get("vuln_type"), f.get("url"))
            if key in seen:
                continue
            seen.add(key)
            rep.false_positives += 1
            rep.by_detector[det] = rep.by_detector.get(det, 0) + 1

    known = all_rule_names()
    rep.exercised = sorted(fired & set(known))
    rep.unreachable = sorted(set(known) - fired)
    return rep


def format_report(rep: Report) -> str:
    lines = [
        "FALSE-POSITIVE CLEANROOM",
        f"  fixtures            {rep.fixtures}  (zone A {rep.zone_a}, zone B {rep.zone_b})",
        f"  false positives     {rep.false_positives}   <- deduped on (vuln_type, url)",
        f"  zone-B findings     {rep.zone_b_findings}   <- must be 0",
        f"  rules exercised     {len(rep.exercised)}/{len(all_rule_names())}",
    ]
    if rep.by_detector:
        lines.append("  by detector:")
        for k in sorted(rep.by_detector, key=lambda x: -rep.by_detector[x]):
            lines.append(f"    {rep.by_detector[k]:>3}  {k}")
    if rep.unreachable:
        lines.append("  NOT exercised by this corpus:")
        for r in rep.unreachable:
            lines.append(f"       {r}")
    if rep.mismatches:
        lines.append("  MISMATCHES (corpus drifted from detector behaviour):")
        for m in rep.mismatches:
            lines.append(f"    {m['route']}: expected {m['expected']} got {m['got']}")
    return "\n".join(lines)
