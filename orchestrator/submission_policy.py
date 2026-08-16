"""Submission policy — is this finding submittable, or informational?

Reads policy_catalog/never_submit.yaml and classifies findings at REPORT time.
Nothing here mutates a stored severity: `findings.severity` stays exactly what
the detector wrote, so `severity_score` and every recorded experiment remain
comparable. The verdict is derived on read, which also means a finding the
calibration pass or NVD enrichment later escalates is re-evaluated rather than
held down by a stale write-time stamp.

Design notes worth keeping:

* `max_severity` is a BRAKE, not a filter. A rule only applies while the
  finding sits at or below the severity the rule was written for. A CORS
  finding escalated to `high` is never demoted by a rule scoped to `medium`,
  no matter how broadly that rule's other conditions match.

* `load_rules()` RAISES on a present-but-broken file and returns [] only when
  the file is genuinely absent. The never-raise posture used by
  techniques.load_index() is right for optional prompt enrichment and wrong
  for something that governs a client deliverable — a typo there must not
  silently disable the policy.

* `classify()` reports WHY a rule did not apply (`rejected_by`), so a negative
  control can assert the specific condition that refused a finding instead of
  passing vacuously against an empty rule table.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

RULES_PATH = Path(__file__).resolve().parent.parent / "policy_catalog" / "never_submit.yaml"

_SEVERITY_RANK = {"info": 0, "informational": 0, "low": 1, "medium": 2,
                  "high": 3, "critical": 4}

SUBMIT = "submit"
INFORMATIONAL = "informational"


def _rank(severity: str | None) -> int:
    return _SEVERITY_RANK.get((severity or "info").strip().lower(), 0)


@dataclass(frozen=True)
class Rule:
    id: str
    vuln_types: tuple[str, ...]
    max_severity: str
    action: str
    rationale: str = ""
    evidence_prefix: str | None = None
    evidence_contains: tuple[str, ...] = ()
    unless_field: str | None = None


@dataclass(frozen=True)
class Decision:
    action: str
    effective_severity: str
    rule: str | None = None
    rejected_by: tuple[tuple[str, str], ...] = field(default=())

    @property
    def is_informational(self) -> bool:
        return self.action == INFORMATIONAL


class PolicyError(RuntimeError):
    """The policy file exists but could not be used."""


def load_rules(path: Path | None = None) -> tuple[list[Rule], str]:
    """Return (rules, policy_version).

    Absent file -> ([], "unloaded"): a deployment that has not shipped the
    catalogue is honestly unstamped, and the caller can say so.
    Broken file  -> PolicyError. Never a silent empty rule set.
    """
    p = path or RULES_PATH
    if not p.exists():
        return [], "unloaded"
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        raise PolicyError(f"{p} is not valid YAML: {e}") from e
    if not isinstance(raw, dict):
        raise PolicyError(f"{p}: expected a mapping at the top level")

    version = str(raw.get("version", "")) or "unloaded"
    rules: list[Rule] = []
    for i, r in enumerate(raw.get("rules") or []):
        if not isinstance(r, dict):
            raise PolicyError(f"{p}: rule #{i} is not a mapping")
        missing = [k for k in ("id", "vuln_types", "max_severity", "action") if k not in r]
        if missing:
            raise PolicyError(f"{p}: rule #{i} missing {missing}")
        if r["action"] != INFORMATIONAL:
            # Suppression was deliberately dropped from this policy; a rule
            # asking for it is a mistake, not a feature to silently honour.
            raise PolicyError(
                f"{p}: rule {r['id']!r} has action {r['action']!r}; only "
                f"{INFORMATIONAL!r} is supported (suppression is not)")
        if r["max_severity"].strip().lower() not in _SEVERITY_RANK:
            raise PolicyError(f"{p}: rule {r['id']!r} has unknown max_severity")
        if not r.get("evidence_prefix") and not r.get("evidence_contains"):
            raise PolicyError(
                f"{p}: rule {r['id']!r} matches on vuln_type alone; every rule "
                f"must key on a code-controlled evidence string")
        rules.append(Rule(
            id=str(r["id"]),
            vuln_types=tuple(r["vuln_types"]),
            max_severity=str(r["max_severity"]).strip().lower(),
            action=str(r["action"]),
            rationale=str(r.get("rationale", "")).strip(),
            evidence_prefix=r.get("evidence_prefix"),
            evidence_contains=tuple(r.get("evidence_contains") or ()),
            unless_field=r.get("unless_field"),
        ))
    ids = [r.id for r in rules]
    if len(ids) != len(set(ids)):
        raise PolicyError(f"{p}: duplicate rule id(s)")
    return rules, version


_CACHE: tuple[list[Rule], str] | None = None


def cached_rules() -> tuple[list[Rule], str]:
    """Load once per process. A broken catalogue raises on FIRST use.

    Deliberately not swallowed: this governs a client deliverable, so a typo in
    the policy must stop a report rather than silently produce one with the
    policy disabled — which would look identical to a report where nothing
    matched.
    """
    global _CACHE
    if _CACHE is None:
        _CACHE = load_rules()
    return _CACHE


def reset_cache() -> None:
    """Test hook."""
    global _CACHE
    _CACHE = None


def current_severity(finding: dict) -> str:
    """The severity a report would show, before policy.

    Re-derived on every call rather than stamped at write time, so escalation
    by the calibration pass or by NVD enrichment is respected.
    """
    return (finding.get("severity_override")
            or finding.get("calibrated_severity")
            or finding.get("severity")
            or "info")


def classify(finding: dict, rules: list[Rule]) -> Decision:
    """Decide whether `finding` is submittable. Never mutates `finding`."""
    sev = current_severity(finding)
    vuln_type = (finding.get("vuln_type") or "").strip()
    evidence = finding.get("evidence") or ""
    rejected: list[tuple[str, str]] = []

    for rule in rules:
        if vuln_type not in rule.vuln_types:
            rejected.append((rule.id, "vuln_type"))
            continue
        if rule.evidence_prefix and not evidence.startswith(rule.evidence_prefix):
            rejected.append((rule.id, "evidence_prefix"))
            continue
        if rule.evidence_contains and not any(s in evidence for s in rule.evidence_contains):
            rejected.append((rule.id, "evidence_contains"))
            continue
        if rule.unless_field and finding.get(rule.unless_field):
            rejected.append((rule.id, "unless_field"))
            continue
        if _rank(sev) > _rank(rule.max_severity):
            # The brake: something escalated this above the band the rule was
            # written for, so the rule no longer speaks to it.
            rejected.append((rule.id, "max_severity"))
            continue
        return Decision(action=INFORMATIONAL, effective_severity="info",
                        rule=rule.id, rejected_by=tuple(rejected))

    return Decision(action=SUBMIT, effective_severity=sev,
                    rule=None, rejected_by=tuple(rejected))
