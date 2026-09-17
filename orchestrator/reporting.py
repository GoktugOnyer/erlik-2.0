"""Render the validated pentest-report.json into deliverable formats.

The `PentestReport` dict (orchestrator/models.py, built by main._build_report_json)
is the single source of truth; this module renders it to:

  - HTML  — a self-contained, client-ready document (print-to-PDF in a browser)
  - SARIF — SARIF 2.1.0 for CI / security-tool ingestion (GitHub code scanning, DefectDojo, …)

Pure functions, no third-party deps. All interpolated values are HTML-escaped —
finding fields are LLM/target-controlled and must not be trusted in a deliverable.
"""

from __future__ import annotations

import csv
import html
import io
import re
from datetime import datetime

_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNKNOWN"]
_SEV_COLOR = {
    "CRITICAL": "#b3123b", "HIGH": "#d9480f", "MEDIUM": "#b8860b",
    "LOW": "#1c7ed6", "INFORMATIONAL": "#5a5a6a", "UNKNOWN": "#5a5a6a",
}


# WHAT A MODEL MAY SAY ABOUT CONFIDENCE, and the one thing it may not.
#
# `confidence == "confirmed"` is what makes a finding `verified` here and what
# `defectdojo.remote` sends to a client's tracker as verified=true. The legacy lane
# parses the model's own analysis text with `_parse_finding_blocks` and wrote whatever
# it found straight into `findings.confidence` — so a model emitting
# `CONFIDENCE: confirmed` verified its own finding. Measured before this: the parser
# accepts any value that is not a placeholder echo, "confirmed" among them, and the
# report then says verified.
#
# E-014: "Scanner and model agreement alone never upgrades confidence to confirmed."
# E-020 is why it survived: "do not assume the new integration proxy already governs
# every historical execution path" — the integration lane grades honestly (ZAP alerts
# are `suspected`, the cross-arm object check earns `confirmed` from a differential,
# `assertion_grade` needs a control) and none of that governs this path.
#
# CLAMPED RATHER THAN DROPPED. The model's calibration is worth keeping — it reads the
# evidence and "this is weak" is useful — so it may still lower, and may still say
# `likely`, its strongest permitted claim. What it may not do is grant the one value
# that leaves the building as verification.
MODEL_MAX_CONFIDENCE = "likely"
CONFIDENCE_VALUES = ("suspected", "likely", "confirmed")


def model_confidence(value):
    """The confidence a MODEL is allowed to assert, or None if it said nothing usable.

    `confirmed` is earned by a differential, a control, or a second observation — none
    of which a model reading text has done. It becomes `likely` instead, which is the
    difference between "the model is fairly sure" and "erlik verified this".
    """
    text = (value or "").strip().lower()
    if not text:
        return None
    if text not in CONFIDENCE_VALUES:
        return None
    return MODEL_MAX_CONFIDENCE if text == "confirmed" else text


def _e(v) -> str:
    return html.escape("" if v is None else str(v))


def _sev(f: dict) -> str:
    s = (f.get("severity") or "UNKNOWN").upper()
    return s if s in _SEV_ORDER else "UNKNOWN"


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #

# A finding the submission policy marks informational. Every export format
# carries this, because a deliverable that omits it is one an operator can send
# to a client or a bug-bounty programme believing it was gated. Annotated,
# never removed — the same rule the markdown report follows.
def _policy_note(f: dict) -> str:
    if f.get("submittable", True):
        return ""
    rule = f.get("policy_rule") or "submission policy"
    return f"NOT SUBMITTABLE — marked informational by {rule}"


def _evidence_block(f: dict) -> str:
    """The bytes a finding rests on, as plain text for a non-HTML renderer.

    Every deliverable has to carry it or none should: the HTML report is the one
    an operator prints and sends, and it was the one rendering a HIGH-severity
    claim with nothing behind it while report.json carried the proof.
    """
    evidence = (f.get("evidence") or "").strip()
    if not evidence:
        return ""
    return "Evidence (the application's own output, credentials redacted):\n" + evidence


def report_to_html(report: dict) -> str:
    eng = report.get("engagement", {}) or {}
    stats = report.get("statistics", {}) or {}
    findings = report.get("findings", []) or []

    def stat_badge(label, key):
        n = stats.get(key, 0)
        col = _SEV_COLOR.get(label.upper(), "#5a5a6a")
        return (f'<span class="stat" style="border-color:{col};color:{col}">'
                f'{_e(label)}: <b>{_e(n)}</b></span>')

    # findings grouped by severity, in order
    by_sev: dict[str, list] = {}
    for f in findings:
        by_sev.setdefault(_sev(f), []).append(f)

    cards = []
    for sev in _SEV_ORDER:
        for f in by_sev.get(sev, []):
            col = _SEV_COLOR.get(sev, "#5a5a6a")
            refs = f.get("references") or []
            rows = [
                ("Severity", f'<b style="color:{col}">{_e(sev)}</b>'),
                ("CVSS", f'{_e(f.get("cvss_score"))} '
                         f'<code>{_e(f.get("cvss_vector") or "")}</code>'
                         if f.get("cvss_score") is not None else "—"),
                ("CWE", _e(f.get("cwe") or "—")),
                ("OWASP", _e(f.get("owasp") or "—")),
                ("ATT&CK", _e(f.get("mitre") or "—")),
                ("Location", f'<code>{_e(f.get("affected_url") or "—")}</code>'),
                ("Confidence", _e(f.get("confidence") or "—")),
            ]
            meta = "".join(
                f'<tr><th>{_e(k)}</th><td>{v}</td></tr>' for k, v in rows)
            sections = []
            if f.get("description"):
                sections.append(f'<h4>Description</h4><p>{_e(f["description"])}</p>')
            if f.get("impact"):
                sections.append(f'<h4>Impact</h4><p>{_e(f["impact"])}</p>')
            if f.get("remediation"):
                sections.append(f'<h4>Remediation</h4><p>{_e(f["remediation"])}</p>')
            # ESCAPED, and in a <pre>: this is the only field on a finding whose
            # content the target chose, so it is the only one that could be
            # markup. _e is html.escape.
            if (f.get("evidence") or "").strip():
                sections.append('<h4>Evidence</h4>'
                                '<p class="muted">Captured from the application, '
                                'credentials redacted.</p>'
                                f'<pre class="evidence">{_e(f["evidence"])}</pre>')
            if refs:
                items = "".join(f'<li>{_e(r)}</li>' for r in refs)
                sections.append(f'<h4>References</h4><ul>{items}</ul>')
            note = _policy_note(f)
            banner = (f'<p style="margin:6px 0;padding:6px 8px;background:#fff4e5;'
                      f'border:1px solid #f0c68a;font-size:13px;">{_e(note)}</p>'
                      if note else "")
            cards.append(f'''
    <div class="finding" style="border-left:4px solid {col}">
      <h3>{_e(f.get("id") or "F-?")} — {_e(f.get("title") or "Finding")}</h3>
      {banner}
      <table class="meta">{meta}</table>
      {"".join(sections)}
    </div>''')

    findings_html = "".join(cards) if cards else "<p>No findings recorded.</p>"
    generated = datetime.now().strftime("%Y-%m-%d %H:%M")

    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Pentest Report — {_e(eng.get("target") or "")}</title>
<style>
  body{{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1a1a1a;max-width:960px;margin:0 auto;padding:32px;line-height:1.5}}
  h1{{margin:0 0 4px}} .sub{{color:#666;margin-bottom:24px}}
  .stats{{margin:16px 0 28px}} .stat{{display:inline-block;border:1px solid;border-radius:4px;padding:3px 8px;margin:2px;font-size:13px}}
  .finding{{background:#fafafa;border-radius:6px;padding:16px 20px;margin:18px 0}}
  .finding h3{{margin:0 0 10px}} .finding h4{{margin:14px 0 4px;font-size:14px;color:#333}}
  table.meta{{border-collapse:collapse;margin:6px 0 4px;font-size:13px}}
  table.meta th{{text-align:left;color:#666;font-weight:600;padding:2px 12px 2px 0;vertical-align:top;white-space:nowrap}}
  table.meta td{{padding:2px 0}}
  code{{background:#eee;padding:1px 4px;border-radius:3px;font-size:12px;word-break:break-all}}
  p{{margin:4px 0;white-space:pre-wrap}} footer{{margin-top:40px;color:#999;font-size:12px;border-top:1px solid #eee;padding-top:12px}}
</style></head><body>
  <h1>Penetration Test Report</h1>
  <div class="sub"><b>{_e(eng.get("name") or "Engagement")}</b> — target <code>{_e(eng.get("target") or "")}</code>
    · {_e(eng.get("dates") or "")} · status {_e(eng.get("status") or "")}</div>
  <div class="stats">
    <span class="stat" style="border-color:#333;color:#333">TOTAL: <b>{_e(stats.get("total", 0))}</b></span>
    {stat_badge("CRITICAL","critical")}{stat_badge("HIGH","high")}{stat_badge("MEDIUM","medium")}
    {stat_badge("LOW","low")}{stat_badge("INFORMATIONAL","informational")}
  </div>
  <h2>Findings</h2>
  {findings_html}
  <footer>Generated by Erlik 2.0 · {generated} · rendered from the validated pentest-report.json</footer>
</body></html>'''


# --------------------------------------------------------------------------- #
# SARIF 2.1.0
# --------------------------------------------------------------------------- #

def _sarif_level(sev: str) -> str:
    s = (sev or "").upper()
    if s in ("CRITICAL", "HIGH"):
        return "error"
    if s == "MEDIUM":
        return "warning"
    return "note"


def report_to_sarif(report: dict, session_id: str = "") -> dict:
    findings = report.get("findings", []) or []
    eng = report.get("engagement", {}) or {}

    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        rule_id = (f.get("cwe") or f.get("title") or "finding").strip()
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": (f.get("title") or rule_id),
                "shortDescription": {"text": (f.get("title") or rule_id)},
                "properties": {k: f.get(k) for k in ("owasp", "cwe") if f.get(k)},
            }
        props = {k: f.get(k) for k in
                 ("severity", "cvss_score", "cvss_vector", "cwe", "owasp",
                  "confidence", "remediation", "id", "submittable", "policy_rule",
                  "evidence", "parameter")
                 if f.get(k) is not None}
        # SARIF is read by CI gates, which act on `level`. A finding the policy
        # says must not be submitted is downgraded to "note" so an automated
        # consumer does not fail a build on something erlik itself withholds.
        _blocked = not f.get("submittable", True)
        if _blocked:
            props["policy_note"] = _policy_note(f)
        loc = f.get("affected_url") or ""
        results.append({
            "ruleId": rule_id,
            # The downgrade the comment above promised. It was written but
            # never applied: `level` was unconditional, so a NOT-submittable
            # CRITICAL emitted `error`, identical to a submittable one, and a
            # CI gate broke the build on a finding erlik itself withholds.
            "level": "note" if _blocked else _sarif_level(f.get("severity")),
            "message": {"text": (f.get("description") or f.get("title") or "Finding")},
            "locations": ([{"physicalLocation": {"artifactLocation": {"uri": loc}}}]
                          if loc else []),
            "properties": props,
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Erlik 2.0",
                "informationUri": "https://github.com/GoktugOnyer/erlik-2.0",
                "rules": list(rules.values()),
            }},
            "properties": {"engagement": eng, "session_id": session_id},
            "results": results,
        }],
    }


# --------------------------------------------------------------------------- #
# Tracker imports — DefectDojo (generic JSON) and Jira (CSV)
# --------------------------------------------------------------------------- #

_DD_SEV = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium",
           "LOW": "Low", "INFORMATIONAL": "Info", "UNKNOWN": "Info"}
_JIRA_PRIORITY = {"CRITICAL": "Highest", "HIGH": "High", "MEDIUM": "Medium",
                  "LOW": "Low", "INFORMATIONAL": "Lowest", "UNKNOWN": "Lowest"}


def _cwe_int(cwe) -> int | None:
    m = re.search(r"(\d+)", str(cwe or ""))
    return int(m.group(1)) if m else None


def report_to_defectdojo(report: dict) -> dict:
    """DefectDojo 'Generic Findings Import' JSON (upload under that scan type)."""
    out = []
    for f in report.get("findings", []) or []:
        sev = _sev(f)
        out.append({
            "title": f.get("title") or "Finding",
            "description": "\n\n".join(x for x in (
                f.get("description") or "", _policy_note(f), _evidence_block(f)) if x),
            "severity": _DD_SEV.get(sev, "Info"),
            "cwe": _cwe_int(f.get("cwe")),
            "cvssv3": f.get("cvss_vector") or None,
            "cvssv3_score": f.get("cvss_score"),
            "mitigation": f.get("remediation") or "",
            "impact": f.get("impact") or "",
            "references": "\n".join(f.get("references") or []),
            "vuln_id_from_tool": f.get("id"),
            "unique_id_from_tool": f.get("id"),
            "endpoints": [f["affected_url"]] if f.get("affected_url") else [],
            "static_finding": False,
            "dynamic_finding": True,
            # DefectDojo's `active` is what its triage views filter on, so a
            # finding the submission policy withholds must arrive inactive. An
            # earlier version set this key EARLIER in the same dict literal,
            # where the line below silently shadowed it — the change looked
            # applied and did nothing.
            "active": bool(f.get("submittable", True)),
            "verified": (f.get("confidence") == "confirmed"),
        })
    return {"findings": out}


def report_to_jira_csv(report: dict) -> str:
    """CSV for Jira's CSV issue import (map the columns during import)."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Summary", "Priority", "Labels", "Description", "URL", "CVSS", "CWE",
                "OWASP", "Submittable"])
    for f in report.get("findings", []) or []:
        sev = _sev(f)
        parts = [f.get("description") or ""]
        if _policy_note(f):
            parts.append(_policy_note(f))
        if _evidence_block(f):
            parts.append(_evidence_block(f))
        if f.get("impact"):
            parts.append("Impact: " + f["impact"])
        if f.get("remediation"):
            parts.append("Remediation: " + f["remediation"])
        cvss = (f"{f.get('cvss_score')} {f.get('cvss_vector') or ''}".strip()
                if f.get("cvss_score") is not None else "")
        w.writerow([
            f"[{sev}] {f.get('title') or 'Finding'}",
            _JIRA_PRIORITY.get(sev, "Lowest"),
            ("erlik " + (f.get("owasp") or "")).strip(),
            "\n\n".join(p for p in parts if p),
            f.get("affected_url") or "",
            cvss,
            f.get("cwe") or "",
            f.get("owasp") or "",
            "yes" if f.get("submittable", True) else "no",
        ])
    return buf.getvalue()
