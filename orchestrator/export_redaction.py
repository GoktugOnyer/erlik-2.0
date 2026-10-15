"""Export-boundary redaction for a pentest-report.json dict.

WHY THIS EXISTS, and why it is not already everywhere.

`_build_report_json` reads the `findings` rows verbatim: a secret sitting in a
`findings.evidence` row leaves through `/report.json`, `.sarif`, `.html`,
`.defectdojo.json` and `.jira.csv` in the clear. Those five lean entirely on
write-time scrubbing (`runner._scrub_for_storage`, `_record_finding`'s
`safe_label`) — a single defence, and one that never ran for a row imported
from an earlier erlik or written by a path that forgot to scrub. The thesis
export learned this the hard way and answered it with `_mask_export_rows`:
default-deny masking applied AT the boundary, so a column nobody remembered to
scrub is masked anyway.

The two new deliverables (PDF, HackerOne) get that second defence from the
start. `redact_report` runs the report's target-controlled free text through
`orchestrator.redaction.mask` — the single redaction authority — before either
export renders it. A credential that reached a finding row is masked on the way
out even though the five older formats would have shipped it.

Scope of the mask, by the same rule `_EXPORT_STRUCTURAL` uses: everything that
is operator- or target-authored free text is masked; controlled-vocabulary and
numeric fields are left alone so the deliverable stays readable.

  masked            description, impact, remediation, evidence, references
  masked (as URL)   affected_url, engagement.target — query VALUES only, so the
                    URL still parses
  left as-is        title (a controlled vocabulary already guarded at the write
                    path by redaction.safe_label), severity, confidence, cwe,
                    owasp, mitre, cvss_* — ids, enums and numbers

`mask` is None-preserving and only rewrites credential-shaped substrings, so a
legitimate "You have an error in your SQL syntax" proof is untouched while a
leaked `Authorization: Bearer …` is not. The function never mutates its input.
"""

from __future__ import annotations

import copy

from orchestrator.redaction import mask, mask_url

# Finding free-text fields the application or the model controls. Masked.
_FINDING_TEXT = ("description", "impact", "remediation", "evidence")
# Finding URL fields. Masked as URLs so scheme/host/path survive and only the
# query-parameter values are replaced — a SARIF/HackerOne location must parse.
_FINDING_URLS = ("affected_url",)


def redact_finding(f: dict) -> dict:
    """A single finding with its free text and URL masked. Copy, never mutate."""
    g = dict(f)
    for k in _FINDING_TEXT:
        if isinstance(g.get(k), str):
            g[k] = mask(g[k])
    for k in _FINDING_URLS:
        if isinstance(g.get(k), str):
            g[k] = mask_url(g[k])
    refs = g.get("references")
    if isinstance(refs, list):
        g["references"] = [mask(r) if isinstance(r, str) else r for r in refs]
    return g


def redact_report(report: dict) -> dict:
    """Default-deny copy of a pentest-report.json dict for an external export.

    Deep-copied first so the shared `_build_report_json` object a caller may
    still be holding is never altered — the five existing exports read it raw
    and must keep doing so until they are migrated.
    """
    out = copy.deepcopy(report)
    out["findings"] = [redact_finding(f) for f in (report.get("findings") or [])]
    eng = dict(report.get("engagement") or {})
    if isinstance(eng.get("target"), str):
        eng["target"] = mask_url(eng["target"])
    out["engagement"] = eng
    return out
