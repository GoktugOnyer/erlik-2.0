"""Render the validated pentest-report.json into HackerOne submission payloads.

One HackerOne report is one vulnerability, so this produces ONE submission
object per finding, wrapped in `{"reports": [...]}`. Each object mirrors the
JSON:API body HackerOne's "create report" endpoint accepts
(POST /v1/reports) — `data.type == "report"` with the attributes a submitter
fills in: `title`, `vulnerability_information` (markdown), `impact` and
`severity_rating`.

WHAT THIS EXPORT CANNOT KNOW, and therefore does not invent:

  * `team_handle` — the destination programme. A submitter adds it; there is no
    correct value to guess here, so the attribute is omitted rather than filled
    with a placeholder that would post to the wrong programme.
  * `weakness_id` / `structured_scope_id` — HackerOne's own numeric ids for a
    CWE and a scoped asset. They are resolved against a specific programme's
    taxonomy and cannot be derived offline, so the human-readable CWE string and
    the asset URL are carried under `weakness` and `structured_scope` for the
    submitter (or an uploader script) to resolve.

These omissions are declared, not silent — the same rule the rest of erlik's
reporting holds to: a field that cannot be filled honestly stays absent and
named, never faked.

REDACTION AND MARKDOWN SAFETY are two separate jobs and both are done:

  * Credentials: the caller passes a report already run through
    `export_redaction.redact_report`, so a secret that reached a finding row is
    masked before it is rendered here.
  * Markup: `vulnerability_information` and `impact` are HackerOne markdown, and
    the evidence inside them is the application's own bytes. It is quoted as a
    four-space-indented block, which no `` ``` `` fence or heading can break out
    of — the same defence `integrations.defectdojo._quoted` uses.

The submission policy travels with the finding: a NOT-submittable finding is
still emitted (annotate, never remove) with `meta.submittable == false` and a
banner at the top of its `vulnerability_information`, so an operator uploading
the batch can see which entries erlik itself withholds.
"""

from __future__ import annotations

# erlik severity label -> HackerOne severity_rating enum (none|low|medium|high|critical)
_H1_RATING = {
    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
    "LOW": "low", "INFORMATIONAL": "none", "UNKNOWN": "none",
}

_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNKNOWN"]


def _sev(f: dict) -> str:
    s = (f.get("severity") or "UNKNOWN").upper()
    return s if s in _SEV_ORDER else "UNKNOWN"


def _quoted(text: str) -> str:
    """Four-space-indent every line of target-controlled text.

    A markdown fence can be closed from inside the content; a four-space code
    block cannot — so hostile evidence renders inert on HackerOne instead of as
    live markup. Lines are kept, only prefixed, so the proof stays readable.
    """
    return "\n".join("    " + line for line in text.splitlines())


def _policy_banner(f: dict) -> str:
    if f.get("submittable", True):
        return ""
    rule = f.get("policy_rule") or "submission policy"
    return (f"> **NOT SUBMITTABLE** — erlik marked this informational by "
            f"{rule}. It is included for completeness and should not be "
            f"submitted as-is.\n\n")


def _vulnerability_information(f: dict) -> str:
    """The markdown body of a HackerOne report, assembled from the finding."""
    parts: list[str] = []
    banner = _policy_banner(f)
    if banner:
        parts.append(banner.rstrip("\n"))

    desc = (f.get("description") or "").strip()
    if desc:
        parts.append("## Summary\n\n" + desc)

    url = (f.get("affected_url") or "").strip()
    param = (f.get("parameter") or "").strip()
    if url:
        loc = f"- URL: `{url}`"
        if param:
            loc += f"\n- Parameter: `{param}`"
        parts.append("## Affected asset\n\n" + loc)

    # `description` already carries the finding's own evidence in report.json
    # (it is built from the `evidence` column). A separate `evidence` key is
    # honoured too, for callers that set one — quoted as an inert block.
    evidence = (f.get("evidence") or "").strip()
    if evidence and evidence != desc:
        parts.append("## Steps to reproduce / evidence\n\n"
                     "The application's own output (credentials redacted):\n\n"
                     + _quoted(evidence))

    remediation = (f.get("remediation") or "").strip()
    if remediation:
        parts.append("## Remediation\n\n" + remediation)

    refs = [r for r in (f.get("references") or []) if r]
    if refs:
        parts.append("## References\n\n" + "\n".join(f"- {r}" for r in refs))

    tags = []
    for label, key in (("CWE", "cwe"), ("OWASP", "owasp"), ("MITRE ATT&CK", "mitre"),
                       ("Confidence", "confidence")):
        v = f.get(key)
        if v:
            tags.append(f"- {label}: {v}")
    if tags:
        parts.append("## Classification\n\n" + "\n".join(tags))

    return "\n\n".join(parts)


def _report_object(f: dict) -> dict:
    sev = _sev(f)
    attributes: dict = {
        "title": f.get("title") or "Finding",
        "vulnerability_information": _vulnerability_information(f),
        "impact": (f.get("impact") or "").strip(),
        "severity_rating": _H1_RATING.get(sev, "none"),
    }
    # CVSS, when erlik calibrated one. HackerOne accepts a CVSS vector/score
    # alongside the qualitative rating.
    if f.get("cvss_score") is not None:
        attributes["cvss"] = {
            "score": f.get("cvss_score"),
            "vector": f.get("cvss_vector") or None,
        }
    # Human-readable CWE and asset, since HackerOne's numeric ids cannot be
    # resolved offline (see module docstring).
    if f.get("cwe"):
        attributes["weakness"] = {"cwe": f.get("cwe"), "name": f.get("title") or ""}
    if f.get("affected_url"):
        attributes["structured_scope"] = {
            "asset_identifier": f.get("affected_url"),
            "asset_type": "URL",
        }

    return {
        "data": {
            "type": "report",
            "attributes": attributes,
        },
        # erlik-side provenance kept out of `data.attributes` so the submission
        # body stays exactly what HackerOne expects; a submitter or uploader
        # reads `meta` to decide what to send.
        "meta": {
            "finding_id": f.get("id"),
            "owasp": f.get("owasp"),
            "mitre": f.get("mitre"),
            "confidence": f.get("confidence"),
            "submittable": bool(f.get("submittable", True)),
            "policy_rule": f.get("policy_rule"),
        },
    }


def report_to_hackerone(report: dict, session_id: str = "") -> dict:
    """`{"reports": [...]}` — one HackerOne report submission object per finding.

    The caller is expected to pass a report already redacted at the export
    boundary (`export_redaction.redact_report`); this function adds no secret of
    its own and only shapes the fields.
    """
    findings = report.get("findings", []) or []
    return {
        "schema": "hackerone-report-submission",
        "generated_by": "Erlik 2.0",
        "session_id": session_id,
        "reports": [_report_object(f) for f in findings],
    }
