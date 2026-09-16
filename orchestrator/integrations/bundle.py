"""A finding packaged so someone else can check it. E-016.

A finding's supporting material was spread across `integration_evidence` artifacts, the stage
that produced it, the assessment's configuration and three tables. Everything needed to hand a
developer one finding existed; nothing assembled it. This does.

THE RULE THIS IS BUILT AROUND: a bundle carries DECLARATIONS and EVIDENCE, never credentials.
The identity's `headers`, `cookies`, `storage_state` and `check` are the material that makes an
arm that arm, and none of them is here — only the labels the operator chose and the lane
reports (`name`, `role`, `tenant`, `subject_id`). The configuration comes from the PUBLISHED
row rather than the secret store's private copy, which is the same distinction
`service.register` already draws for the same reason.

That is an assertion about this module, so there is a test that serialises a whole bundle and
an archive built over a session whose identity carries a real-shaped token, and looks for the
token in the bytes.

`evidence` and `diagnostics` are separate, as the entry asks. The finding's own
`evidence_ids` are what the claim rests on; everything else the session recorded is context,
and a reader who cannot tell them apart is being asked to weigh a stage's stdout against the
response that proves the finding.

EVERY ARTIFACT IS READ THROUGH `evidence_bytes`, so a changed or missing one is detectable —
that function re-checks the sha256 recorded when it was written. The bundle then carries the
digest itself, so the check can be repeated by whoever receives it rather than trusted.
"""
from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

from . import persistence as db
from .persistence import EvidenceIntegrityError
from .security import SecretStore

# Identity fields a bundle may carry. Everything absent from this set — `headers`, `cookies`,
# `storage_state`, `check` — is how an arm authenticates, and a bundle is a document that
# leaves the building.
DECLARED_IDENTITY_FIELDS = ("name", "role", "tenant", "subject_id", "may_access")

# What a reader needs before they can repeat the run: which schema was scanned and with which
# seed. Recorded per stage; `schema_sha256` is canonical (sorted keys), so it is an identity
# rather than a serialisation — see E-012.
REPRODUCTION_KEYS = ("schema_sha256", "seed", "version", "image")


async def _assessment(session_id) -> dict:
    rows = await db.rows(
        "SELECT target,status,config FROM integration_assessments WHERE session_id=?",
        (session_id,))
    if not rows:
        raise KeyError(f"integration assessment not found: {session_id}")
    return dict(rows[0])


def _declared(identity_id) -> dict:
    """The operator's LABELS for an arm. Never its credentials — see the module docstring."""
    if identity_id in (None, "", "anonymous"):
        return {"name": "anonymous", "declared": False}
    try:
        stored = SecretStore().get(identity_id) or {}
    except Exception:
        return {"name": identity_id[:8], "declared": False,
                "note": "this identity's declaration is no longer resolvable"}
    return {"declared": True,
            **{field: stored.get(field) for field in DECLARED_IDENTITY_FIELDS}}


async def _artifacts(session_id, wanted) -> tuple[list, list]:
    """(cited, unreadable). Content included; integrity re-checked on the way out."""
    cited, unreadable = [], []
    for evidence_id in wanted:
        rows = await db.rows(
            "SELECT id,stage_id,kind,sha256,size,created_at FROM integration_evidence "
            "WHERE id=?", (evidence_id,))
        if not rows:
            unreadable.append({"evidence_id": evidence_id,
                               "reason": "no evidence row with this id"})
            continue
        row = dict(rows[0])
        try:
            content = (await db.evidence_bytes(evidence_id)).decode("utf-8", "replace")
        except (EvidenceIntegrityError, KeyError) as exc:
            # DETECTABLE, which the acceptance asks for by name. A bundle that silently
            # omitted a failed artifact would read as a finding with less evidence rather
            # than as evidence that changed underneath it.
            unreadable.append({"evidence_id": evidence_id, "kind": row["kind"],
                               "reason": f"{type(exc).__name__}: {exc}"})
            continue
        cited.append({**row, "content": content})
    return cited, unreadable


async def finding_bundle(session_id, fingerprint) -> dict:
    """Everything a reviewer needs to check one finding, and nothing that authenticates."""
    rows = await db.rows(
        "SELECT payload FROM integration_findings WHERE session_id=? AND fingerprint=?",
        (session_id, fingerprint))
    if not rows:
        raise KeyError(f"no finding {fingerprint} in session {session_id}")
    finding = json.loads(rows[0]["payload"])
    assessment = await _assessment(session_id)

    stages = [dict(row) for row in await db.rows(
        "SELECT adapter,identity_id,status,reason,result FROM integration_stages "
        "WHERE session_id=?", (session_id,))]
    reproduction = {}
    for stage in stages:
        try:
            metadata = json.loads(stage["result"] or "{}").get("metadata") or {}
        except (ValueError, TypeError):
            metadata = {}
        for key in REPRODUCTION_KEYS:
            if metadata.get(key) is not None:
                reproduction.setdefault(stage["adapter"], {})[key] = metadata[key]

    cited, unreadable = await _artifacts(session_id, finding.get("evidence_ids") or [])
    # Excluded in PYTHON, not in the query. A first version built an `id NOT IN (...)`
    # subquery from `"|".join(evidence_ids)`, which is one id when there is one and matches
    # nothing when there are several — so the SQL appeared to work on the single-artifact
    # case and silently excluded nothing on every real finding. The set below is the cited
    # ids as actually resolved, which is also the right answer when an artifact failed its
    # digest: it is reported in `evidence_not_readable`, and listing it again as a diagnostic
    # would offer the bytes that just failed their check as context.
    cited_ids = {artifact["id"] for artifact in cited} | {
        entry["evidence_id"] for entry in unreadable}
    diagnostics = [dict(row) for row in await db.rows(
        "SELECT id,stage_id,kind,sha256,size FROM integration_evidence WHERE session_id=?",
        (session_id,)) if row["id"] not in cited_ids]

    arms = sorted({stage["identity_id"] for stage in stages})
    return {
        "finding": finding,
        "assessment": {
            "session_id": session_id,
            "target": assessment["target"],
            "status": assessment["status"],
            # The PUBLISHED configuration, never the private copy the secret store holds.
            "configuration": json.loads(assessment["config"] or "{}"),
        },
        # WHO the claim is about, in the operator's own labels. A cross-arm finding names
        # both arms, because "should not have reached it" is meaningful only against the arm
        # it was compared with.
        "authorization_context": {
            "identity": _declared(finding.get("identity")),
            "compared_with": (_declared(finding["compared_with"])
                              if finding.get("compared_with") else None),
            "arms_in_this_assessment": [_declared(arm) for arm in arms],
        },
        # What produced it, and what a reader would have to run again.
        "provenance": {
            "produced_by": finding.get("produced_by", ""),
            "rule": finding.get("rule", ""),
            "methodology": finding.get("methodology") or [],
            "stages": reproduction,
        },
        "evidence": cited,
        # Recorded, never silently dropped — see `_artifacts`.
        "evidence_not_readable": unreadable,
        # Everything else the session stored. Context, not the basis of the claim.
        "diagnostics": diagnostics,
        "establishes": (
            f"{len(cited)} artifact(s) support this finding and each was re-checked against "
            f"the digest recorded when it was written"
            + (f"; {len(unreadable)} cited artifact(s) could NOT be read and the claim rests "
               f"on less than it says" if unreadable else "")
            + ". Credentials are absent by construction: this carries the operator's "
              "declarations, not the material an arm authenticates with."),
    }


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


async def write_bundle_archive(session_id, destination, fingerprints=None) -> dict:
    """Write one zip holding a bundle per finding, plus a manifest of digests.

    The manifest is what makes a delivered archive checkable without erlik: every member is
    listed with the sha256 of the bytes as written, so a reader can verify the archive they
    received is the archive that was made.
    """
    selected = fingerprints if fingerprints is not None else [
        row["fingerprint"] for row in await db.rows(
            "SELECT fingerprint FROM integration_findings WHERE session_id=? "
            "ORDER BY fingerprint", (session_id,))]
    bundles = {name: await finding_bundle(session_id, name) for name in selected}

    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    members = {}
    for name, payload in bundles.items():
        members[f"findings/{name}.json"] = json.dumps(payload, indent=2,
                                                      sort_keys=True).encode()
    manifest = {
        "session_id": session_id,
        "findings": sorted(bundles),
        "members": {name: {"sha256": _digest(body), "size": len(body)}
                    for name, body in sorted(members.items())},
        "establishes": ("each member's digest is of the bytes as written, so a reader can "
                        "check the archive they received is the archive that was made. It "
                        "does not attest that the evidence inside was not altered before "
                        "the bundle was built — `finding_bundle` re-checks that against the "
                        "digest recorded at write time and reports any artifact that failed."),
    }
    members["MANIFEST.json"] = json.dumps(manifest, indent=2, sort_keys=True).encode()
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, body in sorted(members.items()):
            archive.writestr(name, body)
    return manifest
