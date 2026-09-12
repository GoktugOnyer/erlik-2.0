"""Integration routes. All are protected by the application's token middleware."""
import json
from pathlib import Path
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field
from .contracts import Identity, AssessmentConfig
from typing import Literal
from .security import SecretStore, runtime_root
from .runtime import availability
from .defectdojo import ExportConfig, RemoteError, export, reconcile
from . import persistence as db

router = APIRouter(prefix="/api/integrations", tags=["integrations"])


@router.get("/availability")
async def get_availability():
    return {"images": await availability(), "adapters": ["zap", "schemathesis", "interactsh", "katana", "defectdojo"]}


@router.post("/identities")
async def create_identity(body: Identity):
    """Register an identity. A SECOND registration of the same one orphans its findings.

    E-032: the handle is in every finding's fingerprint, so a rotated credential registered
    here is a different identity as far as the export is concerned — the same violation
    arrives at the client's tracker as a NEW finding at `triage_state` open, and the old row
    stays active forever. Token expiry makes rotation the normal rhythm, so one test
    accumulates a copy per rotation. Measured: `POST` again gives a new handle and a
    different fingerprint; `PUT /identities/{id}` gives the same handle, the same
    fingerprint, and the credential replaced.

    So `PUT` is the rotation route, and this one stops being silent about it. The
    registration still happens — two genuinely different callers may share a name, and the
    operator is the authority on who the caller is — but the collision is named in the
    response.

    THE FINGERPRINT IS NOT THE PLACE TO FIX THIS, which is the fix that first suggests
    itself. Keying the identity term on `(name, target_origin)` instead of the handle would
    make rotation free and would also collapse two genuinely distinct callers who share a
    name into one fingerprint — so a finding about one arm would arrive as a finding about
    the other. The whole lane rests on telling arms apart; `test_identity_rotation_keeps_its
    _findings` guards the distinctness as well as the collision.
    """
    key = SecretStore().put(body.model_dump())
    existing = await db.rows("SELECT id FROM integration_identities WHERE name=? AND target_origin=?",
                            (body.name, body.target_origin))
    await db.execute("INSERT INTO integration_identities VALUES(?,?,?)", (key, body.name, body.target_origin))
    out = {"id": key, "name": body.name, "target_origin": body.target_origin}
    if existing:
        out["already_registered"] = [row["id"] for row in existing]
        out["note"] = ("an identity with this name and origin is already registered. This is "
                       "a NEW identity: its handle is in every finding's fingerprint, so "
                       "findings from it will not update the earlier one's rows on an export "
                       "destination. To rotate a credential and keep its findings attached, "
                       "PUT the replacement to the existing identity instead")
    return out


@router.put("/identities/{identity_id}")
async def replace_identity(identity_id: str, body: Identity):
    old = await db.rows("SELECT * FROM integration_identities WHERE id=?", (identity_id,))
    if not old:
        raise HTTPException(404, "identity not found")
    if old[0]["target_origin"] != body.target_origin:
        raise HTTPException(422, "replacement must retain the identity origin")
    SecretStore().put(body.model_dump(), identity_id)
    await db.execute("UPDATE integration_identities SET name=? WHERE id=?", (body.name, identity_id))
    return {"id": identity_id, "name": body.name}


@router.get("/identities")
async def list_identities():
    return await db.rows("SELECT id,name,target_origin FROM integration_identities")


class ServiceSecret(BaseModel):
    token: str = Field(min_length=1)


@router.post("/secrets")
async def create_secret(body: ServiceSecret):
    return {"id": SecretStore().put(body.model_dump())}


@router.get("/sessions/{session_id}")
async def assessment_status(session_id: str):
    assessment = await db.rows("SELECT * FROM integration_assessments WHERE session_id=?", (session_id,))
    if not assessment:
        raise HTTPException(404, "integration assessment not found")
    stages = await db.rows("SELECT * FROM integration_stages WHERE session_id=? ORDER BY rowid", (session_id,))
    for stage in stages:
        stage["result"] = json.loads(stage["result"])
    return {"status": assessment[0]["status"], "config": json.loads(assessment[0]["config"]), "stages": stages,
            "exports": await db.rows("SELECT * FROM integration_exports WHERE session_id=?", (session_id,))}


@router.get("/sessions/{session_id}/endpoints")
async def endpoints(session_id: str):
    result = await db.rows("SELECT * FROM integration_endpoints WHERE session_id=? ORDER BY url,method", (session_id,))
    for item in result:
        item["sources"] = json.loads(item["sources"])
        item["parameters"] = json.loads(item.get("parameters") or "[]")
        from .inventory import eligible_test_cases
        # Answered with THIS endpoint's parameters, so a case that tests one is
        # listed only where there is one to give it.
        item["test_cases"] = eligible_test_cases(item["url"], item["method"],
                                                 parameters=item["parameters"])
    return result


@router.get("/sessions/{session_id}/preview")
async def launch_preview(session_id: str, identity_id: str | None = None):
    """What the next run will NOT reach, before it starts.

    The mirror of `/coverage`, which answers the same question afterwards. E-010 asks the
    preview to "state what the run **will not** do, not only what it will", because the
    cost of not saying so is measured: at the default budget the 2026-09-10 run tested
    one or two parameters per case out of eight and lost six of nine findings, reporting
    it only in observations nobody reads before launch.
    """
    from .inventory import preview

    rows = await db.rows("SELECT config,config_secret_id FROM integration_assessments "
                         "WHERE session_id=?", (session_id,))
    if not rows:
        raise HTTPException(404, "integration assessment not found")
    # The executable configuration, not the redacted copy: the budget arithmetic needs
    # `max_urls` and the selected cases, and the published copy is for reading.
    config = (AssessmentConfig.model_validate(
                  SecretStore().get(rows[0]["config_secret_id"])["assessment_config"])
              if rows[0].get("config_secret_id")
              else AssessmentConfig.model_validate_json(rows[0]["config"]))
    return await preview(session_id, config, identity_id)


class AuthorizationCheck(BaseModel):
    """Which arms to compare, and where the application names an object's owner."""
    caller: str = Field(min_length=1)
    owner: str = Field(min_length=1)
    # A dotted path into the response body: Juice Shop answers GET /rest/basket/1 with
    # {"status":"success","data":{"id":1,"UserId":1,...}}, so "data.UserId".
    owner_field: str = Field(min_length=1, max_length=200)
    # min_length, because `""` named no arm and then passed an `is None` presence check —
    # so the clause that makes a finding was never evaluated, and the caller was told
    # nothing was refused.
    anonymous: str | None = Field(default=None, min_length=1)


@router.post("/sessions/{session_id}/authorization")
async def authorization_check(session_id: str, body: AuthorizationCheck):
    """Object-level authorization, compared across two arms of a finished assessment.

    A lane stage carries one identity, so the three-arm check cannot run inside one. This
    asks the same question of what each stage recorded.

    READ `refused_because` BEFORE `findings`. A refusal means the comparison did not run —
    the arms described different surfaces, an identity declared no `subject_id`, there was
    no anonymous arm — and an empty `findings` list is then not a clean result. The payload
    says so in `establishes` for the same reason.
    """
    from .inventory import authorization_findings, cross_arm_authorization

    rows = await db.rows("SELECT target FROM integration_assessments WHERE session_id=?",
                         (session_id,))
    if not rows:
        raise HTTPException(404, "integration assessment not found")
    result = await cross_arm_authorization(session_id, body.caller, body.owner,
                                          body.owner_field, body.anonymous)
    # RECORDED, not merely returned. These used to exist only as this response body, so they
    # reached no report, no export and no triage — see `inventory.authorization_findings`.
    recorded = authorization_findings(rows[0]["target"], "object", result)
    await db.persist_findings(session_id, recorded)
    return {**result, "recorded": [f.fingerprint for f in recorded]}


class PrivilegedFunctionCheck(BaseModel):
    """Which arms to compare, and what privileged data looks like in a response.

    `marker` is the one thing the lane cannot infer. A function has no owner field to
    read — `GET /api/Users` returns every user and nothing in the payload says who may
    ask — so the operator names a substring that identifies PRIVILEGED data, e.g.
    `"email":"admin@juice-sh.op"`. It is never echoed back into a finding: it describes
    the application's private data, and a finding travels into an export.
    """
    privileged: str = Field(min_length=1)
    unprivileged: str = Field(min_length=1)
    marker: str = Field(min_length=1, max_length=512)
    anonymous: str | None = Field(default=None, min_length=1)


@router.post("/sessions/{session_id}/privileged-function")
async def privileged_function_check(session_id: str, body: PrivilegedFunctionCheck):
    """Function-level authorization, compared across arms of a finished assessment.

    The companion to `/authorization`, which asks the object-level question. Both exist
    because a lane stage carries ONE identity, so no single stage can hold the three arms
    a differential needs.

    READ `refused_because` BEFORE `findings`, for the same reason as the sibling route: a
    refusal means the comparison never ran — the arms share a declared role, a role was
    never declared, there was no anonymous arm, or this session already records the
    OPPOSITE privilege order for these two arms, in which case `contradicting_findings`
    names the rows to triage — and an empty `findings` list is then not a clean result.
    """
    from .inventory import authorization_findings, cross_arm_privileged_function

    rows = await db.rows("SELECT target FROM integration_assessments WHERE session_id=?",
                         (session_id,))
    if not rows:
        raise HTTPException(404, "integration assessment not found")
    result = await cross_arm_privileged_function(session_id, body.privileged,
                                                body.unprivileged, body.marker,
                                                body.anonymous)
    recorded = authorization_findings(rows[0]["target"], "function", result)
    await db.persist_findings(session_id, recorded)
    return {**result, "recorded": [f.fingerprint for f in recorded]}


@router.get("/sessions/{session_id}/coverage")
async def coverage_report(session_id: str, identity_id: str | None = None):
    """What the run did, what it did not, and why — per operation and identity.

    The lane already recorded all of it, scattered across each stage's observations, so
    the one question an operator has ("was this endpoint tested?") had no answer. §E-010
    gives the measured cost: at the default budget the 2026-09-10 run tested one or two
    parameters per case out of eight and lost six of nine findings, saying so only in
    per-case observations nobody reads.

    `summary` counts the states; `rows` carries every known (operation, parameter) pair
    including the ones nothing touched, because a report listing only what ran reads as
    a clean bill of health for everything it omits.
    """
    from .inventory import coverage, COVERAGE_STATES

    rows = await coverage(session_id, identity_id)
    summary = {state: 0 for state in COVERAGE_STATES}
    for row in rows:
        summary[row["state"]] = summary.get(row["state"], 0) + 1
    return {
        "rows": rows,
        "summary": summary,
        # Said in the payload, not only in the docs: a caller that adds `answered` to
        # `verified` and calls the total "tested" has made the claim this refuses to.
        "establishes": ("`verified` means a finding came out of the probe. `answered` "
                        "means bytes came back and nothing matched, which is not proof "
                        "the check exercised the application — a probe refused for want "
                        "of a token still answers. No state means `tested`."),
    }


@router.get("/sessions/{session_id}/evidence")
async def evidence_list(session_id: str):
    return await db.rows("SELECT * FROM integration_evidence WHERE session_id=?", (session_id,))


@router.get("/sessions/{session_id}/findings")
async def list_findings(session_id: str):
    return [json.loads(row["payload"]) for row in await db.rows("SELECT payload FROM integration_findings WHERE session_id=?", (session_id,))]


class TriageInput(BaseModel):
    state: Literal["open", "false_positive", "fixed"]
    note: str = Field(min_length=1, max_length=2000)


@router.post("/sessions/{session_id}/findings/{fingerprint}/triage")
async def triage(session_id: str, fingerprint: str, body: TriageInput):
    entries = await db.rows("SELECT payload FROM integration_findings WHERE session_id=? AND fingerprint=?", (session_id, fingerprint))
    if not entries:
        raise HTTPException(404, "finding not found")
    finding = json.loads(entries[0]["payload"])
    finding.update(triage_state=body.state, triage_note=body.note)
    await db.execute("UPDATE integration_findings SET payload=? WHERE session_id=? AND fingerprint=?", (json.dumps(finding), session_id, fingerprint))
    await db.evidence(session_id, "triage", "review", json.dumps({"fingerprint": fingerprint, **body.model_dump()}))
    return finding


@router.get("/evidence/{evidence_id}")
async def evidence_file(evidence_id: str):
    try:
        content = await db.evidence_bytes(evidence_id)
    except KeyError:
        raise HTTPException(404, "evidence not found")
    except db.EvidenceIntegrityError as exc:
        # Serving bytes that no longer match what was recorded is worse than
        # serving nothing: a reader would check a finding against them.
        raise HTTPException(404, str(exc))
    return Response(content, media_type="text/plain",
                    headers={"Content-Disposition": f'attachment; filename="{evidence_id}.txt"'})


@router.post("/sessions/{session_id}/defectdojo")
async def export_defectdojo(session_id: str, body: ExportConfig):
    try:
        return await export(session_id, body)
    except (ValueError, FileNotFoundError, KeyError) as exc:
        raise HTTPException(422, str(exc)) from exc


@router.post("/exports/{export_id}/reconcile")
async def reconcile_defectdojo(export_id: str, body: ExportConfig):
    try:
        return await reconcile(export_id, body)
    except (ValueError, FileNotFoundError, KeyError) as exc:
        raise HTTPException(422, str(exc)) from exc
    # `export()` catches RemoteError itself and records it on the export row, so
    # only reconciliation lets one reach a caller. RemoteError is a RuntimeError,
    # so it fell through to a bare 500 with no body — and the condition it most
    # often carries is the actionable one: "Multiple remote findings share one
    # fingerprint; reconcile the remote test", which the operator can only act on
    # if they are told. 502, because the remote is what did not cooperate.
    except RemoteError as exc:
        raise HTTPException(502, str(exc)) from exc
