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
    key = SecretStore().put(body.model_dump())
    await db.execute("INSERT INTO integration_identities VALUES(?,?,?)", (key, body.name, body.target_origin))
    return {"id": key, "name": body.name, "target_origin": body.target_origin}


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
