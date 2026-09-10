"""Explicit import and synchronization to an existing self-hosted engagement/test.

Reimport alone leaves ordinary matched finding fields untouched. We therefore
resolve stable tool IDs and PATCH locally authoritative fields by remote ID.
Only new fingerprints are sent to the importer; missing local findings never
close remote findings. Ambiguous writes block subsequent exports to that test.
"""
import asyncio
import hashlib
import json
import uuid
from typing import Literal
from urllib.parse import urlsplit
from pydantic import Field, model_validator
from .contracts import StrictModel, AssessmentConfig, canonical_origin
from .security import SecretStore, runtime_root
from .runtime import Sandbox
from .adapters import rpc
from . import persistence as db


class ExportConfig(StrictModel):
    server: str
    secret_id: str
    action: Literal["import", "reimport"] = "reimport"
    test_id: int | None = Field(default=None, gt=0)
    engagement_id: int | None = Field(default=None, gt=0)
    test_title: str | None = Field(default=None, min_length=1, max_length=255)

    @model_validator(mode="after")
    def validate_destination(self):
        u = urlsplit(self.server)
        if u.scheme != "https" or not u.hostname or u.username or u.path not in ("", "/") or u.query or u.fragment:
            raise ValueError("DefectDojo requires an explicit HTTPS origin")
        self.server = canonical_origin(self.server)
        if self.server.endswith(":443"):
            self.server = self.server[:-4]
        if self.action == "import":
            if not self.engagement_id or not self.test_title or not self.test_title.strip() or self.test_id:
                raise ValueError("initial import requires an existing engagement_id and test_title, without test_id")
        elif not self.test_id or self.engagement_id or self.test_title:
            raise ValueError("reimport requires an existing test_id, without engagement_id or test_title")
        return self

    @property
    def destination(self):
        if self.action == "reimport":
            return self.server + f"/test/{self.test_id}"
        title_hash = hashlib.sha256(self.test_title.encode()).hexdigest()
        return self.server + f"/engagement/{self.engagement_id}/erlik/{title_hash}"


_lock = asyncio.Lock()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def remote_mismatches(item, expected):
    """Which of the fields we asserted the remote did NOT come back with.

    Named, not counted: "did not retain the locally authoritative finding
    fields" is true of a title truncation and of DefectDojo deriving its own
    mitigation state, and those need opposite responses from whoever reads the
    export row.
    """
    differing = []
    for key, value in expected.items():
        if key == "endpoints":
            continue
        actual = item.get(key)
        # DefectDojo 2.58.4 normalizes Finding.title using titlecase and a
        # 511-character limit in the model's save method.
        if key == "title" and isinstance(actual, str) and isinstance(value, str):
            if actual.casefold() != value[:511].casefold():
                differing.append(f"{key}({actual!r}!={value!r})")
        elif actual != value:
            differing.append(f"{key}({actual!r}!={value!r})")
    return differing


def matches_remote(item, expected):
    return not remote_mismatches(item, expected)


def _quoted(evidence: str) -> str:
    """Target bytes, indented into a markdown code block.

    INDENTATION, not a fence. DefectDojo renders a description as markdown, and
    the content here is chosen by the application under test — so a fence can be
    closed from inside it with three backticks and whatever follows is rendered
    as markup in the client's own issue tracker. Four leading spaces cannot be
    escaped by anything the content contains.

    Carriage returns go too: a lone CR rewinds a line in some renderers, which
    is how quoted evidence gets to hide what it actually says.
    """
    lines = evidence.replace("\r", "").split("\n")
    return "\n".join("    " + line for line in lines)


def finding_payload(finding):
    triage = finding.get("triage_state", "open")
    description = finding["basis"]
    # THE PROOF TRAVELS WITH THE CLAIM. Without this the description was one
    # sentence — "regex evaluator matched captured tool output" — and a client
    # could not check a HIGH-severity finding against anything. Labelled as the
    # application's own output, because that is what a reader needs to know
    # about it before trusting a single character.
    if finding.get("evidence"):
        description += ("\n\nEvidence — captured from the application's own response, "
                        "with known credentials redacted:\n\n" + _quoted(finding["evidence"]))
    if finding.get("triage_note"):
        description += "\n\nErlik triage: " + finding["triage_note"]
    payload = {"title": finding["title"], "description": description,
               "severity": finding["severity"].capitalize() if finding["severity"] != "informational" else "Info",
               "unique_id_from_tool": finding["fingerprint"], "vuln_id_from_tool": finding["fingerprint"],
               "endpoints": [finding["url"]], "active": triage == "open", "false_p": triage == "false_positive",
               "verified": finding["confidence"] == "confirmed" and triage != "false_positive",
               "static_finding": False, "dynamic_finding": True}
    # `is_mitigated` is only ours to assert while WE are the ones claiming it.
    # Closing a finding as a false positive hands the mitigation lifecycle to
    # DefectDojo: 2.58.4 sets is_mitigated=True on the closed finding, so
    # sending is_mitigated=False made every triage export fail its own
    # read-back check and land as `uncertain` — a write that had in fact
    # succeeded, reported as one that might not have. Verified against a live
    # 2.58.4 instance; the drift was exactly is_mitigated(True!=False).
    if triage != "false_positive":
        payload["is_mitigated"] = triage == "fixed"
    return payload


class RemoteError(RuntimeError):
    def __init__(self, status, message):
        self.status = status
        super().__init__(message)


async def remote(sandbox, config, token, audit, path, *, method="GET", body=None, fields=None, report=None):
    # Paths are generated locally. Never follow pagination links or redirects
    # supplied by the remote server; they cannot grant another service scope.
    args = {"action": "defectdojo", "url": config.server + path, "token": token}
    if method == "POST":
        args.update(fields=fields, report=report)
    else:
        args.update(method=method, body=body)
    response = await rpc(sandbox, args)
    audit.append({"method": method, "path": path, "status": response["status"], "body": response.get("body", "")})
    if response["status"] not in (200, 201):
        raise RemoteError(response["status"], f"DefectDojo {method} returned HTTP {response['status']}")
    try:
        return json.loads(response["body"])
    except (ValueError, TypeError) as exc:
        raise RemoteError(502, "DefectDojo returned invalid JSON") from exc


async def remote_inventory(sandbox, config, token, audit, test_id):
    records = {}
    offset = 0
    for _ in range(1000):
        page = await remote(sandbox, config, token, audit, f"/api/v2/findings/?test={test_id}&limit=100&offset={offset}")
        if not isinstance(page, dict) or not isinstance(page.get("results"), list):
            raise RemoteError(502, "DefectDojo finding inventory was malformed")
        for item in page["results"]:
            if not isinstance(item, dict) or item.get("test") != test_id or not isinstance(item.get("id"), int):
                raise RemoteError(502, "DefectDojo returned findings outside the selected test")
            fingerprint = item.get("unique_id_from_tool")
            if fingerprint:
                if fingerprint in records:
                    raise RemoteError(409, "Multiple remote findings share one fingerprint; reconcile the remote test")
                records[fingerprint] = item
        if not page.get("next"):
            return records
        if not page["results"]:
            break
        offset += len(page["results"])
    raise RemoteError(502, "DefectDojo finding inventory exceeded its pagination bound")


async def reconcile(export_id, config: ExportConfig):
    """Resolve an uncertain write using read-only comparison, without replay.

    An operator supplies the exact test ID if the initial response was lost.
    Nothing is marked completed unless every intended local field is present.
    """
    if config.action != "reimport":
        raise ValueError("reconciliation requires the existing remote test_id")
    async with _lock:
        rows = await db.rows("SELECT * FROM integration_exports WHERE id=?", (export_id,))
        if not rows:
            raise ValueError("export not found")
        record = rows[0]
        if not record["destination"].startswith(config.server + "/"):
            raise ValueError("reconciliation server must match the original export")
        if record["remote_test_id"] and record["remote_test_id"] != config.test_id:
            raise ValueError("reconciliation test_id must match the original export")
        if record["status"] not in ("uncertain", "running"):
            return record
        if not record.get("evidence_id"):
            raise ValueError("export evidence unavailable; inspect the remote test manually")
        original = json.loads((runtime_root() / "evidence" / record["evidence_id"]).read_text())
        expected = original[0]["report"]["findings"]
        assessment = (await db.rows("SELECT config FROM integration_assessments WHERE session_id=?", (record["session_id"],)))[0]
        token = SecretStore().get(config.secret_id)["token"]
        audit = []
        try:
            async with Sandbox(AssessmentConfig.model_validate_json(assessment["config"]), services=[config.server]) as sandbox:
                inventory = await remote_inventory(sandbox, config, token, audit, config.test_id)
            matches = all(f["unique_id_from_tool"] in inventory and matches_remote(
                inventory[f["unique_id_from_tool"]], f) for f in expected)
            # Empty uncertain initial imports cannot be identified by content;
            # verify the supplied test exists before considering it resolved.
            if not expected:
                async with Sandbox(AssessmentConfig.model_validate_json(assessment["config"]), services=[config.server]) as sandbox:
                    test = await remote(sandbox, config, token, audit, f"/api/v2/tests/{config.test_id}/")
                    matches = test.get("id") == config.test_id
            if not matches:
                await db.execute("UPDATE integration_exports SET detail='Remote state differs from intended export; no requests replayed' WHERE id=?", (export_id,))
            else:
                for finding in expected:
                    fp = finding["unique_id_from_tool"]
                    await db.execute("INSERT OR REPLACE INTO integration_remote_findings(server,remote_test_id,fingerprint,remote_finding_id,payload_hash) VALUES(?,?,?,?,?)",
                                     (config.server, config.test_id, fp, inventory[fp]["id"], digest(finding)))
                await db.execute("INSERT OR REPLACE INTO integration_export_destinations(destination,server,remote_test_id,remote_engagement_id) VALUES(?,?,?,?)",
                                 (record["destination"], config.server, config.test_id, record["remote_engagement_id"]))
                await db.execute("UPDATE integration_exports SET status='completed',remote_test_id=?,detail='Remote state verified; no requests replayed' WHERE id=?", (config.test_id, export_id))
        finally:
            await db.evidence(record["session_id"], "defectdojo-" + export_id, "defectdojo_reconciliation", json.dumps(audit), [token])
        return (await db.rows("SELECT * FROM integration_exports WHERE id=?", (export_id,)))[0]


async def export(session_id, config: ExportConfig):
    async with _lock:
        assessment = await db.rows("SELECT * FROM integration_assessments WHERE session_id=?", (session_id,))
        if not assessment:
            raise ValueError("integration assessment not found")
        findings = [json.loads(row["payload"]) for row in await db.rows(
            "SELECT payload FROM integration_findings WHERE session_id=? ORDER BY fingerprint", (session_id,))]
        report = {"findings": [finding_payload(f) for f in findings]}
        payload_hash, destination = digest(report), config.destination
        mapping = await db.rows("SELECT * FROM integration_export_destinations WHERE destination=?", (destination,))
        test_id = mapping[0]["remote_test_id"] if mapping else config.test_id
        # Guard the remote destination, not merely one session/hash. A changed
        # report must not bypass uncertainty about a previous remote write.
        blocking = await db.rows("SELECT * FROM integration_exports WHERE status IN ('running','uncertain') "
            "AND (destination=? OR (remote_test_id=? AND instr(destination,?)=1)) ORDER BY rowid DESC",
            (destination, test_id, config.server + "/"))
        if blocking:
            return blocking[0]
        prior = await db.rows("SELECT * FROM integration_exports WHERE status='completed' "
            "AND (destination=? OR (remote_test_id=? AND instr(destination,?)=1)) ORDER BY rowid DESC LIMIT 1",
            (destination, test_id, config.server + "/"))
        if prior and prior[0]["payload_hash"] == payload_hash:
            return prior[0]
        key = uuid.uuid4().hex
        action = "reimport" if test_id else "import"
        await db.execute("INSERT INTO integration_exports(id,session_id,destination,payload_hash,status,remote_test_id,action,remote_engagement_id) VALUES(?,?,?,?,?,?,?,?)",
                         (key, session_id, destination, payload_hash, "running", test_id, action, config.engagement_id))
        audit = [{"action": action, "assessment_status": assessment[0]["status"], "report": report,
                  "close_old_findings": False, "local_triage_authoritative": True}]
        token = None
        wrote = False
        status, detail = "completed", "Synchronized by stable fingerprint"
        try:
            token = SecretStore().get(config.secret_id)["token"]
            assessment_config = AssessmentConfig.model_validate_json(assessment[0]["config"])
            async with Sandbox(assessment_config, services=[config.server]) as sandbox:
                inventory = await remote_inventory(sandbox, config, token, audit, test_id) if test_id and findings else {}
                new_findings = [f for f in report["findings"] if f["unique_id_from_tool"] not in inventory]
                if not test_id or new_findings or not findings:
                    fields = {"scan_type": "Generic Findings Import", "close_old_findings": "false",
                              "close_old_findings_product_scope": "false", "do_not_reactivate": "true",
                              "background_import": "false", "auto_create_context": "false"}
                    fields.update({"test": str(test_id)} if test_id else {
                        "engagement": str(config.engagement_id), "test_title": config.test_title})
                    wrote = True
                    response = await remote(sandbox, config, token, audit, f"/api/v2/{action}-scan/",
                                            method="POST", fields=fields, report={"findings": new_findings})
                    returned_test = response.get("test_id", response.get("test"))
                    if isinstance(returned_test, dict):
                        returned_test = returned_test.get("id")
                    if isinstance(returned_test, bool) or not isinstance(returned_test, int) or returned_test <= 0 or (test_id and returned_test != test_id):
                        raise RemoteError(502, "DefectDojo did not return the selected remote test ID")
                    test_id = returned_test
                    await db.execute("UPDATE integration_exports SET remote_test_id=? WHERE id=?", (test_id, key))
                    await db.execute("INSERT OR REPLACE INTO integration_export_destinations(destination,server,remote_test_id,remote_engagement_id) VALUES(?,?,?,?)",
                                     (destination, config.server, test_id, config.engagement_id))
                    if findings:
                        inventory = await remote_inventory(sandbox, config, token, audit, test_id)
                for finding in report["findings"]:
                    fingerprint = finding["unique_id_from_tool"]
                    item = inventory.get(fingerprint)
                    if item is None:
                        raise RemoteError(502, "Imported fingerprint missing from remote test; check importer deduplication settings")
                    # Endpoints are stable within a fingerprint; the API expects
                    # endpoint primary keys, so never send URLs in a PATCH.
                    patch = {k: v for k, v in finding.items() if k != "endpoints"}
                    if not matches_remote(item, patch):
                        wrote = True
                        updated = await remote(sandbox, config, token, audit, f"/api/v2/findings/{item['id']}/", method="PATCH", body=patch)
                        if updated.get("id") != item["id"] or updated.get("unique_id_from_tool") != fingerprint:
                            raise RemoteError(502, "DefectDojo returned a mismatched finding after update")
                        drifted = remote_mismatches(updated, patch)
                        if drifted:
                            raise RemoteError(502, "DefectDojo did not retain the locally authoritative finding "
                                                   "fields: " + ", ".join(drifted))
                    await db.execute("INSERT OR REPLACE INTO integration_remote_findings(server,remote_test_id,fingerprint,remote_finding_id,payload_hash) VALUES(?,?,?,?,?)",
                                     (config.server, test_id, fingerprint, item["id"], digest(finding)))
        except RemoteError as exc:
            # A rejected read has not changed anything; after any successful or
            # ambiguous write, retain uncertainty even if a later PATCH fails.
            status = "uncertain" if wrote else "failed"
            detail = str(exc)
            if exc.status < 500 and exc.status != 202 and len(audit) == 2 and audit[-1].get("method") == "POST":
                status = "failed"  # initial request explicitly rejected
        except (Exception, asyncio.CancelledError):
            await db.execute("UPDATE integration_exports SET status='uncertain',detail='Check the remote test before retrying' WHERE id=?", (key,))
            raise
        finally:
            evidence_id = await db.evidence(session_id, "defectdojo-" + key, "defectdojo_export", json.dumps(audit), [token] if token else ())
            await db.execute("UPDATE integration_exports SET evidence_id=? WHERE id=?", (evidence_id, key))
        await db.execute("UPDATE integration_exports SET status=?,detail=? WHERE id=?", (status, detail, key))
        return (await db.rows("SELECT * FROM integration_exports WHERE id=?", (key,)))[0]
