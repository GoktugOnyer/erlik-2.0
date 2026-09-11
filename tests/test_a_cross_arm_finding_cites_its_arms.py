"""The product's strongest findings were the only ones a reader could not check.

Measured on the real Juice Shop assessment: eleven findings, nine citing a resolvable
evidence artifact — and the two citing none were the two the lane graded highest, the only
two that set DefectDojo's `verified=True`. Of five high-severity findings, three cited
evidence; of the two confirmed ones, zero did. The six artifacts existed the whole time,
read and discarded by `arm_responses`, which holds `row["id"]` in its hand.

IT HAS TO COME FROM THE SATISFYING KEY, not from the URL. A URL does not have one artifact:
27 of one arm's 96 urls carry more than one `(url, case, step, parameter)` key, sixteen of
them for `/socket.io/`. A lookup by URL afterwards would hand a reader a capture no clause
ever read — the recurring shape where a confident output comes from a path that did nothing.

AND IT PUBLISHES NOTHING NEW. `evidence_ids` appears nowhere in `defectdojo.py`; it feeds
`service.report`, `GET /sessions/{id}/findings`, and the download route, which re-checks the
stored digest before serving a byte. The captures themselves hold no credential — the proxy
injects identity headers after curl has emitted the request, so a capture cannot contain
them — which the assertion below states rather than assumes.
"""
import json
import uuid

import pytest

TARGET = "http://app.test/"
MARKER = '"email":"target@app.test"'
MARKED = ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
          '{"data":{"id":7,"email":"target@app.test"}}')
REFUSED = "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html\r\n\r\nno"
URL = "http://app.test/api/Users/7"


@pytest.fixture
async def lab(tmp_path, monkeypatch):
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    from orchestrator.integrations.security import SecretStore
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    await db.execute("INSERT INTO integration_assessments(session_id,target,status,config) "
                     "VALUES(?,?,?,?)", ("s", TARGET, "completed", "{}"))
    return {"db": db, "h": {
        "admin": SecretStore().put({"name": "admin", "target_origin": "http://app.test",
                                    "role": "admin", "subject_id": "1"}),
        "jim": SecretStore().put({"name": "jim", "target_origin": "http://app.test",
                                  "role": "customer", "subject_id": "2"})}}


async def surface(lab, arm, output, url=URL, case="ERLIK-SURFACE-READ", step="read"):
    stage = uuid.uuid4().hex
    await lab["db"].execute(
        "INSERT INTO integration_stages(id,session_id,adapter,identity_id,status) "
        "VALUES(?,?,?,?,?)", (stage, "s", "testcases", arm, "completed"))
    await lab["db"].execute(
        "INSERT OR IGNORE INTO integration_endpoints"
        "(session_id,url,method,identity_id,sources) VALUES(?,?,?,?,?)",
        ("s", url, "GET", arm, json.dumps(["katana"])))
    return await lab["db"].evidence("s", stage, f"testcase:{case}", json.dumps({
        "test_case_id": case, "target": {"url": url},
        "steps": [{"step": step, "output": output}]}))


async def three_arms(lab, **kw):
    return {
        "admin": await surface(lab, lab["h"]["admin"], MARKED, **kw),
        "jim": await surface(lab, lab["h"]["jim"], MARKED, **kw),
        "anonymous": await surface(lab, "anonymous", REFUSED, **kw),
    }


async def findings(lab):
    from orchestrator.integrations.inventory import (authorization_findings,
                                                     cross_arm_privileged_function)
    result = await cross_arm_privileged_function("s", lab["h"]["admin"], lab["h"]["jim"],
                                                 MARKER, anonymous="anonymous")
    assert result["refused_because"] == [], result["refused_because"]
    return result, authorization_findings(TARGET, "function", result)


# ------------------------------------------------------------------- it cites all three

async def test_the_finding_cites_one_artifact_per_arm(lab):
    ids = await three_arms(lab)
    _, found = await findings(lab)
    assert len(found) == 1
    assert found[0].evidence_ids == sorted(ids.values())


async def test_every_cited_artifact_resolves(lab):
    """Through the same digest check the download route performs, because an id that does
    not resolve is worse than no id: a reader would go looking."""
    await three_arms(lab)
    _, found = await findings(lab)
    for evidence_id in found[0].evidence_ids:
        raw = await lab["db"].evidence_bytes(evidence_id)
        assert json.loads(raw)["target"]["url"] == URL


async def test_the_evidence_text_says_where_to_read_them(lab):
    ids = await three_arms(lab)
    _, found = await findings(lab)
    for evidence_id in ids.values():
        assert f"/api/integrations/evidence/{evidence_id}" in found[0].evidence


async def test_the_citation_survives_a_collapsed_group(lab):
    """`evidence` is capped, so the order matters: a collapsed group of long urls would
    otherwise truncate the proof away and keep the context."""
    from orchestrator.integrations.contracts import MAX_EVIDENCE_CHARS
    from orchestrator.integrations.inventory import authorization_findings
    ids = await three_arms(lab)
    result, _ = await findings(lab)
    padded = dict(result)
    long_urls = [f"http://app.test/api/Users/7?to=" + "x" * 90 + str(n) for n in range(14)]
    padded["findings"] = [{**result["findings"][0], "url": u}
                          for u in [URL] + long_urls]
    found = authorization_findings(TARGET, "function", padded)
    assert len(found) == 2, "the padded urls share a key; the real one keeps its own"
    collapsed = [f for f in found if "urls that a fingerprint" in f.evidence][0]
    assert len(collapsed.evidence) <= MAX_EVIDENCE_CHARS
    assert "/api/integrations/evidence/" in collapsed.evidence, (
        "the proof is named before the group, so the bound cannot eat it")


# ------------------------------------------------- and never an artifact nothing read

async def test_an_ambiguous_capture_is_not_cited(lab):
    """`arm_responses` drops a key recorded twice with different captures, because neither
    is more the arm's answer than the other. A finding must not then cite either: it would
    offer as proof a capture the comparison refused to use."""
    from orchestrator.integrations.inventory import arm_responses
    await three_arms(lab)
    await surface(lab, lab["h"]["admin"], REFUSED)        # same key, different bytes
    out, ambiguous, artifacts = await arm_responses("s", lab["h"]["admin"])
    assert ambiguous, "the premise: this key is now ambiguous"
    assert set(artifacts) == set(out), "no id survives for a dropped key"


async def test_two_keys_on_one_url_cite_the_one_that_satisfied_the_clauses(lab):
    """The decisive correctness point. A second recorded read of the SAME url under a
    different test case must not change which artifacts the finding cites."""
    ids = await three_arms(lab)
    for arm in ("admin", "jim"):
        await surface(lab, lab["h"][arm], REFUSED, case="WSTG-OTHER", step="probe")
    await surface(lab, "anonymous", REFUSED, case="WSTG-OTHER", step="probe")
    _, found = await findings(lab)
    assert len(found) == 1
    assert found[0].evidence_ids == sorted(ids.values()), (
        "the surface read satisfied the clauses; the other case's captures are not the proof")


async def test_a_catalogue_finding_still_cites_its_own(lab):
    """The change must not disturb the producers that already worked."""
    from orchestrator.integrations.contracts import IntegrationFinding
    assert IntegrationFinding(fingerprint="f", title="t", url="u", rule="r", source="zap",
                              basis="b", evidence_ids=["abc"]).evidence_ids == ["abc"]
