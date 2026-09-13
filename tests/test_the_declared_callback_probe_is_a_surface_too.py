"""E-033: `coverage()` could not see the out-of-band case at all.

`coverage` enumerates `integration_endpoints`. The out-of-band case's targets come from
`config.callback.probes`, which no endpoint row holds, and `WSTG-INPV-19` never appears in
`eligible_test_cases` for any url or parameter. Measured on three sessions differing ONLY in
what happened to that case:

    the case ran against the probe        1 row, not_attempted
    the case was skipped, no collector    1 row, not_attempted
    the case was never selected           1 row, not_attempted

byte-identical, with the probe URL absent and `WSTG-INPV-19` absent. So the one check whose
whole purpose is to detect what an in-band response cannot show was invisible to the report
that exists to say what was tested — and the honest `test_case_not_run` observation added for
the skipped case (see `test_a_skipped_callback_case_is_recorded_as_skipped`) reached nothing.

NOT FIXED BY GIVING THE PROBE AN ENDPOINT ROW. Measured: `eligible_test_cases` returns 12
cases for a URL carrying a parameter, so the probe would become a target for every catalogue
check at a URL the operator nominated for ONE out-of-band payload, and those 12 would draw
from a URL budget shared with the real surface. The plan's warning stands: a case testable
somewhere it should not be is a worse defect than a case nobody can see.

A separate enumeration beside the endpoint rows, then. `integration_endpoints` is untouched.
"""
import hashlib
import json
import uuid

import pytest

from orchestrator.integrations.contracts import AssessmentConfig

PROBE = "https://app.test/fetch"
PARAM = "next"
CASE = "WSTG-INPV-19"


@pytest.fixture
async def lane(tmp_path, monkeypatch):
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    return db


def config(*, selected=True, probes=((PROBE, PARAM),)):
    # `AssessmentConfig` refuses the interactsh stage without explicit probes, and refuses
    # the out-of-band case without the stage — so "no probes" necessarily means neither.
    # That is the shape an assessment with no callback surface actually has.
    extra = ({"stages": ["interactsh"], "test_cases": [CASE] if selected else [],
              "callback": {"server": "https://callback.test",
                           "probes": [{"url": url, "parameter": name}
                                      for url, name in probes]}}
             if probes else {})
    return AssessmentConfig(
        scope={"allow_hosts": ["app.test"], "allow_ports": [443]},
        active=True, surface_read=False, **extra)


async def build(db, session, observations, *, selected=True, arms=("anonymous",),
                probes=((PROBE, PARAM),), endpoints=(("https://app.test/search", "q"),)):
    await db.execute("INSERT INTO integration_assessments(session_id,target,status,config) "
                     "VALUES(?,?,?,?)",
                     (session, "https://app.test/", "completed",
                      config(selected=selected, probes=probes).model_dump_json()))
    for arm in arms:
        await db.execute(
            "INSERT INTO integration_stages(id,session_id,adapter,identity_id,status,result) "
            "VALUES(?,?,?,?,?,?)",
            (uuid.uuid4().hex, session, "testcases" if selected else "interactsh", arm,
             "completed", json.dumps({"observations": observations})))
        for url, name in endpoints:
            await db.execute(
                "INSERT INTO integration_endpoints(session_id,url,method,identity_id,sources,"
                "parameters) VALUES(?,?,?,?,?,?)",
                (session, url, "GET", arm, json.dumps(["katana"]), json.dumps([name])))


def ran(url=PROBE, parameter=PARAM):
    return [{"type": "test_case", "test_case_id": CASE, "url": url, "parameter": parameter,
             "steps": [{"name": "probe", "success": True, "skipped": False, "error": None}],
             "evidence_id": "e1"}]


def not_run(url=PROBE, parameter=PARAM):
    return [{"type": "test_case_not_run", "test_case_id": CASE, "url": url,
             "parameter": parameter, "steps": [],
             "reason": ("the callback collector for this arm is unavailable, so no "
                        "out-of-band payload was issued and nothing was probed")}]


async def probe_row(db, session, url=PROBE):
    from orchestrator.integrations.inventory import coverage

    rows = await coverage(session)
    matching = [r for r in rows if url in r["url"]]
    assert len(matching) == 1, f"expected exactly one row for {url}: {matching}"
    return matching[0]


# ------------------------------------------------------------- the three outcomes differ


async def test_three_different_outcomes_are_three_different_reports(lane):
    """The headline. Byte-identical before; one digest each now."""
    from orchestrator.integrations.inventory import coverage

    digests = {}
    for label, (observations, selected) in {
            "ran": (ran(), True),
            "skipped": (not_run(), True),
            "unselected": ([], False)}.items():
        session = "s-" + label
        await build(lane, session, observations, selected=selected)
        rows = await coverage(session)
        digests[label] = hashlib.sha256(
            json.dumps(rows, sort_keys=True, default=str).encode()).hexdigest()
    assert len(set(digests.values())) == 3, (
        f"two of the three outcomes still report identically: {digests}")


@pytest.mark.parametrize("observations,selected,state", [
    pytest.param(ran(), True, "answered", id="the case ran against the probe"),
    pytest.param(not_run(), True, "not_run", id="the arm had no collector"),
    pytest.param([], False, "not_attempted", id="the case was never selected"),
])
async def test_the_probe_carries_the_state_the_run_earned(lane, observations, selected, state):
    await build(lane, "s", observations, selected=selected)
    row = await probe_row(lane, "s")
    assert row["state"] == state, row


async def test_a_skipped_probe_carries_the_reason_the_adapter_recorded(lane):
    """`test_a_skipped_callback_case_is_recorded_as_skipped` made the adapter record this.
    It reached nothing until now; the point of recording it was that coverage would say it."""
    await build(lane, "s", not_run(), selected=True)
    row = await probe_row(lane, "s")
    assert "collector for this arm is unavailable" in row["reason"], row["reason"]
    assert row["test_case_id"] == CASE


async def test_an_unselected_probe_does_not_blame_the_case_selection_generically(lane):
    """The generic `not_attempted` sentence — "it may not have been selected, or no selected
    case tests a parameter" — is about the catalogue's own surface. For a probe the operator
    nominated, it is the wrong answer offered with confidence."""
    await build(lane, "s", [], selected=False)
    row = await probe_row(lane, "s")
    assert "declared as a callback probe" in row["reason"], row["reason"]
    assert "no out-of-band case is selected" in row["reason"], row["reason"]
    assert "no selected case tests a parameter" not in row["reason"], (
        "the probe row inherited the catalogue's generic reason")


async def test_a_selected_case_that_reported_nothing_is_not_the_same_answer(lane):
    """Selected and silent means the stage did not get there. Unselected means nothing was
    ever going to. Both are "no record", and they are not the same fact."""
    await build(lane, "a", [], selected=True)
    await build(lane, "b", [], selected=False)
    selected_reason = (await probe_row(lane, "a"))["reason"]
    unselected_reason = (await probe_row(lane, "b"))["reason"]
    assert selected_reason != unselected_reason, selected_reason
    assert CASE in selected_reason, selected_reason
    assert "untested, not clean" in selected_reason, selected_reason


async def test_the_probe_row_names_itself_as_a_declared_probe(lane):
    """A reader must be able to tell a nominated probe from a crawled endpoint: a larger
    `max_urls` reaches more of the second and none of the first."""
    await build(lane, "s", ran(), selected=True)
    row = await probe_row(lane, "s")
    assert row["sources"] == ["callback"], row
    assert row["parameter"] == PARAM and row["method"] == "GET"
    assert PROBE.split("://", 1)[1].split("/", 1)[1] in row["operation"], row["operation"]


# --------------------------------------------------- and what it must NOT disturb


async def test_the_endpoint_inventory_is_untouched(lane):
    """The whole reason this is a separate enumeration. An endpoint row for the probe makes
    12 catalogue cases eligible at a URL the operator nominated for one out-of-band payload,
    and they would draw from a budget shared with the real surface."""
    await build(lane, "s", ran(), selected=True)
    await probe_row(lane, "s")          # force the report to be built
    rows = await lane.rows("SELECT url FROM integration_endpoints WHERE session_id='s'")
    assert [r["url"] for r in rows] == ["https://app.test/search"], (
        "the probe was written into integration_endpoints, which is the worse defect")


async def test_the_crawled_surface_reports_exactly_as_before(lane):
    """A regression guard on the rows that already worked."""
    from orchestrator.integrations.inventory import coverage

    await build(lane, "with", ran(), selected=True)
    await build(lane, "without", ran(), selected=True, probes=())
    crawled = {(r["url"], r["parameter"], r["state"], r["reason"])
               for r in await coverage("with") if "callback" not in r["sources"]}
    baseline = {(r["url"], r["parameter"], r["state"], r["reason"])
                for r in await coverage("without")}
    assert crawled == baseline, (
        f"adding the probe enumeration changed the crawled rows: "
        f"{crawled ^ baseline}")


async def test_a_probe_the_crawler_also_found_is_reported_once(lane):
    """Otherwise the report carries two rows for one pair — a defect of its own."""
    from orchestrator.integrations.inventory import coverage

    await build(lane, "s", ran(), selected=True, endpoints=((PROBE, PARAM),))
    rows = [r for r in await coverage("s") if PROBE in r["url"]]
    assert len(rows) == 1, rows
    assert rows[0]["state"] == "answered", rows[0]
    assert "katana" in rows[0]["sources"], (
        "the discovered endpoint row was displaced by the declared one")


async def test_an_assessment_with_no_probes_gains_no_rows(lane):
    from orchestrator.integrations.inventory import coverage, declared_probe_pairs

    await build(lane, "s", [], selected=False, probes=())
    assert await declared_probe_pairs("s") == []
    assert all("callback" not in r["sources"] for r in await coverage("s"))


async def test_every_arm_gets_its_own_probe_row(lane):
    """The probe is declared once and every arm runs it, so "was it tested" is a per-arm
    question — which is the question the cross-arm work made load-bearing."""
    from orchestrator.integrations.inventory import coverage

    await build(lane, "s", ran(), selected=True, arms=("anonymous", "id-admin"))
    rows = [r for r in await coverage("s") if "callback" in r["sources"]]
    assert {r["identity"] for r in rows} == {"anonymous", "id-admin"}, rows


async def test_one_arm_can_be_asked_about_on_its_own(lane):
    """`coverage(session, identity)` is what the route exposes per arm."""
    from orchestrator.integrations.inventory import coverage

    await build(lane, "s", ran(), selected=True, arms=("anonymous", "id-admin"))
    rows = [r for r in await coverage("s", "id-admin") if "callback" in r["sources"]]
    assert [r["identity"] for r in rows] == ["id-admin"], rows


async def test_every_declared_probe_is_enumerated(lane):
    from orchestrator.integrations.inventory import coverage

    probes = ((PROBE, PARAM), ("https://app.test/import", "src"))
    await build(lane, "s", ran(), selected=True, probes=probes)
    rows = [r for r in await coverage("s") if "callback" in r["sources"]]
    assert {r["parameter"] for r in rows} == {PARAM, "src"}, rows


async def test_the_case_that_owns_the_probe_keeps_its_own_budget_truncation(lane):
    """`eligible_test_cases` never names a collector case — it lists what the curl dialect
    can execute. A probe row filtered through it would drop the truncation of the very case
    that owns the probe, which is the one arm-wide fact that explains a silent probe."""
    from orchestrator.integrations.inventory import coverage

    truncated = [{"type": "test_case_truncated", "test_case_id": CASE, "url": None,
                  "steps": [], "reason": "1 of 2 targets were not reached before the "
                                         "stage budget ran out"}]
    await build(lane, "s", truncated, selected=True)
    row = await probe_row(lane, "s")
    assert row["state"] == "not_run", row
    assert "budget ran out" in row["reason"], row["reason"]


async def test_another_cases_truncation_does_not_reach_the_probe(lane):
    """The filter has to still filter. A SQL injection case's budget running out says
    nothing about an out-of-band probe it was never going to touch."""
    await build(lane, "s", [{"type": "test_case_truncated", "test_case_id": "WSTG-INPV-05.2",
                             "url": None, "steps": [],
                             "reason": "9 of 21 targets were not reached"}], selected=True)
    row = await probe_row(lane, "s")
    assert "9 of 21" not in row["reason"], row["reason"]


async def test_an_arm_with_no_crawled_endpoints_still_reports_its_failed_stage(lane):
    """The arm set for the unfinished-stage rollup was read from `integration_endpoints`, so
    an arm whose crawl found nothing was absent from it — and katana finding nothing is not
    hypothetical, it is what it does on DVWA. That arm's probe row would then be the one row
    in the report that could not say its catalogue stage had failed."""
    from orchestrator.integrations.inventory import coverage

    await lane.execute("INSERT INTO integration_assessments(session_id,target,status,config) "
                       "VALUES(?,?,?,?)",
                       ("s", "https://app.test/", "partial", config().model_dump_json()))
    await lane.execute(
        "INSERT INTO integration_stages(id,session_id,adapter,identity_id,status,reason,result)"
        " VALUES(?,?,?,?,?,?,?)",
        (uuid.uuid4().hex, "s", "testcases", "anonymous", "failed",
         "the worker container exited", json.dumps({"observations": []})))
    rows = [r for r in await coverage("s") if "callback" in r["sources"]]
    assert len(rows) == 1, rows
    assert "did not finish reading" in rows[0]["reason"], rows[0]["reason"]
    assert "testcases: failed" in rows[0]["reason"], rows[0]["reason"]
