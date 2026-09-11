"""Increment 5: what the run did, what it did not, and why.

The plan's slice sentence asks that an operator "sees its coverage", and §E-010 gives
the measured case: at the default `max_urls` with every runnable case selected, the
2026-09-10 run tested one or two parameters per case out of eight and **lost six of
nine findings**. It said so twelve times, in per-case observations nobody reads.

That is the shape of the gap. The lane already records everything needed — `test_case`,
`test_case_not_run`, `test_case_truncated`, `test_case_unreachable`, `parameter_refused`,
`form_url_withheld`, `inferred_from_javascript` — and nothing aggregates it, so the one
question an operator actually has ("was this endpoint tested?") has no answer. The same
shape as the schema digest in E-030: recorded, never read.

WHAT THE STATES DELIBERATELY DO NOT CLAIM. `answered` means the probe ran and the
target returned bytes. It does NOT mean the handler ran, and the lane cannot know that
it did: measured on DVWA, a probe refused for want of a CSRF token answers HTTP 200 with
389 bytes of PHP warnings, so the emptiness-only `test_case_unreachable` detector does
not fire and nothing was tested all the same. So `verified` is reserved for "a finding
came out of it" and `answered` says only what is known. Naming the state `tested` would
be the claim this project keeps removing.
"""
import json

import pytest


@pytest.fixture
async def store(tmp_path, monkeypatch):
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    return db


SQLI = "http://app.test/vulnerabilities/sqli/"
XSS = "http://app.test/vulnerabilities/xss_r/"
SEARCH = "http://app.test/rest/products/search"


async def endpoint(db, url, parameters, identity="anonymous", sources=("katana",)):
    await db.execute(
        "INSERT OR REPLACE INTO integration_endpoints"
        "(session_id,url,method,identity_id,sources,parameters) VALUES(?,?,?,?,?,?)",
        ("s", url, "GET", identity, json.dumps(list(sources)), json.dumps(parameters)))


async def stage(db, observations=(), findings=(), identity="anonymous", adapter="testcases"):
    import uuid
    result = {"status": "partial", "observations": list(observations), "metadata": {}}
    await db.execute(
        "INSERT INTO integration_stages(id,session_id,adapter,identity_id,status,result) "
        "VALUES(?,?,?,?,?,?)",
        (uuid.uuid4().hex, "s", adapter, identity, "partial", json.dumps(result)))
    for fingerprint, payload in findings:
        await db.execute("INSERT OR REPLACE INTO integration_findings VALUES(?,?,?)",
                         ("s", fingerprint, json.dumps(payload)))


# --------------------------------------------------------------- the states

async def test_a_probe_that_produced_a_finding_is_verified(store):
    from orchestrator.integrations.inventory import coverage

    await endpoint(store, SQLI, ["id"])
    await stage(store,
                observations=[{"type": "test_case", "test_case_id": "WSTG-INPV-05.2",
                               "url": SQLI, "parameter": "id", "steps": []}],
                findings=[("fp1", {"fingerprint": "fp1", "rule": "WSTG-INPV-05.2:single_quote",
                                   "url": SQLI, "parameter": "id", "identity": "anonymous",
                                   "severity": "high", "title": "t", "source": "testcases"})])

    rows = await coverage("s")
    entry = next(r for r in rows if r["parameter"] == "id")
    assert entry["state"] == "verified"
    assert entry["test_case_id"] == "WSTG-INPV-05.2"
    assert entry["reason"]


async def test_a_probe_that_ran_without_a_finding_is_answered_not_tested(store):
    """`answered` is the strongest honest word.

    Bytes came back and nothing matched. That is NOT proof the check exercised the
    application: measured on DVWA, a probe missing its CSRF token answers 200 with 389
    bytes of PHP warnings, which is non-empty and tests nothing.
    """
    from orchestrator.integrations.inventory import coverage

    await endpoint(store, SQLI, ["id"])
    await stage(store, observations=[{"type": "test_case", "test_case_id": "WSTG-INPV-05.2",
                                      "url": SQLI, "parameter": "id", "steps": []}])

    entry = next(r for r in await coverage("s") if r["parameter"] == "id")
    assert entry["state"] == "answered"
    assert "not proof" in entry["reason"].lower() or "does not" in entry["reason"].lower()
    assert entry["state"] != "tested", "no state may claim the handler ran"


async def test_an_empty_response_is_unreachable(store):
    from orchestrator.integrations.inventory import coverage

    await endpoint(store, SQLI, ["id"])
    await stage(store, observations=[
        {"type": "test_case_unreachable", "test_case_id": "WSTG-INPV-05.2",
         "url": SQLI, "parameter": "id", "steps": [],
         "reason": "all 4 executed steps received an empty response"}])

    entry = next(r for r in await coverage("s") if r["parameter"] == "id")
    assert entry["state"] == "unreachable"
    assert "empty response" in entry["reason"]


async def test_a_truncated_case_is_not_run_and_says_why(store):
    """The measured case: six of nine findings lost to the URL budget."""
    from orchestrator.integrations.inventory import coverage

    await endpoint(store, SQLI, ["id"])
    await stage(store, observations=[
        {"type": "test_case_truncated", "test_case_id": "WSTG-INPV-05.2", "url": None,
         "steps": [], "reason": "6 of 8 (endpoint, parameter) pairs were not tested; "
                                "raise max_urls to cover them"}])

    entry = next(r for r in await coverage("s") if r["parameter"] == "id")
    assert entry["state"] == "not_run"
    assert "max_urls" in entry["reason"]


async def test_a_refused_parameter_is_refused_with_its_reason(store):
    from orchestrator.integrations.inventory import coverage

    await endpoint(store, SQLI, ["id"])
    await stage(store, observations=[
        {"type": "parameter_refused", "test_case_id": "WSTG-INPV-05.2", "url": None,
         "steps": [], "parameters": ["id"],
         "reason": "these parameter names match this case's own evidence pattern"}])

    entry = next(r for r in await coverage("s") if r["parameter"] == "id")
    assert entry["state"] == "refused"
    assert "evidence pattern" in entry["reason"]


async def test_an_inferred_operation_is_never_reported_as_covered(store):
    """E-007: "Avoid turning an inferred URL into a claim of tested coverage."

    A route read out of a JavaScript body has not been requested by anything, and the
    lane deliberately withholds it from probing — so its coverage state must say so
    rather than leaving a reader to assume a gap is a pass.
    """
    from orchestrator.integrations.inventory import coverage

    await endpoint(store, SEARCH, ["q"], sources=("javascript",))
    await stage(store, observations=[])

    entry = next(r for r in await coverage("s") if r["parameter"] == "q")
    assert entry["state"] == "inferred"
    assert "not been requested" in entry["reason"] or "never" in entry["reason"]


async def test_an_endpoint_nothing_touched_is_not_silently_absent(store):
    """The question an operator has is "was this tested?", and the answer for most of
    the inventory is no. A coverage report that listed only what ran would read as a
    clean bill of health for everything it omitted."""
    from orchestrator.integrations.inventory import coverage

    await endpoint(store, SQLI, ["id"])
    await endpoint(store, XSS, ["name"])
    await stage(store, observations=[{"type": "test_case", "test_case_id": "WSTG-INPV-05.2",
                                      "url": SQLI, "parameter": "id", "steps": []}])

    rows = await coverage("s")
    states = {r["parameter"]: r["state"] for r in rows}
    assert states["id"] == "answered"
    assert states["name"] == "not_attempted", states
    untouched = next(r for r in rows if r["parameter"] == "name")
    assert untouched["reason"], "an untested operation must say why"


async def test_coverage_is_per_identity(store):
    """Two arms test different things, and merging them would claim one arm's coverage
    for the other — the defect the isolation gate exists to stop."""
    from orchestrator.integrations.inventory import coverage

    await endpoint(store, SQLI, ["id"], identity="low")
    await endpoint(store, SQLI, ["id"], identity="high")
    await stage(store, identity="low",
                observations=[{"type": "test_case", "test_case_id": "WSTG-INPV-05.2",
                               "url": SQLI, "parameter": "id", "steps": []}])

    low = {r["state"] for r in await coverage("s", "low")}
    high = {r["state"] for r in await coverage("s", "high")}
    assert low == {"answered"}
    assert high == {"not_attempted"}, high


# ------------------------------------------------------------- the route

async def test_the_route_counts_the_states_and_refuses_to_say_tested(store):
    from orchestrator.integrations.api import coverage_report

    await endpoint(store, SQLI, ["id"])
    await endpoint(store, XSS, ["name"])
    await endpoint(store, SEARCH, ["q"], sources=("javascript",))
    await stage(store, observations=[{"type": "test_case", "test_case_id": "WSTG-INPV-05.2",
                                      "url": SQLI, "parameter": "id", "steps": []}])

    payload = await coverage_report("s")
    assert payload["summary"]["answered"] == 1
    assert payload["summary"]["not_attempted"] == 1
    assert payload["summary"]["inferred"] == 1
    assert payload["summary"]["verified"] == 0
    assert len(payload["rows"]) == 3
    # Every state the route can report must be in the summary, so a zero is visible
    # rather than absent.
    from orchestrator.integrations.inventory import COVERAGE_STATES
    assert set(payload["summary"]) == set(COVERAGE_STATES)
    assert "not proof" in payload["establishes"]
    assert "No state means `tested`" in payload["establishes"]


async def test_the_route_can_narrow_to_one_identity(store):
    from orchestrator.integrations.api import coverage_report

    await endpoint(store, SQLI, ["id"], identity="low")
    await endpoint(store, SQLI, ["id"], identity="high")
    assert (await coverage_report("s", "low"))["summary"]["not_attempted"] == 1
    assert len((await coverage_report("s"))["rows"]) == 2


async def test_an_inferred_route_is_not_reported_as_merely_out_of_budget(store):
    """`not_run` says "a bigger `max_urls` would have covered this". For an inferred
    route that is false: nothing was ever going to probe it, because it is withheld
    from `parameters_by_url` by design. Measured on Juice Shop, where a case-wide
    truncation was being applied to all five inferred routes and hid them.

    Only a URL-SPECIFIC observation may override it — that would mean something really
    did reach the route.
    """
    from orchestrator.integrations.inventory import coverage

    await endpoint(store, SEARCH, ["q"], sources=("javascript",))
    await stage(store, observations=[
        {"type": "test_case_truncated", "test_case_id": "WSTG-INPV-05.2", "url": None,
         "steps": [], "reason": "3 of 7 pairs were not tested; raise max_urls"}])

    entry = next(r for r in await coverage("s") if r["parameter"] == "q")
    assert entry["state"] == "inferred", entry
    assert "max_urls" not in entry["reason"]


async def test_an_inferred_route_something_actually_reached_reports_what_happened(store):
    """If a probe did run against it — because an operator selected it — the real
    outcome wins over the `inferred` label."""
    from orchestrator.integrations.inventory import coverage

    await endpoint(store, SEARCH, ["q"], sources=("javascript", "katana"))
    await stage(store, observations=[
        {"type": "test_case", "test_case_id": "WSTG-INPV-05.2", "url": SEARCH,
         "parameter": "q", "steps": []}])

    entry = next(r for r in await coverage("s") if r["parameter"] == "q")
    assert entry["state"] == "answered", entry


async def test_a_probe_attaches_to_the_endpoint_row_it_came_from(store):
    """The join, and it was wrong in the first version of this function.

    `parameters_by_url` hands a case the QUERY-STRIPPED url — a crawled
    `/search?q=hello` becomes `/search`, because the query holds the sample value, not
    the name being tested. So the `test_case` observation records `/search` while the
    endpoint row records `/search?q=hello`, and matching them literally attaches almost
    nothing.

    Measured on Juice Shop: 13 probes ran and coverage credited 2 — a report claiming
    six times less coverage than the run delivered, which sends an operator chasing gaps
    that are not there. The launch preview predicted 13 correctly, which is how the
    disagreement surfaced.
    """
    from orchestrator.integrations.inventory import coverage

    await endpoint(store, "http://app.test/search?q=hello", ["q"])
    await stage(store, observations=[{"type": "test_case", "test_case_id": "WSTG-INPV-05.2",
                                      "url": "http://app.test/search", "parameter": "q",
                                      "steps": []}])

    entry = next(r for r in await coverage("s") if r["parameter"] == "q")
    assert entry["state"] == "answered", entry


async def test_a_finding_attaches_the_same_way(store):
    """A finding's url is the one the probe used, so it needs the same normalisation or
    a verified pair would be reported as merely answered."""
    from orchestrator.integrations.inventory import coverage

    await endpoint(store, "http://app.test/search?q=hello", ["q"])
    await stage(store,
                observations=[{"type": "test_case", "test_case_id": "WSTG-INPV-05.2",
                               "url": "http://app.test/search", "parameter": "q", "steps": []}],
                findings=[("fp", {"fingerprint": "fp", "rule": "WSTG-INPV-05.2:single_quote",
                                  "url": "http://app.test/search", "parameter": "q",
                                  "identity": "anonymous", "severity": "high",
                                  "title": "t", "source": "testcases"})])

    entry = next(r for r in await coverage("s") if r["parameter"] == "q")
    assert entry["state"] == "verified", entry


async def test_a_form_action_still_matches_with_its_query_intact(store):
    """The other direction. A form action keeps its companion query, and the probe runs
    against that exact URL — so normalising must not prevent it matching itself."""
    from orchestrator.integrations.inventory import coverage

    action = "http://app.test/vulnerabilities/sqli/?Submit=Submit"
    await endpoint(store, action, ["id"], sources=("form",))
    await stage(store, observations=[{"type": "test_case", "test_case_id": "WSTG-INPV-05.2",
                                      "url": action, "parameter": "id", "steps": []}])

    entry = next(r for r in await coverage("s") if r["parameter"] == "id")
    assert entry["state"] == "answered", entry
