"""Two thirds of the surface went unread and the report could not attribute a row of it.

`coverage()` indexed seven observation kinds and dropped the two that say the most.
Measured on the real Juice Shop run — the one whose findings the product is judged on:

    124 of 182 in-scope URLs were not read as the admin arm
    123 of 181 as the customer arm, 126 of 184 as the anonymous arm
    2 to 4 object instances per arm never fetched

six `surface_read_truncated` observations, one of which says in its own reason "so the
cross-arm authorization checks have no evidence for them" — and not one reached a coverage
row. `crawl_truncated` was dropped the same way.

THE FIRST FIX MADE THE REPORT WORSE, which is why the shape here is additive. Ranking on
state alone let an arm-wide record displace a better reason: those 459 `not_run` rows carried
"161 of 182 in-scope URLs were not tested; this check's share of the 260 URL budget is …"
from `WSTG-INFO-03`, and indexing the surface read replaced it with "2 of 30 object instances
… were not fetched" — same state, narrower fact, winning on insertion order. So an arm-wide
record loses every tie and its reason is appended instead. Re-measured: all 459 rows keep
their original reason AND gain the arm-wide one, and the state counts are byte-identical.

They are also exempt from the eligibility filter, and that exemption is the interesting part.
The filter exists because applying a case's truncation to the whole inventory labelled 41
pairs `not_run` where no selected case was eligible for them. The surface read is the case
that proves the rule rather than breaking it: its scope IS every in-scope URL, and
`ERLIK-SURFACE-READ` is deliberately absent from `eligible_test_cases`, which would otherwise
have dropped every one of these records on the floor.
"""
import json
import uuid

import pytest

from orchestrator.integrations.inventory import ARM_WIDE_OBSERVATIONS

URL = "http://app.test/a"


@pytest.fixture
async def store(tmp_path, monkeypatch):
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    await db.execute("INSERT INTO integration_assessments(session_id,target,status,config) "
                     "VALUES(?,?,?,?)", ("s", "http://app.test/", "completed", "{}"))
    await db.execute("INSERT INTO integration_endpoints"
                     "(session_id,url,method,identity_id,sources) VALUES(?,?,?,?,?)",
                     ("s", URL, "GET", "anonymous", json.dumps(["katana"])))
    return db


async def stage(store, *observations):
    await store.execute(
        "INSERT INTO integration_stages(id,session_id,adapter,identity_id,status,result) "
        "VALUES(?,?,?,?,?,?)", (uuid.uuid4().hex, "s", "testcases", "anonymous", "completed",
                                json.dumps({"observations": list(observations)})))


def truncation(kind="surface_read_truncated", case="ERLIK-SURFACE-READ",
               reason="126 of 184 in-scope URLs were not read as this identity"):
    return {"type": kind, "test_case_id": case, "url": None, "steps": [], "reason": reason}


async def only_row(store):
    from orchestrator.integrations.inventory import coverage
    rows = await coverage("s")
    assert len(rows) == 1, rows
    return rows[0]


# ------------------------------------------------------------------ it reaches the report

@pytest.mark.parametrize("kind", ARM_WIDE_OBSERVATIONS)
async def test_an_arm_wide_truncation_reaches_a_coverage_row(store, kind):
    await stage(store, truncation(kind=kind, case=""))
    row = await only_row(store)
    assert row["state"] == "not_run"
    assert "were not read" in row["reason"]


async def test_it_survives_the_eligibility_filter(store):
    """`ERLIK-SURFACE-READ` is in no endpoint's eligible set, so a case-wide record carrying
    it would have been filtered out for every pair. Asserted, because that is the clause the
    exemption exists for."""
    from orchestrator.integrations.inventory import eligible_test_cases
    assert "ERLIK-SURFACE-READ" not in eligible_test_cases(URL, "GET", [])
    await stage(store, truncation())
    assert (await only_row(store))["state"] == "not_run"


# ------------------------------------------------- and it never displaces a better answer

async def test_a_case_specific_reason_stays_primary(store):
    """The regression the first version of this caused."""
    # THE ARM-WIDE RECORD FIRST, deliberately. `sorted` is stable, so with the
    # case-specific record first the case wins on insertion order and the tie-break is never
    # exercised — ablating it changed nothing. This is the order the real run produced, and
    # the order in which the regression actually happened.
    await stage(store, truncation(),
                {"type": "test_case_truncated", "test_case_id": "WSTG-INFO-03", "url": None,
                 "steps": [], "reason": "161 of 182 in-scope URLs were not tested"})
    row = await only_row(store)
    assert row["reason"].startswith("161 of 182 in-scope URLs were not tested")
    assert "also 126 of 184" in row["reason"], "and the arm-wide fact is added, not dropped"
    assert row["test_case_id"] == "WSTG-INFO-03", "the primary record is still the case's"


@pytest.mark.parametrize("kind,state", [("test_case", "answered"),
                                        ("test_case_unreachable", "unreachable"),
                                        ("parameter_refused", "refused")])
async def test_it_cannot_lower_a_pair_that_was_reached(store, kind, state):
    """A read is not a check, and an arm-wide truncation elsewhere is not a fact about a pair
    something did probe. The state must be the probe's, and the reason must not be diluted."""
    await stage(store, {"type": kind, "test_case_id": "WSTG-CONF-06", "url": URL,
                        "parameter": None, "steps": [], "reason": ""},
                truncation())
    row = await only_row(store)
    assert row["state"] == state
    assert "also " not in (row["reason"] or "")


async def test_a_verified_pair_keeps_its_finding_reason(store):
    """`verified` outranks everything and says a finding came out of the pair; an arm-wide
    truncation must not be appended to that sentence."""
    from orchestrator.integrations.contracts import IntegrationFinding
    await store.persist_findings("s", [IntegrationFinding(
        fingerprint="f", title="t", url=URL, rule="erlik:authorization:object",
        source="cross-arm", identity="anonymous", basis="b")])
    await stage(store, truncation())
    row = await only_row(store)
    assert row["state"] == "verified"
    assert "also " not in (row["reason"] or "")


# ------------------------------------------------------------------------ the direction

async def test_the_only_direction_it_can_move_a_pair_is_downward(store):
    """The rule the old source-text assertion was standing in for: a READ must never be
    credited as a check. An observation that says work did not happen cannot do that."""
    from orchestrator.integrations.inventory import COVERAGE_STATES
    await stage(store, truncation())
    row = await only_row(store)
    assert COVERAGE_STATES.index(row["state"]) >= COVERAGE_STATES.index("not_run")


# ===========================================================================
# The class, not the two instances.
#
# `coverage()` has an allow-list, so any NEW observation kind is dropped by
# default — silently, which is how `surface_read_truncated` came to be written
# six times on the flagship run and read nowhere. This enumerates every kind the
# lane writes and forces each to be either indexed or exempted with a reason, so
# the next one fails here instead of disappearing.
# ===========================================================================

# Kinds that deliberately do NOT reach coverage, and why. A kind in neither this
# table nor `coverage`'s allow-list is a skip nobody is told about.
NOT_COVERAGE = {
    "security_assertion": "a finding was made; the finding is the record",
    "security_assertion_refused": "an operator assertion the validator rejected — about the "
                                  "declaration, not about whether an endpoint was tested",
    "api_contract_failure": "a schema mismatch a finding already carries",
    "finding_subsumed": "two detectors agreeing; the surviving finding is the record",
    "oob_callback": "a callback that arrived, which is evidence rather than coverage",
    "oob_probe": "the out-of-band probe record; its targets are the operator's declared "
                 "callback probes, which coverage does not model at all (E-033)",
    "workflow": "the operator's Schemathesis workflow, which has no endpoint pair",
}


def _kinds_written():
    import re
    from pathlib import Path
    found = set()
    for name in ("deterministic.py", "adapters.py", "interactsh.py", "service.py"):
        src = (Path("orchestrator/integrations") / name).read_text()
        for match in re.finditer(r"observations\.(?:append|extend)\(", src):
            window = src[match.start():match.start() + 400]
            found.update(re.findall(r'"type": "([a-z_]+)"', window))
    return found


def _kinds_indexed():
    import inspect
    import re

    from orchestrator.integrations import inventory
    source = inspect.getsource(inventory.coverage)
    block = source[source.index("if kind not in ("):]
    return set(re.findall(r'"([a-z_]+)"', block[:block.index("):")]))


def test_every_observation_kind_is_indexed_or_exempted():
    written, indexed = _kinds_written(), _kinds_indexed()
    assert written, "found no observation kinds at all; this guard would be vacuous"
    assert indexed, "could not read coverage()'s allow-list"
    unaccounted = written - indexed - set(NOT_COVERAGE)
    assert not unaccounted, (
        f"these observation kinds reach no coverage row and are not exempted: "
        f"{sorted(unaccounted)}. Either index them in `inventory.coverage` or add them to "
        f"NOT_COVERAGE with the reason they are not coverage.")


def test_the_exemptions_are_not_stale():
    """An exemption for a kind nobody writes any more is a comment pretending to be a
    decision."""
    written = _kinds_written()
    stale = [kind for kind in NOT_COVERAGE if kind not in written]
    assert stale == ["oob_probe"], (
        f"exemptions for kinds nothing writes: {stale}. `oob_probe` is the known one — it is "
        f"written through a helper this grep cannot see; everything else should be removed.")


def test_a_budget_truncation_names_one_case_per_record():
    """`test_case_id` was `",".join(remaining)`, and `coverage()` filters a case-wide record
    by `case not in eligible_test_cases(...)` — which returns individual ids, so a joined
    string matched nothing and the whole truncation was dropped for every pair."""
    import inspect

    from orchestrator.integrations import deterministic
    source = inspect.getsource(deterministic.CatalogueAdapter.run)
    assert '",".join(remaining)' not in source
    assert "for unrun in remaining:" in source


# ===========================================================================
# A stage that FAILED records no observations at all, so the arm-wide indexing
# above cannot help it — and every pair it never reached came out
# `not_attempted`, whose reason offers a by-design cause with confidence for an
# accident. Measured with one arm's catalogue stage set `failed` and its evidence
# removed: 176 of that arm's 185 rows said "it may not have been selected, or no
# selected case tests a parameter" and NOT ONE mentioned the failure.
# ===========================================================================

async def failed_arm(store, status="failed", adapter="testcases"):
    await store.execute(
        "INSERT INTO integration_stages(id,session_id,adapter,identity_id,status,reason,result) "
        "VALUES(?,?,?,?,?,?,?)", (uuid.uuid4().hex, "s", adapter, "anonymous", status,
                                  "adapter failed before parsing completed", "{}"))


async def test_a_pair_an_unfinished_arm_never_reached_says_so(store):
    await failed_arm(store)
    row = await only_row(store)
    assert row["state"] == "not_attempted"
    assert "did not finish reading" in row["reason"]
    assert "testcases: failed" in row["reason"]
    assert "not evidence that nothing tests it" in row["reason"]


async def test_the_original_reason_is_kept(store):
    """The by-design sentence is not wrong in general — it is the right answer for a pair no
    selected case covers. It stays, and the arm's state is added to it."""
    await failed_arm(store)
    row = await only_row(store)
    assert row["reason"].startswith("no catalogue check ran against this pair")


async def test_a_finished_arm_says_nothing(store):
    """The control. On all three recorded real runs this adds zero rows."""
    await failed_arm(store, status="completed")
    row = await only_row(store)
    assert "did not finish reading" not in (row["reason"] or "")


async def test_a_crawler_at_its_budget_is_not_an_unfinished_arm(store):
    """Scoped to the adapter whose evidence the comparison reads, for the same reason the
    cross-arm signal is: 7 of 57 stage rows across the recorded databases are `partial` from
    the URL budget, and all of them are crawlers doing what `max_urls` said."""
    await failed_arm(store, status="partial", adapter="katana")
    row = await only_row(store)
    assert "did not finish reading" not in (row["reason"] or "")


async def test_it_does_not_speak_for_another_arm(store):
    """Measured: with one arm failed, its 176 unreached rows name it and the other arms' 381
    rows are untouched."""
    await store.execute("INSERT INTO integration_endpoints"
                        "(session_id,url,method,identity_id,sources) VALUES(?,?,?,?,?)",
                        ("s", URL, "GET", "other-arm", json.dumps(["katana"])))
    await failed_arm(store)
    from orchestrator.integrations.inventory import coverage
    rows = {r["identity"]: r["reason"] or "" for r in await coverage("s")}
    assert "did not finish reading" in rows["anonymous"]
    assert "did not finish reading" not in rows["other-arm"]


async def test_a_pair_that_was_reached_is_not_annotated(store):
    """`answered` means a probe ran against this pair, and the arm's other troubles are not a
    fact about it."""
    await stage(store, {"type": "test_case", "test_case_id": "WSTG-CONF-06", "url": URL,
                        "parameter": None, "steps": [], "reason": ""})
    await failed_arm(store)
    row = await only_row(store)
    assert row["state"] == "answered"
    assert "did not finish reading" not in (row["reason"] or "")
