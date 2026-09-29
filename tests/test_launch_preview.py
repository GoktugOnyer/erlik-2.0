"""Increment 5, second half: say what the run will NOT do, before it starts.

E-010's acceptance is narrow — "the preview shows per-case target budgets before the run
starts" — and §E-010 gives the reason: "at the default `max_urls` with every runnable
case selected, the 2026-09-10 run tested one or two parameters per case out of eight and
lost six of nine findings. It said so twelve times, in per-case observations nobody reads
before launch."

Measured again while building the coverage report that is this preview's mirror: on Juice
Shop at `max_urls=140` — seven times the default share per case — **158 of 163
(endpoint, parameter) pairs were still not run.** That is the number an operator needs
before launching, not after.

The arithmetic is shared with the runner rather than restated. Two copies of one fact is
the defect this codebase already names about its own catalogue lists: "two
hand-maintained lists and one parser is two claims and one fact, and the claims were
already stale".
"""
import json

import pytest

from orchestrator.integrations.contracts import AssessmentConfig


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


async def endpoint(db, url, parameters, identity="anonymous"):
    await db.execute(
        "INSERT OR REPLACE INTO integration_endpoints"
        "(session_id,url,method,identity_id,sources,parameters) VALUES(?,?,?,?,?,?)",
        ("s", url, "GET", identity, json.dumps(["katana"]), json.dumps(parameters)))


async def stage(db, observations=()):
    import uuid
    await db.execute(
        "INSERT INTO integration_stages(id,session_id,adapter,identity_id,status,result) "
        "VALUES(?,?,?,?,?,?)",
        (uuid.uuid4().hex, "s", "testcases", "anonymous", "partial",
         json.dumps({"status": "partial", "observations": list(observations)})))


def config(**kw):
    #  because selecting deterministic probes requires it — the product
    # refuses the combination otherwise, which is correct and is not what is under test.
    kw.setdefault("active", True)
    return AssessmentConfig(scope={"allow_hosts": ["app.test"], "allow_ports": [80]}, **kw)


def test_the_budget_arithmetic_has_one_definition():
    """The runner and the preview must not each carry their own copy."""
    from pathlib import Path
    from orchestrator.integrations.deterministic import target_budget

    source = Path("orchestrator/integrations/deterministic.py").read_text()
    assert source.count("def target_budget") == 1, "the arithmetic is defined twice"
    # 40 urls over 2 cases is 20 each; a 4-step case gets 5 targets.
    assert target_budget(max_urls=40, selected=2, steps=4) == 5
    assert target_budget(max_urls=40, selected=2, steps=1) == 20
    # Never zero: a selected case always gets at least one target, or selecting it
    # would silently mean nothing.
    assert target_budget(max_urls=1, selected=50, steps=50) == 1


async def test_the_preview_states_what_will_not_be_reached(store):
    from orchestrator.integrations.inventory import preview

    for n in range(8):
        await endpoint(store, f"http://app.test/p{n}", ["q"])
    cfg = config(max_urls=20, test_cases=["WSTG-INPV-05.2", "WSTG-INPV-11.2"])

    plan = await preview("s", cfg)
    by_case = {row["test_case_id"]: row for row in plan["cases"]}
    assert set(by_case) == {"WSTG-INPV-05.2", "WSTG-INPV-11.2"}
    for row in by_case.values():
        assert row["eligible_pairs"] == 8
        assert row["target_budget"] < 8, row
        assert row["not_reached"] == row["eligible_pairs"] - row["target_budget"]
        assert row["not_reached"] > 0
    assert plan["not_reached"] == sum(r["not_reached"] for r in by_case.values())
    assert "max_urls" in plan["remedy"]


async def test_a_budget_that_covers_everything_says_so(store):
    """The preview must be able to say "nothing is left out", or a non-zero number
    carries no information."""
    from orchestrator.integrations.inventory import preview

    await endpoint(store, "http://app.test/p0", ["q"])
    plan = await preview("s", config(max_urls=500, test_cases=["WSTG-INPV-05.2"]))
    assert plan["not_reached"] == 0
    assert plan["cases"][0]["eligible_pairs"] == 1
    assert plan["cases"][0]["target_budget"] >= 1


async def test_a_case_eligible_for_nothing_is_named_not_hidden(store):
    """A selected case with no target is the quietest failure of all: it runs, finds
    nothing, and the zero reads as clean."""
    from orchestrator.integrations.inventory import preview

    # WSTG-INFO-03 reads webserver metafiles and needs no parameter; WSTG-INPV-05.2
    # needs one and there is no parameter anywhere in this inventory.
    #
    # It was WSTG-SESS-02 in this role until SESS-02 stopped being lane-runnable --
    # one of its steps is a `bash -c '...'` shell program now, which curl_request
    # refuses. test_curl_dialect.TestWhatTheLaneCannotRunIsDeclared pins that and
    # the two other cases it took with it; what INFO-03 stands for here is the same
    # thing, a selected case that needs nothing discovery cannot supply.
    await endpoint(store, "http://app.test/p0", [])
    plan = await preview("s", config(max_urls=500,
                                     test_cases=["WSTG-INPV-05.2", "WSTG-INFO-03"]))
    by_case = {row["test_case_id"]: row for row in plan["cases"]}
    assert by_case["WSTG-INPV-05.2"]["eligible_pairs"] == 0
    assert "parameter" in by_case["WSTG-INPV-05.2"]["note"].lower()
    assert by_case["WSTG-INFO-03"]["eligible_pairs"] == 1


async def test_the_preview_is_per_identity(store):
    from orchestrator.integrations.inventory import preview

    for n in range(4):
        await endpoint(store, f"http://app.test/a{n}", ["q"], identity="low")
    await endpoint(store, "http://app.test/b0", ["q"], identity="high")
    cfg = config(max_urls=500, test_cases=["WSTG-INPV-05.2"])

    assert (await preview("s", cfg, "low"))["cases"][0]["eligible_pairs"] == 4
    assert (await preview("s", cfg, "high"))["cases"][0]["eligible_pairs"] == 1


async def test_an_inferred_route_is_not_counted_as_a_target(store):
    """It is withheld from probing, so counting it would promise coverage the run will
    not deliver — the mirror of the coverage report's `inferred` state."""
    from orchestrator.integrations.inventory import preview

    await store.execute(
        "INSERT OR REPLACE INTO integration_endpoints"
        "(session_id,url,method,identity_id,sources,parameters) VALUES(?,?,?,?,?,?)",
        ("s", "http://app.test/rest/search", "GET", "anonymous",
         json.dumps(["javascript"]), json.dumps(["q"])))
    plan = await preview("s", config(max_urls=500, test_cases=["WSTG-INPV-05.2"]))
    assert plan["cases"][0]["eligible_pairs"] == 0
    assert plan["inferred_not_probed"] == 1


async def test_the_route_reads_the_executable_configuration(store):
    """Not the redacted copy. The budget arithmetic needs `max_urls` and the selected
    cases, and the published configuration exists for reading rather than for running.
    """
    from orchestrator.integrations import service
    from orchestrator.integrations.api import launch_preview

    await endpoint(store, "http://app.test/p0", ["q"])
    await service.register("s", "http://app.test",
                           config(max_urls=4, test_cases=["WSTG-INPV-05.2"]))
    plan = await launch_preview("s")
    assert plan["max_urls"] == 4
    assert plan["cases"][0]["test_case_id"] == "WSTG-INPV-05.2"


async def test_an_unknown_session_is_a_404(store):
    import pytest as _p
    from fastapi import HTTPException
    from orchestrator.integrations.api import launch_preview

    with _p.raises(HTTPException) as exc:
        await launch_preview("nope")
    assert exc.value.status_code == 404


async def test_what_the_preview_calls_eligible_does_not_come_back_not_attempted(store):
    """The invariant that makes the pair trustworthy.

    The preview's promise is "these pairs are what the selected cases can test". If a
    pair it counted as eligible comes back from `coverage` as `not_attempted`, the two
    views disagree about the unit of work and an operator planning from the preview is
    planning from fiction. They share `probe_key` precisely so this holds.
    """
    from orchestrator.integrations.inventory import coverage, preview

    # Three crawled variants of one path: ONE probeable pair, not three.
    for sample in ("a", "b", "c"):
        await endpoint(store, f"http://app.test/search?q={sample}", ["q"])
    await endpoint(store, "http://app.test/other?page=1", ["page"])
    cfg = config(max_urls=500, test_cases=["WSTG-INPV-05.2"])

    plan = await preview("s", cfg)
    assert plan["distinct_pairs"] == 2, plan
    assert plan["cases"][0]["eligible_pairs"] == 2
    assert plan["not_reached"] == 0

    # Nothing has run, so every pair is not_attempted — and there are exactly two of
    # them, not four. A report that counted endpoint rows would say four.
    rows = await coverage("s")
    assert len(rows) == 2, [r["url"] for r in rows]
    assert {r["state"] for r in rows} == {"not_attempted"}

    # Now one of them runs, and the count does not change — only the state.
    await stage(store, observations=[{"type": "test_case", "test_case_id": "WSTG-INPV-05.2",
                                      "url": "http://app.test/search", "parameter": "q",
                                      "steps": []}])
    rows = await coverage("s")
    assert len(rows) == 2
    assert {r["parameter"]: r["state"] for r in rows} == {"q": "answered", "page": "not_attempted"}
