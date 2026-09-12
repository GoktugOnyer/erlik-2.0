"""The preview told the operator a case would do nothing, about a case that was about to run.

`preview()` exists to say what a run WILL NOT do before it starts — §E-010 gives the measured
reason, a run that tested one or two parameters per case out of eight and lost six of nine
findings, saying so only in per-case observations nobody reads before launch.

`WSTG-INPV-19`'s targets are the operator's `callback.probes`, which `eligible_test_cases`
knows nothing about. So the parameter branch counted zero eligible pairs and the preview
reported:

    eligible_pairs=0
    "no discovered parameter to test — this case needs one, so it will run against nothing
     and report nothing"

for a session with a declared probe, a selected case, and a run that would issue it. A
confident wrong prediction in the one surface whose job is prediction — and the operator's
remedy for that sentence is to deselect the case.
"""
import json
import tempfile
from pathlib import Path

import pytest

from orchestrator.integrations.contracts import AssessmentConfig
from orchestrator.integrations.inventory import COLLECTOR_CASES


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
                     "VALUES(?,?,?,?)", ("s", "http://app.test/", "queued", "{}"))
    await db.execute("INSERT INTO integration_endpoints"
                     "(session_id,url,method,identity_id,sources) VALUES(?,?,?,?,?)",
                     ("s", "http://app.test/p", "GET", "anonymous", json.dumps(["katana"])))
    return db


def config(probes):
    return AssessmentConfig(
        scope={"allow_hosts": ["app.test"], "allow_ports": [80]}, active=True,
        stages=["interactsh"], test_cases=["WSTG-INPV-19"], surface_read=False,
        callback={"server": "https://cb.test", "probes": probes})


async def ssrf_row(store, probes):
    from orchestrator.integrations.inventory import preview
    out = await preview("s", config(probes))
    return [c for c in out["cases"] if c["test_case_id"] == "WSTG-INPV-19"][0]


async def test_a_declared_probe_is_an_eligible_target(store):
    row = await ssrf_row(store, [{"url": "http://app.test/p", "parameter": "imageUrl"}])
    assert row["eligible_pairs"] == 1
    assert row["note"] == "", row["note"]


async def test_every_declared_probe_counts(store):
    row = await ssrf_row(store, [{"url": "http://app.test/p", "parameter": "imageUrl"},
                                 {"url": "http://app.test/q", "parameter": "next"}])
    assert row["eligible_pairs"] == 2


async def test_it_never_says_the_case_will_do_nothing(store):
    """The sentence itself, which is the defect."""
    row = await ssrf_row(store, [{"url": "http://app.test/p", "parameter": "imageUrl"}])
    assert "run against nothing" not in row["note"]
    assert "no discovered parameter" not in row["note"]


async def test_an_ordinary_parameter_case_is_unaffected(store):
    """The negative control: the branch must only catch collector cases. A case that really
    does need a discovered parameter and has none must still say so — that prediction is
    right, and it is the reason the sentence exists."""
    from orchestrator.integrations.inventory import preview
    base = AssessmentConfig(scope={"allow_hosts": ["app.test"], "allow_ports": [80]},
                            active=True, test_cases=["WSTG-INPV-05.2"], surface_read=False)
    out = await preview("s", base)
    row = [c for c in out["cases"] if c["test_case_id"] == "WSTG-INPV-05.2"][0]
    assert row["eligible_pairs"] == 0
    assert "no discovered parameter" in row["note"]


def test_the_case_cannot_be_selected_without_probes():
    """Why there is no "none declared" note: that state is unbuildable, so a sentence for it
    would be one no run can produce."""
    with pytest.raises(ValueError, match="explicit probes"):
        AssessmentConfig(scope={"allow_hosts": ["app.test"], "allow_ports": [80]},
                         active=True, test_cases=["WSTG-INPV-19"], stages=["interactsh"])


def test_the_branch_is_keyed_on_the_collector_case_list():
    """Not on a literal, so a second collector case gets the same treatment by construction."""
    import inspect

    from orchestrator.integrations import inventory
    assert "case_id in COLLECTOR_CASES" in inspect.getsource(inventory.preview)
    assert COLLECTOR_CASES == ("WSTG-INPV-19",)
