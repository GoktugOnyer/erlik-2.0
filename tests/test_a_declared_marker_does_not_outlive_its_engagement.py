"""E-032: the operator's marker reached a cross-session store and a model prompt.

`private_object_marker` is, by its own definition, a fragment of the application's private
data — "this datum identifies the privileged object". The `idor` and `ownership` evaluators
quote it into a finding's evidence ON PURPOSE: a differential claim is only checkable if a
reader can see what crossed, and the reader of a finding is the data's owner.

`recon_context` is not that reader, and the handoff wrote the evidence there verbatim.
Measured on the committed code:

    the evaluator's evidence    "the private object is identified by: 'admin@juice-sh.op'"
    recon_context.value         the same string, keyed on host:port — no session, no expiry
    a LATER session, same host  `_get_warm_start_context` renders `value` in full, so the
                                marker reached an agent prompt verbatim
    `_get_handoff_context`      cuts the line at 110 characters, which saved it by ONE
                                character on a long URL and not at all on a short one

The plan recorded this as "a reachable shape rather than a measured leak", on the premise
that the legacy lane carries no marker. It does: `private_object_marker` has been declarable
since E-027, and the two evaluators that read it both quote it.

Two properties make it worse than the quotation in the finding. The row is keyed on host:port
with no session and no expiry, so a datum declared in one engagement is handed to agents in
later ones; and what it is handed to is a model prompt.

THE FIX IS AT THE WRITE, not at either reader: both readers go through one column, a
reader-side fix would have to be repeated in each, and the store itself would still hold the
value. It is NOT retroactive and cannot be — nothing records which substring of an existing
row was the declared value.
"""
import asyncio
import json

import pytest

import orchestrator.database as db_mod
import orchestrator.main as main
from orchestrator import handoff
from orchestrator.testcase.runner import Finding, RunResult

MARKER = "admin@juice-sh.op"
TARGET = "http://localhost:3000/api/Addresss/4"


@pytest.fixture
async def store(tmp_path, monkeypatch):
    monkeypatch.setattr(db_mod, "DB_DIR", tmp_path)
    monkeypatch.setattr(db_mod, "DB_PATH", tmp_path / "t.db")
    await db_mod.init_db()

    async def _get_db():
        import aiosqlite
        conn = await aiosqlite.connect(tmp_path / "t.db")
        conn.row_factory = aiosqlite.Row
        return conn

    monkeypatch.setattr(main, "get_db", _get_db)
    return tmp_path / "t.db"


def crossing(evidence=None, url=TARGET):
    """A finding shaped the way the `idor` evaluator builds one."""
    return Finding(
        test_case_id="WSTG-AUTHZ-04", step="fetch_as_low_priv", confidence="confirmed",
        vuln_type="Broken Access Control", severity="high", url=url,
        evidence=evidence if evidence is not None else (
            "erlik comparison of two identities\n"
            f"  the private object is identified by: {MARKER!r}\n"
            "  both returned it, and the two identities differ"))


async def run_and_save(marker=MARKER, **overrides):
    """The REAL path: save_run -> bridge_run. Not bridge_run called directly.

    The fix lives at the call site, so a test that calls `bridge_run` itself would pass on
    the committed code and prove nothing.
    """
    from orchestrator.testcase.persistence import save_run

    target = {"url": TARGET, "private_object_marker": marker}
    target.update(overrides)
    result = RunResult(test_case_id="WSTG-AUTHZ-04", target=target,
                       findings=[crossing()], steps=[])
    return await save_run(result, provider=None, model=None)


async def context_rows():
    db = await main.get_db()
    try:
        return [dict(r) for r in await (await db.execute(
            "SELECT session_id, context_type, key, value, target_key FROM recon_context"
        )).fetchall()]
    finally:
        await db.close()


# ----------------------------------------------------------------- the store


async def test_the_marker_does_not_reach_the_cross_session_store(store):
    run_id = await run_and_save()
    rows = await context_rows()
    assert rows, "the handoff wrote nothing, so this test proves nothing"
    assert all(MARKER not in row["value"] for row in rows), (
        f"the declared marker is in recon_context, keyed on "
        f"{rows[0]['target_key']!r} with no session and no expiry: {rows[0]['value']!r}")


async def test_what_the_handoff_is_for_still_arrives(store):
    """The withholding must not gut the handoff. The agent needs the endpoint and the fact
    that a crossing was established there; it never needed the value."""
    await run_and_save()
    rows = await context_rows()
    assert len(rows) == 1, rows
    assert TARGET in rows[0]["value"], rows[0]["value"]
    assert "comparison of two identities" in rows[0]["value"], rows[0]["value"]
    assert handoff.WITHHELD in rows[0]["value"], (
        "the marker vanished without a trace; a reader cannot tell a withheld value from "
        "evidence that never named one")
    assert rows[0]["key"] == "WSTG-AUTHZ-04:Broken Access Control"


async def test_a_run_that_declared_no_marker_is_unchanged(store):
    """Most cases declare none, and nothing about them should change."""
    from orchestrator.testcase.persistence import save_run

    result = RunResult(test_case_id="WSTG-CONF-06", target={"url": TARGET},
                       findings=[crossing(evidence="Server: nginx/1.25 disclosed")],
                       steps=[])
    await save_run(result, provider=None, model=None)
    rows = await context_rows()
    assert len(rows) == 1 and handoff.WITHHELD not in rows[0]["value"], rows
    assert "nginx/1.25" in rows[0]["value"]


async def test_a_marker_in_the_url_is_withheld_too(store):
    """A marker can arrive in the URL — a reflected one, or an object id in a path. The
    composed value is scrubbed, not just the evidence half."""
    from orchestrator.testcase.persistence import save_run

    url = f"http://localhost:3000/search?q={MARKER}"
    result = RunResult(test_case_id="WSTG-AUTHZ-04",
                       target={"url": url, "private_object_marker": MARKER},
                       findings=[crossing(url=url)], steps=[])
    await save_run(result, provider=None, model=None)
    rows = await context_rows()
    assert rows and MARKER not in rows[0]["value"], rows[0]["value"]
    assert "localhost:3000/search" in rows[0]["value"], (
        "the endpoint was lost with the marker; the agent needs somewhere to look")


async def test_the_withholding_happens_before_the_length_cut(store):
    """Cutting first and withholding after leaves a PREFIX of the marker, which is still
    disclosure.

    The stored value is cut at 500 characters. If the cut runs first, a marker straddling
    that boundary arrives as its own first N characters — a string the scrub can no longer
    match, because it no longer equals the declared value. `admin@juice-s` is not a safe
    rendering of `admin@juice-sh.op`.

    The offset is computed from the real lengths rather than hard-coded, so a change to the
    cut or to the composed value cannot quietly make this test vacuous — which is what an
    earlier version of it was.
    """
    from orchestrator.testcase.persistence import save_run

    keep = 10                                  # characters of the marker left by the cut
    prefix = len(TARGET) + 1                   # `f"{url} {ev}"`
    pad = 500 - keep - prefix
    assert pad > 0, "the URL alone exceeds the cut; this test would prove nothing"
    result = RunResult(test_case_id="WSTG-AUTHZ-04",
                       target={"url": TARGET, "private_object_marker": MARKER},
                       findings=[crossing(evidence="x" * pad + MARKER + " tail")],
                       steps=[])
    await save_run(result, provider=None, model=None)
    value = (await context_rows())[0]["value"]
    assert MARKER not in value
    assert MARKER[:keep] not in value, (
        f"{MARKER[:keep]!r} survived the cut: the value was truncated before it was "
        f"withheld, so a straddling marker arrives as its own prefix")


# ----------------------------------------------------------------- the prompts


async def test_the_marker_does_not_reach_a_later_session_s_brief(store):
    """`_get_handoff_context` reads `value` for any session but this one, keyed on
    host:port. A short URL put the marker in the brief verbatim."""
    from orchestrator.testcase.persistence import save_run

    result = RunResult(test_case_id="A-04",
                       target={"url": "http://localhost:3000/p",
                               "private_object_marker": MARKER},
                       findings=[Finding(test_case_id="A-04", step="s", vuln_type="BAC",
                                         severity="high", url="http://localhost:3000/p",
                                         evidence=f"crossed: {MARKER!r} reached the low arm")],
                       steps=[])
    await save_run(result, provider=None, model=None)
    brief = await main._get_handoff_context("a-different-session", "http://localhost:3000/")
    assert brief, "the brief is empty, so this test proves nothing"
    assert MARKER not in brief, brief


async def test_the_marker_does_not_reach_a_warm_start_context(store):
    """`_get_warm_start_context` renders `value` in FULL — no 110-character cut — so this
    is the path that leaked regardless of URL length."""
    run_id = await run_and_save()
    warm = await main._get_warm_start_context(run_id)
    assert warm, "the warm-start context is empty, so this test proves nothing"
    assert MARKER not in warm, warm


# ------------------------------------------------- and the claim the docs make


def test_the_docs_state_the_marker_rule_per_path():
    """"The marker never travels" was written as a product property and is not one: the
    cross-arm check withholds it, and `SecurityAssertion` and the catalogue's marker
    evaluators quote it deliberately because there the quotation IS the proof.

    A security-posture claim that is wrong is worse than no claim, which is what
    `test_security_doc.py` exists for. This holds the per-path statement in place.
    """
    from pathlib import Path

    doc = (Path(__file__).resolve().parents[1] / "docs" / "integrations.md").read_text()
    assert "**The marker never travels.**" not in doc, (
        "the product-wide claim is back; it is false for SecurityAssertion, for the "
        "catalogue's marker evaluators, and for the legacy idor evidence")
    section = doc[doc.index("Where the marker does and does not travel"):][:4000]
    for required in ("SecurityAssertion", "recon_context", "cross-arm"):
        assert required in section, (
            f"the per-path statement does not mention {required}, so a reader cannot tell "
            f"which paths quote the marker from which must never carry it")


def test_the_withheld_marker_list_is_read_from_the_one_that_names_it():
    """A second evaluator-only field must not be addable without the handoff following it."""
    from orchestrator.testcase.declared import EVALUATOR_ONLY

    for field in EVALUATOR_ONLY:
        assert handoff.declared_markers({field: "sentinel-value"}) == ("sentinel-value",), (
            f"{field} is declared evaluator-only and the handoff does not withhold it")
    assert handoff.declared_markers({"url": "http://x/"}) == (), (
        "a field that is not evaluator-only is being withheld, which would scrub the "
        "endpoint the handoff exists to pass on")


def test_every_caller_of_the_bridge_withholds():
    """A boundary one call site honours and another does not is not a boundary.

    There is one caller today. `declared=` is a keyword with a default, so a second one would
    compile, pass its own tests, and write the marker — the failure mode that makes a
    structural check worth more here than it usually is.
    """
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "orchestrator"
    calls = []
    for source in root.rglob("*.py"):
        text = source.read_text()
        for match in re.finditer(r"await bridge_run\((.*?)\)", text, re.S):
            calls.append((source.relative_to(root), match.group(1)))
    assert calls, "no call to bridge_run found at all; this test is vacuous"
    missing = [str(path) for path, args in calls if "declared=" not in args]
    assert not missing, (
        f"these call sites bridge findings into recon_context without withholding the "
        f"declared markers: {missing}")
