"""Learning loop, Track A: a VERIFIED, confirmed finding becomes a PENDING
candidate playbook for its target.

The source gate is the whole point -- only `verified = 1 AND poc_status =
'confirmed'` (never an unverified agent claim) -- and the sink is a separate
table, never `findings`, so no metric can move. One harvest also builds the
Track-B training shards (seam only; A1 does not persist them).
"""

import asyncio

SID = "sess-learn-1"

CONFIRMED = {"vuln_type": "SQL Injection", "url": "http://t.example/search",
             "parameter": "q", "evidence": "You have an error in your SQL syntax",
             "verified": 1, "poc_status": "confirmed"}


async def _seed(db, findings):
    await db.execute("INSERT INTO sessions (id, target_url) VALUES (?, ?)",
                     (SID, "http://t.example"))
    for f in findings:
        await db.execute(
            "INSERT INTO findings (session_id, vuln_type, severity, url, parameter, "
            "evidence, verified, poc_status, false_positive) VALUES (?,?,?,?,?,?,?,?,?)",
            (SID, f["vuln_type"], f.get("severity", "high"), f.get("url", ""),
             f.get("parameter", ""), f.get("evidence", ""),
             f.get("verified", 0), f.get("poc_status"), f.get("false_positive", 0)))
    await db.commit()


def _harvest(tmp_path, monkeypatch, findings):
    import orchestrator.database as db_mod
    monkeypatch.setattr(db_mod, "DB_PATH", str(tmp_path / "ll.db"))
    from orchestrator.main import _harvest_candidates

    async def go():
        await db_mod.init_db()
        db = await db_mod.get_db()
        await _seed(db, findings)
        await db.close()
        res = await _harvest_candidates(SID)
        db = await db_mod.get_db()
        rows = [dict(r) for r in await (await db.execute(
            "SELECT * FROM candidate_playbooks")).fetchall()]
        fcount = (await (await db.execute(
            "SELECT COUNT(*) c FROM findings")).fetchone())["c"]
        await db.close()
        return res, rows, fcount

    return asyncio.run(go())


class TestHarvestSource:
    def test_a_confirmed_finding_becomes_a_pending_candidate(self, tmp_path, monkeypatch):
        res, rows, _ = _harvest(tmp_path, monkeypatch, [CONFIRMED])
        assert res["candidates"] == 1 and len(rows) == 1
        c = rows[0]
        assert c["status"] == "pending"
        assert c["target_key"] == "t.example:80"
        assert c["source_session_id"] == SID
        assert c["source_finding_id"] is not None
        assert "SQL Injection" in (c["body"] or "")

    def test_only_verified_and_confirmed_findings_are_harvested(self, tmp_path, monkeypatch):
        res, rows, _ = _harvest(tmp_path, monkeypatch, [
            {**CONFIRMED, "verified": 0},                   # not verified
            {**CONFIRMED, "poc_status": "not_reproduced"},  # did not reproduce
            {**CONFIRMED, "poc_status": None},              # never tested
            {**CONFIRMED, "false_positive": 1},             # marked false positive
        ])
        assert res["candidates"] == 0 and rows == []

    def test_the_findings_table_is_never_written(self, tmp_path, monkeypatch):
        _, rows, fcount = _harvest(tmp_path, monkeypatch, [CONFIRMED])
        assert fcount == 1, "harvest must not add or remove findings rows"
        assert len(rows) == 1


class TestDedup:
    def test_same_class_and_url_collapse_to_one_candidate(self, tmp_path, monkeypatch):
        res, rows, _ = _harvest(tmp_path, monkeypatch, [CONFIRMED, dict(CONFIRMED)])
        assert res["candidates"] == 1 and len(rows) == 1


class TestTrainingShardSeam:
    def test_a_shard_is_built_for_every_confirmed_finding(self, tmp_path, monkeypatch):
        # Two confirmed findings -> two shards (the seam is per-finding), even
        # though dedup collapses them to one candidate playbook.
        res, _, _ = _harvest(tmp_path, monkeypatch, [CONFIRMED, dict(CONFIRMED)])
        assert len(res["shards"]) == 2
        s = res["shards"][0]
        assert s["label"] == "verified_confirmed"
        assert s["vuln_type"] == "SQL Injection"
        assert s["finding_id"] is not None


def test_the_pipeline_gates_the_harvest_on_the_lever():
    """Wiring guard: harvest runs only under learned_playbooks; a key nothing
    reads is this codebase's signature defect."""
    import pathlib
    src = (pathlib.Path(__file__).resolve().parents[1]
           / "orchestrator" / "main.py").read_text()
    assert 'if runcfg.get("learned_playbooks"):' in src
    assert "await _harvest_candidates(session_id)" in src
