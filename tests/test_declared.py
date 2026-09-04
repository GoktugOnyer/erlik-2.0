"""Operator-declared per-case targeting — PROFILES as data.

`sweep.PROFILES` describes two lab applications in Python source. An operator
running against a real customer could not supply the same knowledge without
editing that file and restarting, and `build_target` correctly REFUSES to
guess a required `parameter` or `login_url` — so on any real target the SQLi,
XSS, SSRF and open-redirect cases were all named skips, permanently.
"""

import asyncio
import warnings

import pytest

warnings.filterwarnings("ignore", category=DeprecationWarning)

from orchestrator.testcase import declared as D
from orchestrator.testcase import sweep as S

BASE = "http://shop.acme-client.example"
SQLI = {"id": "WSTG-INPV-05", "name": "SQLi", "category": "INPV",
        "severity": "high", "target_schema": {"required": ["url", "parameter"]}}


@pytest.fixture
def _db(tmp_path):
    """A real database, initialised from the real schema — and RESTORED.

    `db_mod.DB_PATH` is module-level global state. An earlier version of this
    file set it and never put it back, which silently turned nine corpus-backed
    tests in test_thesis_export_redaction.py into "corpus present but empty"
    skips. A test that disables other tests is the same defect this project
    keeps removing, wearing a green suite.
    """
    import orchestrator.database as db_mod
    old = db_mod.DB_DIR, db_mod.DB_PATH
    db_mod.DB_DIR = tmp_path
    db_mod.DB_PATH = tmp_path / "d.db"
    try:
        yield db_mod
    finally:
        db_mod.DB_DIR, db_mod.DB_PATH = old


class TestADeclarationBeatsADiscoveredPath:
    """THE bug this had to fix before it could be built on.

    A fanned value is passed through `extra`, and `extra` beats the profile in
    build_target — so ONE discovered path deleted the profile's declared
    endpoint from the plan. On the shipped dvwa profile, WSTG-INPV-05 stopped
    running at /vulnerabilities/sqli/ and ran at /, /robots.txt and /ftp
    instead, each with parameter=id: three confident "no SQLi" verdicts about
    pages with no `id` parameter, and zero runs where it mattered.

    `endpoints.record` runs after every v2 run, so a target ACQUIRES discovered
    paths and then permanently stops being tested at its real endpoints.
    """

    DISCOVERED = {"url": ["http://dvwa/robots.txt", "http://dvwa/ftp"]}

    def test_the_declared_endpoint_survives_discovery(self):
        plan = S.plan_sweep([SQLI], "http://dvwa", "dvwa",
                            discovered=self.DISCOVERED)
        urls = [r["target"]["url"] for r in plan["runnable"]]
        assert urls == ["http://dvwa/vulnerabilities/sqli/"], urls

    def test_the_suppression_is_named_not_silent(self):
        """An operator seeing fewer rows must be able to tell a declaration
        taking over from a regression."""
        plan = S.plan_sweep([SQLI], "http://dvwa", "dvwa",
                            discovered=self.DISCOVERED)
        assert plan["runnable"][0]["suppressed_discovered"] == ["url"]

    def test_an_unbound_field_still_fans_out(self):
        """Only the BOUND field stops fanning. A case with no declaration keeps
        the discovery behaviour that exists to widen coverage."""
        case = dict(SQLI, id="WSTG-INPV-99")     # nothing declared for it
        plan = S.plan_sweep([case], "http://dvwa", "dvwa",
                            discovered=self.DISCOVERED, extra={"parameter": "id"})
        urls = sorted(r["target"]["url"] for r in plan["runnable"])
        assert urls == ["http://dvwa", "http://dvwa/ftp", "http://dvwa/robots.txt"]

    def test_caller_supplied_extra_is_not_deleted_either(self):
        """main.py says "Caller-supplied `extra` wins". It did not: a discovered
        path removed the operator's own typed URL from the plan."""
        plan = S.plan_sweep([SQLI], "http://dvwa", "",
                            extra={"url": "http://dvwa/mine", "parameter": "id"},
                            discovered=self.DISCOVERED)
        urls = [r["target"]["url"] for r in plan["runnable"]]
        assert urls == ["http://dvwa/mine"], urls


class TestANonStringValueCannotSkipTheGate:
    """`if isinstance(v, str)` let every non-string value past `looks_injectable`
    untouched, and the runner stringifies whatever it is into the command
    template. Harmless while profiles were Python we wrote; not harmless once
    this is data an operator types."""

    def test_a_list_is_refused(self):
        t, why = S.build_target(SQLI, "http://dvwa", {
            "WSTG-INPV-05": {"url": "{base}/p", "parameter": ["q", "x'; id; #"]}})
        assert t is None
        assert "must be text" in why

    def test_a_number_is_still_allowed(self):
        """port and parallel_n are legitimately numeric and have no shell
        surface — refusing them would break real cases."""
        case = {"id": "C", "name": "c", "category": "CONF", "severity": "low",
                "target_schema": {"required": ["host", "port"]}}
        t, why = S.build_target(case, "http://dvwa:8080", {})
        assert t is not None, why
        assert t["port"] == 8080


class TestTheWriteGateRefusesWithAReason:
    """A silent drop reads as "my entry vanished". Every refusal names the
    field and the reason."""

    @pytest.mark.parametrize("field,value,fragment", [
        ("url", "http://evil.example/x", "not a URL"),
        ("url", "//evil.example/x", "not a URL"),
        ("url", "user@evil.example", "not a URL"),
        ("url", "no-leading-slash", "must start with '/'"),
        ("url", "/x{base}", "braces"),
        ("parameter", "a`whoami`", "shell metacharacter"),
        ("parameter", "a$(id)", "shell metacharacter"),
        ("parameter", "", "is empty"),
        ("parameter", "x" * 513, "longer than"),
        ("host", "internal-db", "derived from the target URL"),
        ("port", "5432", "derived from the target URL"),
        ("nonsense", "x", "not a declarable field"),
    ])
    def test_refused(self, field, value, fragment):
        why = D.validate(field, value)
        assert why, f"{field}={value!r} was accepted"
        assert fragment in why, why

    @pytest.mark.parametrize("field,value", [
        ("url", "/catalogue/item.php"),
        ("login_url", "/account/signin"),
        ("parameter", "sku"),
        ("submit", "Upload=Upload"),
    ])
    def test_accepted(self, field, value):
        assert D.validate(field, value) == ""

    def test_a_declaration_cannot_name_a_host_at_all(self):
        """Structural, not a comparison: url-ish values are stored as PATHS and
        rendered under the caller's base, so there is nowhere to put a host."""
        assert D.render("url", "/x", "http://a.example") == "http://a.example/x"
        assert D.validate("url", "http://other.example/x")


class TestTheReadGateAlsoRuns:
    """A database is a trust boundary. These values are substituted into
    `bash -c '...'` templates, so a row must not be trusted because it passed
    the gate once — and a row that fails it now is REPORTED, not dropped."""

    def test_a_poisoned_row_is_refused_not_silently_dropped(self, _db):
        db_mod = _db

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            ok, why = await D.declare(db, BASE, "WSTG-INPV-05", "parameter", "sku")
            assert ok, why
            # Poison it behind the write gate's back.
            await db.execute(
                "UPDATE target_case_inputs SET value = ? WHERE field = 'parameter'",
                ("sku`whoami`",))
            await db.commit()
            prof, refused = await D.profile_for(db, BASE, BASE)
            await db.close()
            return prof, refused

        prof, refused = asyncio.run(go())
        assert prof == {}, "a poisoned value reached the planner"
        assert len(refused) == 1
        assert "shell metacharacter" in refused[0]["reason"]
        assert refused[0]["value"] == "sku`whoami`", "the row was dropped, not reported"


class TestMergeIsPerFieldNotPerCase:
    def test_correcting_one_field_keeps_the_rest(self):
        """An operator fixing a stale parameter must not silently discard the
        profile's URL for the same case."""
        builtin = {"C1": {"url": "http://x/a", "parameter": "old"},
                   "C2": {"url": "http://x/b"}}
        out = D.merge(builtin, {"C1": {"parameter": "new"}})
        assert out["C1"] == {"url": "http://x/a", "parameter": "new"}
        assert out["C2"] == {"url": "http://x/b"}

    def test_the_builtin_is_not_mutated(self):
        builtin = {"C1": {"url": "http://x/a"}}
        D.merge(builtin, {"C1": {"url": "http://y/z"}})
        assert builtin == {"C1": {"url": "http://x/a"}}


class TestTheBuiltinProfilesStillWorkWithNoDatabase:
    """scripts/deterministic_sweep.py imports PROFILES directly, five tests
    subscript it synchronously with no event loop, and the benchmark depends on
    the two lab profiles resolving with no DB at all."""

    def test_profiles_is_still_a_plain_dict(self):
        assert isinstance(S.PROFILES, dict)
        assert {"juiceshop", "dvwa"} <= set(S.PROFILES)

    def test_a_plan_with_no_declarations_is_unchanged(self):
        a = S.plan_sweep([SQLI], "http://dvwa", "dvwa")
        b = S.plan_sweep([SQLI], "http://dvwa", "dvwa", declared={})
        assert a == b

    def test_the_cli_still_imports_it(self):
        from pathlib import Path
        src = Path("scripts/deterministic_sweep.py").read_text()
        assert "from orchestrator.testcase.sweep import" in src
        assert "PROFILES" in src


class TestARealCustomerCanBeTargeted:
    """The point of the whole change."""

    def test_declaring_turns_named_skips_into_runs(self, _db):
        db_mod = _db
        cases = [SQLI, {"id": "WSTG-ATHN-01", "name": "creds over http",
                        "category": "ATHN", "severity": "high",
                        "target_schema": {"required": ["login_url"]}}]

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            before = S.plan_sweep(cases, BASE, "")
            for tc, f, v in (("WSTG-INPV-05", "url", "/catalogue/item.php"),
                             ("WSTG-INPV-05", "parameter", "sku"),
                             ("WSTG-ATHN-01", "login_url", "/account/signin")):
                ok, why = await D.declare(db, BASE, tc, f, v)
                assert ok, why
            await db.commit()
            prof, refused = await D.profile_for(db, BASE, BASE)
            await db.close()
            return before, S.plan_sweep(cases, BASE, "", declared=prof), refused

        before, after, refused = asyncio.run(go())
        assert refused == []
        assert before["counts"]["runnable"] == 0
        assert before["counts"]["skipped"] == 2
        assert after["counts"]["runnable"] == 2, after["skipped"]
        by = {r["id"]: r["target"] for r in after["runnable"]}
        assert by["WSTG-INPV-05"]["url"] == f"{BASE}/catalogue/item.php"
        assert by["WSTG-INPV-05"]["parameter"] == "sku"
        assert by["WSTG-ATHN-01"]["login_url"] == f"{BASE}/account/signin"

    def test_retiring_is_not_deleting(self, _db):
        db_mod = _db

        async def go():
            await db_mod.init_db()
            db = await db_mod.get_db()
            await D.declare(db, BASE, "WSTG-INPV-05", "parameter", "sku")
            await D.retire(db, BASE, "WSTG-INPV-05", "parameter")
            await db.commit()
            live = await D.rows_for(db, BASE)
            kept = await (await db.execute(
                "SELECT value, retired_at FROM target_case_inputs")).fetchall()
            await db.close()
            return live, [tuple(r) for r in kept]

        live, kept = asyncio.run(go())
        assert live == [], "a retired declaration still applies"
        assert len(kept) == 1 and kept[0][0] == "sku", "the row was deleted"
        assert kept[0][1] is not None


class TestTheEndpointIsWired:
    def test_plan_applies_declarations_end_to_end(self, _db, tmp_path):
        from fastapi.testclient import TestClient
        db_mod = _db
        db_mod.DB_PATH = str(tmp_path / "api.db")
        asyncio.run(db_mod.init_db())
        import orchestrator.main as M
        c = TestClient(M.app)
        before = c.post("/api/v2/sweep/plan", json={"target": BASE}).json()
        r = c.post("/api/v2/targets/declared", json={
            "target": BASE, "test_case_id": "WSTG-INPV-05",
            "field": "parameter", "value": "sku"})
        assert r.status_code == 200, r.text
        bad = c.post("/api/v2/targets/declared", json={
            "target": BASE, "test_case_id": "WSTG-INPV-05",
            "field": "url", "value": "http://evil.example/x"})
        assert bad.status_code == 400
        assert "not a URL" in bad.json()["detail"]
        after = c.post("/api/v2/sweep/plan", json={"target": BASE}).json()
        assert after["inputs"]["declared"] == 1
        assert after["counts"]["skipped"] < before["counts"]["skipped"]

    def test_the_ui_panel_exists_and_is_bound(self):
        from pathlib import Path
        html = Path("dashboard/templates/index.html").read_text()
        assert 'id="tl-decl-rows"' in html
        assert "async function tlDeclSet" in html
        i = html.index("async function tlDeclSet")
        blk = html[i:i + 1600]
        assert "/api/v2/targets/declared" in blk
        assert "j.detail" in blk, "a refusal is not shown to the operator"
