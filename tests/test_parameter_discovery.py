"""Discovered parameters, from the scanner that saw one to the case that tests it.

Twelve of the 29 catalogue cases were out of reach for want of a target field
the lane never produced, and eight of those wanted only a `parameter` name. This
is that field: extracted from query strings and from ZAP's own `param`, stored
per endpoint and per identity, and paired back to the URL it was observed on.

A parameter name is TARGET-CONTROLLED text that ends up rendered into a command,
so most of what follows is about what must not be accepted.
"""
import json

import pytest
from unittest.mock import AsyncMock

from orchestrator.integrations.contracts import (
    AssessmentConfig, Endpoint, StageResult, parameter_names,
)
from orchestrator.integrations.adapters import Context
from orchestrator.integrations.deterministic import CatalogueAdapter, curl_request
from orchestrator.integrations.inventory import (
    MAX_PARAMETERS_PER_URL, base_url, case_needs_parameter, eligible_test_cases,
    executable_test_cases, parameters_by_url,
)
from orchestrator.integrations.runtime import JobOutput
from orchestrator.testcase.loader import find_by_id
from orchestrator.testcase.runner import _render
from orchestrator.testcase.scope import ScopeViolation
from test_integrations import database  # noqa: F401


def config(**kw):
    return AssessmentConfig(scope={"allow_hosts": ["app.test"], "allow_ports": [443]}, **kw)


# --- what counts as a parameter name ----------------------------------------

class TestAParameterNameIsNarrowerThanNotInjectable:
    """`looks_injectable` is the wrong instrument here, twice over: it passes
    names that silently CORRUPT the probe, and rejects names that were never
    dangerous in a quoted slot. Each of the corruptions below was measured by
    rendering the real templates and parsing them.
    """

    @pytest.mark.parametrize("name,why", [
        ("a#b", "the # opens a FRAGMENT, so the request is `?a` and the case tests a probe it never sent"),
        ("a&b", "two parameters, neither the one under test"),
        ("a=b", "parameter `a` carrying the value `b=<payload>`"),
        ("-o", "a leading dash could read as an option if it ever reached an unquoted slot"),
        ("--output", "likewise"),
        ("a b", "a space is not part of a name"),
        ('a"x', "a quote closes the slot the name is interpolated into"),
        ("", "there is no anonymous parameter"),
        ("x" * 65, "64 characters is the limit, and this is one past it"),
    ])
    def test_a_corrupting_or_dangerous_name_is_not_a_parameter(self, name, why):
        assert parameter_names("http://app.test/s", name) == [], why

    @pytest.mark.parametrize("name", ["q", "page", "user[id]", "x-token", "a.b", "_next", "id2", "x" * 64])
    def test_a_real_name_is_kept(self, name):
        assert parameter_names("http://app.test/s", name) == [name]

    def test_zaps_param_field_is_not_a_query_parameter(self):
        """ZAP names the input vector its alert fired on, which is a cookie or
        a header at least as often as a query parameter — the real-ZAP
        assertion in test_integration_lifecycle pins zap:10010 reporting
        `fixture_session` on /zap/private, a cookie name on a URL with no query
        string. parse_zap therefore passes only the URI-derived names.

        Its marginal value is the wrong set anyway: when ZAP attacks a real GET
        parameter the instance URI carries that query, so anything the field
        adds beyond the URI is by construction not a query parameter."""
        import inspect
        from orchestrator.integrations import adapters
        source = inspect.getsource(adapters.parse_zap)
        assert "parameter_names(url)" in source
        assert "parameter_names(url, parameter)" not in source, (
            "a cookie or header name would become `?name=<payload>`")

    def test_names_come_from_the_query_string_and_the_scanner_alike(self):
        # `#b=x` is a fragment, never sent, so `a` is the only real name here —
        # which is exactly what the server would have seen.
        assert parameter_names("http://app.test/s?a#b=x") == ["a"]
        assert parameter_names("http://app.test/s?q=1&page=2", "token") == ["q", "page", "token"]
        assert parameter_names("http://app.test/s?q=1", "q") == ["q"], "deduplicated"


# --- the url a parameter is tested against ----------------------------------

def test_the_url_loses_its_query_because_the_case_supplies_one():
    """WSTG-CLNT-04 interpolates `"{{url}}?{{parameter}}=…"`. A url that still
    carried its own query would produce two `?` and test nothing."""
    assert base_url("http://app.test/s?q=1&page=2#frag") == "http://app.test/s"
    assert base_url("http://app.test/s") == "http://app.test/s"

    rendered = _render('curl -s -D - -o /dev/null "{{url}}?{{parameter}}=//erlik-redir.oast.test/"',
                       {"url": base_url("http://app.test/s?q=1"), "parameter": "q"})
    _, url, _ = curl_request(rendered)
    assert url == "http://app.test/s?q=//erlik-redir.oast.test/"
    assert url.count("?") == 1


# --- storage ----------------------------------------------------------------

async def test_parameters_merge_across_sources_and_never_across_identities(database):
    """katana sees the query string; ZAP names the field it exercised. Neither
    is a superset of the other, so they merge — but only within one identity."""
    await database.persist_result("s", "stage", StageResult(endpoints=[
        Endpoint(url="https://app.test/s?q=1", source="katana", identity="reader", parameters=["q"]),
        Endpoint(url="https://app.test/s?q=1", source="zap", identity="reader", parameters=["token"]),
        Endpoint(url="https://app.test/s?q=1", source="zap", identity="admin", parameters=["adminonly"]),
    ]))
    rows = {(r["identity_id"]): json.loads(r["parameters"])
            for r in await database.rows("SELECT identity_id,parameters FROM integration_endpoints")}
    assert rows["reader"] == ["q", "token"]
    assert rows["admin"] == ["adminonly"]
    assert "adminonly" not in rows["reader"], "an admin's parameter must not reach an anonymous stage"


async def test_the_column_is_added_to_a_database_that_already_has_endpoints(database, tmp_path):
    """CREATE TABLE IF NOT EXISTS is a no-op on an existing table, so the
    column has to be added explicitly or every upgrade loses this feature."""
    import aiosqlite
    import orchestrator.database as original
    conn = await aiosqlite.connect(original.DB_PATH)
    await conn.execute("DROP TABLE integration_endpoints")
    await conn.execute("""CREATE TABLE integration_endpoints (
        session_id TEXT NOT NULL, url TEXT NOT NULL, method TEXT NOT NULL,
        identity_id TEXT NOT NULL, sources TEXT NOT NULL,
        PRIMARY KEY(session_id,url,method,identity_id))""")
    await conn.execute("INSERT INTO integration_endpoints VALUES('s','https://app.test/old','GET','reader','[\"katana\"]')")
    await conn.commit()
    await conn.close()

    await database.migrate()
    rows = await database.rows("SELECT url,parameters FROM integration_endpoints")
    assert rows[0]["url"] == "https://app.test/old", "the existing row survives"
    assert json.loads(rows[0]["parameters"]) == [], "and says what was true of it: nothing known"


class Ctx:
    session_id, identity_id, target = "s", "reader", "https://app.test/"

    class config:
        max_urls = 500


POLICY = {"scope": {"allow_hosts": ["app.test"], "allow_ports": [443]}}


async def test_a_stripped_url_is_re_checked_against_scope(database):
    """Removing the query produces a URL discovery never saw and scope never
    approved, so it cannot inherit the original's approval."""
    await database.persist_result("s", "stage", StageResult(endpoints=[
        Endpoint(url="https://app.test/ok?q=1", source="katana", identity="reader", parameters=["q"]),
        Endpoint(url="https://app.test:9999/other?q=1", source="katana", identity="reader", parameters=["q"]),
    ]))
    found = await parameters_by_url(Ctx(), POLICY)
    assert found == {"https://app.test/ok": ["q"]}, "the out-of-scope port is dropped, not inherited"


async def test_one_endpoint_cannot_consume_the_whole_budget(database):
    await database.persist_result("s", "stage", StageResult(endpoints=[
        Endpoint(url="https://app.test/wide", source="katana", identity="reader",
                 parameters=[f"p{n}" for n in range(50)]),
    ]))
    found = await parameters_by_url(Ctx(), POLICY)
    assert len(found["https://app.test/wide"]) == MAX_PARAMETERS_PER_URL


async def test_a_parameter_stored_before_the_rules_tightened_is_still_filtered(database):
    """The column is data, and rows outlive the code that wrote them."""
    await database.execute(
        "INSERT INTO integration_endpoints VALUES(?,?,?,?,?,?)",
        ("s", "https://app.test/s", "GET", "reader", '["katana"]', json.dumps(["q", "a#b", "-o", 'a"x'])))
    found = await parameters_by_url(Ctx(), POLICY)
    assert found == {"https://app.test/s": ["q"]}


# --- eligibility -------------------------------------------------------------

def test_a_case_that_tests_a_parameter_runs_only_where_there_is_one():
    with_none = eligible_test_cases("https://app.test/s")
    with_one = eligible_test_cases("https://app.test/s", parameters=["q"])
    assert set(with_one) - set(with_none) == {"WSTG-CLNT-04", "WSTG-INPV-11.2", "WSTG-INPV-18"}
    for case_id in ("WSTG-CLNT-04", "WSTG-INPV-11.2", "WSTG-INPV-18"):
        assert case_needs_parameter(find_by_id(case_id))
    for case_id in with_none:
        assert not case_needs_parameter(find_by_id(case_id))


def test_the_three_cases_are_what_the_parameter_field_bought():
    assert set(executable_test_cases()) == {
        "WSTG-CLNT-04", "WSTG-CLNT-07", "WSTG-CLNT-07b", "WSTG-CONF-06", "WSTG-INFO-03",
        "WSTG-INPV-07", "WSTG-INPV-11.2", "WSTG-INPV-18", "WSTG-SESS-02"}


# --- end to end through the adapter -----------------------------------------

class Sandbox:
    """Records the argv of every request the lane actually makes."""

    def __init__(self, tmp_path, policy):
        self.policy = policy
        self.directory = tmp_path
        self.output = tmp_path / "output"
        self.output.mkdir(exist_ok=True)
        self.images = {}
        self.proxy_url = "http://proxy:8080"
        self.calls = []

    async def run(self, argv, **kw):
        self.calls.append(argv)
        return JobOutput(0, "HTTP/1.1 200 OK\r\n\r\nnothing interesting", "")


async def test_a_parameter_is_only_tested_on_the_url_it_was_seen_on(database, tmp_path):
    cfg = config(active=True, test_cases=["WSTG-INPV-18"])
    await database.persist_result("s", "discovery", StageResult(endpoints=[
        Endpoint(url="https://app.test/search?q=hello", source="katana", identity="anonymous", parameters=["q"]),
        Endpoint(url="https://app.test/profile?uid=7", source="katana", identity="anonymous", parameters=["uid"]),
    ]))
    sandbox = Sandbox(tmp_path, cfg.model_dump())
    result = await CatalogueAdapter().run(Context("s", "tests", "https://app.test", cfg), sandbox)

    pairs = set()
    for argv in sandbox.calls:
        target = next(a for a in argv if a.startswith("https://"))
        data = [a for a in argv if "=" in a and not a.startswith("-") and not a.startswith("https://")]
        pairs.add((target, data[0].split("=", 1)[0] if data else None))
    assert pairs == {("https://app.test/search", "q"), ("https://app.test/profile", "uid")}, (
        "a parameter must never be tested against a URL it was not observed on")
    assert result.metadata["parameters_discovered"] == 2


async def test_a_case_with_no_parameter_to_test_says_so(database, tmp_path):
    """Distinguishable from a case that ran and found nothing — the operator
    selected it, so they are owed the reason."""
    cfg = config(active=True, test_cases=["WSTG-INPV-18"])
    await database.persist_result("s", "discovery", StageResult(endpoints=[
        Endpoint(url="https://app.test/static", source="katana", identity="anonymous"),
    ]))
    sandbox = Sandbox(tmp_path, cfg.model_dump())
    result = await CatalogueAdapter().run(Context("s", "tests", "https://app.test", cfg), sandbox)
    assert sandbox.calls == []
    skipped = [o for o in result.observations if o["type"] == "test_case_not_run"]
    assert len(skipped) == 1 and "no parameter was discovered" in skipped[0]["reason"]


async def test_a_step_that_can_only_be_judged_by_a_model_is_recorded_as_not_run(database, tmp_path):
    """WSTG-CLNT-04's `client_side_sink_review` has one evaluator, of type llm.
    The lane runs allow_llm=False for reproducibility and the runner skips such
    evaluators SILENTLY, so the step would issue a real request, be recorded
    success=True/skipped=False, count toward executed_checks, and decide
    nothing. The case keeps its three regex arms; this arm says it did not run.
    """
    cfg = config(active=True, test_cases=["WSTG-CLNT-04"])
    await database.persist_result("s", "discovery", StageResult(endpoints=[
        Endpoint(url="https://app.test/r?next=/home", source="katana",
                 identity="anonymous", parameters=["next"]),
    ]))
    sandbox = Sandbox(tmp_path, cfg.model_dump())
    result = await CatalogueAdapter().run(Context("s", "tests", "https://app.test", cfg), sandbox)

    steps = {s["name"]: s for row in result.observations if row["type"] == "test_case"
             for s in row["steps"]}
    assert steps["client_side_sink_review"]["skipped"] is True
    assert "LLM evaluator" in steps["client_side_sink_review"]["error"]
    assert not steps["declared_parameter_probe"]["skipped"], "the real arms still run"
    assert result.metadata["executed_checks"] == 3, "the inert arm is not counted as a check"


async def test_two_parameters_on_one_url_do_not_collapse_into_one_finding(database, tmp_path):
    """fingerprint() has always taken a `parameter` and never been given one.
    Harmless while a case ran once per URL; running it once per parameter made
    two findings hash identically, and persist_result writes findings INSERT OR
    REPLACE on (session_id, fingerprint)."""
    from orchestrator.integrations.contracts import fingerprint
    same_url = ("https://app.test", "WSTG-INPV-18:jinja", "GET", "https://app.test/s")
    assert fingerprint(*same_url, "q", "anon") != fingerprint(*same_url, "lang", "anon")
    assert fingerprint(*same_url, "", "anon") == fingerprint(*same_url, "", "anon")

    import inspect
    from orchestrator.integrations import deterministic
    source = inspect.getsource(deterministic.CatalogueAdapter.run)
    assert "probed, ctx.identity_id" in source, "the parameter must reach the fingerprint"
    assert "parameter=probed" in source, "and the finding must name it"
