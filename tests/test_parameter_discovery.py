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
    runnable = [st for st in find_by_id("WSTG-CLNT-04").steps
                if not (st.evaluators and all(ev.type == "llm" for ev in st.evaluators))]
    assert result.metadata["executed_checks"] == len(runnable), (
        "the inert arm is not counted as a check")


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


async def test_the_operators_own_target_can_name_a_parameter(database):
    """If they pointed the assessment at https://app.test/search?q=… they named
    one; waiting for a crawler to rediscover it would be perverse. seeds()
    already treats the target as a URL candidate for the same reason."""
    class TargetCtx(Ctx):
        target = "https://app.test/search?q=hello&page=2"
    found = await parameters_by_url(TargetCtx(), POLICY)
    assert found == {"https://app.test/search": ["q", "page"]}


async def test_a_truncated_sweep_says_so(database, tmp_path):
    """A truncated sweep that reports nothing looks exactly like a clean one.

    The cap is denominated in REQUESTS: the proxy spends max_urls on distinct
    (method, URL) and one pair costs a case one request per step, so a
    pair-denominated cap was looser than the wall it protects by exactly the
    step count and could never bind first."""
    cfg = config(active=True, test_cases=["WSTG-INPV-18"], max_urls=12)
    steps = len(find_by_id("WSTG-INPV-18").steps)
    await database.persist_result("s", "discovery", StageResult(endpoints=[
        Endpoint(url=f"https://app.test/p{n}", source="katana", identity="anonymous",
                 parameters=["a", "b"]) for n in range(4)
    ]))
    sandbox = Sandbox(tmp_path, cfg.model_dump())
    result = await CatalogueAdapter().run(Context("s", "tests", "https://app.test", cfg), sandbox)

    allowed = max(1, cfg.max_urls // steps)
    assert allowed < 8, "the fixture must actually exceed the budget"
    urls = {a for argv in sandbox.calls for a in argv if a.startswith("https://")}
    assert len(urls) <= cfg.max_urls, "the sweep stays inside the budget the proxy enforces"
    truncated = [o for o in result.observations if o["type"] == "test_case_truncated"]
    assert len(truncated) == 1
    assert f"{8 - allowed} of 8" in truncated[0]["reason"], truncated[0]["reason"]
    assert f"one pair costs {steps}" in truncated[0]["reason"]


class TestATargetCannotChooseTheEvidence:
    """The name is chosen by the target; so is the response. Most applications
    echo an unrecognised parameter name back, so a name matching the case's own
    marker makes that echo the evidence."""

    @pytest.mark.parametrize("case_id,name,vuln", [
        ("WSTG-INPV-18", "219359", "Server-Side Template Injection"),
        ("WSTG-INPV-18", "7777777", "string repetition"),
        ("WSTG-INPV-11.2", "XPathException", "reaches an interpreter"),
        ("WSTG-INPV-11.2", "smtplib", "mail/header layer"),
    ])
    async def test_a_name_that_is_the_marker_never_reaches_the_case(self, case_id, name, vuln):
        from orchestrator.testcase.runner import run_test_case
        from orchestrator.integrations.inventory import parameter_can_forge
        tc = find_by_id(case_id)

        async def echoes_the_name(command, **kw):
            body = f'<input type="hidden" name="{name}">Unknown field: {name}'
            return {"success": True, "exit_code": 0, "error": None,
                    "output": f"HTTP/1.1 200 OK\r\n\r\n{body}"}

        # Without the gate this stub — an ordinary app with no template engine —
        # produces the finding outright.
        run = await run_test_case(tc, {"url": "https://app.test/s", "parameter": name,
                                       "scope": {"allow_hosts": ["app.test"]}},
                                  executor=echoes_the_name, allow_llm=False)
        assert any(vuln in (f.vuln_type or "") for f in run.findings), (
            "the stub must actually forge it, or this test proves nothing")
        # The gate is what stops the pair ever being built.
        assert parameter_can_forge(tc, name)

    @pytest.mark.parametrize("name", ["q", "page", "next", "user[id]", "search", "id"])
    def test_an_ordinary_name_is_not_refused_by_any_case(self, name):
        from orchestrator.integrations.inventory import parameter_can_forge
        for case_id in ("WSTG-INPV-18", "WSTG-INPV-11.2", "WSTG-CLNT-04"):
            assert not parameter_can_forge(find_by_id(case_id), name)

    async def test_a_forgeable_name_is_dropped_and_reported(self, database, tmp_path):
        cfg = config(active=True, test_cases=["WSTG-INPV-18"])
        await database.persist_result("s", "discovery", StageResult(endpoints=[
            Endpoint(url="https://app.test/s?219359=1&q=2", source="katana",
                     identity="anonymous", parameters=["219359", "q"]),
        ]))
        sandbox = Sandbox(tmp_path, cfg.model_dump())
        result = await CatalogueAdapter().run(Context("s", "tests", "https://app.test", cfg), sandbox)
        probed = {a.split("=", 1)[0] for argv in sandbox.calls for a in argv
                  if "=" in a and not a.startswith("-") and not a.startswith("http")}
        assert probed == {"q"}, "the planted name is never sent"
        refused = [o for o in result.observations if o["type"] == "parameter_refused"]
        assert refused and refused[0]["parameters"] == ["219359"]


class TestTheSchemaIsTheOneSourceTheTargetDoesNotControl:
    """Every crawler-derived name is text the application chose to publish. The
    OpenAPI document is the operator's, and it states each parameter's location
    outright instead of leaving it to be inferred from a URL — so a name from
    here cannot be planted to match a case's evidence."""

    DOC = {"paths": {
        "/search": {"parameters": [{"name": "lang", "in": "query"}],
                    "get": {"parameters": [{"name": "q", "in": "query"},
                                           {"name": "X-Trace", "in": "header"},
                                           {"name": "sid", "in": "cookie"}]}},
        "/items/{id}": {"get": {"parameters": [{"name": "expand", "in": "query"}]}},
        "/submit": {"post": {"parameters": [{"name": "csrf", "in": "query"}]}},
        "/none": {"get": {}},
    }}

    def test_only_query_parameters_of_untemplated_safe_operations(self):
        from orchestrator.integrations.adapters import schema_endpoints
        found = schema_endpoints(self.DOC, "https://app.test/api/", "reader")
        assert [(e.url, e.method, e.parameters, e.source) for e in found] == [
            ("https://app.test/search", "GET", ["lang", "q"], "openapi")]

    def test_a_header_or_cookie_parameter_never_becomes_a_query_probe(self):
        from orchestrator.integrations.adapters import schema_endpoints
        names = {n for e in schema_endpoints(self.DOC, "https://app.test/", "reader") for n in e.parameters}
        assert "X-Trace" not in names and "sid" not in names

    def test_it_is_recorded_whether_or_not_the_scanner_reaches_anything(self):
        """The schema is known before the run; endpoints from it must not
        depend on Schemathesis producing a request log."""
        import inspect
        from orchestrator.integrations import adapters
        source = inspect.getsource(adapters.SchemathesisAdapter.run)
        assert source.index("schema_declared = schema_endpoints") < source.index("requests.har")


async def test_schema_file_returns_the_same_shape_with_and_without_a_schema():
    """It grew a third return value (the parsed document) and the no-schema
    early return kept two, so every ZAP run — which calls this whether or not a
    schema was configured — died unpacking it. Four Docker acceptance tests
    caught it; nothing in the unit suite would have."""
    from orchestrator.integrations.adapters import schema_file
    assert len(await schema_file(Context("s", "stage", "https://app.test", config()), None)) == 3


async def test_a_stage_that_runs_out_of_time_keeps_what_it_found(database, tmp_path):
    """service.py wraps each stage in asyncio.timeout and on expiry REPLACES the
    accumulated StageResult with an empty one, so everything found before the
    deadline is discarded. Measured against Juice Shop: a 120-URL inventory
    times out here long before it finishes. The adapter therefore stops on its
    own, short of the outer deadline, and returns what it has."""
    import time
    cfg = config(active=True, test_cases=["WSTG-SESS-02", "WSTG-INFO-03"],
                 budget={"stage_seconds": 3})
    await database.persist_result("s", "discovery", StageResult(endpoints=[
        Endpoint(url=f"https://app.test/p{n}", source="katana", identity="anonymous")
        for n in range(60)]))

    class SlowSandbox(Sandbox):
        async def run(self, argv, **kw):
            time.sleep(0.1)                        # blocking, like a container start
            return await super().run(argv, **kw)

    sandbox = SlowSandbox(tmp_path, cfg.model_dump())
    result = await CatalogueAdapter().run(Context("s", "tests", "https://app.test", cfg), sandbox)

    assert result.status == "partial"
    assert "budget" in (result.reason or "")
    assert sandbox.calls, "it did real work before stopping"
    unrun = [o for o in result.observations
             if o["type"] in ("test_case_not_run", "test_case_truncated")]
    assert unrun, "and says what it did not reach"


async def test_a_crawler_that_finds_nothing_does_not_report_success(database, tmp_path):
    """Measured against DVWA: katana emits no output and exits 0 there, while
    working normally on Juice Shop. The stage was recorded "completed", which
    reads as a clean result for an application famously full of holes — and
    everything downstream is sized by this inventory, so no endpoints means no
    parameters means every case that tests one reports nothing."""
    from orchestrator.integrations.adapters import ADAPTERS

    class EmptySandbox(Sandbox):
        async def run(self, argv, **kw):
            await super().run(argv, **kw)
            return JobOutput(0, "", "")               # katana's DVWA behaviour

    cfg = config()
    sandbox = EmptySandbox(tmp_path, cfg.model_dump())
    result = await ADAPTERS["katana"].run(Context("s", "katana", "https://app.test", cfg), sandbox)
    assert result.endpoints == []
    assert result.status == "partial", "an empty inventory is not a clean result"
    assert "no endpoints" in (result.reason or "")


class TestFormControlsBecomeTestableParameters:
    """An input the crawler cannot see is an input nothing can test. DVWA's
    injectable fields are all behind GET forms, which is why the lane found
    nothing there in the 2026-09-09 baseline."""

    DVWA_SQLI = {"action": "http://dvwa/vulnerabilities/sqli/", "method": "GET", "controls": [
        {"name": "id", "type": "text", "value": ""},
        {"name": "Submit", "type": "submit", "value": "Submit"},
        {"name": "user_token", "type": "hidden", "value": "98185e14d0ebc2fd25e0691270fce03f"},
    ]}

    def test_the_companion_fields_ride_along(self):
        """Measured on the running application: `?id=<payload>` returns nothing
        and `?id=<payload>&Submit=Submit` returns the rows. A discovery that
        reported `id` alone would hand every case a probe that cannot reach the
        handler — an input discovered and untestable, reported as tested."""
        from orchestrator.integrations.contracts import form_endpoint
        url, names = form_endpoint(self.DVWA_SQLI, "http://dvwa/vulnerabilities/sqli/")
        assert names == ["id"], "only the control an operator would type into"
        assert "Submit=Submit" in url and "user_token=" in url
        assert "id=" not in url, "the name under test must not already be in the query"

    def test_a_post_form_is_not_a_query_parameter_source(self):
        """Its controls are BODY parameters; probing them as query parameters is
        the same category error as trusting ZAP's `param`."""
        from orchestrator.integrations.contracts import form_endpoint
        assert form_endpoint({**self.DVWA_SQLI, "method": "POST"}, "http://dvwa/") is None

    @pytest.mark.parametrize("controls,why", [
        ([{"name": "go", "type": "submit", "value": "Go"}], "nothing an operator would type into"),
        ([{"name": "a#b", "type": "text", "value": ""}], "the name is not a parameter name"),
        ([], "no controls at all"),
    ])
    def test_a_form_with_nothing_to_test_produces_no_endpoint(self, controls, why):
        from orchestrator.integrations.contracts import form_endpoint
        assert form_endpoint({"action": "http://a.test/", "method": "GET", "controls": controls},
                             "http://a.test/") is None, why

    def test_a_companion_value_cannot_break_out_of_the_query(self):
        """Companion values are target-controlled text going into a URL."""
        from orchestrator.integrations.contracts import form_endpoint
        url, names = form_endpoint({"action": "http://a.test/s", "method": "GET", "controls": [
            {"name": "q", "type": "text", "value": ""},
            {"name": "t", "type": "hidden", "value": "a&b=c#d /x?y"}]}, "http://a.test/s")
        assert names == ["q"]
        assert url == "http://a.test/s?t=a%26b%3Dc%23d+%2Fx%3Fy"
        curl_request(f'curl -s -G "{url}" --data "q=probe"')     # must still parse

    def test_every_parameter_case_joins_a_companion_query_correctly(self):
        """WSTG-CLNT-04 used `"{{url}}?{{parameter}}=…"`, which against a form
        endpoint produces `?Submit=Submit?id=…` — one parameter whose value
        contains a question mark, silently probing nothing."""
        from urllib.parse import parse_qs, urlsplit
        from orchestrator.testcase.runner import _render, _origin_fields
        form_url = "http://dvwa/vulnerabilities/sqli/?Submit=Submit&user_token=abc"
        derived = _origin_fields(form_url)
        for case_id in ("WSTG-CLNT-04", "WSTG-INPV-11.2", "WSTG-INPV-18"):
            for step in find_by_id(case_id).steps:
                _, url, _ = curl_request(_render(step.command, {**derived, "url": form_url,
                                                                "parameter": "id"}))
                # The property is that the JOIN is well formed — the query
                # parses and both the companion and the name under test are
                # keys in it. Counting "?" characters cannot tell a malformed
                # join from a payload that legitimately contains one, and
                # WSTG-CLNT-04's allow-listed-string payload does.
                query = parse_qs(urlsplit(url).query, keep_blank_values=True)
                assert "Submit" in query, f"{case_id}/{step.name} dropped the companion: {url}"
                assert url.split("?", 1)[0] == "http://dvwa/vulnerabilities/sqli/", (
                    f"{case_id}/{step.name} moved the path: {url}")

    async def test_a_form_endpoint_keeps_its_query_a_crawled_one_does_not(self, database):
        await database.persist_result("s", "discovery", StageResult(endpoints=[
            Endpoint(url="https://app.test/f?Submit=Submit", source="form",
                     identity="reader", parameters=["id"]),
            Endpoint(url="https://app.test/c?q=hello", source="katana",
                     identity="reader", parameters=["q"]),
        ]))
        found = await parameters_by_url(Ctx(), POLICY)
        assert found == {"https://app.test/f?Submit=Submit": ["id"],
                         "https://app.test/c": ["q"]}
