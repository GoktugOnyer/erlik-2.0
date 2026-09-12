"""The cross-arm authorization checks were a capability with no input.

Three increments built `cross_arm_authorization` and `cross_arm_privileged_function`, which
compare what each arm received for the SAME request. They read the evidence catalogue cases
leave behind — and not one runnable case simply reads a discovered endpoint. Measured on the
first real three-arm run:

    privileged-function  findings=0  checked=34  refused_because=[]
    object-level         findings=0  checked=34  refused_because=[]

Both ran clean, compared 34 operations, and found nothing, because no arm had ever asked for
a privileged object. The zero was honest and useless.

`ERLIK-SURFACE-READ` is one plain GET of each discovered endpoint, per arm, recorded as
evidence and evaluating NOTHING. It is deliberately not a WSTG case: a single read by a
single identity cannot tell privileged data from published data — that is the whole reason
the comparison is cross-arm — and a catalogue entry whose evaluator can never fire is the
vacuous-case shape this project keeps deleting.
"""
import json
import uuid

import pytest

from orchestrator.integrations.deterministic import (SURFACE_READ, SURFACE_READ_ID,
                                                    surface_read_budget, target_budget)


# ------------------------------------------------------- what it is, and is not

def test_the_probe_concludes_nothing_on_its_own():
    """It has no evaluator. One read by one identity cannot distinguish a privileged
    response from a public one, and a probe that claimed otherwise would be asserting the
    very thing the cross-arm comparison exists to establish."""
    assert len(SURFACE_READ.steps) == 1
    assert SURFACE_READ.steps[0].evaluators == []


def test_it_is_not_in_the_catalogue():
    """It is not a WSTG test and must not be selectable as one, or an operator would pick it
    expecting a verdict."""
    from orchestrator.integrations.inventory import executable_test_cases
    from orchestrator.testcase.loader import find_by_id

    assert find_by_id(SURFACE_READ_ID) is None
    assert SURFACE_READ_ID not in executable_test_cases()


def test_an_assessment_cannot_select_it_as_a_test_case():
    import pydantic
    from orchestrator.integrations.contracts import AssessmentConfig

    with pytest.raises(pydantic.ValidationError):
        AssessmentConfig(scope={"allow_hosts": ["a"], "allow_ports": [80]},
                         active=True, test_cases=[SURFACE_READ_ID])


def test_the_read_is_a_plain_GET_that_the_dialect_accepts():
    from orchestrator.integrations.deterministic import curl_request

    command = SURFACE_READ.steps[0].command.replace("{{url}}", "http://app.test/x")
    argv, url, method = curl_request(command)
    assert method == "GET"
    assert "-X" not in argv and "--data" not in argv and "-d" not in argv
    assert "-i" in argv, "the capture must include the status line, or nothing can read it"
    assert "--max-time" in argv, "an unbounded read can wedge the stage"


# ------------------------------------- the key the cross-arm checks compare on

def test_every_arm_uses_THE_SAME_id_and_step():
    """`arm_responses` keys evidence on (url, test_case, step, parameter). A comparison
    needs the arms to agree on all four, so the id and the step name are constants rather
    than anything derived from the arm."""
    assert SURFACE_READ.id == SURFACE_READ_ID
    assert SURFACE_READ.steps[0].name == "read"


async def test_a_cross_arm_check_finds_a_violation_from_SURFACE_READ_EVIDENCE_ALONE(
        tmp_path, monkeypatch):
    """The end-to-end point of the increment: with no catalogue case involved at all, the
    evidence this probe records is enough for the shipped check to fire."""
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    from orchestrator.integrations.contracts import Identity
    from orchestrator.integrations.inventory import cross_arm_privileged_function
    from orchestrator.integrations.security import SecretStore

    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    await db.execute("INSERT INTO integration_assessments(session_id,target,status,config) "
                     "VALUES(?,?,?,?)", ("s", "http://app.test", "completed", "{}"))

    url = "http://app.test/api/Users"
    marker = '"email":"admin@app.test"'
    roster = ('HTTP/1.1 200 OK\r\n\r\n{"status":"success","data":'
              '[{"id":1,"email":"admin@app.test","role":"admin"}]}')
    denied = "HTTP/1.1 401 Unauthorized\r\n\r\nUnauthorizedError"

    store, handles = SecretStore(), {}
    for name, role in (("admin", "admin"), ("jim", "customer")):
        handles[name] = store.put(Identity.model_validate({
            "name": name, "target_origin": "http://app.test", "role": role,
            "check": {"url": "http://app.test/me", "body_contains": name}}).model_dump())
        await db.execute("INSERT INTO integration_identities VALUES(?,?,?)",
                         (handles[name], name, "http://app.test"))
    handles["anonymous"] = "anonymous"

    for arm, capture in (("admin", roster), ("jim", roster), ("anonymous", denied)):
        stage_id = uuid.uuid4().hex
        await db.execute("INSERT INTO integration_stages(id,session_id,adapter,identity_id,"
                         "status,result) VALUES(?,?,?,?,?,?)",
                         (stage_id, "s", "testcases", handles[arm], "completed",
                          json.dumps({"status": "completed"})))
        await db.execute("INSERT OR REPLACE INTO integration_endpoints(session_id,url,method,"
                         "identity_id,sources,parameters) VALUES(?,?,?,?,?,?)",
                         ("s", url, "GET", handles[arm], json.dumps(["katana"]), "[]"))
        # Exactly what the probe writes: its id, its step, no parameter, no findings.
        run = {"test_case_id": SURFACE_READ_ID, "target": {"url": url, "parameter": ""},
               "findings": [], "chain_next": [], "stopped_early": False, "duration_ms": 1,
               "produced": {},
               "steps": [{"step": "read", "command": "curl", "success": True,
                          "duration_ms": 1, "exit_code": 0, "skipped": False,
                          "error": None, "output": capture}]}
        await db.evidence("s", stage_id, "testcase:" + SURFACE_READ_ID, json.dumps(run))

    result = await cross_arm_privileged_function("s", handles["admin"], handles["jim"],
                                                marker, anonymous="anonymous")
    assert result["refused_because"] == [], result
    assert [f["url"] for f in result["findings"]] == [url]


# ----------------------------------------------------------------- the budget

def test_it_takes_one_share_rather_than_half_of_everyones():
    """Enabling it must not quietly halve what each catalogue case gets. It counts as one
    more single-step case."""
    assert surface_read_budget(500, 4) == target_budget(500, 5, 1)
    # A selected case's own share is unchanged by its existence.
    assert target_budget(500, 4, 1) == 125


def test_it_is_never_zero():
    """A probe that could read nothing at all would run, record nothing, and the cross-arm
    checks would report an honest zero for the wrong reason."""
    assert surface_read_budget(1, 20) >= 1


# ------------------------------------------------- what it must never do

@pytest.fixture
async def stage(tmp_path, monkeypatch):
    """Drive the real CatalogueAdapter against a stubbed sandbox.

    Behavioural rather than source-grep: three of these assertions were first written as
    `assert "..." in inspect.getsource(...)`, and ablating the GATE they describe was then
    "caught" only because the source string moved — which is caught by nothing.
    """
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    from orchestrator.integrations import deterministic as det
    from orchestrator.integrations.adapters import Context
    from orchestrator.integrations.contracts import AssessmentConfig
    from orchestrator.integrations.security import SecretStore
    from orchestrator.integrations.contracts import Identity

    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()

    PAGE = "http://app.test/page"
    FORM = "http://app.test/vulnerabilities/csrf/?Change=Change"
    issued = []

    class _Output:
        code, stdout, stderr = 0, "HTTP/1.1 200 OK\r\n\r\nbody", ""

    class _Sandbox:
        policy = {"scope": {"allow_hosts": ["app.test"], "allow_ports": [80]},
                  "state_changing": False, "excluded_paths": []}
        proxy_url = "http://proxy:8080"
        images = {}
        directory = tmp_path / "job"
        output = tmp_path / "job" / "output"

        async def run(self, argv):
            issued.append(" ".join(str(a) for a in argv))
            return _Output()

        async def audit(self):
            return []

    async def seeds(ctx, policy, include_form_actions=False):
        return [PAGE, FORM] if include_form_actions else [PAGE]

    async def form_urls(ctx):
        return {FORM}

    async def parameters_by_url(ctx, policy):
        return {}

    monkeypatch.setattr(det, "seeds", seeds)
    monkeypatch.setattr(det, "form_urls", form_urls)
    monkeypatch.setattr(det, "parameters_by_url", parameters_by_url)

    async def go(**overrides):
        issued.clear()
        handle = SecretStore().put(Identity.model_validate({
            "name": "admin", "target_origin": "http://app.test", "role": "admin",
            "check": {"url": "http://app.test/me", "body_contains": "admin"}}).model_dump())
        config = AssessmentConfig(
            scope={"allow_hosts": ["app.test"], "allow_ports": [80]}, active=True,
            identity_ids=overrides.pop("identity_ids", [handle]),
            test_cases=[], max_urls=50,
            budget={"stage_seconds": 60, "assessment_seconds": 120}, **overrides)
        ctx = Context("s", "st", "http://app.test/", config, handle, {"name": "admin"})
        await db.execute("INSERT INTO integration_stages(id,session_id,adapter,identity_id,"
                         "status,result) VALUES(?,?,?,?,?,?)",
                         ("st", "s", "testcases", handle, "running", "{}"))
        result = await det.CatalogueAdapter().run(ctx, _Sandbox())
        reads = await db.rows("SELECT id FROM integration_evidence WHERE session_id='s' "
                              "AND kind=?", ("testcase:" + SURFACE_READ_ID,))
        return result, reads, list(issued), PAGE, FORM

    return go


async def test_it_reads_the_discovered_page(stage):
    result, reads, issued, page, _ = await stage()
    assert len(reads) == 1, "the probe did not run"
    assert result.metadata["surface_read"]["urls_read"] == 1
    assert any(page in str(a) for a in issued)


async def test_it_never_fetches_a_form_synthesised_url(stage):
    """A URL that exists only because a GET form was found is not a page; requesting it
    performs the form's action. Measured on DVWA: a bare GET of
    `/vulnerabilities/csrf/?Change=Change` sets the admin password to md5("")."""
    result, _, issued, _, form = await stage()
    assert not any(form in str(a) for a in issued), (
        "the surface read submitted a form; on DVWA that changes the admin password")
    assert result.metadata["surface_read"]["urls_withheld_as_form_actions"] == 1


async def test_it_is_inert_without_a_second_arm(stage):
    """Nothing to difference, so the requests would buy nothing."""
    _, reads, issued, page, _ = await stage(identity_ids=[])
    assert reads == [] and not any(page in str(a) for a in issued)


async def test_the_operator_can_switch_it_off(stage):
    _, reads, issued, page, _ = await stage(surface_read=False)
    assert reads == [] and not any(page in str(a) for a in issued)


async def test_it_records_no_test_case_observation(stage):
    """`coverage()` counts a `test_case` observation as a check having run against an
    endpoint. This is not a check, so one would overstate what was tested by exactly the
    number of URLs read."""
    result, reads, _, page, _ = await stage()
    assert reads, "the probe must have run, or this proves nothing"
    assert [o for o in result.observations if o.get("type") == "test_case"] == []


async def test_what_it_did_is_on_the_record(stage):
    """Not as coverage, but not invisible either: an operator has to be able to see which
    arm read how much of the surface."""
    result, _, _, _, _ = await stage()
    record = result.metadata["surface_read"]
    assert record["urls_read"] == 1 and record["urls_available"] == 1
    assert "nothing on its own" in record["establishes"]


async def test_it_cannot_raise_any_pair_above_not_run(tmp_path, monkeypatch):
    """THE PROPERTY, not the source text.

    This asserted `"surface_read_truncated" not in inspect.getsource(inventory.coverage)` —
    a proxy for the real rule, which is that a READ must never be credited as a check. The
    sibling test above keeps that rule where it belongs, on the `test_case` observation.

    The proxy forbade more than the rule does. `coverage()` now indexes the TRUNCATION, which
    is a statement that work did NOT happen: it maps to `not_run`, it loses every tie so it
    cannot displace a better state, and its reason is appended only to pairs nothing reached.
    Measured on the real Juice Shop run, states before and after: verified 8, answered 99,
    not_run 459 — identical — while 459 rows gained the sentence "126 of 184 in-scope URLs
    were not read as this identity, so the cross-arm authorization checks have no evidence for
    them", which no row carried before and which is the fact that decides whether the
    authorization findings could have seen an operation at all.

    So what must hold is the DIRECTION: a surface-read observation can only ever make a pair
    look less tested, never more.
    """
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    from orchestrator.integrations.deterministic import SURFACE_READ_ID
    from orchestrator.integrations.inventory import coverage

    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    await db.execute("INSERT INTO integration_assessments(session_id,target,status,config) "
                     "VALUES(?,?,?,?)", ("s", "http://app.test/", "completed", "{}"))
    await db.execute("INSERT INTO integration_endpoints"
                     "(session_id,url,method,identity_id,sources) VALUES(?,?,?,?,?)",
                     ("s", "http://app.test/a", "GET", "anonymous", '["katana"]'))
    await db.execute("INSERT INTO integration_stages"
                     "(id,session_id,adapter,identity_id,status,result) VALUES(?,?,?,?,?,?)",
                     ("st", "s", "testcases", "anonymous", "completed", json.dumps({
                         "observations": [{"type": "surface_read_truncated",
                                           "test_case_id": SURFACE_READ_ID, "url": None,
                                           "steps": [], "reason": "9 of 10 were not read"}]})))
    rows = await coverage("s")
    assert rows, "no coverage row at all; this would prove nothing"
    assert {r["state"] for r in rows} == {"not_run"}, (
        "a surface READ must never be credited as a check having run")
    assert "9 of 10 were not read" in rows[0]["reason"]


def test_the_operator_can_turn_it_off():
    from orchestrator.integrations.contracts import AssessmentConfig

    base = {"scope": {"allow_hosts": ["a"], "allow_ports": [80]}}
    assert AssessmentConfig(**base).surface_read is True
    assert AssessmentConfig(**base, surface_read=False).surface_read is False


# ------------------------------------------- where it spends a budget it cannot finish

def test_a_static_asset_goes_last_because_it_cannot_differ_by_identity():
    """`seeds()` returns `ORDER BY url`, and alphabetical wasted the share. Measured on a
    real 63-URL Juice Shop inventory at `max_urls=60` with four cases, where the share is
    twelve: the twelve were the homepage, `MaterialIcons-Regular.woff2`, two JSON APIs,
    `favicon_js.ico`, `assets/i18n/en.json` and six product JPEGs, and the first `/rest/` URL
    sat at rank 24. Reordering took it from 3 of 12 API URLs to 10 of 12."""
    from orchestrator.integrations.deterministic import surface_read_order

    urls = ["http://app.test/MaterialIcons.woff2", "http://app.test/api/Users",
            "http://app.test/assets/i18n/en.json", "http://app.test/b.jpg",
            "http://app.test/main.js", "http://app.test/rest/basket/1"]
    ordered = surface_read_order(urls)
    assert ordered == ["http://app.test/api/Users", "http://app.test/rest/basket/1",
                       "http://app.test/MaterialIcons.woff2",
                       "http://app.test/assets/i18n/en.json", "http://app.test/b.jpg",
                       "http://app.test/main.js"], ordered


def test_it_is_a_REORDERING_not_a_filter():
    """A generous budget must still read everything. Dropping static assets would make the
    probe's coverage depend on a guess about what matters."""
    from orchestrator.integrations.deterministic import surface_read_order

    urls = ["http://app.test/a.jpg", "http://app.test/api/Users", "http://app.test/b.css"]
    assert sorted(surface_read_order(urls)) == sorted(urls)


def test_the_probes_input_carries_no_fragment_to_collapse():
    """`seeds()` defragments every candidate before returning it, so the ordering must not
    re-implement that. A fragment is never sent to a server — `/#/about` and `/` answer 200
    with an identical 3748 bytes on Juice Shop — and a draft of the ordering collapsed them,
    which could never fire. Measured on a real run: 0 of the 86 URLs read carried a fragment.
    """
    import inspect

    from orchestrator.integrations import inventory
    from orchestrator.integrations.deterministic import surface_read_order

    assert "urldefrag" in inspect.getsource(inventory.seeds), (
        "the ordering relies on seeds() doing this; if it stops, the ordering must start")
    # The ordering therefore does NOT do it again — it passes both variants through, which is
    # how a reader can tell the responsibility lives in one place.
    assert surface_read_order(["http://app.test/#/a", "http://app.test/"]) == [
        "http://app.test/", "http://app.test/#/a"]


@pytest.mark.parametrize("url,static", [
    ("http://app.test/api/Users", False),
    ("http://app.test/rest/admin/application-configuration", False),
    ("http://app.test/main.js", True),
    ("http://app.test/assets/i18n/en.json", True),
    ("http://app.test/MaterialIcons-Regular.woff2", True),
    ("http://app.test/favicon.ico", True),
    ("http://app.test/static/app/data", True),
    ("http://app.test/.json", False),
])
def test_what_counts_as_bytes_off_a_disk(url, static):
    from orchestrator.integrations.deterministic import looks_static

    assert looks_static(url) is static


# ------------------------------------- the operator can reconcile read with compared

async def test_the_check_says_how_many_reads_it_could_not_compare(tmp_path, monkeypatch):
    """Measured on a real run: each arm held evidence for 130 URLs, `gated` was 46, and the
    only visible trace was `checked=46`. The 84 missing were all `/socket.io/?…&sid=…`, whose
    per-arm session id puts them in one arm's endpoint rows and not the other's — correct to
    drop, and not something an operator should have to infer from a subtraction."""
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    from orchestrator.integrations.contracts import Identity
    from orchestrator.integrations.inventory import cross_arm_privileged_function
    from orchestrator.integrations.security import SecretStore

    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    await db.execute("INSERT INTO integration_assessments(session_id,target,status,config) "
                     "VALUES(?,?,?,?)", ("s", "http://app.test", "completed", "{}"))
    store, handles = SecretStore(), {}
    for name, role in (("admin", "admin"), ("jim", "customer")):
        handles[name] = store.put(Identity.model_validate({
            "name": name, "target_origin": "http://app.test", "role": role,
            "check": {"url": "http://app.test/me", "body_contains": name}}).model_dump())
        await db.execute("INSERT INTO integration_identities VALUES(?,?,?)",
                         (handles[name], name, "http://app.test"))
    shared = "http://app.test/api/Users"
    only_admin = "http://app.test/socket.io/?sid=aaa"
    for arm, urls in (("admin", [shared, only_admin]), ("jim", [shared]),
                      ("anonymous", [shared])):
        identity = handles.get(arm, "anonymous")
        stage_id = uuid.uuid4().hex
        await db.execute("INSERT INTO integration_stages(id,session_id,adapter,identity_id,"
                         "status,result) VALUES(?,?,?,?,?,?)",
                         (stage_id, "s", "testcases", identity, "completed",
                          json.dumps({"status": "completed"})))
        for url in urls:
            await db.execute("INSERT OR REPLACE INTO integration_endpoints(session_id,url,"
                             "method,identity_id,sources,parameters) VALUES(?,?,?,?,?,?)",
                             ("s", url, "GET", identity, json.dumps(["katana"]), "[]"))
            run = {"test_case_id": SURFACE_READ_ID,
                   "target": {"url": url, "parameter": ""}, "findings": [],
                   "chain_next": [], "stopped_early": False, "duration_ms": 1, "produced": {},
                   "steps": [{"step": "read", "command": "curl", "success": True,
                              "duration_ms": 1, "exit_code": 0, "skipped": False,
                              "error": None,
                              "output": "HTTP/1.1 200 OK\r\n\r\n{\"x\":1}"}]}
            await db.evidence("s", stage_id, "testcase:" + SURFACE_READ_ID, json.dumps(run))

    result = await cross_arm_privileged_function("s", handles["admin"], handles["jim"],
                                                '"x":1', anonymous="anonymous")
    assert result["urls_not_shared_by_both_arms"] == 1, (
        "the admin arm read a URL the other arm has no endpoint row for, and the report must "
        "say so rather than leave a gap between 2 read and 1 checked")


async def test_it_reads_only_what_this_arm_already_requested(stage):
    """WHAT BOUNDS THE EXPOSURE. A plain GET is not always a read — measured on Juice Shop, a
    bare `GET /rest/captcha/` runs `CaptchaModel.build().save()` and rotates the live captcha
    (captchaId 51 then 52 on two consecutive reads), and retrieving five static PNGs under
    `/assets/public/images/padding/` flips challenges to solved. `state_changing: false`
    cannot express that, because it is about the METHOD.

    What does bound it is the input: `seeds()` returns only this arm's own endpoint rows, so
    every URL read was already requested by this arm's crawler. Verified on a real run: 0 of
    86 URLs read were absent from that arm's rows. The probe changes the volume of requests,
    not the class of side effect the lane already causes.
    """
    result, _, issued, page, form = await stage()
    fetched = [a for a in issued if "http://" in a]
    # The only URL it fetched is the one discovery had already produced a row for.
    assert all(page in a or "/input/ca.pem" in a for a in fetched), fetched
    assert result.metadata["surface_read"]["urls_read"] == 1
