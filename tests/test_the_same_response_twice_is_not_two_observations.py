"""Half the lane's read budget bought the same document twice.

Everything the lane does is rationed by `max_urls`. Measured on a real three-arm Juice Shop
assessment: of 86 surface reads, **37 returned a response the lane had already seen**, absorbed
into THREE survivors — `/`, `/api/Feedbacks` and `/api/Quantitys`. The 36-strong group is the
single-page application's shell, which its server returns for any route it does not know:

    /  /%5C/index.html  /.json  /2fa/enter  /Edge/  /Trident/  /about  /accounting
    /address/create   ...and 27 more

`/Edge/` and `/Trident/` are browser-detection regex fragments katana mined out of a JavaScript
bundle. A catalogue case probing those for injection cannot find anything, and a coverage report
listing them as untested reads as outstanding work when there is none — that report said 461 of
566 rows were `not_run`.

THE RULE IS A COMPARISON, NOT A GUESS. Two URLs that answered with the same status, the same
stable headers and the same body produced one observation; the second is a spelling of the first.
"""
import json

import pytest

from orchestrator.integrations.inventory import indistinct_urls, response_signature


def capture(body, status=200, extra="", date="Fri, 11 Sep 2026 12:00:00 GMT"):
    return (f"HTTP/1.1 {status} OK\r\nDate: {date}\r\n"
            f"Content-Length: {len(body)}\r\n{extra}\r\n{body}")


SHELL = capture("<html>app shell</html>")


# ------------------------------------------------------ what counts as the same response

def test_the_spa_shell_collapses_to_one_observation():
    pruned = indistinct_urls([("http://a/", SHELL), ("http://a/Edge/", SHELL),
                              ("http://a/Trident/", SHELL), ("http://a/about", SHELL),
                              ("http://a/api/Users", capture('{"data":[{"id":1}]}'))])
    assert pruned == {"http://a/Edge/": "http://a/", "http://a/Trident/": "http://a/",
                      "http://a/about": "http://a/"}


def test_the_first_spelling_survives():
    """The caller controls which URL is kept by the order it reads in, and the surface read
    reads dynamic-first then alphabetically — so `/` survives and the SPA routes go."""
    assert indistinct_urls([("http://a/x", SHELL), ("http://a/y", SHELL)]) == {
        "http://a/y": "http://a/x"}


def test_a_trailing_slash_alias_collapses_too():
    """`/api/Feedbacks` and `/api/Feedbacks/` are separate endpoint rows with identical bodies
    on Juice Shop — one rule folds in both cases."""
    body = capture('{"data":[]}')
    assert indistinct_urls([("http://a/api/Feedbacks", body),
                            ("http://a/api/Feedbacks/", body)]) == {
        "http://a/api/Feedbacks/": "http://a/api/Feedbacks"}


@pytest.mark.parametrize("one,two,why", [
    (capture("same"), capture("same", date="Sat, 12 Sep 2026 09:00:00 GMT"),
     "Date differs between any two requests"),
])
def test_a_volatile_header_does_not_prevent_grouping(one, two, why):
    assert indistinct_urls([("http://a/x", one), ("http://a/y", two)]) == {
        "http://a/y": "http://a/x"}, why


# ------------------------------------------ what must NOT be called the same response

def test_an_empty_body_is_never_evidence():
    """The clause a real measurement forced. On DVWA six genuinely different static files —
    `detail.png`, `overview.png`, `main.css`, `logo.png` — grouped together because the
    captures came from an OPTIONS probe and every body was 0 bytes. Pruning them would have
    discarded four real assets."""
    assert indistinct_urls([("http://a/logo.png", capture("")),
                            ("http://a/main.css", capture("")),
                            ("http://a/detail.png", capture("   "))]) == {}


def test_a_shared_refusal_is_not_a_shared_answer():
    """Every refusal looks alike. Two URLs that both answer 401 have told the lane nothing about
    each other, and on DVWA an unauthenticated arm is redirected away from the whole surface."""
    denied = capture("Unauthorized", status=401)
    assert indistinct_urls([("http://a/x", denied), ("http://a/y", denied)]) == {}


@pytest.mark.parametrize("extra,why", [
    ("Set-Cookie: SESSIONID=1; Path=/\r\n",
     "WSTG-SESS-02 decides entirely on Set-Cookie, so a body-only rule could prune the only "
     "URL whose finding lives in a header"),
    ("Allow: GET,PUT,DELETE\r\n", "WSTG-CONF-06 decides on Allow"),
    ("Access-Control-Allow-Origin: *\r\n", "the CORS checks decide on these"),
    ("Content-Security-Policy: default-src *\r\n", "a security-header check decides on this"),
])
def test_a_header_a_check_decides_on_keeps_the_urls_apart(extra, why):
    assert indistinct_urls([("http://a/x", capture("same")),
                            ("http://a/y", capture("same", extra=extra))]) == {}, why


def test_a_different_status_keeps_them_apart():
    assert indistinct_urls([("http://a/x", capture("same")),
                            ("http://a/y", capture("same", status=203))]) == {}


def test_a_url_is_never_pruned_against_itself():
    assert indistinct_urls([("http://a/x", SHELL), ("http://a/x", SHELL)]) == {}


def test_the_signature_is_stable_and_discriminating():
    assert response_signature(SHELL) == response_signature(SHELL)
    assert response_signature(SHELL) != response_signature(capture("<html>other</html>"))


# -------------------------------------------------- what the lane does with the answer

def test_it_is_a_coverage_state_rather_than_untested_work():
    """`not_run` reads as outstanding work. These URLs have nothing left to test."""
    from orchestrator.integrations.inventory import COVERAGE_STATES

    assert "indistinct" in COVERAGE_STATES
    # Ordered after the states that mean something was attempted and before the absences.
    assert COVERAGE_STATES.index("indistinct") > COVERAGE_STATES.index("answered")


def test_only_the_no_parameter_cases_are_pruned():
    """A parameter probe is a DIFFERENT request from the bare read that grouped: a URL whose
    base response is the shell could still answer differently to `?id=1'`. Measured on a real
    run no pruned URL carried a discovered parameter at all, but the safety is structural —
    `parameters_by_url` pairs are never consulted against the pruned set."""
    import inspect

    from orchestrator.integrations import deterministic

    source = inspect.getsource(deterministic.CatalogueAdapter.run)
    parameter_branch = source[source.index("elif case_needs_parameter(tc):"):
                              source.index("            else:\n                eligible =")]
    assert "indistinct" not in parameter_branch, (
        "pruning reached the parameter pairs, which are a different request")
    no_parameter_branch = source[source.index("            else:\n                eligible ="):]
    assert "url not in indistinct" in no_parameter_branch


# -------------------------------------------- driven through the real adapter

@pytest.fixture
async def stage(tmp_path, monkeypatch):
    """Two URLs that answer with one document, and one that does not."""
    import orchestrator.database as original
    from orchestrator.integrations import deterministic as det
    from orchestrator.integrations import persistence as db
    from orchestrator.integrations.adapters import Context
    from orchestrator.integrations.contracts import AssessmentConfig, Identity
    from orchestrator.integrations.security import SecretStore

    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()

    ROOT, SPA, REAL = ("http://app.test/", "http://app.test/Edge/",
                       "http://app.test/api/Users")
    probed = []

    class _Sandbox:
        policy = {"scope": {"allow_hosts": ["app.test"], "allow_ports": [80]},
                  "state_changing": False, "excluded_paths": []}
        proxy_url, images = "http://proxy:8080", {}
        directory, output = tmp_path / "job", tmp_path / "job" / "output"

        async def run(self, argv):
            line = " ".join(str(a) for a in argv)
            probed.append(line)

            class _Output:
                code, stderr = 0, ""
                stdout = (capture('{"data":[{"id":1}]}') if REAL in line
                          else capture("<html>app shell</html>"))
            return _Output()

        async def audit(self):
            return []

    monkeypatch.setattr(det, "seeds",
                        lambda ctx, policy, include_form_actions=False: _done([ROOT, SPA, REAL]))
    monkeypatch.setattr(det, "form_urls", lambda ctx: _done(set()))
    monkeypatch.setattr(det, "parameters_by_url", lambda ctx, policy: _done({}))

    async def go(**overrides):
        probed.clear()
        handle = SecretStore().put(Identity.model_validate({
            "name": "admin", "target_origin": "http://app.test", "role": "admin",
            "check": {"url": "http://app.test/me", "body_contains": "admin"}}).model_dump())
        config = AssessmentConfig(
            scope={"allow_hosts": ["app.test"], "allow_ports": [80]},
            identity_ids=[handle], active=True, max_urls=200,
            test_cases=overrides.pop("test_cases", ["WSTG-INFO-03"]),
            budget={"stage_seconds": 60, "assessment_seconds": 120}, **overrides)
        ctx = Context("s", "st", "http://app.test/", config, handle, {"name": "admin"})
        await db.execute("INSERT INTO integration_stages(id,session_id,adapter,identity_id,"
                         "status,result) VALUES(?,?,?,?,?,?)",
                         ("st", "s", "testcases", handle, "running", "{}"))
        result = await det.CatalogueAdapter().run(ctx, _Sandbox())
        return result, list(probed), ROOT, SPA, REAL

    return go


async def _done(value):
    return value


async def test_the_stage_records_which_urls_were_the_same_response(stage):
    result, _, root, spa, real = await stage()
    record = result.metadata["indistinct_urls"]
    assert record["count"] == 1
    assert record["survivors"] == [root]
    assert "nothing left to find" in record["establishes"]


async def test_a_case_that_reads_a_url_is_not_run_against_a_repeat(stage):
    """The budget win. `WSTG-INFO-03` takes no parameter, so it spends one target per URL —
    and a target whose response another URL already gave cannot tell it anything new."""
    result, probed, root, spa, real = await stage()
    ran = [o["url"] for o in result.observations if o.get("type") == "test_case"]
    assert spa not in ran, ran
    assert root in ran or real in ran, ran


async def test_the_repeat_is_reported_as_indistinct_rather_than_untested(stage):
    result, _, root, spa, real = await stage()
    noted = [o for o in result.observations if o.get("type") == "indistinct_url"]
    assert [o["url"] for o in noted] == [spa]
    assert root in noted[0]["reason"]


async def test_coverage_calls_it_indistinct(stage, tmp_path):
    """End to end into the report: `not_run` reads as outstanding work, and this is not."""
    from orchestrator.integrations import persistence as db
    from orchestrator.integrations.inventory import coverage

    result, _, root, spa, real = await stage()
    await db.persist_result("s", "st", result)
    for url in (root, spa, real):
        await db.execute("INSERT OR REPLACE INTO integration_endpoints(session_id,url,method,"
                         "identity_id,sources,parameters) VALUES(?,?,?,?,?,?)",
                         ("s", url, "GET", (await db.rows(
                             "SELECT identity_id FROM integration_stages WHERE id='st'"
                         ))[0]["identity_id"], json.dumps(["katana"]), "[]"))
    rows = await coverage("s")
    states = {r["url"]: r["state"] for r in rows}
    assert states.get(spa) == "indistinct", states
