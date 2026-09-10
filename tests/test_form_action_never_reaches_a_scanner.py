"""The same defect, a third time, in the one path nobody covered.

A URL that exists only because a GET form was found is not a page. Requesting it
performs that form's action — on DVWA a bare GET of
`/vulnerabilities/csrf/?Change=Change` sets the admin password to the md5 of an
empty string. That was fixed twice: the crawler no longer receives such URLs as
seeds, and the catalogue adapter withholds them from cases that would merely
fetch them (tests/test_form_url_is_not_a_page.py pins both).

`inventory.seeds()` applies no source filter, and `ZapAdapter.run` passes its
output straight into `plan()`, where it becomes a **requestor job** — a list of
URLs ZAP is told to GET before it does anything else. So the withholding lived in
the catalogue adapter only, and the scanner was still handed the form action.

The shape of this is worth naming: the first two fixes were applied at the two
call sites that were known about, rather than at the function that produces the
hazard. This moves it to the producer, so a future fourth caller is safe by
default and has to ask to be unsafe.
"""
import json

import pytest

from orchestrator.integrations.inventory import seeds, form_urls


DANGEROUS = "http://app.test/vulnerabilities/csrf/?Change=Change"
ORDINARY = "http://app.test/about"
FORM_WITH_PARAMS = "http://app.test/vulnerabilities/sqli/?Submit=Submit"


@pytest.fixture
async def store(tmp_path, monkeypatch):
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    for url, sources, params in (
        (DANGEROUS, ["form"], []),
        (FORM_WITH_PARAMS, ["form"], ["id"]),
        (ORDINARY, ["katana"], []),
    ):
        await db.execute(
            "INSERT OR REPLACE INTO integration_endpoints"
            "(session_id,url,method,identity_id,sources,parameters) VALUES(?,?,?,?,?,?)",
            ("s", url, "GET", "anonymous", json.dumps(sources), json.dumps(params)))
    return db


class Ctx:
    session_id = "s"
    identity_id = "anonymous"
    target = "http://app.test/"

    class config:
        max_urls = 50
        excluded_paths = ["/logout", "/signout"]
        crawl_depth = 2
        active = False
        schema_input = None

        class budget:
            stage_seconds = 600


POLICY = {"scope": {"allow_hosts": ["app.test"], "allow_ports": [80]},
          "excluded_paths": ["/logout", "/signout"], "target": "http://app.test/"}


async def test_seeds_withholds_a_form_action_by_default(store):
    """The fix: the producer is safe, so every consumer is."""
    selected = await seeds(Ctx, POLICY)
    assert DANGEROUS not in selected, (
        "a form action reached seeds(); every consumer of it will GET this URL")
    assert FORM_WITH_PARAMS not in selected
    assert ORDINARY in selected, "an ordinary crawled page must still be a seed"


async def test_the_catalogue_adapter_can_still_see_them_to_report_them(store):
    """Withholding must not become silence.

    The catalogue adapter records a `form_url_withheld` observation naming each
    URL it declined to fetch, which an operator reads to know that surface
    exists and why nothing touched it. That needs the URLs, so it asks for them
    explicitly — the one caller that does.
    """
    everything = await seeds(Ctx, POLICY, include_form_actions=True)
    assert DANGEROUS in everything
    assert FORM_WITH_PARAMS in everything
    assert ORDINARY in everything


async def test_the_zap_requestor_job_never_names_a_form_action(store):
    """The measured path, end to end, at the point the URL becomes a request.

    `plan()` turns its inventory into {"type": "requestor", "requests": [...]},
    which is ZAP being told to GET each one. This asserts against the generated
    plan rather than against seeds(), because that is where the harm happens and
    a future refactor could reintroduce it anywhere in between.
    """
    from orchestrator.integrations.adapters import ADAPTERS

    inventory = await seeds(Ctx, POLICY)
    plan = ADAPTERS["zap"].plan(Ctx, None, inventory)
    requested = [r["url"] for job in plan["jobs"]
                 if job.get("type") == "requestor" for r in job["requests"]]
    assert DANGEROUS not in requested, (
        f"ZAP would have requested the form action:\n  {requested}")
    assert ORDINARY in requested, "the requestor job lost its legitimate seeds"
