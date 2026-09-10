"""A URL synthesised from a GET form is an ACTION, not a page.

Measured against DVWA on 2026-09-10, during a full-lane run that declared
`state_changing: false`:

    GET     /vulnerabilities/csrf/?Change=Change                  -> password changed
    HEAD    /vulnerabilities/csrf/?Change=Change                  -> password changed
    OPTIONS /vulnerabilities/csrf/?Change=Change                  -> password changed
    GET     /vulnerabilities/csrf/?Change=Change&password_new=x    -> no change
    GET     /vulnerabilities/csrf/                                -> no change

The module's handler runs on `isset($_GET['Change'])` and compares
`password_new` with `password_conf`; with neither present both are NULL,
NULL == NULL, and the admin password becomes md5(""). The lane changed the
target's admin credential, and did it through the three methods a scope gate
trusts most.

The harm is exclusively in the PARAMETER-FREE fetch — which buys nothing, since
a case that reads a URL learns the same thing from the form's page without its
submit control. A parameter probe, the thing the lane exists to do, mutates
nothing. So form URLs are kept for the cases that probe a parameter on them and
withheld from the ones that would merely fetch them.
"""
import json

import pytest

from orchestrator.integrations.inventory import form_urls


class _Ctx:
    session_id = "s"
    identity_id = "i"


@pytest.fixture
def rows(monkeypatch):
    store = []

    async def _rows(query, params):
        return store

    from orchestrator.integrations import inventory
    monkeypatch.setattr(inventory.db, "rows", _rows)
    return store


async def test_form_urls_names_only_the_urls_a_form_created(rows):
    rows.extend([
        {"url": "http://app.test/vulnerabilities/csrf/?Change=Change",
         "sources": json.dumps(["form"])},
        {"url": "http://app.test/vulnerabilities/sqli/?Submit=Submit",
         "sources": json.dumps(["form", "playwright"])},
        {"url": "http://app.test/vulnerabilities/csrf/", "sources": json.dumps(["playwright"])},
        {"url": "http://app.test/about", "sources": json.dumps(["katana"])},
        {"url": "http://app.test/no-sources", "sources": None},
    ])
    found = await form_urls(_Ctx)
    assert found == {"http://app.test/vulnerabilities/csrf/?Change=Change",
                     "http://app.test/vulnerabilities/sqli/?Submit=Submit"}


def test_the_per_url_branch_withholds_them_and_the_parameter_branch_does_not():
    """The two branches of the target builder have to differ, and a comment
    cannot enforce that. Read the source: the per-URL branch filters on
    `submit_urls` and the parameter branch does not, because a parameter probe
    on a form URL is exactly what the form URL is for."""
    import inspect
    from orchestrator.integrations import deterministic
    source = inspect.getsource(deterministic.CatalogueAdapter.run)
    per_url = source.split("else:\n                eligible = [", 1)[1]
    assert "url not in submit_urls" in per_url.split("case_targets =", 1)[0]
    parameter_branch = source.split("elif case_needs_parameter(tc):", 1)[1].split("else:", 1)[0]
    assert "submit_urls" not in parameter_branch, (
        "withholding form URLs from parameter probes would undo the only thing "
        "form discovery bought: DVWA's injectable inputs are all behind one")
    assert "form_url_withheld" in source, "a withheld target must be reported, not silently dropped"


async def test_a_case_that_received_nothing_is_reported_as_untested():
    """curl exits 0 on an empty body, so a target that refuses every request
    comes back success=True with zero bytes and the case reads as a clean probe.

    Measured on 2026-09-10: DVWA at security=impossible puts a SINGLE-USE
    user_token in its forms, form_endpoint baked it into the discovered URL, and
    it was stale by the time the cases ran. 156 of 208 injection-case steps
    received zero bytes — every probe of sqli, sqli_blind, xss_r and csrf — and
    the stage reported `completed` with no findings. That zero was then read as
    'the hardened application is clean', which is the one thing it cannot mean."""
    import inspect
    from orchestrator.integrations import deterministic
    source = inspect.getsource(deterministic.CatalogueAdapter.run)
    assert "test_case_unreachable" in source
    # One step with bytes is enough to say the target answered.
    assert "ran and not any(s.output for s in ran)" in source
    assert "never reached their target" in source


def test_a_step_that_ignores_its_parameter_cannot_submit_a_form_blank():
    """The narrower and sharper half of the same defect.

    WSTG-CLNT-04's `common_parameter_sweep` appends six GUESSED redirect names
    and none of the form's own, so on a form URL it submits that form with every
    field blank. Measured on DVWA: one such request set the admin password to
    md5("") in a run that declared state_changing: false. Its five sibling steps
    all carry {{parameter}} and are harmless — the hazard is the shape, not the
    case."""
    import inspect
    from orchestrator.testcase.loader import find_by_id
    from orchestrator.integrations import deterministic

    steps = {s.name: ("{{parameter}}" in s.command) for s in find_by_id("WSTG-CLNT-04").steps}
    assert steps["common_parameter_sweep"] is False, (
        "if this step now carries the parameter the guard is moot, but keep the guard")
    assert all(v for k, v in steps.items() if k != "common_parameter_sweep")

    source = inspect.getsource(deterministic.CatalogueAdapter.run)
    guard = source.split("def step_policy(step, command):", 1)[1]
    assert 'f"{probing}=" not in command' in guard
    assert "url in submit_urls and probing" in guard


def test_a_form_synthesised_url_is_never_handed_to_the_crawler():
    """The root of the whole defect, and the last of its three paths.

    form_endpoint builds `/vulnerabilities/csrf/?Change=Change` so a parameter
    probe can reach the form's handler. The katana adapter then seeded the
    crawler with every endpoint it had found — including that one — so katana
    FETCHED it, which submits the form with every field blank. Measured on DVWA:
    that single crawl request set the admin password to md5(""), in a run
    declaring state_changing: false.

    The URL must stay in result.endpoints: that is how the catalogue finds the
    parameters on it, and those parameters produced every true positive the run
    had. It just is not a page to visit."""
    import inspect
    from orchestrator.integrations import adapters
    source = inspect.getsource(adapters.KatanaAdapter.run)
    assert 'e.source != "form"' in source, "form URLs are crawlable again"
    seeding = next(line for line in source.splitlines() if line.strip().startswith("seeds = ["))
    assert "crawlable" in seeding, seeding
    assert "browser_endpoints" not in seeding, "every discovered endpoint is a crawl seed again"
    # ...and they must still be recorded, or parameter discovery loses them.
    assert 'source="form"' in source
