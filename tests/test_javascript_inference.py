"""Increment 4: discovery is the binding constraint, and it is measurable.

The lane's own measurement of Juice Shop: 136 endpoints, **4 parameters**, 2 findings,
both informational. Yet the application has a reachable error-based SQL injection:

    GET /rest/products/search?q=erlik'probe
      -> HTTP 500, SQLITE_ERROR: near "probe": syntax error

Handed that URL as its crawl root, the lane reports it HIGH in 21 seconds. So
detection works and discovery does not reach it — the call is an Angular XHR rather
than a link. And the route is not hidden: `main.js`, a 456 KB file the lane already
fetches and records as an endpoint, contains

    .get(`${this.hostServer}/rest/products/search?q=${e}`)

so the path AND the parameter name are sitting in a body the lane has. E-007 asks for
exactly this: operations "inferred from JavaScript/schema", kept distinct from
discovered ones, with the warning that matters — "Avoid turning an inferred URL into a
claim of tested coverage."

WHY THIS IS THE MOST DANGEROUS EXTRACTOR IN THE LANE. Every string it returns is
TARGET-CONTROLLED text about to become a URL the lane requests and a parameter name
the lane injects into. Measured from the same bundle, the ten candidates include both

    /rest/products/search?q=             the prize
    /rest/user/change-password?current=  a mutating endpoint (401 anonymously, so an
                                        AUTHENTICATED arm reaches the real logic)
    //w.soundcloud.com/player/?url=      resolves to a DIFFERENT HOST

Nothing syntactic separates the first from the second, so this extractor proposes and
never probes: inferred endpoints are withheld from `seeds()` and from
`parameters_by_url()` until an operator selects them. Surfacing a route the crawler
cannot reach is the whole value; requesting it unasked is how a tool changes a
password while enumerating.
"""
import pytest

from orchestrator.integrations.contracts import infer_endpoints, MAX_INFERRED


# Verbatim from Juice Shop v17.1.1's main.js.
REAL = '.get(`${this.hostServer}/rest/products/search?q=${e}`).pipe((0,v.U)(o=>o.data)'


def paths(body, **kw):
    return {path for path, _ in infer_endpoints(body, **kw)}


def test_the_measured_injection_route_is_recovered():
    found = dict(infer_endpoints(REAL))
    assert "/rest/products/search" in found, found
    assert found["/rest/products/search"] == ["q"]


@pytest.mark.parametrize("fragment,path,names", [
    ('"/rest/user/security-question?email="', "/rest/user/security-question", ["email"]),
    ('"/api/Challenges/?key="', "/api/Challenges/", ["key"]),
    ('`/redirect?to=${u}`', "/redirect", ["to"]),
    ('"/search?q=a&category=b"', "/search", ["category", "q"]),
])
def test_the_other_real_shapes_are_recovered(fragment, path, names):
    found = dict(infer_endpoints(fragment))
    assert path in found, found
    assert found[path] == names


# ------------------------------------------------------- what it must refuse

def test_a_protocol_relative_url_is_refused():
    """`//w.soundcloud.com/player/?url=` starts with a slash and is NOT a path.

    Resolved against the target it becomes `http://w.soundcloud.com/player/?url=` — a
    different host. The scope check would refuse the request later, but by then the
    candidate is already in the inventory and counted as surface. It is refused here.
    """
    assert paths('"//w.soundcloud.com/player/?url="') == set()
    assert paths('"//accounts.google.com/o/oauth2/v2/auth?client_id="') == set()


def test_a_full_url_is_refused():
    assert paths('"https://evil.test/x?a="') == set()
    assert paths('"http://evil.test/x?a="') == set()


def test_a_traversal_is_refused():
    assert paths('"/a/../../etc/passwd?x="') == set()
    assert paths('"/..%2f..%2fetc?x="') == set()


def test_a_parameter_name_the_lane_would_not_accept_is_dropped():
    """The same rule `parameter_names` applies to a discovered query string. A name
    the lane cannot put in a command is not a name it may learn from a JS body."""
    from orchestrator.integrations.contracts import PARAMETER_NAME

    found = dict(infer_endpoints('"/x?ok=1&-bad=3&also_ok=4"'))
    assert found.get("/x") == ["also_ok", "ok"], found
    for name in found.get("/x", []):
        assert PARAMETER_NAME.match(name)


def test_a_fragment_refuses_the_whole_candidate_rather_than_truncating():
    """`?ok=1&a#b=2` is not a query of two names.

    Everything from the `#` is a fragment the server never sees, so a candidate cut
    around it would hand back `ok` and `a` — and `a` was never a parameter. That is
    the same silent truncation the parameter-name rule refuses for `a#b`, where the
    README's reasoning is that reporting on a request you did not make is worse than
    not making it. So the candidate goes, not the tail.
    """
    assert infer_endpoints('"/x?ok=1&a#b=2"') == []
    assert infer_endpoints('"/x?ok=1#frag"') == []


def test_no_inferred_path_can_open_the_argv():
    """The property that matters: the PATH handed on is free of shell metacharacters.

    Not "nothing is extracted from a line containing one". `"/a$(id)/b?x="` yields
    `/b`, because the match starts after the `)` — and `/b` is a clean path. What that
    costs is a candidate the application may not serve, which an operator sees and
    declines; it cannot open a command line. A bogus candidate is a precision cost,
    and this extractor proposes rather than probes.
    """
    from orchestrator.engagement import looks_injectable

    for body in ('"/a$(id)/b?x="', '"/a`id`/b?x="', "\"/a'b?x=\"", '"/a\\"b?x="',
                 '`${h}/rest/x?q=${v}`'):
        for path, names in infer_endpoints(body):
            assert not looks_injectable(path), (body, path)
            assert "$" not in path and "{" not in path, (body, path)


def test_a_template_placeholder_is_not_mistaken_for_a_path_segment():
    """`${id}` inside a route is a variable, not a segment. Taking it literally would
    request a path the application never serves and report on it."""
    found = paths('.get(`${h}/api/Users/${id}/cards?page=${p}`)')
    assert found == set() or all("$" not in p and "{" not in p for p in found), found


def test_a_bare_path_with_no_parameter_is_not_inferred():
    """The value is the PARAMETER. A path with none buys a request and no injection
    point, and an unobserved path is the riskiest thing to request."""
    assert paths('"/api/Products"') == set()
    assert paths('"/rest/admin/application-configuration"') == set()


# ------------------------------------------------------------- bounds

def test_the_number_of_candidates_is_bounded():
    body = " ".join(f'"/p{i}?q{i}="' for i in range(MAX_INFERRED * 4))
    assert len(infer_endpoints(body)) == MAX_INFERRED


def test_an_absurdly_long_path_is_refused():
    assert paths('"/' + "a" * 400 + '?x="') == set()


def test_duplicates_collapse():
    body = REAL * 5
    assert len(infer_endpoints(body)) == 1


def test_a_body_that_is_not_javascript_yields_nothing_surprising():
    assert paths("") == set()
    assert paths("<html><body>no routes here</body></html>") == set()


# ------------------------------------- relative routes, and the base they need

REDIRECT = 'url:"./redirect?to=https://blockchain.test/x"'   # verbatim shape from main.js


def test_a_relative_route_is_refused_without_the_document_it_came_from():
    """`./redirect` means nothing on its own.

    Resolving it would be a guess about which directory the script was served from,
    and a guess that is wrong produces a request to a path the application does not
    serve — reported against a URL the lane invented.
    """
    assert infer_endpoints(REDIRECT) == []


def test_a_relative_route_resolves_against_the_script_url():
    """With the document, it is not a guess: this is what a browser resolves it to.

    Juice Shop's bundle spells its open redirect exactly this way, and the lane
    already knows which URL each script came from — it recorded the script as an
    endpoint in order to fetch it.
    """
    assert infer_endpoints(REDIRECT, base="http://localhost:3000/main.js") == [("/redirect", ["to"])]
    assert infer_endpoints(REDIRECT, base="http://localhost:3000/static/js/main.js") == \
        [("/static/js/redirect", ["to"])]


def test_a_relative_route_cannot_leave_the_origin():
    """The property is the ORIGIN, not the spelling.

    `.//evil.test/x?y=1` resolves to `http://localhost:3000/evil.test/x` — the
    hostname becomes a path SEGMENT on the target, which is harmless and probably a
    404. Asserting that the string `evil.test` is absent would be checking the wrong
    thing; what must hold is that resolving the candidate never changes the host the
    lane will contact.
    """
    from orchestrator.integrations.contracts import canonical_origin
    from urllib.parse import urljoin

    base = "http://localhost:3000/main.js"
    for body in ('url:"./../../other?x=1"', 'url:".//evil.test/x?y=1"',
                 'url:"./a/b/../../../../x?y=1"'):
        for path, _ in infer_endpoints(body, base=base):
            assert not path.startswith("//"), (body, path)
            assert canonical_origin(urljoin(base, path)) == canonical_origin(base), (body, path)


def test_the_measured_bundle_yields_its_five_routes():
    """The whole point, as a regression.

    Recovered from Juice Shop v17.1.1's main.js (456 KB): the SQL injection route, the
    open redirect, and three others — while the four off-origin candidates in the same
    file (soundcloud, twitter, googleapis, accounts.google) are refused.
    """
    body = (
        '.get(`${this.hostServer}/rest/products/search?q=${e}`)'
        'url:"./redirect?to=https://blockchain.test/x"'
        '"/rest/user/security-question?email="'
        '"/rest/user/change-password?current="'
        '"/api/Challenges/?key="'
        '"//w.soundcloud.com/player/?url="'
        '"//twitter.com/intent/tweet?text="'
        '"//www.googleapis.com/oauth2/v1/userinfo?alt="'
        '"//accounts.google.com/o/oauth2/v2/auth?client_id="'
    )
    found = infer_endpoints(body, base="http://localhost:3000/main.js")
    assert [p for p, _ in found] == [
        "/api/Challenges/", "/redirect", "/rest/products/search",
        "/rest/user/change-password", "/rest/user/security-question"], found
    assert dict(found)["/rest/products/search"] == ["q"]
    for path, _ in found:
        assert "soundcloud" not in path and "google" not in path and "twitter" not in path


# ------------------------------- an inferred route is a proposal, not a target

@pytest.fixture
async def store(tmp_path, monkeypatch):
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    return db


SEARCH = "http://app.test/rest/products/search"
CHANGE = "http://app.test/rest/user/change-password"
CRAWLED = "http://app.test/about"


async def row(db, url, sources, parameters):
    import json as _j
    await db.execute(
        "INSERT OR REPLACE INTO integration_endpoints"
        "(session_id,url,method,identity_id,sources,parameters) VALUES(?,?,?,?,?,?)",
        ("s", url, "GET", "anonymous", _j.dumps(sources), _j.dumps(parameters)))


class Ctx:
    session_id = "s"
    identity_id = "anonymous"
    target = "http://app.test/"

    class config:
        max_urls = 50


POLICY = {"scope": {"allow_hosts": ["app.test"], "allow_ports": [80]},
          "excluded_paths": [], "target": "http://app.test/"}


async def test_an_inferred_route_is_never_fetched(store):
    """`seeds()` feeds every stage that reads a page, ZAP's requestor job included.

    A route read out of a body has never been requested by anything, and the same
    bundle that names the search endpoint names the password change. So it is withheld
    — the same shape as the form-action withholding, for the same reason.
    """
    from orchestrator.integrations.inventory import seeds

    await row(store, CRAWLED, ["katana"], [])
    await row(store, SEARCH, ["javascript"], ["q"])
    await row(store, CHANGE, ["javascript"], ["current"])

    selected = await seeds(Ctx, POLICY)
    assert CRAWLED in selected
    assert SEARCH not in selected, "an inferred route was handed out as a page to fetch"
    assert CHANGE not in selected


async def test_an_inferred_parameter_is_never_probed(store):
    """The parameter is the valuable half AND the dangerous half.

    Injecting into `change-password?current=` as an authenticated identity IS the
    password change — measured: it answers 401 anonymously, so authentication is the
    only thing between the lane and a changed credential.
    """
    from orchestrator.integrations.inventory import parameters_by_url

    await row(store, CRAWLED + "?page=1", ["katana"], ["page"])
    await row(store, SEARCH, ["javascript"], ["q"])
    await row(store, CHANGE, ["javascript"], ["current"])

    found = await parameters_by_url(Ctx, POLICY)
    assert any("about" in url for url in found), found
    assert not any("search" in url or "change-password" in url for url in found), found


async def test_it_is_still_visible_in_the_inventory(store):
    """Withholding must not become hiding. Surfacing a route the crawler cannot reach
    is the whole value — the operator selects it, which is the authorization."""
    from orchestrator.integrations.inventory import operations

    await row(store, SEARCH, ["javascript"], ["q"])
    grouped = await operations("s")
    entry = next(iter(grouped.values()))
    assert entry["sources"] == ["javascript"]
    assert entry["parameters"] == ["q"]
    assert any("search" in o["url"] for o in entry["observations"])


# ------------------------- a rendered pass that fails is lost coverage, not a failure

def test_the_landing_navigation_falls_back_instead_of_failing():
    """The actual binding constraint, and it was not what the plan assumed.

    The rendered pass is the only source of form discovery, and its landing
    `page.goto` waited for `networkidle` with a fatal timeout. An application whose
    front end polls never goes idle: measured on Juice Shop, `Page.goto: Timeout
    30000ms exceeded` — and because `rpc` raises, the exception left the adapter and
    took the whole katana stage with it, discarding a crawl that would have reported
    133 endpoints.

    E-029 is why this mattered now: before it the rendered pass ran only on request,
    and it now runs for every authenticated assessment.

    Asserted against the source because the navigation happens inside the worker
    image; the end-to-end behaviour is measured by the Docker suite and was measured by
    hand against Juice Shop, where the pass went from 0 to 122 observed endpoints.
    """
    from pathlib import Path
    source = Path("orchestrator/integrations/worker.py").read_text()
    action = source[source.index('elif action == "browser"'):source.index('elif action == "baseline_browser"')]
    assert 'wait_until="networkidle"' in action, "idle is still tried first, and should be"
    assert 'wait_until="domcontentloaded", timeout=' in action, (
        "there is no fallback, so a front end that never goes idle still kills the pass")
    # The fallback must be inside a try/except around the idle attempt, not a
    # replacement for it: a settled page is where the XHR routes are.
    idle = action.index('wait_until="networkidle"')
    assert "try:" in action[max(0, idle - 200):idle]


def test_a_failed_rendered_pass_degrades_the_stage_rather_than_aborting_it():
    """And if it fails anyway, the fetched crawl must survive it."""
    from pathlib import Path
    source = Path("orchestrator/integrations/adapters.py").read_text()
    run = source[source.index("class KatanaAdapter"):source.index("class SchemathesisAdapter")]
    assert "browser_failure" in run
    assert '"type": "rendered_pass_failed"' in run, "the failure is not reported"
    assert "except Exception as exc:" in run, "the failure still propagates"
    # And the stage says it is incomplete rather than claiming success.
    assert 'result.status = "partial"' in run
