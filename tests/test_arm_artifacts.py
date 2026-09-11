"""E-030: divergence the lane manufactures, as opposed to divergence the target has.

The operation key absorbed the companion-VALUE family. What remained were two
different kinds of thing, and they need opposite treatment:

  - genuine application differences — a form whose METHOD moves GET->POST between
    security levels, a form that GAINS an input. These must stay visible, and E-008
    asks that they be DISTINGUISHABLE rather than normalised away.
  - artifacts of the lane itself — a cap applied in DOM order, a withholding rule
    that fires on the wrong rows, a default exclusion list that misses the common
    spellings of "log out". These must stop forking the arms, because a difference
    the tool invented is not a finding about anything.

This file covers the artifacts. The genuine differences are covered by the
classification tests in tests/test_identity_isolation.py.
"""
import json

import pytest

from orchestrator.integrations.contracts import form_endpoint, MAX_FORM_PARAMETERS
from orchestrator.integrations.inventory import form_urls


# ---------------------------------------------------- the companion-free collision

class Ctx:
    session_id = "s"
    identity_id = "anonymous"
    target = "http://app.test/"


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


async def row(db, url, sources, identity="anonymous"):
    await db.execute(
        "INSERT OR REPLACE INTO integration_endpoints"
        "(session_id,url,method,identity_id,sources,parameters) VALUES(?,?,?,?,?,?)",
        ("s", url, "GET", identity, json.dumps(sources), "[]"))


XSS = "http://app.test/vulnerabilities/xss_r/"
CSRF_ACTION = "http://app.test/vulnerabilities/csrf/?Change=Change"


async def test_a_companion_free_form_url_is_not_withheld(store):
    """Measured on DVWA: xss_r's submit control has NO `name` attribute.

        <form name="XSS" action="#" method="GET">
          <input type="text" name="name">
          <input type="submit" value="Submit">       <- unnamed

    So at `security=low` the form has no named companions, `form_endpoint` produces
    the page's own URL with an empty query, and the row key
    (session_id, url, method, identity_id) merges it with the crawled page row —
    `sources` becomes ["form","playwright"]. Withholding on "form in sources" then
    hid the PAGE from every read-only case.

    At `impossible` the hidden `user_token` IS a named companion, so the form URL
    carries a query and is a separate row — and the page row survives. The token's
    ABSENCE therefore forked the reading arms in the opposite direction from its
    presence: the vulnerable arm read one URL FEWER than the hardened one.

    A query is what makes a form URL an action. form_urls' own measured table says
    so: `GET /vulnerabilities/csrf/` -> no change, while
    `GET /vulnerabilities/csrf/?Change=Change` -> password changed. With no named
    companion there is no submission signal for a handler to fire on.
    """
    await row(store, XSS, ["form", "playwright"])
    withheld = await form_urls(Ctx)
    assert XSS not in withheld, (
        "a companion-free form URL is byte-identical to its page and performs "
        "nothing; withholding it costs the reading cases a real page")


async def test_a_form_url_that_carries_a_query_is_still_withheld(store):
    """The case the rule exists for, and it must not be weakened."""
    await row(store, CSRF_ACTION, ["form"])
    assert CSRF_ACTION in await form_urls(Ctx)


async def test_the_two_arms_withhold_the_same_page(store):
    """The fork, stated as the arms seeing it.

    `reader` is the vulnerable arm (no token, so form URL == page URL);
    `admin` is the hardened one (token, so they are two rows).
    """
    await row(store, XSS, ["form", "playwright"], identity="reader")
    await row(store, XSS, ["playwright"], identity="admin")
    await row(store, XSS + "?user_token=b3ae1ff6", ["form"], identity="admin")

    class Reader(Ctx):
        identity_id = "reader"

    class Admin(Ctx):
        identity_id = "admin"

    assert XSS not in await form_urls(Reader)
    assert XSS not in await form_urls(Admin)
    assert (XSS + "?user_token=b3ae1ff6") in await form_urls(Admin)


# -------------------------------------------------------- the DOM-order cap

def form(*controls, action="http://app.test/p"):
    return {"method": "GET", "action": action,
            "controls": [dict(zip(("name", "type", "value"), c)) for c in controls]}


def test_the_parameter_cap_does_not_depend_on_render_order():
    """`testable[:MAX_FORM_PARAMETERS]` was applied in DOM order, so a control
    inserted at the FRONT in one arm pushed a different one off the end — exactly
    what DVWA's csrf form does at `impossible`, where `password_current` appears
    first.

    No DVWA form has eleven testable controls, so this never fired there. It is a
    cap interacting with render order, and a difference the cap invented is not a
    property of the application. Sorting makes the kept set depend on the NAMES the
    target used, which both arms agree about.
    """
    count = MAX_FORM_PARAMETERS + 1
    plain = [(f"f{i}", "text", "") for i in range(count)]
    reordered = [plain[-1]] + plain[:-1]

    _, first = form_endpoint(form(*plain), "x")
    _, second = form_endpoint(form(*reordered), "x")
    assert len(first) == MAX_FORM_PARAMETERS
    assert set(first) == set(second), (
        "the cap kept different parameters in the two arms:\n"
        f"  only in first : {sorted(set(first) - set(second))}\n"
        f"  only in second: {sorted(set(second) - set(first))}")


def test_the_cap_still_bounds_what_it_returns():
    many = [(f"f{i}", "text", "") for i in range(40)]
    _, names = form_endpoint(form(*many), "x")
    assert len(names) == MAX_FORM_PARAMETERS


def test_a_form_within_the_cap_keeps_every_control():
    _, names = form_endpoint(form(("b", "text", ""), ("a", "text", ""),
                                 ("Submit", "submit", "Submit")), "x")
    assert sorted(names) == ["a", "b"], names


# ------------------------------------------- the session-destroying link

SIGN_OUT = [
    "/logout", "/logout.php", "/signout", "/logoff", "/sign-out", "/sign_out",
    "/users/sign_out",            # Rails / Devise
    "/accounts/logout/",          # Django
    "/Account/LogOff",            # ASP.NET MVC — note the casing
    "/auth/logout", "/api/v1/logout", "/user/logout", "/admin/logout",
]

# Paths that merely CONTAIN one of those words, and must still be crawled.
KEEP = [
    "/", "/about", "/blog/how-to-logout-safely",
    "/docs/signout-api", "/users/profile", "/login", "/signin",
]

# `/logoutpolicy` is NOT in KEEP. The default operator list still contains
# `/logout`, matched as a prefix, so that path is refused — existing documented
# behaviour, in the safe direction, and not what this guard is about. The guard
# fixes the UNDER-match; the prefix over-match is the operator's list working as
# specified.


def policy(paths=None):
    from orchestrator.integrations.contracts import AssessmentConfig
    config = AssessmentConfig(scope={"allow_hosts": ["app.test"], "allow_ports": [80]},
                              **({"excluded_paths": paths} if paths else {}))
    return {"scope": config.scope.model_dump(), "state_changing": False,
            "excluded_paths": config.excluded_paths}


@pytest.mark.parametrize("path", SIGN_OUT)
def test_a_sign_out_link_is_refused_by_default(path):
    """An arm whose session dies mid-crawl discovers only login forms afterwards,
    and says nothing about it — so its surface silently shrinks and the two arms
    are no longer comparable. The only guard was a prefix match on `/logout` and
    `/signout`, which every framework spelling in this list walks straight past.
    """
    from orchestrator.integrations.egress_policy import EgressPolicy
    allowed, reason = EgressPolicy(policy()).check("http://app.test" + path, "GET")
    assert not allowed, f"{path} would be crawled, and it ends the session"
    assert reason == "excluded path"


@pytest.mark.parametrize("path", KEEP)
def test_an_ordinary_path_is_not_refused_for_containing_the_word(path):
    """The guard matches a whole path SEGMENT. A blog post about logging out is a
    page, and an exclusion list that eats it is removing coverage for nothing."""
    from orchestrator.integrations.egress_policy import EgressPolicy
    allowed, _ = EgressPolicy(policy()).check("http://app.test" + path, "GET")
    assert allowed, f"{path} was refused, and it is an ordinary page"


def test_an_operator_list_still_works_and_is_still_a_prefix():
    from orchestrator.integrations.egress_policy import EgressPolicy
    p = policy(["/admin", "/internal/reports"])
    assert not EgressPolicy(p).check("http://app.test/admin/users", "GET")[0]
    assert not EgressPolicy(p).check("http://app.test/internal/reports/q1", "GET")[0]
    assert EgressPolicy(p).check("http://app.test/public", "GET")[0]


def test_an_operator_list_does_not_lose_the_sign_out_guard():
    """Replacing the defaults is how an operator adds an exclusion, and it must not
    be how they silently remove the one that protects the run from itself."""
    from orchestrator.integrations.egress_policy import EgressPolicy
    p = policy(["/admin"])
    assert not EgressPolicy(p).check("http://app.test/users/sign_out", "GET")[0]
    assert not EgressPolicy(p).check("http://app.test/admin", "GET")[0]


async def test_a_sign_out_url_never_reaches_a_seed_list(store):
    """The guard lives in the policy, and `seeds()` consults the policy — so a
    sign-out URL a crawler reported is not handed back out as something to fetch."""
    from orchestrator.integrations.inventory import seeds

    for url in ("http://app.test/about", "http://app.test/users/sign_out",
                "http://app.test/Account/LogOff"):
        await row(store, url, ["katana"])

    class Conf:
        max_urls = 50

    class C(Ctx):
        config = Conf

    selected = await seeds(C, policy())
    assert "http://app.test/about" in selected
    assert "http://app.test/users/sign_out" not in selected
    assert "http://app.test/Account/LogOff" not in selected


def test_zap_is_told_about_the_sign_out_paths_too():
    """The proxy is the boundary and it holds — a ZAP spider request to a sign-out
    path is refused there, so the session survives. But ZAP was never TOLD, so it
    spends requests discovering that. The two layers should agree.
    """
    from orchestrator.integrations.adapters import ADAPTERS
    from orchestrator.integrations.contracts import AssessmentConfig

    class C:
        target = "http://app.test/"
        config = AssessmentConfig(scope={"allow_hosts": ["app.test"], "allow_ports": [80]})

    import re
    excluded = ADAPTERS["zap"].plan(C, None, None)["env"]["contexts"][0]["excludePaths"]

    def zap_excludes(url):
        return any(re.fullmatch(p, url) for p in excluded)

    for path in ("/logout", "/users/sign_out", "/accounts/logout/",
                 "/Account/LogOff", "/auth/logout"):
        assert zap_excludes("http://app.test" + path), (
            f"ZAP would spend a request on {path}: {excluded}")
    # And the same precision the proxy guard keeps.
    for path in ("/about", "/blog/how-to-logout-safely", "/docs/signout-api"):
        assert not zap_excludes("http://app.test" + path), f"{path} was excluded from the crawl"


# ------------------------------------- the diagnosis that turned out to be wrong

async def test_a_page_row_and_a_form_row_at_one_url_both_survive(store):
    """E-030 recorded this as data loss. It is not, and the record was corrected.

    My note said the row key "has no `source` column, so a page row and a form row
    for one URL cannot coexist — `INSERT OR REPLACE` keeps the last writer".
    `persist_result` in fact UNIONS both `sources` and `parameters`, so nothing is
    lost in either arrival order. Pinned here because the claim was plausible from
    reading the SQL statement alone and wrong once the surrounding code was read —
    and because a future reader of that note needs the correction next to the
    behaviour.

    What genuinely remains at `/vulnerabilities/xss_r/` is an operation-identity
    question rather than a storage one: the vulnerable arm merges the page and the
    form into one row (the form adds no companion, so the URLs coincide) while the
    hardened arm has two rows (its form URL carries a token), so the hardened arm
    has one extra parameter-free operation. Absorbing that difference would
    reintroduce the page/action merge an adversarial pass called blocking — see
    `test_a_page_never_merges_with_that_path_s_form_action`. It is reported as
    `parameters_changed`, which is what it is.
    """
    from orchestrator.integrations.contracts import Endpoint, StageResult

    page = Endpoint(url=XSS, source="playwright", identity="a", parameters=[])
    form = Endpoint(url=XSS, source="form", identity="a", parameters=["name"])
    flipped_page = Endpoint(url=XSS, source="playwright", identity="b", parameters=[])
    flipped_form = Endpoint(url=XSS, source="form", identity="b", parameters=["name"])

    await store.persist_result("s", "stage-1", StageResult(endpoints=[page, form]))
    await store.persist_result("s", "stage-2", StageResult(endpoints=[flipped_form, flipped_page]))

    rows = {r["identity_id"]: r for r in await store.rows(
        "SELECT identity_id,sources,parameters FROM integration_endpoints WHERE url=?", (XSS,))}
    for identity, label in (("a", "page then form"), ("b", "form then page")):
        sources = json.loads(rows[identity]["sources"])
        parameters = json.loads(rows[identity]["parameters"])
        assert sorted(sources) == ["form", "playwright"], (label, sources)
        assert parameters == ["name"], (
            f"{label}: the form's parameter was lost, so the merge really is "
            f"last-writer-wins after all: {parameters}")
