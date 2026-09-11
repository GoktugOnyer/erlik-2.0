"""The check's fourth false-positive class, and the only one a structural rule reaches.

Measured on the real Juice Shop assessment with a marker naming the CUSTOMER's own email:
`/api/Users/2` satisfies every clause — the privileged arm received the marked data, the
unprivileged arm received byte-identical bytes, the anonymous arm asked and got 401 — and
the claim is false, because record 2 IS the customer. jim's declared `subject_id` is "2".

NO MARKER RULE CAN FIX THIS, which is what the first proposal got wrong. A gate comparing
the marker against the identity's declarations assigns one grade per MARKER, and the two
findings from that marker differ only in URL: `/api/Users` is real and `/api/Users/2` is
not. Measured over 16 markers and 26 findings, the proposed gate left the motivating false
positive at `confirmed` and downgraded two true findings; and `"email":"jim@juice-sh.op"`
contains neither jim's subject_id ("2") nor his role ("customer"), so it never fired on the
case it was written for.

The rule that works keys on the URL. Both sides come from outside the target — the id
segment is one the LANE chose by deriving an instance from a collection body, and the
principal it is compared against is the OPERATOR's declaration — so a target cannot move a
finding out of reach with it.

Measured, same five realistic markers, with and without the clause:

    with     8 true, 0 false, precision 1.00, urls {/api/Users, /api/Users/1}
    without  8 true, 2 false, precision 0.80, urls {..., /api/Users/2}

Recall is identical: it cost zero true findings. It is a LISTED skip all the same, because
the honest cost is that an object id can equal an identity id by coincidence — with
subject_id "2", eight of the run's derived urls carry a "2" segment.
"""
import json

import pytest

from orchestrator.integrations.inventory import _names_the_caller

URL = "http://app.test/api/Users"


# ----------------------------------------------------------------- the relation itself

@pytest.mark.parametrize("url,subject,expected", [
    ("http://app.test/api/Users/2", "2", True),
    ("http://app.test/api/Users/1", "2", False),
    ("http://app.test/api/Users", "2", False),
    # Only the LAST segment, because that is the one `instance_urls` appends. Matching any
    # segment made the rule depend on path vocabulary: a declared `subject_id` of "api"
    # skipped 25 of the run's 31 derived urls, and "Users" skipped 2.
    ("http://app.test/api/Users/2/orders", "2", False),
    ("http://app.test/api/2/Users", "2", False),
    ("http://app.test/api/Users", "Users", True),
    ("http://app.test/api/Users/1", "api", False),
    ("http://app.test/api/Users/22", "2", False),
    ("http://app.test/api/Users/2", "", False),
    # The case the empty-segment filter exists for: a trailing slash makes the last raw
    # segment "", which an UNDECLARED subject_id would match, and then every collection url
    # on the target would read as the caller's own record.
    ("http://app.test/api/Users/", "", False),
    ("http://app.test/api/Users/", "Users", True),
    # The QUERY is not a path segment, and a declaration cannot be made to depend on a
    # value a probe chose — the same line `_entitled` already draws.
    ("http://app.test/api/Users?id=2", "2", False),
    # And the HOST is not a segment either, or `subject_id` "app.test" would match every
    # url on the target.
    ("http://app.test/api/Users/1", "app.test", False),
])
def test_when_a_url_names_the_caller(url, subject, expected):
    assert _names_the_caller(url, subject) is expected


# ------------------------------------------------------- and what the check does with it

@pytest.fixture
async def lab(tmp_path, monkeypatch):
    """Three arms, one derived instance that names the caller and one that does not."""
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    from orchestrator.integrations.security import SecretStore
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    await db.execute("INSERT INTO integration_assessments(session_id,target,status,config) "
                     "VALUES(?,?,?,?)", ("s", "http://app.test/", "completed", "{}"))
    handles = {
        "admin": SecretStore().put({"name": "admin", "target_origin": "http://app.test",
                                    "role": "admin", "subject_id": "1"}),
        "jim": SecretStore().put({"name": "jim", "target_origin": "http://app.test",
                                  "role": "customer", "subject_id": "2"}),
    }
    return {"db": db, "h": handles}


MARKED = ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
          '{"data":{"id":%s,"email":"target@app.test"}}')
REFUSED = "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html\r\n\r\nno"


async def surface(lab, arm, url, output, source="derived"):
    """One recorded read of `url` by `arm`, and the endpoint row that gates it."""
    import uuid
    stage = uuid.uuid4().hex
    await lab["db"].execute(
        "INSERT INTO integration_stages(id,session_id,adapter,identity_id,status) "
        "VALUES(?,?,?,?,?)", (stage, "s", "testcases", arm, "completed"))
    await lab["db"].execute(
        "INSERT INTO integration_endpoints(session_id,url,method,identity_id,sources) "
        "VALUES(?,?,?,?,?)", ("s", url, "GET", arm, json.dumps([source])))
    return await lab["db"].evidence("s", stage, "testcase:ERLIK-SURFACE-READ", json.dumps({
        "test_case_id": "ERLIK-SURFACE-READ", "target": {"url": url},
        "steps": [{"step": "read", "output": output}]}))


async def check(lab, marker='"email":"target@app.test"'):
    from orchestrator.integrations.inventory import cross_arm_privileged_function
    return await cross_arm_privileged_function("s", lab["h"]["admin"], lab["h"]["jim"],
                                               marker, anonymous="anonymous")


async def test_a_derived_instance_naming_the_caller_is_skipped_and_listed(lab):
    own = "http://app.test/api/Users/2"
    for arm, out in (("admin", MARKED % 2), ("jim", MARKED % 2), ("anonymous", REFUSED)):
        await surface(lab, lab["h"].get(arm, "anonymous"), own, out)
    result = await check(lab)
    assert result["refused_because"] == []
    assert result["findings"] == [], "record 2 IS the caller, by the operator's own account"
    assert result["skipped_url_names_the_caller"] == [own], (
        "listed, because an object id can equal an identity id by coincidence")
    assert result["caller_own_records_not_excluded"] is False


async def test_another_principals_instance_is_still_a_finding(lab):
    """The negative control that matters: the clause must not suppress the real thing."""
    other = "http://app.test/api/Users/1"
    for arm, out in (("admin", MARKED % 1), ("jim", MARKED % 1), ("anonymous", REFUSED)):
        await surface(lab, lab["h"].get(arm, "anonymous"), other, out)
    result = await check(lab)
    assert [f["url"] for f in result["findings"]] == [other]
    assert result["skipped_url_names_the_caller"] == []


async def test_a_collection_is_never_skipped(lab):
    """`/api/Users` has no id segment, which is why refusing the whole marker or the whole
    check would have lost the one finding that marker legitimately produces."""
    for arm, out in (("admin", MARKED % 2), ("jim", MARKED % 2), ("anonymous", REFUSED)):
        await surface(lab, lab["h"].get(arm, "anonymous"), URL, out)
    result = await check(lab)
    assert [f["url"] for f in result["findings"]] == [URL]


async def test_a_discovered_url_naming_the_caller_is_not_skipped(lab):
    """Scoped to urls the LANE invented. On a crawled url the target chose to publish the
    link, and the clause's safety argument — that erlik picked the id segment itself — does
    not apply, so the finding stands and the operator judges it."""
    own = "http://app.test/api/Users/2"
    for arm, out in (("admin", MARKED % 2), ("jim", MARKED % 2), ("anonymous", REFUSED)):
        await surface(lab, lab["h"].get(arm, "anonymous"), own, out, source="katana")
    result = await check(lab)
    assert [f["url"] for f in result["findings"]] == [own]
    assert result["skipped_url_names_the_caller"] == []


async def test_an_identity_with_no_subject_id_suppresses_nothing(lab):
    """An empty declaration must remove no finding — the open-world rule `_declared_access`
    already states. Otherwise an undeclared identity would silently suppress by matching
    the empty string."""
    from orchestrator.integrations.security import SecretStore
    SecretStore().put({"name": "jim", "target_origin": "http://app.test",
                       "role": "customer"}, lab["h"]["jim"])
    own = "http://app.test/api/Users/2"
    for arm, out in (("admin", MARKED % 2), ("jim", MARKED % 2), ("anonymous", REFUSED)):
        await surface(lab, lab["h"].get(arm, "anonymous"), own, out)
    result = await check(lab)
    assert [f["url"] for f in result["findings"]] == [own]


# ------------------------------------------ and it runs last, so the list means something

async def test_the_skip_names_only_operations_that_would_have_been_findings(lab):
    """Placed before the evidence clauses this reported every derived url carrying the
    caller's id segment — 8 of 31 on the real run, identically for a marker where nothing
    was wrong — so the list was 8:1 noise and the one case it mattered was invisible.

    Here a derived instance that names the caller but that NO marker matched is simply not
    a finding and not a skip, because the rule never reached it.
    """
    own, other = "http://app.test/api/Users/2", "http://app.test/api/Orders/2"
    for arm, out in (("admin", MARKED % 2), ("jim", MARKED % 2), ("anonymous", REFUSED)):
        await surface(lab, lab["h"].get(arm, "anonymous"), own, out)
    # a second derived instance naming the caller, which the marker does NOT appear in
    plain = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"data\":{\"id\":2}}"
    for arm in ("admin", "jim", "anonymous"):
        await surface(lab, lab["h"].get(arm, "anonymous"), other, plain)
    result = await check(lab)
    assert result["skipped_url_names_the_caller"] == [own], (
        "only the operation the rule actually took away")


async def test_an_undeclared_subject_id_is_reported_not_silent(lab):
    """An inert clause that says nothing is a protection that is not there."""
    from orchestrator.integrations.security import SecretStore
    SecretStore().put({"name": "jim", "target_origin": "http://app.test",
                       "role": "customer"}, lab["h"]["jim"])
    own = "http://app.test/api/Users/2"
    for arm, out in (("admin", MARKED % 2), ("jim", MARKED % 2), ("anonymous", REFUSED)):
        await surface(lab, lab["h"].get(arm, "anonymous"), own, out)
    result = await check(lab)
    assert result["caller_own_records_not_excluded"] is True
    assert [f["url"] for f in result["findings"]] == [own], (
        "and the finding stands, because refusing would withdraw findings that are fine")


# ------------------------------------------------- an unfollowed redirect is not a denial

async def test_an_anonymous_redirect_is_not_a_denial(lab):
    """`carries` requires a 2xx, so a 3xx with an empty body satisfied "asked and did not
    receive" for free — while what it points at may be public. Measured on DVWA, the
    negative-control target: the anonymous capture for `/` is 302 to login.php, the same arm
    holds login.php 200 with that page's text, and three markers naming it each produced a
    finding where nothing was wrong."""
    url = "http://app.test/api/Users"
    redirect = "HTTP/1.1 302 Found\r\nLocation: /login\r\nContent-Length: 0\r\n\r\n"
    for arm, out in (("admin", MARKED % 9), ("jim", MARKED % 9), ("anonymous", redirect)):
        await surface(lab, lab["h"].get(arm, "anonymous"), url, out)
    result = await check(lab)
    assert result["findings"] == []
    assert result["skipped_anonymous_was_redirected"] == [url]


async def test_a_redirect_that_carries_a_body_is_still_judged(lab):
    """Scoped to an EMPTY body. A 3xx that answers with content was answered, and the
    existing clauses decide it — widening this to every 3xx would withdraw real findings."""
    url = "http://app.test/api/Users"
    body = ("HTTP/1.1 302 Found\r\nLocation: /login\r\nContent-Type: text/html\r\n\r\n"
            "moved, and here is the page anyway")
    for arm, out in (("admin", MARKED % 9), ("jim", MARKED % 9), ("anonymous", body)):
        await surface(lab, lab["h"].get(arm, "anonymous"), url, out)
    result = await check(lab)
    assert result["skipped_anonymous_was_redirected"] == []
    assert [f["url"] for f in result["findings"]] == [url]


async def test_a_plain_denial_is_still_a_denial(lab):
    """The negative control for the redirect clause: a 401 must still count."""
    url = "http://app.test/api/Users"
    for arm, out in (("admin", MARKED % 9), ("jim", MARKED % 9), ("anonymous", REFUSED)):
        await surface(lab, lab["h"].get(arm, "anonymous"), url, out)
    result = await check(lab)
    assert [f["url"] for f in result["findings"]] == [url]
    assert result["skipped_anonymous_was_redirected"] == []
