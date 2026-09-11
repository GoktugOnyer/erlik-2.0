"""The lane discovered collections and never instances, so BOLA was unreachable.

Measured on a real three-arm Juice Shop run through `service.run()`:

    /api/Users                          3 endpoint rows
    /api/Cards                          3 endpoint rows
    /api/Users/1                        0
    /rest/basket/1                      0
    /rest/user/authentication-details   0

and only 5 of 234 discovered URLs contained a numeric path segment. Object-level
authorization lives on INSTANCES, so three of the four known violations were unreachable for
that reason alone — not because the checks were wrong.

The surface read's own evidence already named the instances: 15 collections in that run
carried integer row ids, `/api/Users` among them with [1,2,3,4,5,6].

THE HAZARD THIS RAISES is the sharpest one in this codebase's threat model: "a discovered
value fed back into a probe lets the target choose the evidence" — a planted
`<a href="/search?219359=1">` once turned a discovered parameter name into a CRITICAL
template-injection finding against an application with no template engine. An id read out of
a response body is the same kind of text. So the gate is a whitelist of SHAPES, and the URL
is rebuilt from the collection's own scheme, netloc and path rather than concatenated.

It is also the one part of the read that cannot claim to re-issue a request the crawler
already made, so it is tied to `active` and has its own switch.
"""
import json

import pytest

from orchestrator.integrations.inventory import (MAX_DERIVED_PER_COLLECTION, instance_urls,
                                                safe_object_id)

COLLECTION = "http://app.test:3000/api/Users"
ROWS = '{"status":"success","data":[{"id":1},{"id":2},{"id":3},{"id":4},{"id":5}]}'


# ----------------------------------------------------- the gate on a target-chosen value

@pytest.mark.parametrize("value,expected,why", [
    (1, "1", "an integer key"),
    ("1", "1", "the same as a string"),
    (0, "0", "zero is an id"),
    ("3fa85f64-5717-4562-b3fc-2c963f66afa6", "3fa85f64-5717-4562-b3fc-2c963f66afa6", "a UUID"),
    ("../../etc/passwd", "", "a traversal"),
    ("..", "", "a bare dot segment"),
    ("a/b", "", "a slash would add a path segment"),
    ("%2e%2e%2f", "", "a percent-encoded traversal"),
    ("1 ", "", "a trailing space"),
    (" 1", "", "a leading space"),
    ("-1", "", "a sign is not part of an id shape"),
    ("1.0", "", "a float"),
    ("1e3", "", "scientific notation"),
    ("1'OR'1", "", "an injection payload"),
    ("http://evil.test/", "", "an id that is a URL"),
    ("١", "", "Arabic-Indic ONE is not an ASCII digit"),
    ("１", "", "fullwidth ONE is not an ASCII digit"),
    ("1" * 13, "", "longer than any plausible integer key"),
    (True, "", "isinstance(True, int) is True in Python; /api/Users/True is not an object"),
    (None, "", "absent"),
    ({"id": 1}, "", "a container"),
    ("", "", "empty"),
])
def test_only_a_structural_identifier_reaches_a_url(value, expected, why):
    assert safe_object_id(value) == expected, why


def test_the_rule_is_a_whitelist_of_shapes_not_a_blacklist_of_characters():
    """A blacklist is a list of the attacks someone thought of. Every hostile value above
    fails because it is not an integer or a UUID, not because it was enumerated."""
    import inspect

    source = inspect.getsource(safe_object_id)
    assert "_SAFE_ID.match" in source
    # And the pattern uses explicit [0-9] rather than \\d, which matches unicode digits.
    from orchestrator.integrations.inventory import _SAFE_ID
    assert "\\d" not in _SAFE_ID.pattern
    assert _SAFE_ID.match("١") is None


# -------------------------------------------------- the url, which cannot escape

def test_instances_are_derived_from_the_rows_ids():
    assert instance_urls(COLLECTION, ROWS) == (
        "http://app.test:3000/api/Users/1", "http://app.test:3000/api/Users/2",
        "http://app.test:3000/api/Users/3")


def test_at_most_a_few_per_collection():
    """The flood control. A measured run holds 15 collections and several return six or more
    rows, so unbounded derivation would be 90+ extra requests per arm."""
    assert len(instance_urls(COLLECTION, ROWS)) == MAX_DERIVED_PER_COLLECTION
    assert instance_urls(COLLECTION, ROWS, limit=1) == ("http://app.test:3000/api/Users/1",)
    assert instance_urls(COLLECTION, ROWS, limit=0) == ()


def test_the_collections_query_is_dropped():
    """A collection's filter is not an instance's. Measured: `/api/Challenges/?name=Score
    Board` names id 74, and the instance is `/api/Challenges/74`."""
    derived = instance_urls("http://app.test:3000/api/Challenges/?name=Score%20Board",
                            '{"data":[{"id":74}]}')
    assert derived == ("http://app.test:3000/api/Challenges/74",)


def test_a_trailing_slash_does_not_become_a_double_slash():
    """`/api/Feedbacks` and `/api/Feedbacks/` are separate endpoint rows with identical
    bodies on Juice Shop. Concatenating onto the second gives `/api/Feedbacks//1`, which
    Express normalises — so the lane would issue byte-identical duplicate probes and pay for
    them twice. Measured on an independent implementation: 6 of 36 derived probes, 18 of 108
    requests, were pure duplicates of that kind."""
    assert instance_urls("http://app.test:3000/api/Feedbacks/", '{"data":[{"id":1}]}') == (
        "http://app.test:3000/api/Feedbacks/1",)
    # Both spellings derive the SAME url, so the candidate set collapses them to one probe.
    assert (instance_urls("http://app.test:3000/api/Feedbacks", '{"data":[{"id":1}]}')
            == instance_urls("http://app.test:3000/api/Feedbacks/", '{"data":[{"id":1}]}'))


def test_the_id_gate_is_a_safety_gate_not_a_precision_filter():
    """Stated because it would otherwise read as one. Measured across all 15 collection
    bodies in a real run: 889 rows, every `id` an int, 0 rejected. The gate exists for the
    target that returns something else — it is what makes the feature safe to have, not what
    makes it useful."""
    rows = json.dumps({"data": [{"id": n} for n in range(889)]})
    assert len(instance_urls(COLLECTION, rows, limit=1000)) == 889


def test_an_instance_does_not_derive_further_instances():
    """Otherwise `/api/Users/1` begets `/api/Users/1/1`."""
    assert instance_urls("http://app.test:3000/api/Users/1", ROWS) == ()


@pytest.mark.parametrize("body,why", [
    ("<html>not json</html>", "an HTML body"),
    ("", "an empty body"),
    ('{"status":"success"}', "no data key"),
    ('{"data":{"id":1}}', "a single object, not a collection"),
    ('{"data":[1,2,3]}', "rows that are not objects"),
    ('{"data":[{"name":"x"}]}', "rows with no id"),
    ('{"data":[{"id":"../../x"}]}', "rows whose id is not an identifier"),
])
def test_nothing_is_derived_from_a_body_that_names_no_ids(body, why):
    assert instance_urls(COLLECTION, body) == (), why


def test_a_bare_array_is_also_a_collection():
    assert instance_urls(COLLECTION, '[{"id":7},{"id":8}]') == (
        "http://app.test:3000/api/Users/7", "http://app.test:3000/api/Users/8")


def test_a_hostile_id_is_skipped_without_losing_the_legitimate_one_beside_it():
    assert instance_urls(COLLECTION, '{"data":[{"id":"../../admin"},{"id":"1"}]}') == (
        "http://app.test:3000/api/Users/1",)


def test_duplicate_ids_derive_one_url():
    assert instance_urls(COLLECTION, '{"data":[{"id":1},{"id":1},{"id":2}]}') == (
        "http://app.test:3000/api/Users/1", "http://app.test:3000/api/Users/2")


@pytest.mark.parametrize("collection", [
    "http://app.test:3000/api/Users",
    "https://other.test/v1/accounts",
    "http://app.test:8081/a/b/c",
])
def test_a_derived_url_is_always_on_the_collections_own_origin_and_path(collection):
    """Scheme and netloc are copied and the id is one path segment, so no id can move the
    request to another host or above the collection's path."""
    from urllib.parse import urlsplit

    base = urlsplit(collection)
    for derived in instance_urls(collection, ROWS):
        parts = urlsplit(derived)
        assert (parts.scheme, parts.netloc) == (base.scheme, base.netloc)
        assert parts.path.startswith(base.path.rstrip("/") + "/")
        assert parts.query == "" and parts.fragment == ""
        assert parts.path.count("/") == base.path.rstrip("/").count("/") + 1


# --------------------------------------------- the second pass, driven through the adapter

@pytest.fixture
async def stage(tmp_path, monkeypatch):
    """Drive the real CatalogueAdapter with a sandbox that answers a collection body."""
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

    LIST = "http://app.test/api/Users"
    issued = []

    class _Output:
        code, stderr = 0, ""
        stdout = ('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n'
                  '{"status":"success","data":[{"id":1},{"id":2},{"id":3},{"id":4}]}')

    class _Sandbox:
        policy = {"scope": {"allow_hosts": ["app.test"], "allow_ports": [80]},
                  "state_changing": False, "excluded_paths": []}
        proxy_url, images = "http://proxy:8080", {}
        directory, output = tmp_path / "job", tmp_path / "job" / "output"

        async def run(self, argv):
            issued.append(" ".join(str(a) for a in argv))
            return _Output()

        async def audit(self):
            return []

    async def seeds(ctx, policy, include_form_actions=False):
        return [LIST]

    async def form_urls(ctx):
        return set()

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
            scope={"allow_hosts": ["app.test"], "allow_ports": [80]},
            identity_ids=[handle], test_cases=[], max_urls=90,
            active=overrides.pop("active", True),
            derive_instances=overrides.pop("derive_instances", True),
            budget={"stage_seconds": 60, "assessment_seconds": 120}, **overrides)
        ctx = Context("s", "st", "http://app.test/", config, handle, {"name": "admin"})
        await db.execute("INSERT INTO integration_stages(id,session_id,adapter,identity_id,"
                         "status,result) VALUES(?,?,?,?,?,?)",
                         ("st", "s", "testcases", handle, "running", "{}"))
        result = await det.CatalogueAdapter().run(ctx, _Sandbox())
        fetched = [a for a in issued if "http://app.test" in a]
        return result, fetched, LIST

    return go


async def test_the_instances_a_collection_names_are_read(stage):
    result, fetched, listing = await stage()
    assert any(f"{listing}/1" in f for f in fetched), fetched
    assert result.metadata["derived_instances"]["read"] >= 1
    assert result.metadata["derived_instances"]["from_collections"] == 1


async def test_a_derived_instance_is_recorded_as_an_endpoint(stage):
    """Without a row the cross-arm checks' `gated` intersection skips it, and the pass would
    produce evidence nothing could compare. `source` says it was derived, because a URL
    nothing crawled must be distinguishable from one something did."""
    result, _, listing = await stage()
    derived = [e for e in result.endpoints if e.source == "derived"]
    assert derived, result.endpoints
    assert all(e.url.startswith(listing + "/") for e in derived)
    assert all(e.identity for e in derived)


async def test_it_needs_active_because_nothing_crawled_these_urls(stage):
    """Pass one can say every URL it fetches was already fetched during discovery. A derived
    instance was not, so it is tied to the operator's existing declaration that this run may
    probe."""
    result, fetched, listing = await stage(active=False)
    assert not any(f"{listing}/1" in f for f in fetched)
    assert "derived_instances" not in result.metadata


async def test_it_is_off_unless_the_operator_asks(stage):
    """A derived instance measurably writes to the target — `GET /rest/memories/1` answers 500,
    Juice Shop's `errorHandlingChallenge` fires above 401, and `solve()` runs
    `challenge.save()`. The surface read changes the volume of requests; this changes the class
    of side effect, so it is the operator's decision."""
    from orchestrator.integrations.contracts import AssessmentConfig

    assert AssessmentConfig(scope={"allow_hosts": ["a"], "allow_ports": [80]},
                            active=True).derive_instances is False
    result, fetched, listing = await stage(derive_instances=False)
    assert not any(f"{listing}/1" in f for f in fetched)
    assert "derived_instances" not in result.metadata
    # ...and the surface read itself still runs.
    assert result.metadata["surface_read"]["urls_read"] == 1


async def test_the_share_is_split_not_doubled(stage):
    """A second pass that helped itself to another whole share would make `max_urls` mean
    something other than what the operator set."""
    from orchestrator.integrations.deterministic import surface_read_budget

    result, fetched, _ = await stage()
    share = surface_read_budget(90, 0)
    read = result.metadata["surface_read"]["urls_read"]
    derived = result.metadata["derived_instances"]["read"]
    assert result.metadata["derived_instances"]["share_of_url_budget"] == share // 3
    assert read + derived <= share, (read, derived, share)


async def test_what_it_could_not_reach_is_reported(stage):
    """Four ids are named and the bound is three; the one left is said out loud rather than
    leaving the report to look complete."""
    result, _, _ = await stage()
    record = result.metadata["derived_instances"]
    assert record["candidates"] >= record["read"]


# ------------------------- what the object-level check must not be shown

async def test_the_object_level_check_never_sees_a_url_the_lane_invented(tmp_path, monkeypatch):
    """On a derived instance the asserted owner IS the path segment the lane chose. Measured:
    `GET /api/Users/1` answers `{"data":{"id":1,…}}`, so `owner_field: data.id` reads back the
    `1` the lane put in the URL.

    An adversarial pass scored it on real captures across four owner_field declarations:
    derivation took the object-level check from 0 findings to 1 true positive and SEVEN false
    positives — precision over all declarations from 1.00 to 0.42 — and porting the reflection
    clause removed all seven along with the only true positive. There is nothing for it to
    keep on a URL the lane invented. The function-level check is unaffected and gains, because
    its marker is the OPERATOR'S and no choice of URL satisfies it.
    """
    import uuid

    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    from orchestrator.integrations.contracts import Identity
    from orchestrator.integrations.inventory import (cross_arm_authorization,
                                                     cross_arm_privileged_function)
    from orchestrator.integrations.security import SecretStore

    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    await db.execute("INSERT INTO integration_assessments(session_id,target,status,config) "
                     "VALUES(?,?,?,?)", ("s", "http://app.test", "completed", "{}"))

    store, handles = SecretStore(), {}
    for name, role, subject in (("admin", "admin", "1"), ("jim", "customer", "2")):
        handles[name] = store.put(Identity.model_validate({
            "name": name, "target_origin": "http://app.test", "role": role,
            "subject_id": subject,
            "check": {"url": "http://app.test/me", "body_contains": name}}).model_dump())
        await db.execute("INSERT INTO integration_identities VALUES(?,?,?)",
                         (handles[name], name, "http://app.test"))
    handles["anonymous"] = "anonymous"

    url = "http://app.test/api/Users/1"
    # The body a derived instance returns: its `id` is the segment the lane put in the path.
    served = ('HTTP/1.1 200 OK\r\n\r\n{"status":"success","data":'
              '{"id":1,"email":"admin@app.test","role":"admin"}}')
    denied = "HTTP/1.1 401 Unauthorized\r\n\r\nUnauthorizedError"
    for arm, capture in (("admin", served), ("jim", served), ("anonymous", denied)):
        identity = handles[arm]
        stage_id = uuid.uuid4().hex
        await db.execute("INSERT INTO integration_stages(id,session_id,adapter,identity_id,"
                         "status,result) VALUES(?,?,?,?,?,?)",
                         (stage_id, "s", "testcases", identity, "completed",
                          json.dumps({"status": "completed"})))
        await db.execute("INSERT OR REPLACE INTO integration_endpoints(session_id,url,method,"
                         "identity_id,sources,parameters) VALUES(?,?,?,?,?,?)",
                         ("s", url, "GET", identity, json.dumps(["derived"]), "[]"))
        run = {"test_case_id": "ERLIK-SURFACE-READ",
               "target": {"url": url, "parameter": ""}, "findings": [], "chain_next": [],
               "stopped_early": False, "duration_ms": 1, "produced": {},
               "steps": [{"step": "read", "command": "curl", "success": True,
                          "duration_ms": 1, "exit_code": 0, "skipped": False,
                          "error": None, "output": capture}]}
        await db.evidence("s", stage_id, "testcase:ERLIK-SURFACE-READ", json.dumps(run))

    # jim reads an object the response attributes to subject 1 — which is the id the lane
    # chose, so this must NOT be reported.
    authz = await cross_arm_authorization("s", handles["jim"], handles["admin"],
                                          "data.id", "anonymous")
    assert authz["findings"] == [], authz
    assert authz["derived_urls_excluded"] == 1

    # The same evidence IS usable by the function-level check, whose marker is the
    # operator's and which no choice of URL can satisfy.
    priv = await cross_arm_privileged_function("s", handles["admin"], handles["jim"],
                                              '"email":"admin@app.test"',
                                              anonymous="anonymous")
    assert [f["url"] for f in priv["findings"]] == [url], priv


@pytest.mark.parametrize("collection,why", [
    ("http://app.test/d22/x/../..", "dot segments reach above the collection"),
    ("http://app.test/api/Users/..", "a trailing .."),
    ("http://app.test/a/./b", "a single-dot segment"),
    ("http://app.test/a%2f../b", "an encoded separator"),
])
def test_a_collection_path_that_is_not_what_curl_will_send_derives_nothing(collection, why):
    """THE COLLECTION'S PATH IS ALSO TARGET-SUPPLIED, and it was the real lever — the id gate
    is irrelevant to it, the id stays `7`. Measured on the wire with the pinned worker curl
    against DVWA: collection `http://h/d22/x/../..` produced the recorded URL
    `/d22/x/../../7` while apache logged `GET /7`. So the request was neither under the
    collection's path nor the URL written into the endpoint row and the evidence key — and
    `EgressPolicy.check` matches `excluded_paths` and `ends_the_session` against the RAW path,
    so `/x/../../logout` passes that check while curl sends `/logout`.

    Refused rather than normalised: normalising would make the lane probe a URL the crawler
    never reported. No path in any measured inventory contains a dot segment.
    """
    assert instance_urls(collection, '{"data":[{"id":7}]}') == (), why


def test_an_ordinary_path_still_derives():
    """The positive control for the clause above."""
    assert instance_urls("http://app.test/api/Users", '{"data":[{"id":7}]}') == (
        "http://app.test/api/Users/7",)


def test_every_collection_gets_its_first_instance_before_any_gets_a_second():
    """Depth-first spends a tight budget on whichever collections sort first: measured on a
    real run, 30 candidates against a share of 28 dropped exactly `/api/Users/2` and
    `/api/Users/3`, because `/api/Users` comes last alphabetically — and `/api/Users/1` is the
    one instance carrying a known violation."""
    from orchestrator.integrations.inventory import breadth_first

    per_collection = [["/a/1", "/a/2", "/a/3"], ["/b/1", "/b/2"], ["/z/1"]]
    assert breadth_first(per_collection) == [
        "/a/1", "/b/1", "/z/1", "/a/2", "/b/2", "/a/3"]
    # At a share of 3 every collection is represented; depth-first would have read /a/1,2,3.
    assert breadth_first(per_collection)[:3] == ["/a/1", "/b/1", "/z/1"]


def test_breadth_first_drops_duplicates_and_tolerates_nothing():
    from orchestrator.integrations.inventory import breadth_first

    assert breadth_first([["/a/1"], ["/a/1"], []]) == ["/a/1"]
    assert breadth_first([]) == []


def test_a_bool_id_needs_no_special_case():
    """`isinstance(True, int)` is True in Python, so a draft refused bools explicitly — and
    that clause could never fire, because `True` renders as "True", which is not an id shape.
    """
    assert safe_object_id(True) == "" and safe_object_id(False) == ""
    assert safe_object_id("True") == ""


async def test_the_anonymous_arm_is_given_the_instances_other_arms_derived(tmp_path, monkeypatch):
    """An arm derives from collections IT can read, and the anonymous arm is refused exactly
    the interesting ones. Measured on a clean three-arm run: the only derived instances all
    three arms shared were of PUBLIC collections, while `/api/Users/1` was derived by both
    identity arms and by neither the anonymous one — so the function-level check skipped it,
    because clause 3 requires the anonymous arm to have ASKED. It is right to require that: an
    arm that never requested a URL proves nothing about whether the URL is public.

    So the arm whose whole job is to establish "not published" is handed the URLs it must ask
    about. It cannot invent a finding — an anonymous 2xx SUPPRESSES one — so the only thing
    asking can do is remove findings the lane would otherwise have reported.
    """
    import orchestrator.database as original
    from orchestrator.integrations import deterministic as det
    from orchestrator.integrations import persistence as db
    from orchestrator.integrations.adapters import Context
    from orchestrator.integrations.contracts import AssessmentConfig

    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()

    PUBLIC = "http://app.test/api/Feedbacks"
    PRIVATE_INSTANCE = "http://app.test/api/Users/1"
    issued = []

    class _Output:
        code, stderr = 0, ""
        stdout = ('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n'
                  '{"status":"success","data":[{"id":9}]}')

    class _Sandbox:
        policy = {"scope": {"allow_hosts": ["app.test"], "allow_ports": [80]},
                  "state_changing": False, "excluded_paths": []}
        proxy_url, images = "http://proxy:8080", {}
        directory, output = tmp_path / "job", tmp_path / "job" / "output"

        async def run(self, argv):
            issued.append(" ".join(str(a) for a in argv))
            return _Output()

        async def audit(self):
            return []

    # The anonymous arm can read only the PUBLIC collection...
    monkeypatch.setattr(det, "seeds", lambda ctx, policy, include_form_actions=False:
                        _resolved([PUBLIC]))
    monkeypatch.setattr(det, "form_urls", lambda ctx: _resolved(set()))
    monkeypatch.setattr(det, "parameters_by_url", lambda ctx, policy: _resolved({}))

    # ...while an identity arm has already recorded a derived instance of a private one.
    await db.execute("INSERT OR REPLACE INTO integration_endpoints(session_id,url,method,"
                     "identity_id,sources,parameters) VALUES(?,?,?,?,?,?)",
                     ("s", PRIVATE_INSTANCE, "GET", "some-identity",
                      json.dumps(["derived"]), "[]"))
    await db.execute("INSERT INTO integration_stages(id,session_id,adapter,identity_id,"
                     "status,result) VALUES(?,?,?,?,?,?)",
                     ("st", "s", "testcases", "anonymous", "running", "{}"))

    config = AssessmentConfig(
        scope={"allow_hosts": ["app.test"], "allow_ports": [80]},
        identity_ids=["some-identity"], test_cases=[], max_urls=90, active=True,
        derive_instances=True, budget={"stage_seconds": 60, "assessment_seconds": 120})
    ctx = Context("s", "st", "http://app.test/", config, "anonymous", None)
    await det.CatalogueAdapter().run(ctx, _Sandbox())

    assert any(PRIVATE_INSTANCE in a for a in issued), (
        "the anonymous arm did not ask about the instance another arm derived, so the "
        "function-level check can never establish that it is not public")


async def _resolved(value):
    return value
