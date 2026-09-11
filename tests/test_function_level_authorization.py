"""Increment 8: function-level authorization across stages — E-011's last half.

Object-level authorization reads an owner out of the response, so the target itself says
who a record belongs to. A FUNCTION has no owner to read: `GET /api/Users` returns every
user, and nothing in the payload says "only an administrator may ask this". So the
operator supplies the thing that cannot be inferred — a marker identifying PRIVILEGED
data — and the lane supplies only what happened.

WHY A MARKER AND NOT A STATUS COMPARISON. "Both authenticated arms got 200 and anonymous
did not" describes every ordinary authenticated endpoint in the application. Measured on
Juice Shop v17.1.1, all three arms of each of these:

    /api/Users                              admin 200   customer 200   anon 401
    /rest/user/authentication-details        200          200            401
    /rest/order-history                      200          200            500

The first two are real violations; the third is a customer reading their OWN order
history, and a status-shaped rule cannot tell them apart. The marker can, because admin's
order data is not in the customer's response.

WHY THE ANONYMOUS ARM CARRIES MOST OF THE WEIGHT. Three of the first four candidates
measured turned out to be PUBLIC — and two of them have `admin` in the path:

    /rest/admin/application-configuration   200  200  200
    /rest/admin/application-version         200  200  200
    /api/Feedbacks                          200  200  200
    /api/Recycles                           200  200  200

A path-name heuristic would report all four. A rule without the anonymous arm would
report all four. They are published content.

AND A DENIAL IS NOT ALWAYS A 4xx. Juice Shop refuses the customer's access to another
card with HTTP **400** `{"status":"error","data":"Malicious activity detected"}`, and DVWA
refuses with HTTP **200** `{"result":"fail","error":"Access denied"}`. The marker handles
both without a denial list: a refused arm does not contain the privileged data.
"""
import json
import uuid

import pytest

from orchestrator.integrations.contracts import Identity


USERS = "http://app.test/api/Users"
MARKER = '"email":"admin@app.test"'


def _mentions(value, needle):
    """True if `needle` appears in any string anywhere in `value`.

    Not `needle in json.dumps(value)`: json.dumps escapes the marker's quotes, so
    `"email":"admin@app.test"` is absent from the encoding even when the value is
    echoed verbatim — an assertion that could never fail.
    """
    if isinstance(value, str):
        return needle in value
    if isinstance(value, dict):
        return any(_mentions(v, needle) for v in value.values()) or any(
            _mentions(k, needle) for k in value)
    if isinstance(value, (list, tuple)):
        return any(_mentions(v, needle) for v in value)
    return False


def who(name, role, **kw):
    return Identity.model_validate({
        "name": name, "target_origin": "http://app.test", "role": role,
        "check": {"url": "http://app.test/me", "method": "GET"}, **kw})


@pytest.fixture
async def lab(tmp_path, monkeypatch):
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    from orchestrator.integrations.security import SecretStore
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()

    store = SecretStore()
    handles = {}
    for name, role in (("admin", "admin"), ("jim", "customer")):
        handle = store.put(who(name, role).model_dump())
        handles[name] = handle
        await db.execute("INSERT INTO integration_identities VALUES(?,?,?)",
                         (handle, name, "http://app.test"))
    handles["anonymous"] = "anonymous"
    return {"db": db, "handles": handles}


async def arm(lab, identity, body, status=200, url=USERS, output=None):
    db = lab["db"]
    stage_id = uuid.uuid4().hex
    await db.execute(
        "INSERT INTO integration_stages(id,session_id,adapter,identity_id,status,result) "
        "VALUES(?,?,?,?,?,?)",
        (stage_id, "s", "testcases", identity, "completed", json.dumps({"status": "completed"})))
    await db.execute(
        "INSERT OR REPLACE INTO integration_endpoints"
        "(session_id,url,method,identity_id,sources,parameters) VALUES(?,?,?,?,?,?)",
        ("s", url, "GET", identity, json.dumps(["katana"]), "[]"))
    run = {"test_case_id": "read", "target": {"url": url, "parameter": ""}, "findings": [],
           "chain_next": [], "stopped_early": False, "duration_ms": 1, "produced": {},
           "steps": [{"step": "read", "command": "curl", "success": True, "duration_ms": 1,
                      "exit_code": 0, "skipped": False, "error": None,
                      "output": (output if output is not None
                                 else f"HTTP/1.1 {status} OK\r\n\r\n{body}")}]}
    await db.evidence("s", stage_id, "testcase:read", json.dumps(run))


def body(payload):
    """Compact, the way an API answers. `json.dumps` defaults to a space after each
    colon, so a marker written as a real one is — `"email":"admin@app.test"` — is not a
    substring of its output, and the positive control silently found nothing."""
    return json.dumps(payload, separators=(",", ":"))


PRIVILEGED = body({"status": "success",
                   "data": [{"id": 1, "email": "admin@app.test", "role": "admin"}]})
DENIED_401 = "<html><title>UnauthorizedError</title></html>"


# ------------------------------------------------------------------ the finding

async def test_a_customer_reaching_an_admin_function_is_reported(lab):
    """The measured positive control: GET /api/Users, admin 200, customer 200, anon 401."""
    from orchestrator.integrations.inventory import cross_arm_privileged_function

    await arm(lab, lab["handles"]["admin"], PRIVILEGED)
    await arm(lab, lab["handles"]["jim"], PRIVILEGED)
    await arm(lab, "anonymous", DENIED_401, status=401)

    result = await cross_arm_privileged_function(
        "s", lab["handles"]["admin"], lab["handles"]["jim"], MARKER, anonymous="anonymous")
    assert result["refused_because"] == [], result
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["url"] == USERS
    assert finding["privileged_role"] == "admin"
    assert finding["unprivileged_role"] == "customer"
    assert not _mentions(result, MARKER), (
        "the marker is operator text about the application's data and must not be echoed "
        "back verbatim into a payload that may be shared")


# ------------------------------------------------------- the negative controls

async def test_published_content_is_not_a_privilege_crossing(lab):
    """Three of the first four candidates measured were public, and two had `admin` in the
    path. This is the clause that refuses them."""
    from orchestrator.integrations.inventory import cross_arm_privileged_function

    await arm(lab, lab["handles"]["admin"], PRIVILEGED)
    await arm(lab, lab["handles"]["jim"], PRIVILEGED)
    await arm(lab, "anonymous", PRIVILEGED, status=200)

    result = await cross_arm_privileged_function(
        "s", lab["handles"]["admin"], lab["handles"]["jim"], MARKER, anonymous="anonymous")
    assert result["findings"] == []


@pytest.mark.parametrize("status,body", [
    (400, '{"status":"error","data":"Malicious activity detected"}'),
    (403, '{"error":"Malicious activity detected"}'),
    (200, '{"result":"fail","error":"Access denied"}'),
    (401, DENIED_401),
])
async def test_a_denied_arm_is_not_a_finding_whatever_its_status(lab, status, body):
    """A denial is not always a 4xx. Juice Shop refuses with 400, DVWA with 200. No denial
    list is needed: a refused arm does not contain the privileged data."""
    from orchestrator.integrations.inventory import cross_arm_privileged_function

    await arm(lab, lab["handles"]["admin"], PRIVILEGED)
    await arm(lab, lab["handles"]["jim"], body, status=status)
    await arm(lab, "anonymous", DENIED_401, status=401)

    result = await cross_arm_privileged_function(
        "s", lab["handles"]["admin"], lab["handles"]["jim"], MARKER, anonymous="anonymous")
    assert result["findings"] == []


async def test_each_arm_seeing_its_own_data_is_not_a_finding(lab):
    """Measured: /rest/order-history answers 200 to both arms and 500 to anonymous, and a
    customer reading their own orders is expected. A status-shaped rule reports it."""
    from orchestrator.integrations.inventory import cross_arm_privileged_function

    await arm(lab, lab["handles"]["admin"], PRIVILEGED)
    await arm(lab, lab["handles"]["jim"],
              body({"status": "success", "data": [{"id": 9, "email": "jim@app.test"}]}))
    await arm(lab, "anonymous", "server error", status=500)

    result = await cross_arm_privileged_function(
        "s", lab["handles"]["admin"], lab["handles"]["jim"], MARKER, anonymous="anonymous")
    assert result["findings"] == []


async def test_a_privileged_arm_that_never_saw_the_data_is_not_a_finding(lab):
    """If the marker is absent from the PRIVILEGED arm, the operator named something this
    endpoint does not return — so there is no privileged function here to cross into, and
    reporting one would be reporting on the declaration rather than the application."""
    from orchestrator.integrations.inventory import cross_arm_privileged_function

    await arm(lab, lab["handles"]["admin"], body({"data": []}))
    await arm(lab, lab["handles"]["jim"], body({"data": []}))
    await arm(lab, "anonymous", DENIED_401, status=401)

    result = await cross_arm_privileged_function(
        "s", lab["handles"]["admin"], lab["handles"]["jim"], MARKER, anonymous="anonymous")
    assert result["findings"] == []
    assert result["checked"] >= 1, "it looked, and found nothing to report"


# ------------------------------------------- it refuses rather than concluding

async def test_a_missing_anonymous_arm_is_refused(lab):
    from orchestrator.integrations.inventory import cross_arm_privileged_function

    await arm(lab, lab["handles"]["admin"], PRIVILEGED)
    await arm(lab, lab["handles"]["jim"], PRIVILEGED)
    result = await cross_arm_privileged_function(
        "s", lab["handles"]["admin"], lab["handles"]["jim"], MARKER)
    assert result["findings"] == []
    assert "no_anonymous_arm" in result["refused_because"]


async def test_two_arms_of_the_same_declared_role_are_refused(lab):
    """A privilege crossing needs two different privilege levels, and the operator is the
    only one who can say which is which. Two identities the operator labelled the same way
    is a configuration mistake, and reporting a finding from it would be reporting that
    mistake as a vulnerability."""
    from orchestrator.integrations.inventory import cross_arm_privileged_function
    from orchestrator.integrations.security import SecretStore

    twin = SecretStore().put(who("admin2", "admin").model_dump())
    await lab["db"].execute("INSERT INTO integration_identities VALUES(?,?,?)",
                            (twin, "admin2", "http://app.test"))
    await arm(lab, lab["handles"]["admin"], PRIVILEGED)
    await arm(lab, twin, PRIVILEGED)
    await arm(lab, "anonymous", DENIED_401, status=401)

    result = await cross_arm_privileged_function("s", lab["handles"]["admin"], twin,
                                                 MARKER, anonymous="anonymous")
    assert result["findings"] == []
    assert "arms_share_a_role" in result["refused_because"]


async def test_an_undeclared_role_is_refused(lab):
    """Without declared roles there is no privileged and unprivileged, only two
    identities — and guessing which is which from their names is exactly the kind of
    inference that would let the lane report on its own assumption."""
    from orchestrator.integrations.inventory import cross_arm_privileged_function
    from orchestrator.integrations.security import SecretStore

    nameless = SecretStore().put(who("ghost", "").model_dump())
    await lab["db"].execute("INSERT INTO integration_identities VALUES(?,?,?)",
                            (nameless, "ghost", "http://app.test"))
    await arm(lab, lab["handles"]["admin"], PRIVILEGED)
    await arm(lab, nameless, PRIVILEGED)
    await arm(lab, "anonymous", DENIED_401, status=401)

    result = await cross_arm_privileged_function("s", lab["handles"]["admin"], nameless,
                                                 MARKER, anonymous="anonymous")
    assert result["findings"] == []
    assert "role_not_declared" in result["refused_because"]


async def test_a_marker_that_is_not_comparable_is_refused(lab):
    from orchestrator.integrations.inventory import cross_arm_privileged_function

    await arm(lab, lab["handles"]["admin"], PRIVILEGED)
    await arm(lab, lab["handles"]["jim"], PRIVILEGED)
    await arm(lab, "anonymous", DENIED_401, status=401)
    for bad in ("", "   ", "x" * 513, "a\nb"):
        result = await cross_arm_privileged_function(
            "s", lab["handles"]["admin"], lab["handles"]["jim"], bad, anonymous="anonymous")
        assert result["findings"] == []
        assert "marker_unusable" in result["refused_because"], bad


async def test_an_anonymous_arm_that_never_asked_is_not_a_denial(lab):
    """The anonymous clause needs the arm to have ASKED. Reading "never probed this URL"
    as "was refused this URL" is how an unrun clause passes itself, and here it would
    convert every unvisited endpoint into a reported violation."""
    from orchestrator.integrations.inventory import cross_arm_privileged_function

    await arm(lab, lab["handles"]["admin"], PRIVILEGED)
    await arm(lab, lab["handles"]["jim"], PRIVILEGED)
    await arm(lab, "anonymous", DENIED_401, status=401, url="http://app.test/api/Other")

    result = await cross_arm_privileged_function(
        "s", lab["handles"]["admin"], lab["handles"]["jim"], MARKER, anonymous="anonymous")
    assert result["findings"] == [], (
        "the anonymous arm probed a different URL, so nothing establishes that this "
        "operation is not public")


async def test_a_marker_only_in_the_response_HEADERS_is_not_the_data(lab):
    """The lane proxies every probe, and a proxy that echoes the request URL into a
    response header is ordinary. If the declared marker appears in that echo, the header
    block would satisfy the clause while the application handed over nothing."""
    from orchestrator.integrations.inventory import cross_arm_privileged_function

    echoed = (f"HTTP/1.1 200 OK\r\nX-Echo-Request: /api/Users?filter={MARKER}\r\n"
              f"\r\n" + body({"status": "success", "data": []}))
    await arm(lab, lab["handles"]["admin"], PRIVILEGED)
    await arm(lab, lab["handles"]["jim"], None, output=echoed)
    await arm(lab, "anonymous", DENIED_401, status=401)

    result = await cross_arm_privileged_function(
        "s", lab["handles"]["admin"], lab["handles"]["jim"], MARKER, anonymous="anonymous")
    assert result["findings"] == []


async def test_a_capture_with_no_body_at_all_matches_nothing(lab):
    """A HEAD-shaped or truncated capture is header block only. Treating the whole
    capture as the body there would let the echo above match after all."""
    from orchestrator.integrations.inventory import cross_arm_privileged_function

    headers_only = f"HTTP/1.1 200 OK\r\nX-Echo-Request: /api/Users?filter={MARKER}"
    await arm(lab, lab["handles"]["admin"], PRIVILEGED)
    await arm(lab, lab["handles"]["jim"], None, output=headers_only)
    await arm(lab, "anonymous", DENIED_401, status=401)

    result = await cross_arm_privileged_function(
        "s", lab["handles"]["admin"], lab["handles"]["jim"], MARKER, anonymous="anonymous")
    assert result["findings"] == []


async def test_a_marker_echoed_by_a_refusal_is_not_access(lab):
    """Measured: Juice Shop refuses `/api/Cards/3` to the wrong customer with HTTP **400**.
    A 400 that echoes the submitted value back — and the marker may BE a submitted
    value — is the application saying no while repeating the question."""
    from orchestrator.integrations.inventory import cross_arm_privileged_function

    await arm(lab, lab["handles"]["admin"], PRIVILEGED)
    # RAW, not JSON-encoded. `json.dumps` escapes the marker's own quotes, so an echo
    # built with it does not contain the marker and this control tested nothing. A
    # reflected value in a stack trace or a plain-text error arrives unescaped.
    await arm(lab, lab["handles"]["jim"], None,
              output=f"HTTP/1.1 400 Bad Request\r\n\r\nInvalid filter: {MARKER}")
    await arm(lab, "anonymous", DENIED_401, status=401)

    result = await cross_arm_privileged_function(
        "s", lab["handles"]["admin"], lab["handles"]["jim"], MARKER, anonymous="anonymous")
    assert result["findings"] == []


async def test_a_marker_naming_the_UNPRIVILEGED_arms_own_data_is_not_a_finding(lab):
    """The operator can declare a marker that identifies the wrong side's data. Here the
    customer's own email: the customer receives it, the administrator does not, and the
    anonymous arm is refused. Without the first clause this reads as a crossing — it is a
    customer reading their own record."""
    from orchestrator.integrations.inventory import cross_arm_privileged_function

    mine = '"email":"jim@app.test"'
    await arm(lab, lab["handles"]["admin"], PRIVILEGED)
    await arm(lab, lab["handles"]["jim"],
              body({"status": "success", "data": [{"id": 2, "email": "jim@app.test"}]}))
    await arm(lab, "anonymous", DENIED_401, status=401)

    result = await cross_arm_privileged_function(
        "s", lab["handles"]["admin"], lab["handles"]["jim"], mine, anonymous="anonymous")
    assert result["findings"] == [], (
        "the privileged arm never received this data, so there is no privileged "
        "function here to have crossed into")


async def test_a_marker_the_caller_put_in_the_URL_is_not_disclosure(lab):
    """Measured: `GET /rest/track-order/99999` answers 200 with
    `{"data":[{"orderId":"99999"}]}` — the entire record is the value from the path.

    An endpoint that echoes input AND requires a session satisfies all three clauses
    while disclosing nothing, because the TARGET would be supplying the evidence for its
    own verdict. That inverts the safety asymmetry this check rests on, so it is the one
    shape that has to be refused before the clauses run rather than rejected by them.
    """
    from orchestrator.integrations.inventory import cross_arm_privileged_function

    url = f"http://app.test/rest/track-order/{MARKER}"
    echo = body({"status": "success", "data": [{"orderId": "admin@app.test"}]})
    reflected = f'HTTP/1.1 200 OK\r\n\r\n{{"data":[{{{MARKER}}}]}}'
    for identity in (lab["handles"]["admin"], lab["handles"]["jim"]):
        await arm(lab, identity, None, url=url, output=reflected)
    await arm(lab, "anonymous", DENIED_401, status=401, url=url)

    result = await cross_arm_privileged_function(
        "s", lab["handles"]["admin"], lab["handles"]["jim"], MARKER, anonymous="anonymous")
    assert result["findings"] == []
    assert result["skipped_reflected_marker"] == [url], (
        "and it must SAY it skipped the operation — an operation silently dropped reads "
        "as a clean result for it")


async def test_a_percent_encoded_marker_in_the_query_is_also_reflection(lab):
    """A marker in a query arrives percent-encoded, so the raw substring check misses it."""
    from urllib.parse import quote

    from orchestrator.integrations.inventory import cross_arm_privileged_function

    url = f"http://app.test/api/search?q={quote(MARKER)}"
    reflected = f"HTTP/1.1 200 OK\r\n\r\nno results for {MARKER}"
    for identity in (lab["handles"]["admin"], lab["handles"]["jim"]):
        await arm(lab, identity, None, url=url, output=reflected)
    await arm(lab, "anonymous", DENIED_401, status=401, url=url)

    result = await cross_arm_privileged_function(
        "s", lab["handles"]["admin"], lab["handles"]["jim"], MARKER, anonymous="anonymous")
    assert result["findings"] == []
    assert result["skipped_reflected_marker"] == [url]


async def test_an_absent_record_answered_200_is_not_a_finding(lab):
    """The lab's worst-shaped false positive for an equality rule: Juice Shop answers
    `GET /rest/basket/99999` with HTTP 200 `{"status":"success","data":null}`,
    byte-identical between arms, with the anonymous arm hard-refused. Status, equality and
    anon-refused all pass, and the object does not exist. The marker is what notices."""
    from orchestrator.integrations.inventory import cross_arm_privileged_function

    absent = body({"status": "success", "data": None})
    await arm(lab, lab["handles"]["admin"], absent)
    await arm(lab, lab["handles"]["jim"], absent)
    await arm(lab, "anonymous", DENIED_401, status=401)

    result = await cross_arm_privileged_function(
        "s", lab["handles"]["admin"], lab["handles"]["jim"], MARKER, anonymous="anonymous")
    assert result["findings"] == []


async def test_the_declared_privileged_arm_may_itself_be_denied(lab):
    """`admin` is not universally the most privileged role. Measured: Juice Shop gates
    `/rest/order-history/orders` on `security.isAccounting()`, so ALL THREE arms — admin
    included — receive a byte-identical 403, and only `accountant@juice-sh.op` (JWT role
    `accounting`) receives the data. An equality rule reports it; clause 1 rejects it,
    because the arm the operator called privileged never received the marked data."""
    from orchestrator.integrations.inventory import cross_arm_privileged_function

    forbidden = body({"error": "Malicious activity detected"})
    for identity in (lab["handles"]["admin"], lab["handles"]["jim"], "anonymous"):
        await arm(lab, identity, forbidden, status=403)

    result = await cross_arm_privileged_function(
        "s", lab["handles"]["admin"], lab["handles"]["jim"], MARKER, anonymous="anonymous")
    assert result["findings"] == []


# ---------------------------------------------- entitlement, which no response expresses

async def test_data_the_operator_declared_this_identity_entitled_to_is_not_a_crossing(lab):
    """Measured on Juice Shop: `GET /rest/basket/2` is JIM'S OWN basket, and the
    administrator can read it too — so a marker naming jim's own data is present in the
    privileged arm AND the unprivileged arm while anonymous is refused. Every clause is
    satisfied and nothing is wrong.

        admin  200 {"status":"success","data":{"id":2,...,"UserId":2,...}}
        jim    200 byte-identical
        anon   401

    No rule reading only responses can separate that from a real crossing, because the
    difference is ENTITLEMENT. `Identity.may_access` is where the operator says so — a
    field that until now was validated and read by nothing.
    """
    from orchestrator.integrations.inventory import cross_arm_privileged_function
    from orchestrator.integrations.security import SecretStore

    own = '"UserId":2'
    url = "http://app.test/rest/basket/2"
    jim = SecretStore().put(who("jim2", "customer", may_access=["/rest/basket/2"]).model_dump())
    await lab["db"].execute("INSERT INTO integration_identities VALUES(?,?,?)",
                            (jim, "jim2", "http://app.test"))
    mine = body({"status": "success", "data": {"id": 2, "UserId": 2}})
    await arm(lab, lab["handles"]["admin"], mine, url=url)
    await arm(lab, jim, mine, url=url)
    await arm(lab, "anonymous", DENIED_401, status=401, url=url)

    result = await cross_arm_privileged_function(
        "s", lab["handles"]["admin"], jim, own, anonymous="anonymous")
    assert result["findings"] == []
    assert result["suppressed_declared_access"] == [url], (
        "and it must SAY what it suppressed — a suppression nobody can see is "
        "indistinguishable from a check that never looked")


async def test_an_undeclared_operation_is_still_reported(lab):
    """The positive control for the clause above. `may_access` is an open-world
    suppression: an empty declaration suppresses nothing, so it can only ever remove a
    finding and never manufacture one."""
    from orchestrator.integrations.inventory import cross_arm_privileged_function
    from orchestrator.integrations.security import SecretStore

    jim = SecretStore().put(who("jim3", "customer",
                                may_access=["/rest/basket/2"]).model_dump())
    await lab["db"].execute("INSERT INTO integration_identities VALUES(?,?,?)",
                            (jim, "jim3", "http://app.test"))
    await arm(lab, lab["handles"]["admin"], PRIVILEGED)
    await arm(lab, jim, PRIVILEGED)
    await arm(lab, "anonymous", DENIED_401, status=401)

    result = await cross_arm_privileged_function(
        "s", lab["handles"]["admin"], jim, MARKER, anonymous="anonymous")
    assert len(result["findings"]) == 1, "/api/Users was not declared"
    assert result["suppressed_declared_access"] == []


async def test_a_form_encoded_reflection_is_caught(lab):
    """`unquote` alone missed it: a form-encoded marker carries `+` for space, so
    `?name=Vulnerability%3A+Reflected` did not match the marker `Vulnerability: Reflected`
    that DVWA reflects three times into that very page."""
    from orchestrator.integrations.inventory import cross_arm_privileged_function

    marker = "Vulnerability: Reflected"
    url = "http://app.test/vulnerabilities/xss_r/?name=Vulnerability%3A+Reflected"
    echo = f"HTTP/1.1 200 OK\r\n\r\n<h1>{marker}</h1><p>{marker}</p>"
    for identity in (lab["handles"]["admin"], lab["handles"]["jim"]):
        await arm(lab, identity, None, url=url, output=echo)
    await arm(lab, "anonymous", DENIED_401, status=401, url=url)

    result = await cross_arm_privileged_function(
        "s", lab["handles"]["admin"], lab["handles"]["jim"], marker, anonymous="anonymous")
    assert result["findings"] == []
    assert result["skipped_reflected_marker"] == [url]
