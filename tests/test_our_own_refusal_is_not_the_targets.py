"""An absence is only evidence when something was there to be absent FROM.

Four checks asked "did the anonymous arm fail to receive this?" and accepted SILENCE as
the answer. `deterministic.curl_request` deliberately replaces a proxy refusal with

    "[erlik] the assessment proxy refused this request; the target was never contacted,
     so there is nothing to evaluate"

— a NON-EMPTY string with no status line — and a curl timeout arrives as zero bytes. Both
read as "not a 2xx", which is indistinguishable from the target saying no, and only one of
those is evidence about the application. The lane's own audit recorded 29 of 60 probes
refused in a single measured run, so this is the common case, not an edge.

Measured consequences, end to end, on content every arm of Juice Shop can read:

    cross_arm_privileged_function on /rest/products/1/reviews  -> FINDING, refused_because []
    the `idor` evaluator, from `curl --max-time 0.001` (0 bytes) -> HIGH, confidence confirmed

`confirmed` is the grade that marks a finding verified on a client's tracker.

And one more of the same family, with the target rather than the proxy supplying the
silence: `cookie_attributes` parsed `Set-Cookie` out of the whole capture, so a reflected
`%0ASet-Cookie:+JSESSIONID%3Dforged%0A` in the BODY produced a MEDIUM about a cookie the
server never set.
"""
import json
import uuid

import pytest

from orchestrator import http_capture
from orchestrator.integrations.contracts import Identity

OUR_REFUSAL = ("[erlik] the assessment proxy refused this request; the target was never "
               "contacted, so there is nothing to evaluate")
PUBLIC = ('HTTP/1.1 200 OK\r\n\r\n{"status":"success","data":'
          '[{"message":"nice","author":"admin@app.test"}]}')
MARKER = '"author":"admin@app.test"'


# ------------------------------------------------------- the shared primitive

@pytest.mark.parametrize("capture,answered,why", [
    ("HTTP/1.1 401 Unauthorized\r\n\r\nno", True, "the application refused — real evidence"),
    ("HTTP/1.1 200 OK\r\n\r\n{}", True, "the application answered"),
    (OUR_REFUSAL, False, "erlik's own proxy refusal"),
    ("", False, "a timeout, zero bytes"),
    ("   \n  ", False, "whitespace"),
    ("curl: (28) Operation timed out", False, "curl's own error text"),
    ("curl: (7) Failed to connect", False, "a connection failure"),
])
def test_only_a_real_response_counts_as_an_answer(capture, answered, why):
    assert http_capture.answered(capture) is answered, why


# --------------------------------------------- the two cross-arm checks

def who(name, role):
    return Identity.model_validate({
        "name": name, "target_origin": "http://app.test", "role": role, "subject_id":
        "1" if role == "admin" else "2",
        "check": {"url": "http://app.test/me", "body_contains": name}})


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
    await db.execute("INSERT INTO integration_assessments(session_id,target,status,config) "
                     "VALUES(?,?,?,?)", ("s", "http://app.test", "completed", "{}"))
    store, handles = SecretStore(), {}
    for name, role in (("admin", "admin"), ("jim", "customer")):
        handles[name] = store.put(who(name, role).model_dump())
        await db.execute("INSERT INTO integration_identities VALUES(?,?,?)",
                         (handles[name], name, "http://app.test"))
    handles["anonymous"] = "anonymous"
    return {"db": db, "h": handles}


URL = "http://app.test/rest/products/1/reviews"


async def arm(lab, identity, output):
    db = lab["db"]
    stage_id = uuid.uuid4().hex
    await db.execute("INSERT INTO integration_stages(id,session_id,adapter,identity_id,"
                     "status,result) VALUES(?,?,?,?,?,?)",
                     (stage_id, "s", "testcases", identity, "completed",
                      json.dumps({"status": "completed"})))
    await db.execute("INSERT OR REPLACE INTO integration_endpoints(session_id,url,method,"
                     "identity_id,sources,parameters) VALUES(?,?,?,?,?,?)",
                     ("s", URL, "GET", identity, json.dumps(["katana"]), "[]"))
    run = {"test_case_id": "read", "target": {"url": URL, "parameter": ""}, "findings": [],
           "chain_next": [], "stopped_early": False, "duration_ms": 1, "produced": {},
           "steps": [{"step": "read", "command": "curl", "success": True, "duration_ms": 1,
                      "exit_code": 0, "skipped": False, "error": None, "output": output}]}
    await db.evidence("s", stage_id, "testcase:read", json.dumps(run))


@pytest.mark.parametrize("anonymous_capture,why", [
    (OUR_REFUSAL, "erlik's own proxy refusal, the measured false positive"),
    ("", "a timeout"),
    ("curl: (28) Operation timed out", "curl's error text"),
])
async def test_a_privilege_crossing_needs_the_anonymous_arm_to_have_ANSWERED(
        lab, anonymous_capture, why):
    from orchestrator.integrations.inventory import cross_arm_privileged_function

    await arm(lab, lab["h"]["admin"], PUBLIC)
    await arm(lab, lab["h"]["jim"], PUBLIC)
    await arm(lab, "anonymous", anonymous_capture)
    result = await cross_arm_privileged_function(
        "s", lab["h"]["admin"], lab["h"]["jim"], MARKER, anonymous="anonymous")
    assert result["findings"] == [], why


async def test_the_real_refusal_still_produces_the_finding(lab):
    """The positive control: a 401 FROM THE APPLICATION is evidence, and must still fire."""
    from orchestrator.integrations.inventory import cross_arm_privileged_function

    await arm(lab, lab["h"]["admin"], PUBLIC)
    await arm(lab, lab["h"]["jim"], PUBLIC)
    await arm(lab, "anonymous", "HTTP/1.1 401 Unauthorized\r\n\r\nUnauthorizedError")
    result = await cross_arm_privileged_function(
        "s", lab["h"]["admin"], lab["h"]["jim"], MARKER, anonymous="anonymous")
    assert len(result["findings"]) == 1


@pytest.mark.parametrize("anonymous_capture", [OUR_REFUSAL, "", "curl: (28) timed out"])
async def test_object_authorization_needs_the_anonymous_arm_to_have_ANSWERED(
        lab, anonymous_capture):
    from orchestrator.integrations.inventory import cross_arm_authorization

    owned = 'HTTP/1.1 200 OK\r\n\r\n{"status":"success","data":{"id":1,"UserId":1}}'
    await arm(lab, lab["h"]["jim"], owned)
    await arm(lab, lab["h"]["admin"], owned)
    await arm(lab, "anonymous", anonymous_capture)
    result = await cross_arm_authorization("s", lab["h"]["jim"], lab["h"]["admin"],
                                          "data.UserId", "anonymous")
    assert result["findings"] == []


# ------------------------------------------------- the two in-case evaluators

def test_the_idor_evaluator_requires_its_anonymous_arm_to_have_answered():
    """Measured: a real `curl --max-time 0.001` returning zero bytes produced a HIGH
    `confirmed` finding on Juice Shop's PUBLIC reviews endpoint — the content this clause
    exists to refuse."""
    import inspect

    from orchestrator.testcase import runner

    source = inspect.getsource(runner._run_evaluator)
    clause = source[source.index("anonymous_excluded = ("):]
    assert "http_capture.answered(anonymous.output)" in clause
    assert "_response_body(anonymous.output)" in clause, (
        "and the marker must be matched against the body, not the whole capture")


def test_the_ownership_evaluator_requires_its_anonymous_arm_to_have_answered():
    import inspect

    from orchestrator.testcase import runner

    source = inspect.getsource(runner._run_evaluator)
    clause = source[source.index("anonymous_refused = ("):]
    assert "http_capture.answered(anon_step.output)" in clause


async def test_a_set_cookie_the_application_PRINTED_is_not_a_set_cookie():
    """End to end on the real WSTG-SESS-02 case. `_response_headers` exists in that file for
    exactly this reason and the Set-Cookie scan did not use it: measured on DVWA,
    `?name=%0ASet-Cookie:+JSESSIONID%3Dforged%0A` made the application print the line into
    its BODY and the evaluator emitted a MEDIUM about a cookie the server never set.
    WSTG-SESS-02 is the one case AssessmentConfig permits without `active`, and it runs
    against every discovered URL."""
    from orchestrator.testcase.loader import find_by_id
    from orchestrator.testcase.runner import run_test_case

    reflected = ("HTTP/1.1 200 OK\r\n"
                 "Content-Type: text/html\r\n"
                 "\r\n"
                 "<pre>Hello \nSet-Cookie: JSESSIONID=forged\n</pre>")

    async def executor(command, **kwargs):
        return {"success": True, "exit_code": 0, "output": reflected, "error": None}

    run = await run_test_case(
        find_by_id("WSTG-SESS-02"),
        {"url": "http://app.test/", "scope": {"allow_hosts": ["app.test"]}},
        executor=executor, allow_llm=False)
    assert run.findings == [], (
        "a Set-Cookie line the application printed into its body is not a cookie it set")


async def test_a_real_weak_cookie_still_fires():
    """The positive control, so the test above is not satisfied by an evaluator that stopped
    working."""
    from orchestrator.testcase.loader import find_by_id
    from orchestrator.testcase.runner import run_test_case

    weak = ("HTTP/1.1 200 OK\r\n"
            "Set-Cookie: SESSIONID=abc123def456; Path=/\r\n"
            "\r\n<html></html>")

    async def executor(command, **kwargs):
        return {"success": True, "exit_code": 0, "output": weak, "error": None}

    run = await run_test_case(
        find_by_id("WSTG-SESS-02"),
        {"url": "http://app.test/", "scope": {"allow_hosts": ["app.test"]}},
        executor=executor, allow_llm=False)
    assert run.findings, "the evaluator no longer fires on a real cookie with no attributes"


def test_a_forged_set_cookie_in_the_body_is_not_a_header():
    """The primitive behind it, exercised directly."""
    from orchestrator.testcase.runner import _response_body, _response_headers

    capture = ("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
               "<p>Hello\nSet-Cookie: JSESSIONID=forged\n</p>")
    assert "Set-Cookie" not in _response_headers(capture)
    assert "Set-Cookie" in _response_body(capture)


# ------------------------------------- a single-arm assertion, and what it can be shown

def test_a_security_assertion_cannot_be_satisfied_by_its_own_input():
    """Measured: `GET /rest/track-order/ERLIK-PRIVATE-ORDER-4711` answers 200 with a 68-byte
    body containing that id, because the whole record IS the value from the path — and the
    assertion emitted a HIGH `confirmed` Broken Access Control finding from it. Same gate,
    same reason, as the reflection clause in `cross_arm_privileged_function`."""
    import pydantic

    from orchestrator.integrations.contracts import SecurityAssertion

    with pytest.raises(pydantic.ValidationError):
        SecurityAssertion(request={"url": "http://app.test/rest/track-order/ERLIK-PRIV-4711"},
                          identity_id="h", description="d",
                          forbidden_marker="ERLIK-PRIV-4711")


def test_a_percent_encoded_marker_in_the_url_is_also_its_own_input():
    import pydantic

    from orchestrator.integrations.contracts import SecurityAssertion

    with pytest.raises(pydantic.ValidationError):
        # A literal `+` is the form encoding of a space, which plain `unquote` leaves alone.
        SecurityAssertion(request={"url": "http://app.test/s?q=ERLIK%2DPRIV+4711"},
                          identity_id="h", description="d",
                          forbidden_marker="ERLIK-PRIV 4711")


def test_a_marker_the_application_stores_is_still_accepted():
    from orchestrator.integrations.contracts import SecurityAssertion

    ok = SecurityAssertion(request={"url": "http://app.test/api/orders"}, identity_id="h",
                           description="customer must not read the admin ledger",
                           forbidden_marker="admin@app.test")
    assert ok.forbidden_marker == "admin@app.test"


def assertion(url="http://app.test/api/orders", marker="admin@app.test", status=200):
    from orchestrator.integrations.contracts import SecurityAssertion
    return SecurityAssertion(request={"url": url, "expected_status": status},
                             identity_id="h", description="d", forbidden_marker=marker)


def test_a_security_assertion_fires_on_the_response_it_asserted_on():
    """The positive control."""
    from orchestrator.integrations.adapters import assertion_verdict

    fires, refused = assertion_verdict(assertion(), {
        "url": "http://app.test/api/orders", "status": 200, "blocked": False,
        "body": '{"ledger":[{"email":"admin@app.test"}]}'})
    assert fires is True and refused is None


def test_a_security_assertion_does_not_fire_on_a_REDIRECTED_response():
    """Measured on DVWA: `GET /vulnerabilities/exec/` landed on `login.php`, and the marker
    "Login" emitted a HIGH `confirmed` finding whose `url` field named /vulnerabilities/exec/
    while its evidence was the login page. `worker.request` follows up to five redirects and
    reports the final url, so the body can belong to wherever the target sent us."""
    from orchestrator.integrations.adapters import assertion_verdict

    fires, refused = assertion_verdict(
        assertion(url="http://app.test/vulnerabilities/exec/", marker="Login"),
        {"url": "http://app.test/login.php", "status": 200, "blocked": False,
         "body": "<form>Login</form>"})
    assert fires is False
    assert refused and refused["landed_on"] == "http://app.test/login.php"


def test_a_security_assertion_does_not_fire_on_a_response_erlik_REFUSED():
    from orchestrator.integrations.adapters import assertion_verdict

    fires, refused = assertion_verdict(assertion(), {
        "url": "http://app.test/api/orders", "status": 200, "blocked": True,
        "body": "X-Erlik-Blocked: true\nURL budget exhausted\nadmin@app.test"})
    assert fires is False
    assert refused and "never contacted" in refused["reason"]


def test_a_query_string_difference_is_not_a_redirect():
    """The comparison is origin plus path. A probe whose query the target normalises has not
    been redirected somewhere else, and refusing it would lose real findings."""
    from orchestrator.integrations.adapters import assertion_verdict

    fires, _ = assertion_verdict(
        assertion(url="http://app.test/api/orders?page=1"),
        {"url": "http://app.test/api/orders?page=1&sort=id", "status": 200,
         "blocked": False, "body": "admin@app.test"})
    assert fires is True


def test_the_proxys_own_403_does_not_count_as_an_answer():
    """`curl_request` substitutes a status-line-less sentence, which `status()` catches on its
    own — but the proxy's REAL 403 parses exactly like the target saying no, and it reaches a
    capture from any job whose output is not routed through that substitution. The
    `X-Erlik-Blocked` header proxy_addon stamps is the durable marker. The header block only,
    so a body that prints the line cannot suppress a real answer."""
    ours = ("HTTP/1.1 403 Forbidden\r\nX-Erlik-Blocked: true\r\n\r\n"
            "X-Erlik-Blocked: true\nURL budget exhausted\n")
    assert http_capture.answered(ours) is False
    # The SAME 403 from the application is a real answer, which is what makes it load-bearing.
    theirs = "HTTP/1.1 403 Forbidden\r\n\r\n{\"error\":\"Malicious activity detected\"}"
    assert http_capture.answered(theirs) is True
    # And a target that prints the header name into its BODY cannot silence itself.
    # At the start of a line, which is where a reflected value lands in a <pre> block and
    # is the only place the pattern could match.
    echo = ("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
            "you searched for:\nX-Erlik-Blocked: true\n")
    assert http_capture.answered(echo) is True


def test_a_security_assertion_says_what_one_arm_can_establish():
    """It has no second identity and no anonymous control, so it cannot tell a privilege
    crossing from published content. The finding is still emitted — the operator declared
    it — but `basis` must not let a reader think a differential was run. Measured: Juice Shop
    answers `/administration` with index.html, which contains "Juice Shop", so a badly chosen
    marker fires on a catch-all route and no single response can detect that."""
    import inspect

    from orchestrator.integrations import adapters

    basis = inspect.getsource(adapters.SchemathesisAdapter)
    assert "ONE ARM, ONE RESPONSE" in basis, (
        "the finding's own basis must state what it rests on")


def test_a_refused_assertion_is_reported_rather_than_passed_over():
    """A refusal has to reach the stage record, or an operator reads "no finding" as "the
    assertion held"."""
    import inspect

    from orchestrator.integrations import adapters

    source = inspect.getsource(adapters.SchemathesisAdapter)
    assert "security_assertion_refused" in source
