"""A SecurityAssertion fired on the application's generic answer.

`SecurityAssertion` emits `severity="high"`, `confidence="confirmed"` and
`methodology=["WSTG-AUTHZ-04"]` from ONE response to ONE identity — `confirmed` being the grade
that marks a finding verified on a client's tracker. Increment 9 gave it a reflection gate (the
marker must not be the operator's own input echoed back) and a redirect gate (the response must
come from the asserted URL). This is the third false-positive class that pass measured and left:

    a single-page application serves its shell for every route its server does not know,
    and that shell contains the product's own name.

Measured on Juice Shop: `/administration`, `/accounting`, `/Edge/`, `/` and a path that cannot
exist all produce ONE response signature. So "customer must not see 'Juice Shop' at
/administration" was a HIGH confirmed finding made out of index.html.

THE CONTROL IS A PATH THAT CANNOT EXIST. Whatever the application answers there is its generic
response; if the asserted URL answered the same way, the marker was not found in anything
specific to it. It discriminates rather than blanket-refusing — measured on the same
application, `/api/Users`, `/api/Users/1` and `/rest/user/whoami` all differ from the control,
and on DVWA `/` differs while `/administration` does not.
"""
import pytest

from orchestrator.integrations.adapters import assertion_verdict
from orchestrator.integrations.contracts import SecurityAssertion
from orchestrator.integrations.inventory import worker_response_signature


def assertion(url="http://app.test/administration", marker="Juice Shop", status=200):
    return SecurityAssertion(request={"url": url, "expected_status": status},
                             identity_id="h", description="d", forbidden_marker=marker)


def answer(body, url="http://app.test/administration", status=200, headers=None):
    return {"url": url, "status": status, "blocked": False,
            "headers": headers or {"Content-Type": "text/html"}, "body": body}


SHELL = "<html><title>OWASP Juice Shop</title></html>"


# ------------------------------------------------------------------ the refusal

def test_the_generic_response_does_not_satisfy_an_assertion():
    control = answer(SHELL, url="http://app.test/erlik-control-abc123")
    fires, refused = assertion_verdict(assertion(), answer(SHELL), control)
    assert fires is False
    assert "generic response" in refused["reason"]
    assert refused["control_url"].endswith("erlik-control-abc123")


def test_a_response_specific_to_the_url_still_fires():
    """The positive control. Without it the clause above is satisfied by a check that stopped
    working."""
    control = answer(SHELL, url="http://app.test/erlik-control-abc123")
    real = answer('{"users":[{"email":"admin@app.test"}]} Juice Shop',
                  headers={"Content-Type": "application/json"})
    fires, refused = assertion_verdict(assertion(), real, control)
    assert fires is True and refused is None


def test_without_a_control_the_assertion_is_evaluated_as_before():
    """A control that could not be obtained must not silently suppress every assertion — that
    would turn a fetch failure into a clean bill of health."""
    assert assertion_verdict(assertion(), answer(SHELL), None)[0] is True


def test_a_body_difference_alone_is_enough_to_keep_them_apart():
    control = answer(SHELL, url="http://app.test/erlik-control-abc123")
    assert assertion_verdict(assertion(), answer(SHELL + "<!-- admin -->"), control)[0] is True


def test_a_header_difference_alone_is_enough():
    """The signature compares the stable headers too, so a route that returns the same bytes
    with a different content type is a different response."""
    control = answer(SHELL, url="http://app.test/erlik-control-abc123")
    other = answer(SHELL, headers={"Content-Type": "application/json"})
    assert assertion_verdict(assertion(), other, control)[0] is True


# ------------------------------------------- the earlier gates still hold

def test_the_redirect_gate_still_applies():
    control = answer(SHELL, url="http://app.test/erlik-control-abc123")
    landed = answer("<form>Login</form>", url="http://app.test/login.php")
    fires, refused = assertion_verdict(assertion(marker="Login"), landed, control)
    assert fires is False and refused["landed_on"].endswith("/login.php")


def test_a_blocked_response_is_still_refused():
    control = answer(SHELL, url="http://app.test/erlik-control-abc123")
    blocked = {**answer(SHELL), "blocked": True}
    fires, refused = assertion_verdict(assertion(), blocked, control)
    assert fires is False and "never contacted" in refused["reason"]


# ------------------------------------------------- the control itself

@pytest.fixture
def control_probe(monkeypatch):
    """Drive the real `generic_response` with a scripted rpc."""
    from orchestrator.integrations import adapters

    calls = []

    def scripted(answer):
        async def rpc(sandbox, request):
            calls.append(request["request"]["url"])
            if isinstance(answer, Exception):
                raise answer
            return answer
        monkeypatch.setattr(adapters, "rpc", rpc)
        return calls

    return scripted


async def test_the_control_is_what_a_nonexistent_path_answers(control_probe):
    from orchestrator.integrations.adapters import generic_response

    calls = control_probe(answer(SHELL, url="http://app.test/erlik-control-x"))
    got = await generic_response(None, "http://app.test/administration", "sess", {})
    assert got["body"] == SHELL
    assert len(calls) == 1 and "/erlik-control-" in calls[0]


@pytest.mark.parametrize("answer_value,why", [
    ({"url": "http://app.test/p", "status": 403, "blocked": True, "headers": {},
      "body": "X-Erlik-Blocked: true"}, "erlik's own proxy refused it"),
    ({"url": "http://app.test/p", "status": 0, "blocked": False, "headers": {},
      "body": "", "error": "connect timeout"}, "it errored"),
    (RuntimeError("no sandbox"), "the rpc raised"),
])
async def test_a_refused_or_errored_control_is_not_used_as_one(control_probe, answer_value, why):
    """Our own refusal is not the target's answer — the defect this project has now found four
    times. Returning it would make every assertion on that origin compare against erlik's 403,
    so each would be suppressed. `None` leaves the assertion evaluated as before."""
    from orchestrator.integrations.adapters import generic_response

    control_probe(answer_value)
    assert await generic_response(None, "http://app.test/x", "sess", {}) is None, why
    # ...and an assertion then behaves exactly as it did before the control existed.
    assert assertion_verdict(assertion(), answer(SHELL), None)[0] is True


async def test_one_control_is_fetched_per_origin_not_per_assertion(control_probe):
    from orchestrator.integrations.adapters import generic_response

    calls = control_probe(answer(SHELL, url="http://app.test/erlik-control-x"))
    cache: dict = {}
    for url in ("http://app.test/a", "http://app.test/b", "http://app.test/c"):
        await generic_response(None, url, "sess", cache)
    assert len(calls) == 1, calls
    # A second origin is its own control.
    await generic_response(None, "http://other.test/a", "sess", cache)
    assert len(calls) == 2


async def test_the_control_path_is_stable_within_a_run_and_differs_across_runs(control_probe):
    """Stable so two assertions share one fetch; unpredictable so a target cannot special-case
    it."""
    from orchestrator.integrations.adapters import generic_response

    calls = control_probe(answer(SHELL, url="http://app.test/erlik-control-x"))
    await generic_response(None, "http://app.test/a", "session-one", {})
    await generic_response(None, "http://app.test/a", "session-one", {})
    await generic_response(None, "http://app.test/a", "session-two", {})
    assert calls[0] == calls[1] != calls[2]


async def test_the_control_is_on_the_asserted_origin(control_probe):
    from orchestrator.integrations.adapters import generic_response

    calls = control_probe(answer(SHELL, url="http://app.test/erlik-control-x"))
    await generic_response(None, "http://app.test:8081/deep/path?q=1", "sess", {})
    assert calls[0].startswith("http://app.test:8081/erlik-control-")
    assert "?" not in calls[0] and "deep" not in calls[0]


# ------------------------------------------------- the signature it rests on

def test_the_worker_shape_and_the_capture_shape_agree():
    """Two ways of deciding whether two responses are the same response would be one defect
    waiting to happen."""
    from orchestrator.integrations.inventory import response_signature

    capture = "HTTP/1.1 200 OK\r\nDate: X\r\nServer: nginx\r\n\r\n<html>shell</html>"
    worker = {"status": 200, "headers": {"Date": "Y", "Server": "nginx"},
              "body": "<html>shell</html>"}
    assert response_signature(capture) == worker_response_signature(worker)
