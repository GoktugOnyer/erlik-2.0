"""E-032: three paths awarded `confirmed` without a comparison behind it.

`confirmed` is not a word in a report. `defectdojo.py` maps it straight to
`"verified": True`, so it is the grade that tells a client's tracker a human need not
check this. Two producers reached it without the comparison that would earn it, and both
were recorded in docs/future-plan.md as reasoned from source rather than measured. Both
measured real:

    SecurityAssertion    fires on one arm, one response, and graded `confirmed` always.
                         The generic-404 control rules out a single-page application's
                         shell; nothing asked whether the content was gated at all.
                         Juice Shop returns /rest/products/1/reviews, author addresses
                         included, to admin, to jim and to nobody at all — an operator
                         asserting the customer must not see jim's email there got HIGH
                         verified, about content that is public.

    idor evaluator       fires `confirmed` when the marker is the caller's OWN input:
                         measured on `/rest/track-order/99999` answering
                         {"data":[{"orderId":"99999"}]}, and on DVWA's
                         `?name=Vulnerability%3A+Reflected`. The cross-arm check refuses
                         exactly this as its clause 0.

    idor evaluator       fires `confirmed` on a marker echoed into a response HEADER with
                         an empty record in the body — while the anonymous clause three
                         lines below reads the body and says why. The rule was applied to
                         the arm that can only refuse a finding, not to the arm that makes
                         one.

The rule all three now answer to is this repository's own, stated in `login._verify` and
again in `authenticate`: an assertion that holds WITHOUT the credential establishes
nothing.
"""
import pytest

from orchestrator.integrations.adapters import assertion_grade
from orchestrator.integrations.contracts import SecurityAssertion
from orchestrator.testcase.runner import StepResult, _run_evaluator
from orchestrator.testcase.schema import Evaluator
from orchestrator.testcase.schema import TestCase as CatalogueCase

URL = "http://localhost:3000/rest/products/1/reviews"
MARKER = "jim@juice-sh.op"


def declared(url=URL, marker=MARKER):
    return SecurityAssertion(identity_id="id-customer", forbidden_marker=marker,
                             description="the customer must not see another user's email",
                             request={"url": url, "expected_status": 200})


def answer(body, **overrides):
    return {"url": URL, "status": 200, "blocked": False, "body": body, **overrides}


# --------------------------------------------------------------- the operator's assertion


def test_an_assertion_is_graded_on_what_the_credential_changes():
    """The positive control for the grade: absent without the credential, so it is gated."""
    confidence, basis, caveat = assertion_grade(
        declared(), [answer('{"error":"unauthorized"}', status=401)] * 2)
    assert confidence == "confirmed", basis
    assert caveat is None
    assert "REFUTED with the identity dropped" in basis, basis


def test_content_returned_without_a_credential_is_not_an_authorization_finding():
    """The measured counter-example. Reported, because the operator declared the marker
    forbidden and it came back — but not as a verified access-control defect, because
    nothing was gated."""
    confidence, basis, caveat = assertion_grade(
        declared(), [answer(f'[{{"author":"{MARKER}"}}]')] * 2)
    assert confidence == "likely", basis
    assert caveat["type"] == "security_assertion_marker_is_public"
    assert "publishes it" in basis and "not a failure of authorization" in basis, basis


def test_one_identity_free_answer_carrying_the_marker_is_enough_to_withhold_confirmed():
    """Two samples, and the marker in EITHER of them withholds the grade. A target that
    answers non-deterministically must not be able to earn `verified` on a lucky fetch."""
    confidence, _, caveat = assertion_grade(
        declared(), [answer(f'[{{"author":"{MARKER}"}}]'), answer("[]")])
    assert confidence == "likely"
    assert caveat["type"] == "security_assertion_marker_is_public"


@pytest.mark.parametrize("control", [
    pytest.param(None, id="no control at all"),
    pytest.param([], id="an empty control"),
    pytest.param([{"blocked": True, "body": ""}] * 2, id="refused by our own proxy"),
    pytest.param([{"error": "timeout", "body": ""}] * 2, id="errored"),
])
def test_a_missing_control_is_not_a_pass(control):
    """The same answer `authenticate` gives with `control_unavailable`: a clause nobody ran
    is not a clause that passed. Our own refusal is emphatically not the target's answer —
    treating a blocked control as "gated" would award `verified` because erlik's proxy said
    no, which is this project's most-repeated defect."""
    confidence, basis, caveat = assertion_grade(declared(), control)
    assert confidence != "confirmed", (
        f"graded {confidence!r} from a control that established nothing: {control!r}")
    assert caveat["type"] == "security_assertion_control_unavailable"
    assert "nobody ran" in basis


def test_the_assertion_still_fires_whatever_the_grade():
    """Downgrading must not silence it. The operator declared the marker forbidden there
    and it was returned; that is worth a reader's time in all three outcomes."""
    for control in (None, [answer(f'[{{"author":"{MARKER}"}}]')] * 2,
                    [answer('{"error":"no"}', status=401)] * 2):
        confidence, basis, _ = assertion_grade(declared(), control)
        assert confidence in ("likely", "confirmed"), confidence
        assert basis.startswith("Explicit forbidden-content assertion reproduced"), basis


async def test_the_control_is_probed_with_no_identity_and_not_charged_to_the_operator():
    """`assertion_controls` is the only place the identity-free answer can come from, and
    its sandbox must carry NO identity — a control that carried the credential would agree
    with the arm it is supposed to contradict, and every assertion would grade `confirmed`
    again. Its URLs are declared as control URLs so erlik's own differential traffic does
    not consume the surface budget the operator asked for."""
    from orchestrator.integrations import service
    from orchestrator.integrations.contracts import AssessmentConfig

    seen = {}

    class _Sandbox:
        def __init__(self, config, identity, **kw):
            seen["identity"] = identity
            seen["control_urls"] = kw.get("control_urls")

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    async def _rpc(sandbox, payload):
        seen.setdefault("requests", []).append(payload)
        return answer('{"error":"unauthorized"}', status=401)

    import orchestrator.integrations.service as module
    original_sandbox, original_rpc = module.Sandbox, module.rpc
    module.Sandbox, module.rpc = _Sandbox, _rpc
    try:
        config = AssessmentConfig(
            scope={"allow_hosts": ["localhost"], "allow_ports": [3000]}, active=True,
            identity_ids=["id-customer"],
            security_assertions=[{"identity_id": "id-customer", "description": "d",
                                  "forbidden_marker": MARKER,
                                  "request": {"url": URL, "expected_status": 200}}])
        out = await service.assertion_controls("s", config)
    finally:
        module.Sandbox, module.rpc = original_sandbox, original_rpc

    assert seen["identity"] is None, (
        f"the control sandbox carried {seen['identity']!r}, so it is not a control")
    assert seen["control_urls"] == [URL], seen["control_urls"]
    assert len(out[URL]) == service.CONTROL_SAMPLES, out


async def test_two_arms_asserting_on_one_url_share_one_probe():
    """The answer is a property of the URL and the application, not of an arm — the reason
    `authentication_controls` gives for running once per assessment."""
    from orchestrator.integrations import service
    from orchestrator.integrations.contracts import AssessmentConfig
    import orchestrator.integrations.service as module

    calls = {"n": 0}

    class _Sandbox:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    async def _rpc(sandbox, payload):
        calls["n"] += 1
        return answer("[]")

    original_sandbox, original_rpc = module.Sandbox, module.rpc
    module.Sandbox, module.rpc = _Sandbox, _rpc
    try:
        config = AssessmentConfig(
            scope={"allow_hosts": ["localhost"], "allow_ports": [3000]}, active=True,
            identity_ids=["a", "b"],
            security_assertions=[
                {"identity_id": "a", "description": "d", "forbidden_marker": MARKER,
                 "request": {"url": URL, "expected_status": 200}},
                {"identity_id": "b", "description": "e", "forbidden_marker": MARKER,
                 "request": {"url": URL, "expected_status": 200}}])
        out = await service.assertion_controls("s", config)
    finally:
        module.Sandbox, module.rpc = original_sandbox, original_rpc
    assert calls["n"] == service.CONTROL_SAMPLES, (
        f"{calls['n']} requests for one URL across two arms")
    assert list(out) == [URL]


async def test_an_assessment_declaring_no_assertion_starts_no_container():
    from orchestrator.integrations import service
    from orchestrator.integrations.contracts import AssessmentConfig
    import orchestrator.integrations.service as module

    built = {"n": 0}

    class _Sandbox:
        def __init__(self, *a, **kw):
            built["n"] += 1

    original = module.Sandbox
    module.Sandbox = _Sandbox
    try:
        config = AssessmentConfig(scope={"allow_hosts": ["localhost"], "allow_ports": [3000]})
        assert await service.assertion_controls("s", config) == {}
    finally:
        module.Sandbox = original
    assert built["n"] == 0


# ------------------------------------------------------------------ the idor evaluator


def capture(body, headers="HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"):
    return headers + "\r\n" + body


def step(name, body, headers="HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"):
    return StepResult(step=name, command="curl -s -i", success=True,
                      output=capture(body, headers), duration_ms=1)


async def idor(marker, url, caller, baseline, anonymous='{"error":"unauthorized"}',
               caller_headers=None, baseline_headers=None, url_field="url"):
    ev = Evaluator(type="idor", baseline_step="fetch_as_high_priv",
                   anonymous_step="fetch_anonymously",
                   emit_finding={"vuln_type": "Broken Access Control", "severity": "high"})
    tc = CatalogueCase(id="WSTG-AUTHZ-04", name="idor", category="authz", severity="high", steps=[])
    target = {"private_object_marker": marker, url_field: url,
              "baseline_step": "fetch_as_high_priv",
              "low_priv_cookie": "PHPSESSID=low", "high_priv_cookie": "PHPSESSID=high"}
    prior = [step("fetch_as_high_priv", baseline, *( [baseline_headers] if baseline_headers else [])),
             step("fetch_anonymously", anonymous)]
    caller_step = step("fetch_as_low_priv", caller, *([caller_headers] if caller_headers else []))
    finding, *_ = await _run_evaluator(ev, caller_step, tc, target, None, None, prior)
    return finding


async def test_a_genuine_crossing_is_still_confirmed():
    """The positive control. Every refusal below is only meaningful because this fires."""
    finding = await idor(MARKER, "http://localhost:3000/api/Addresss/4",
                         f'{{"data":{{"email":"{MARKER}"}}}}',
                         f'{{"data":{{"email":"{MARKER}"}}}}')
    assert finding is not None and finding.confidence == "confirmed"


@pytest.mark.parametrize("marker,url", [
    pytest.param("99999", "http://localhost:3000/rest/track-order/99999", id="path segment"),
    pytest.param("Vulnerability: Reflected",
                 "http://localhost:8081/vulnerabilities/xss_r/?name=Vulnerability%3A+Reflected",
                 id="query, percent- and plus-encoded"),
])
async def test_a_marker_that_is_the_callers_own_input_is_not_a_crossing(marker, url):
    """The target would be supplying the evidence for its own verdict. `unquote_plus` for
    the second: a form-encoded marker carries `+` for space, which `unquote` leaves alone."""
    assert await idor(marker, url, f'{{"data":[{{"id":"{marker}"}}]}}',
                      f'{{"data":[{{"id":"{marker}"}}]}}') is None


async def test_a_reflected_marker_is_refused_from_a_url_template_too():
    """The access-control cases name their endpoint in `url_template`, and a marker
    reflected out of it is reflected just the same."""
    assert await idor("99999", "http://localhost:3000/rest/track-order/99999",
                      '{"data":[{"orderId":"99999"}]}', '{"data":[{"orderId":"99999"}]}',
                      url_field="url_template") is None


async def test_a_marker_echoed_into_a_header_is_not_disclosed_data():
    """The rule the anonymous clause already applied, now applied to the arm that MAKES a
    finding. The body here is an empty record."""
    echo = f"HTTP/1.1 200 OK\r\nX-Requested-User: {MARKER}\r\n"
    assert await idor(MARKER, "http://localhost:3000/profile",
                      '{"data":{}}', '{"data":{}}',
                      caller_headers=echo, baseline_headers=echo) is None


async def test_the_body_only_match_costs_no_true_positive_on_the_shipped_case():
    """`_http_status_ok` is already required of both arms and is False for a capture with no
    status line, so a case whose curl omits `-i` could never have fired anyway — which is
    what makes the body-only match free. Read out of the shipped case rather than asserted
    about it."""
    import pathlib
    import re

    case = pathlib.Path("tests_catalog/wstg/AUTHZ-04_idor.yaml").read_text()
    curls = re.findall(r"^\s*curl .*", case, re.M)
    assert curls, "the shipped idor case runs no curl; this test is vacuous"
    assert all("-i" in command for command in curls), (
        f"an arm captures no headers, so the body-only match would silence it: {curls}")

    from orchestrator.testcase.runner import _http_status_ok
    assert _http_status_ok('{"data":"no status line"}') is False


# ------------------------------------------- and the grade has to reach the finding itself


async def fired(monkeypatch, identity_free, body=f'[{{"author":"{MARKER}"}}]'):
    """Drive `assertion_findings` — the unit the adapter actually calls — with one arm."""
    from orchestrator.integrations import adapters
    from orchestrator.integrations.contracts import AssessmentConfig

    async def _rpc(sandbox, payload):
        url = payload["request"]["url"]
        if "erlik-control-" in url:
            # A path that cannot exist, answering differently from the asserted URL, so the
            # generic-response clause passes and the grade is what is under test.
            return {"url": url, "status": 404, "blocked": False, "body": "no such route"}
        return {"url": url, "status": 200, "blocked": False, "body": body}

    monkeypatch.setattr(adapters, "rpc", _rpc)
    config = AssessmentConfig(
        scope={"allow_hosts": ["localhost"], "allow_ports": [3000]}, active=True,
        identity_ids=["id-customer"],
        security_assertions=[{"identity_id": "id-customer", "description": "d",
                              "forbidden_marker": MARKER,
                              "request": {"url": URL, "expected_status": 200}}])
    ctx = adapters.Context("s", "stage", "http://localhost:3000/", config, "id-customer",
                           {"name": "customer"},
                           assertion_controls={URL: identity_free} if identity_free else None)
    return await adapters.assertion_findings(ctx, object())


async def test_the_finding_carries_the_grade_the_differential_earned(monkeypatch):
    """The defect was a constant `confidence="confirmed"` in this exact place, so a test
    that only exercises `assertion_grade` would not have noticed it coming back."""
    findings, _ = await fired(monkeypatch, [answer('{"error":"no"}', status=401)] * 2)
    assert [f.confidence for f in findings] == ["confirmed"], findings

    findings, _ = await fired(monkeypatch, [answer(f'[{{"author":"{MARKER}"}}]')] * 2)
    assert [f.confidence for f in findings] == ["likely"], (
        "the finding kept a grade the identity-free answer refuted")
    assert "publishes it" in findings[0].basis


async def test_a_finding_graded_on_no_control_says_so_in_the_stage_record(monkeypatch):
    """The grade alone is a word in a field. The caveat is what tells a reader WHY, and it
    has to reach the observations the report is built from."""
    findings, observations = await fired(monkeypatch, None)
    assert findings and findings[0].confidence == "likely"
    caveats = [o for o in observations
               if o["type"] == "security_assertion_control_unavailable"]
    assert caveats and caveats[0]["url"] == URL, observations


async def test_the_control_is_looked_up_by_the_asserted_url(monkeypatch):
    """A control for some other URL is not a control for this one. Without the lookup the
    arm would grade against whatever the dict happened to hold."""
    findings, observations = await fired(
        monkeypatch, None)
    assert findings[0].confidence == "likely"

    from orchestrator.integrations import adapters
    from orchestrator.integrations.contracts import AssessmentConfig

    async def _rpc(sandbox, payload):
        url = payload["request"]["url"]
        if "erlik-control-" in url:
            return {"url": url, "status": 404, "blocked": False, "body": "no such route"}
        return {"url": url, "status": 200, "blocked": False, "body": f'[{{"a":"{MARKER}"}}]'}

    monkeypatch.setattr(adapters, "rpc", _rpc)
    config = AssessmentConfig(
        scope={"allow_hosts": ["localhost"], "allow_ports": [3000]}, active=True,
        identity_ids=["id-customer"],
        security_assertions=[{"identity_id": "id-customer", "description": "d",
                              "forbidden_marker": MARKER,
                              "request": {"url": URL, "expected_status": 200}}])
    ctx = adapters.Context(
        "s", "stage", "http://localhost:3000/", config, "id-customer", {"name": "c"},
        assertion_controls={"http://localhost:3000/somewhere-else":
                            [answer('{"error":"no"}', status=401)] * 2})
    findings, observations = await adapters.assertion_findings(ctx, object())
    assert findings[0].confidence == "likely", (
        "another URL's control earned this one a verified grade")
    assert any(o["type"] == "security_assertion_control_unavailable" for o in observations)


async def test_a_partly_obtained_control_is_no_control():
    """Two samples are the control. One sample that came back and one that did not is a
    half-measurement, and `confirmed` must not rest on it."""
    from orchestrator.integrations import service
    from orchestrator.integrations.contracts import AssessmentConfig
    import orchestrator.integrations.service as module

    attempts = {"n": 0}

    class _Sandbox:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    async def _rpc(sandbox, payload):
        attempts["n"] += 1
        if attempts["n"] >= 2:
            raise RuntimeError("the second probe did not come back")
        return answer("[]")

    original_sandbox, original_rpc = module.Sandbox, module.rpc
    module.Sandbox, module.rpc = _Sandbox, _rpc
    try:
        config = AssessmentConfig(
            scope={"allow_hosts": ["localhost"], "allow_ports": [3000]}, active=True,
            identity_ids=["id-customer"],
            security_assertions=[{"identity_id": "id-customer", "description": "d",
                                  "forbidden_marker": MARKER,
                                  "request": {"url": URL, "expected_status": 200}}])
        out = await service.assertion_controls("s", config)
    finally:
        module.Sandbox, module.rpc = original_sandbox, original_rpc
    assert out == {}, (
        f"a control with {attempts['n'] - 1} of {service.CONTROL_SAMPLES} samples was kept: {out}")


async def test_the_run_hands_each_arm_the_identity_free_answers(tmp_path, monkeypatch):
    """The sweep and the grade are both right and the run can still never connect them.

    Replacing `run()`'s call with `{}` left every test above passing and every assertion
    graded `likely` with a control-unavailable caveat on a healthy assessment — a
    downgrade nobody would read as a bug.
    """
    import orchestrator.database as original
    from orchestrator.integrations import service
    from orchestrator.integrations.contracts import AssessmentConfig, StageResult
    from orchestrator.integrations.security import SecretStore

    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    from orchestrator.integrations import persistence
    await original.init_db()
    await persistence.migrate()

    sentinel = {URL: [answer('{"error":"no"}', status=401)] * 2}
    handed = {}

    class _Sandbox:
        def __init__(self, *a, **kw):
            self.policy = {}
            self.on_close = None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    class _Recorder:
        async def run(self, ctx, sandbox):
            handed["controls"] = ctx.assertion_controls
            return StageResult(status="completed")

    async def _noop(*a, **kw):
        return None

    async def _controls(session_id, config):
        return sentinel

    async def _auth(*a, **kw):
        return "authenticated"

    async def _auth_controls(session_id, config):
        return {"any": {"blocked": False, "status": 401, "body": ""}}

    monkeypatch.setattr(service, "Sandbox", _Sandbox)
    monkeypatch.setattr(service, "preflight", _noop)
    monkeypatch.setattr(service, "record", _noop)
    monkeypatch.setattr(service, "authenticate", _auth)
    monkeypatch.setattr(service, "authentication_controls", _auth_controls)
    monkeypatch.setattr(service, "assertion_controls", _controls)
    # Any adapter: the Context is built once per stage, before dispatch.
    monkeypatch.setitem(service.ADAPTERS, "katana", _Recorder())

    identity_id = SecretStore().put({
        "name": "customer", "target_origin": "http://localhost:3000",
        "check": {"url": "http://localhost:3000/me", "expected_status": 200,
                  "body_contains": "customer"}})
    config = AssessmentConfig(
        scope={"allow_hosts": ["localhost"], "allow_ports": [3000]}, active=True,
        stages=["katana"], surface_read=False, anonymous_arm=False,
        identity_ids=[identity_id],
        security_assertions=[{"identity_id": identity_id, "description": "d",
                              "forbidden_marker": MARKER,
                              "request": {"url": URL, "expected_status": 200}}])
    await service.register("a", "http://localhost:3000", config)
    await service.run("a")
    assert handed.get("controls") == sentinel, (
        f"the arm was handed {handed.get('controls')!r}, so every assertion would be graded "
        f"as though no control had been probed")
