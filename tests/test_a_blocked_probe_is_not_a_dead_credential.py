"""Erlik's own refusal, read as an expired credential, halted a whole assessment.

Found by the first REAL three-arm run through `service.run()` — not by a unit test, because
the defect lives in the interaction between two budgets and only appears at scale.

    katana, admin arm   needs_auth   "authentication expired during stage; results are
                                      incomplete"
    every other stage   queued

The admin arm crawled 63 endpoints of Juice Shop under `max_urls=60`. The stage's CLOSING
liveness check was then the 61st distinct URL, so the proxy refused it with
`X-Erlik-Blocked: true / URL budget exhausted`; `satisfies` opens with
`not response["blocked"]`, so the refusal read as a failed assertion; and the stage was
recorded as an expired credential. The evidence says so plainly:

    authentication-check     blocked=False status=200 body='{"user":{"id":1,"email":"admin@…'
    authentication-control   blocked=False status=200 body='{"user": {}}'
    authentication-check     blocked=True  status=403 body='X-Erlik-Blocked: true\\nURL budget…'

Then `run()` broke out of the stage loop, so one arm's budget exhaustion cost the other
identity AND the anonymous arm — which has no credential that could expire.

This is the same defect as the blocked CONTROL fixed one increment earlier, sitting one line
above it. Two fixes: a blocked probe is its own verdict, and erlik's own liveness traffic no
longer spends the operator's URL budget.
"""
import pytest

from orchestrator.integrations import service as svc
from orchestrator.integrations.contracts import Identity
from orchestrator.integrations.egress_policy import budget_refusal

BLOCKED = {"blocked": True, "status": 403,
           "body": "X-Erlik-Blocked: true\nURL budget exhausted\n"}
LIVE = {"blocked": False, "status": 200, "body": '{"email":"jim@app.test"}'}
ANON = {"blocked": False, "status": 401, "body": "UnauthorizedError"}


def identity():
    return Identity.model_validate({
        "name": "arm", "target_origin": "http://app.test",
        "headers": {"Authorization": "Bearer live-token"},
        "check": {"url": "http://app.test/me", "body_contains": "jim@app.test"}}).model_dump()


class Ctx:
    def __init__(self, identity):
        self.session_id, self.stage_id, self.identity, self.known = "s", "st", identity, ()


@pytest.fixture
async def lane(tmp_path, monkeypatch):
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()
    return db


# ------------------------------------------------------------------ the verdict

async def test_a_probe_the_proxy_refused_is_not_a_dead_credential(lane, monkeypatch):
    async def rpc(sandbox, request):
        return BLOCKED
    monkeypatch.setattr(svc, "rpc", rpc)
    controls = {svc.check_key(identity()["check"]): [ANON, ANON]}
    assert await svc.authenticate(Ctx(identity()), None, controls) == "probe_refused"


async def test_a_probe_that_errored_is_not_a_dead_credential(lane, monkeypatch):
    async def rpc(sandbox, request):
        return {"error": "connect timeout", "status": 0, "body": "", "blocked": False}
    monkeypatch.setattr(svc, "rpc", rpc)
    controls = {svc.check_key(identity()["check"]): [ANON, ANON]}
    assert await svc.authenticate(Ctx(identity()), None, controls) == "probe_refused"


async def test_a_real_rejection_is_still_a_dead_credential(lane, monkeypatch):
    """The positive control. The application answering 401 IS evidence about the credential,
    and must still be resumable."""
    async def rpc(sandbox, request):
        return ANON
    monkeypatch.setattr(svc, "rpc", rpc)
    controls = {svc.check_key(identity()["check"]): [ANON, ANON]}
    assert await svc.authenticate(Ctx(identity()), None, controls) == "needs_auth"
    assert svc.AUTH_OUTCOMES["needs_auth"][0] == "needs_auth"


def test_probe_refused_does_not_tell_the_operator_to_replace_credentials():
    status, reason = svc.AUTH_OUTCOMES["probe_refused"]
    assert status != "needs_auth", "resuming would hit the same refusal"
    assert "refused by the assessment proxy" in reason
    assert "budget" in reason, "the reason must name the thing the operator can change"


# -------------------------------------------------- the budget, which caused it

def test_erliks_own_liveness_probe_does_not_spend_the_url_budget():
    """`max_urls` bounds how much of the TARGET an assessment explores. One declared,
    already scope-checked URL probed for liveness is not exploration."""
    config = {"max_urls": 2, "max_requests": 100, "control_urls": ["http://app.test/me"]}
    at_ceiling = {("GET", "http://app.test/1"), ("GET", "http://app.test/2"),
                  ("GET", "http://app.test/me")}
    assert budget_refusal(config, 3, at_ceiling, "http://app.test/me") == ""
    assert budget_refusal(config, 3, at_ceiling, "http://app.test/2") == ""


def test_the_liveness_probe_survives_a_budget_THE_CRAWL_ALREADY_EXHAUSTED():
    """The measured failure exactly: katana discovered 63 endpoints under `max_urls=60`, so
    by the time the closing liveness check ran the target budget was already over. Excluding
    control URLs from the COUNT is not enough — the control request itself must be allowed
    through a ceiling the crawl has already broken."""
    config = {"max_urls": 2, "max_requests": 100, "control_urls": ["http://app.test/me"]}
    crawled_past_it = {("GET", f"http://app.test/{n}") for n in range(5)}
    assert budget_refusal(config, 6, crawled_past_it, "http://app.test/me") == "", (
        "the liveness probe is refused after the crawl has spent the budget, which is how a "
        "working credential was reported expired")
    # And a target URL at that point is still refused, which is the budget doing its job.
    assert budget_refusal(config, 6, crawled_past_it,
                          "http://app.test/4") == "URL budget exhausted"


def test_the_url_budget_still_bounds_the_target():
    config = {"max_urls": 2, "max_requests": 100, "control_urls": ["http://app.test/me"]}
    over = {("GET", f"http://app.test/{n}") for n in range(3)}
    assert budget_refusal(config, 3, over, "http://app.test/2") == "URL budget exhausted"


def test_a_control_url_still_counts_against_the_request_budget():
    """Exempting the ceiling must not exempt the rate. An unbounded stream of requests to one
    URL is still a flood."""
    config = {"max_urls": 500, "max_requests": 10, "control_urls": ["http://app.test/me"]}
    assert budget_refusal(config, 11, set(), "http://app.test/me") == "request budget exhausted"


def test_a_control_url_is_not_a_scope_exemption():
    """It is exempt from a BUDGET, not from the policy. Scope is checked separately and
    `preflight` already holds each check URL to it."""
    import inspect
    source = inspect.getsource(budget_refusal)
    assert "scope" not in source.replace("scope-checked", ""), (
        "budget_refusal must not make scope decisions")


def test_the_declared_check_urls_reach_the_proxy_policy():
    """Otherwise the exemption above can never apply — the proxy would not know which URL is
    erlik's own."""
    from orchestrator.integrations.contracts import AssessmentConfig
    from orchestrator.integrations.runtime import Sandbox

    config = AssessmentConfig(scope={"allow_hosts": ["app.test"], "allow_ports": [80]})
    sandbox = Sandbox(config, None, control_urls=["http://app.test/me"])
    assert sandbox.policy["control_urls"] == ["http://app.test/me"]


# --------------------------------------------------- and the run must not halt

async def test_the_run_does_not_halt_when_only_the_CLOSING_check_was_refused(
        tmp_path, monkeypatch):
    """One arm's budget exhaustion cost every other arm, including the anonymous one. The
    stage's own work is finished by then, so `partial` keeps the results and the run."""
    import orchestrator.database as original
    from orchestrator.integrations import persistence as db
    from orchestrator.integrations import service
    from orchestrator.integrations.contracts import AssessmentConfig
    from orchestrator.integrations.security import SecretStore

    monkeypatch.setenv("ERLIK_INTEGRATION_DATA", str(tmp_path / "runtime"))
    monkeypatch.setattr(original, "DB_DIR", tmp_path)
    monkeypatch.setattr(original, "DB_PATH", tmp_path / "test.db")
    await original.init_db()
    await db.migrate()

    class _Sandbox:
        def __init__(self, *a, **kw):
            self.policy, self.on_close, self.assessment_context = {}, None, None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    async def _noop(*a, **kw):
        return None

    calls = {"n": 0}

    async def authenticate(ctx, sandbox, controls=None):
        # Live on entry, refused by our own proxy on the way out.
        calls["n"] += 1
        return "authenticated" if calls["n"] % 2 == 1 else "probe_refused"

    async def controls(session_id, config):
        return {}

    monkeypatch.setattr(service, "Sandbox", _Sandbox)
    monkeypatch.setattr(service, "preflight", _noop)
    monkeypatch.setattr(service, "record", _noop)
    monkeypatch.setattr(service, "authenticate", authenticate)
    monkeypatch.setattr(service, "authentication_controls", controls)

    handle = SecretStore().put(identity())
    config = AssessmentConfig(scope={"allow_hosts": ["app.test"], "allow_ports": [80]},
                              stages=["katana"], identity_ids=[handle])
    await db.execute("INSERT INTO sessions(id,target_url,status) VALUES(?,?,?)",
                     ("s", "http://app.test/", "queued"))

    class _Katana:
        async def run(self, ctx, sandbox):
            from orchestrator.integrations.contracts import StageResult
            return StageResult(status="completed")

    monkeypatch.setitem(service.ADAPTERS, "katana", _Katana())
    await service.register("s", "http://app.test/", config)
    status = await service.run("s")

    rows = await db.rows("SELECT identity_id,status,reason FROM integration_stages "
                         "WHERE session_id='s' ORDER BY rowid")
    by_arm = {("anonymous" if r["identity_id"] == "anonymous" else "identity"): r
              for r in rows}
    assert by_arm["identity"]["status"] == "partial", by_arm["identity"]["reason"]
    assert "could not be confirmed" in by_arm["identity"]["reason"]
    assert by_arm["anonymous"]["status"] == "completed", (
        "the anonymous arm has no credential that could expire and must not be held back")
    assert status != "needs_auth"
