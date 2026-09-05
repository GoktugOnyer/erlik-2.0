"""The API token must cover reads, not only writes.

`_api_token_guard` ran on POST/PUT/PATCH/DELETE only. A deployment that set
ERLIK_API_TOKEN was therefore protected against writes while every read stayed
open: /api/engagements (customer records), /api/v2/targets/credentials,
/api/findings, every report format, and /api/thesis/export, which returns nine
tables. An operator who set a token had every reason to believe the API was
closed.

The comparison was also `provided != token`, which leaks the length of the
matching prefix through timing -- a real oracle against a shared secret an
attacker can probe at will.

What this file does NOT assert is that the guard is on by default. It is not,
and SECURITY.md says so; making it fail closed is a breaking change for the
loopback workflow and belongs in its own change.
"""

import importlib
import inspect
import textwrap

import pytest
from fastapi.testclient import TestClient

TOKEN = "s3cr3t-token"


# ---------------------------------------------------------------------------
# A clean clone has no data/ directory at all -- it is gitignored -- so the
# DB-backed reads these tests probe raise `unable to open database file` rather
# than returning anything the guard could be judged on. CI caught exactly that.
# Point the module at a temporary database and create the schema, following the
# pattern already used in test_redaction.py. The subject here is the auth
# decision, but it has to be read off a route that actually works, or a passing
# assertion means only that the request failed for some other reason.
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _temp_db(tmp_path):
    import asyncio

    import orchestrator.database as db_mod
    old_path, old_dir = db_mod.DB_PATH, db_mod.DB_DIR
    db_mod.DB_DIR = tmp_path
    db_mod.DB_PATH = tmp_path / "auth.db"
    try:
        asyncio.run(db_mod.init_db())
        yield
    finally:
        db_mod.DB_PATH, db_mod.DB_DIR = old_path, old_dir

# Read routes that carry engagement, credential or finding data.
SENSITIVE_READS = [
    "/api/engagements",
    "/api/findings",
    "/api/sessions",
    "/api/thesis/export",
]


@pytest.fixture
def app_with_token(monkeypatch):
    monkeypatch.setenv("ERLIK_API_TOKEN", TOKEN)
    import orchestrator.main as M
    importlib.reload(M)
    yield M
    monkeypatch.delenv("ERLIK_API_TOKEN", raising=False)
    importlib.reload(M)


@pytest.fixture
def app_without_token(monkeypatch):
    monkeypatch.delenv("ERLIK_API_TOKEN", raising=False)
    import orchestrator.main as M
    importlib.reload(M)
    return M


class TestReadsAreCovered:
    @pytest.mark.parametrize("path", SENSITIVE_READS)
    def test_a_read_without_the_token_is_refused(self, app_with_token, path):
        r = TestClient(app_with_token.app).get(path)
        assert r.status_code == 401, (
            f"GET {path} served data with no token; setting ERLIK_API_TOKEN "
            "must not protect writes alone"
        )

    @pytest.mark.parametrize("path", SENSITIVE_READS)
    def test_the_same_read_succeeds_with_it(self, app_with_token, path):
        """The negative control: the guard must not simply break reads."""
        r = TestClient(app_with_token.app).get(path, headers={"X-API-Token": TOKEN})
        assert r.status_code != 401, r.text[:200]

    def test_writes_are_still_covered(self, app_with_token):
        r = TestClient(app_with_token.app).post("/api/sessions", json={})
        assert r.status_code == 401

    def test_both_header_forms_are_accepted(self, app_with_token):
        c = TestClient(app_with_token.app)
        assert c.get("/api/engagements",
                     headers={"X-API-Token": TOKEN}).status_code != 401
        assert c.get("/api/engagements",
                     headers={"Authorization": f"Bearer {TOKEN}"}).status_code != 401

    def test_a_wrong_token_is_refused(self, app_with_token):
        r = TestClient(app_with_token.app).get(
            "/api/engagements", headers={"X-API-Token": "wrong"})
        assert r.status_code == 401


class TestLivenessStaysOpen:
    def test_health_needs_no_token(self, app_with_token):
        """A load balancer must be able to probe it, and it discloses no
        engagement data -- only the provider name and whether Ollama answers."""
        r = TestClient(app_with_token.app).get("/api/health")
        assert r.status_code == 200

    def test_only_health_is_exempt(self, app_with_token):
        """Guard on the exemption list: if it ever grows, this fails and the
        addition has to be justified rather than slipped in."""
        assert app_with_token._UNAUTHENTICATED_PATHS == frozenset({"/api/health"})


class TestTheComparisonIsConstantTime:
    def test_hmac_compare_digest_is_used(self):
        """Checked against the CODE, not the docstring.

        The function's docstring quotes `provided != token` to explain why it
        was wrong, so asserting over the whole source finds the explanation and
        fails on the fix. Strip the docstring first.
        """
        import ast

        import orchestrator.main as M
        src = inspect.getsource(M._api_token_guard)
        tree = ast.parse(textwrap.dedent(src))
        fn = tree.body[0]
        if (fn.body and isinstance(fn.body[0], ast.Expr)
                and isinstance(fn.body[0].value, ast.Constant)):
            fn.body = fn.body[1:]          # drop the docstring
        code = ast.unparse(fn)

        assert "compare_digest" in code, (
            "a plain != on a secret leaks the matching prefix length through "
            "timing"
        )
        assert "provided != token" not in code


class TestNothingChangesWithoutAToken:
    """The guard stays inert when none is configured. This is the documented
    posture, not an oversight -- and it is what keeps the loopback workflow
    working."""

    @pytest.mark.parametrize("path", SENSITIVE_READS)
    def test_reads_are_open(self, app_without_token, path):
        r = TestClient(app_without_token.app).get(path)
        assert r.status_code != 401
