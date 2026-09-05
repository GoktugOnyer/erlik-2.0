"""WSTG-CONF-02 must find a debug endpoint that is not a named platform's.

The case was thorough but organised entirely per PLATFORM: Spring's /actuator,
Apache's /server-status, PHP's /phpinfo.php, Symfony's /_profiler, Laravel's
/telescope, Werkzeug's console. An application that simply mounts /debug or
/status of its own matched none of them.

Found live: a target serving /debug with

    {"debug": true, "db": "postgres://app:hunter2@db.internal:5432/prod",
     "env": "production", "secret_key": "s3cr3t"}

Every existing step passed it clean.

WIDENING A PATH LIST IS THE EASY HALF. The hard half is not turning the case
into a false-positive generator: /status, /metrics and /health are ordinary
healthy paths, and plenty of apps answer 200 with an SPA shell for ANY path.
So none of these evaluators fire on reachability — each requires a signature of
actual disclosure. The controls below are the point of this file.
"""

import re

import pytest

from orchestrator.testcase.loader import find_by_id

CASE = "WSTG-CONF-02"
FLAGS = re.MULTILINE | re.IGNORECASE

LEAKS_CREDENTIALS = (
    '{"debug": true, "db": "postgres://app:hunter2@db.internal:5432/prod", '
    '"env": "production", "secret_key": "s3cr3t"}\n[erlik] 200 http://t/debug\n'
)
SPA_SHELL = "<html><div id=root></div><script src=/app.js></script></html>\n[erlik] 200 http://t/debug\n"
HEALTHY_STATUS = '{"ok": true, "uptime_s": 1234}\n[erlik] 200 http://t/status\n'
DOCS_NO_CREDENTIALS = "Set DATABASE_URL, e.g. postgres://localhost:5432/appdb\n[erlik] 200 http://t/\n"
GO_EXPVAR = '{"cmdline": ["/app/server"], "memstats": {"Alloc": 123}}\n'
PROMETHEUS = "# HELP http_requests_total Total\n# TYPE http_requests_total counter\nhttp_requests_total 5\n"


def _step():
    tc = find_by_id(CASE)
    assert tc is not None, f"{CASE} is not in the catalogue"
    for s in tc.steps:
        if s.name == "generic_debug_endpoints":
            return s
    pytest.fail(f"no generic debug step: {[s.name for s in tc.steps]}")


def _pattern(vuln_fragment):
    for e in _step().evaluators:
        if vuln_fragment.lower() in (e.emit_finding or {}).get("vuln_type", "").lower():
            return e.pattern
    pytest.fail(f"no evaluator emitting {vuln_fragment!r}")


class TestItReachesGenericPaths:
    def test_the_step_exists_and_probes_debug(self):
        cmd = _step().command
        for path in ("/debug", "/status", "/metrics"):
            assert path in cmd, f"{path} is not probed: {cmd}"

    def test_it_does_not_download_profiles(self):
        """/debug/pprof is requested as an index only. The profiles under it are
        large downloads, left alone for the same reason /heapdump is."""
        cmd = _step().command
        assert "/debug/pprof/heap" not in cmd
        assert "/debug/pprof/goroutine" not in cmd


class TestDisclosureNotReachability:
    """Each control here is a server that would break a naive 200-based check."""

    def test_an_inline_credential_is_critical(self):
        p = _pattern("Credentials Disclosed")
        assert re.search(p, LEAKS_CREDENTIALS, FLAGS)

    def test_an_spa_shell_answering_every_path_is_silent(self):
        for frag in ("Credentials Disclosed", "expvar", "pprof", "Prometheus"):
            assert not re.search(_pattern(frag), SPA_SHELL, FLAGS), frag

    def test_a_healthy_status_endpoint_is_silent(self):
        for frag in ("Credentials Disclosed", "expvar", "pprof", "Prometheus"):
            assert not re.search(_pattern(frag), HEALTHY_STATUS, FLAGS), frag

    def test_a_connection_string_without_credentials_is_silent(self):
        """Documentation naming postgres://host:port/db is not a disclosure.
        The pattern requires scheme://user:pass@ — an actual credential pair."""
        assert not re.search(_pattern("Credentials Disclosed"),
                             DOCS_NO_CREDENTIALS, FLAGS)


class TestTheSpecificSignatures:
    def test_go_expvar_needs_both_keys(self):
        p = _pattern("expvar")
        assert re.search(p, GO_EXPVAR, FLAGS)
        # Either key alone appears in ordinary JSON and must not be enough.
        assert not re.search(p, '{"cmdline": ["/app/server"]}', FLAGS)
        assert not re.search(p, '{"memstats": {"Alloc": 1}}', FLAGS)

    def test_prometheus_needs_the_exposition_format(self):
        p = _pattern("Prometheus")
        assert re.search(p, PROMETHEUS, FLAGS)
        assert not re.search(p, "# TYPE is a comment in this file\n", FLAGS)


class TestTheExistingPlatformChecksSurvive:
    def test_every_original_step_is_still_present(self):
        names = {s.name for s in find_by_id(CASE).steps}
        for original in ("actuator_index", "actuator_env_dump",
                         "webserver_status_handlers", "php_info_pages",
                         "dev_debug_consoles"):
            assert original in names, f"{original} was dropped"
