"""WSTG-AUTHZ-01 — Directory Traversal / Local File Include.

The catalogue had no case for this at all. DVWA's file-inclusion module is one
of its headline vulnerabilities and nothing targeted it; the only reason it
surfaced was INPV-19's `file://` probe, which catches it incidentally and
labels it SSRF.

Verified against the live container. Every probe tracks the security level,
which is what makes these controls rather than a demo:

    payload                                   low  medium  high  impossible
    /etc/passwd                               YES   YES     no      no
    ../../../../../etc/passwd  (depth >= 5)   YES   YES     no      no
    php://filter/...resource=index.php        YES   YES     no      no
"""

import pathlib
import re
import subprocess

import pytest
import yaml

CASE = pathlib.Path("tests_catalog/wstg/AUTHZ-01_directory_traversal.yaml")


@pytest.fixture(scope="module")
def case():
    return yaml.safe_load(CASE.read_text())


class TestTheCaseIsWellFormed:
    def test_it_is_registered_and_unique(self):
        seen = {}
        for p in pathlib.Path("tests_catalog/wstg").glob("*.yaml"):
            d = yaml.safe_load(p.read_text())
            assert d["id"] not in seen, f"duplicate id {d['id']} in {p} and {seen[d['id']]}"
            seen[d["id"]] = p
        assert "WSTG-AUTHZ-01" in seen

    def test_every_command_folds_to_one_line(self, case):
        """A YAML folded scalar KEEPS the newline on any line indented more
        than the first, and bash then reads the continuation as a new command.
        That is not theoretical: the first version of this case shipped four
        such steps and they failed with `curl: (2) no URL specified` and
        `-G: command not found` — while the step still reported success,
        because a shell error is not a test failure."""
        for step in case["steps"]:
            assert "\n" not in step["command"], (
                f"{step['name']} spans lines; bash will split it into separate "
                f"commands")

    def test_quotes_balance_in_every_command(self, case):
        for step in case["steps"]:
            assert step["command"].count("'") % 2 == 0, step["name"]
            assert step["command"].count('"') % 2 == 0, step["name"]

    def test_every_probe_carries_the_session(self, case):
        """An include sink is usually behind a login, and a probe without a
        cookie fetches the login form, matches nothing, and reports CLEAN.
        That false negative has been found three times in this catalogue —
        INPV-05, INPV-19, and INPV-15's profile entry — so it is the default
        here rather than an afterthought."""
        for step in case["steps"]:
            assert "{{cookie}}" in step["command"], step["name"]
        assert "cookie" in case["target_schema"]["optional"]


class TestItDemandsEvidenceOfRetrieval:
    """A PHP `Warning: include(...)` proves the parameter reached an include
    and nothing more — the file may not exist, the fetch may have failed.
    Matching on it would report CRITICAL for a sink that disclosed nothing."""

    def test_no_pattern_fires_on_a_failed_attempt(self, case):
        for step in case["steps"]:
            for ev in step.get("evaluators") or []:
                p = (ev.get("pattern") or "").lower()
                for bad in ("warning", "timed out", "failed to open",
                            "no such file"):
                    assert bad not in p, f"{step['name']}: {p!r} fires on failure"

    def test_the_patterns_match_real_disclosed_content(self, case):
        """Positive: the exact bytes DVWA returns."""
        pats = {s["name"]: [ev["pattern"] for ev in (s.get("evaluators") or [])
                            if ev.get("pattern")] for s in case["steps"]}
        assert any(re.search(p, "root:x:0:0:root:/root:/bin/bash")
                   for p in pats["absolute_path"])
        assert any(re.search(p, "ERLIK-LFI-TRAVERSAL depth=5 payload=../../../../../etc/passwd")
                   for p in pats["relative_traversal"])
        assert any(re.search(p, "ERLIK-LFI-SOURCE resource=index.php")
                   for p in pats["php_wrapper_source_disclosure"])

    def test_the_patterns_do_not_match_an_ordinary_page(self, case):
        """Negative: DVWA's own HTML, and its failure warning."""
        benign = ('<!DOCTYPE html><html><body>Vulnerability: File Inclusion'
                  '</body></html>')
        warning = ("<b>Warning</b>:  include(/etc/shadow): Failed to open "
                   "stream: Permission denied in <b>/var/www/html/</b>")
        for step in case["steps"]:
            for ev in step.get("evaluators") or []:
                p = ev.get("pattern")
                if not p:
                    continue
                assert not re.search(p, benign), f"{step['name']} fires on HTML"
                assert not re.search(p, warning), (
                    f"{step['name']} fires on a failed include")

    def test_every_finding_path_is_deterministic(self, case):
        """Ollama is often offline; a case whose verdict needs a model is not
        part of the deterministic lane."""
        emitters = [ev for s in case["steps"] for ev in (s.get("evaluators") or [])
                    if ev.get("emit_finding")]
        assert emitters
        assert all(ev["type"] == "regex" for ev in emitters)


class TestTheTraversalSweepsDepth:
    """The depth is a property of the TARGET, not the payload: the include
    resolves from the script's own directory. DVWA sits four levels down and
    needs five `../` — four returns nothing at all. Measured:

        depth 1-4  no disclosure
        depth 5-8  /etc/passwd

    A single hardcoded depth is how a real traversal gets reported as clean.
    """

    def test_it_tries_a_range_of_depths(self, case):
        cmd = next(s["command"] for s in case["steps"]
                   if s["name"] == "relative_traversal")
        assert "for d in 1 2 3 4 5 6 7 8" in cmd
        assert "depth=$d" in cmd, "the depth that worked is not reported"

    def test_the_loop_logic_finds_the_first_matching_depth(self, tmp_path):
        """Runs the real loop shape against a stub `curl` that only discloses
        at depth 5, exactly like DVWA."""
        stub = tmp_path / "curl"
        stub.write_text(
            '#!/bin/bash\n'
            'for a in "$@"; do case "$a" in *page=../../../../../etc/passwd)\n'
            '  echo "root:x:0:0:root:/root:/bin/bash"; exit 0;; esac; done\n'
            'echo "<html>not found</html>"\n')
        stub.chmod(0o755)
        d = yaml.safe_load(CASE.read_text())
        cmd = next(s["command"] for s in d["steps"]
                   if s["name"] == "relative_traversal")
        for k, v in (("{{submit}}", ""), ("{{cookie}}", "c"),
                     ("{{auth_header}}", ""), ("{{parameter}}", "page"),
                     ("{{url}}", "http://t/x")):
            cmd = cmd.replace(k, v)
        env = {"PATH": f"{tmp_path}:/usr/bin:/bin", "HOME": str(tmp_path)}
        out = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True,
                             env=env, timeout=60).stdout
        assert "ERLIK-LFI-TRAVERSAL depth=5" in out, out
        assert "depth=6" not in out, "it kept going after the first hit"

    def test_it_says_so_when_no_depth_works(self, tmp_path):
        """The negative half: a target with no sink must produce a legible
        'nothing worked', not silence that reads as a pass."""
        stub = tmp_path / "curl"
        stub.write_text('#!/bin/bash\necho "<html>nope</html>"\n')
        stub.chmod(0o755)
        d = yaml.safe_load(CASE.read_text())
        cmd = next(s["command"] for s in d["steps"]
                   if s["name"] == "relative_traversal")
        for k, v in (("{{submit}}", ""), ("{{cookie}}", "c"),
                     ("{{auth_header}}", ""), ("{{parameter}}", "page"),
                     ("{{url}}", "http://t/x")):
            cmd = cmd.replace(k, v)
        env = {"PATH": f"{tmp_path}:/usr/bin:/bin", "HOME": str(tmp_path)}
        r = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True,
                           env=env, timeout=60)
        assert "no traversal depth" in r.stdout
        assert "ERLIK-LFI-TRAVERSAL" not in r.stdout
        assert "command not found" not in r.stderr, r.stderr


class TestItIsWiredIntoTheSweep:
    def test_the_dvwa_profile_points_it_at_the_sink(self):
        from orchestrator.testcase.sweep import PROFILES
        assert PROFILES["dvwa"]["WSTG-AUTHZ-01"] == {
            "url": "{base}/vulnerabilities/fi/", "parameter": "page"}

    def test_it_plans_as_runnable_with_a_session(self):
        from orchestrator.testcase.sweep import plan_sweep
        c = {"id": "WSTG-AUTHZ-01", "name": "LFI", "category": "AUTHZ",
             "severity": "high",
             "target_schema": yaml.safe_load(CASE.read_text())["target_schema"]}
        plan = plan_sweep([c], "http://dvwa", "dvwa", extra={"cookie": "X"})
        assert plan["counts"]["runnable"] == 1, plan["skipped"]
        t = plan["runnable"][0]["target"]
        assert t["url"] == "http://dvwa/vulnerabilities/fi/"
        assert t["parameter"] == "page"
        assert t["cookie"] == "X"

    def test_the_overlap_with_the_ssrf_case_is_deliberate(self):
        """Both target the same DVWA sink and both should. `file://` through a
        URL-fetching sink is standard SSRF practice; a local PATH is distinctly
        LFI. The fixes differ, so a client needs both — but the payloads must
        not be the same, or one is just a duplicate of the other."""
        from orchestrator.testcase.sweep import PROFILES
        assert (PROFILES["dvwa"]["WSTG-AUTHZ-01"]["url"]
                == PROFILES["dvwa"]["WSTG-INPV-19"]["url"])
        # The COMMANDS, not the file text — both files discuss the overlap in
        # comments, and a check on raw text would fail on the explanation
        # rather than on the payloads.
        def cmds(path):
            return " ".join(s["command"] for s in
                            yaml.safe_load(pathlib.Path(path).read_text())["steps"])
        lfi = cmds(CASE)
        ssrf = cmds("tests_catalog/wstg/INPV-19_ssrf.yaml")
        assert "file://" not in lfi, (
            "the LFI case fires the SSRF case's payload; they would report the "
            "same thing twice")
        assert "php://filter" not in ssrf
        assert "php://filter" in lfi and "file://" in ssrf, (
            "each case must still carry its own distinctive payload")


class TestTheCapabilityRegistryTellsTheTruth:
    """`path` is labelled "Path Traversal / File Inclusion" and its only case
    was WSTG-INPV-15 — Hop-by-Hop Header Handling. So erlik advertised a
    path-traversal capability it did not have, and the catalogue had no case
    for the thing the label names. Both halves were wrong and they hid each
    other: the audit passed because every id existed and every case was
    claimed by someone.
    """

    def test_the_path_class_is_backed_by_a_traversal_case(self):
        from orchestrator import capabilities as C
        path = next(c for c in C.CLASSES if c["key"] == "path")
        assert "WSTG-AUTHZ-01" in path["wstg"]
        assert "WSTG-INPV-15" not in path["wstg"], (
            "hop-by-hop header handling is not path traversal")

    def test_the_smuggling_case_has_an_honest_home(self):
        """Its own WSTG reference points at 15-Testing_for_HTTP_Splitting_
        Smuggling, so that is what it is."""
        from orchestrator import capabilities as C
        sm = next((c for c in C.CLASSES if c["key"] == "smuggling"), None)
        assert sm, "WSTG-INPV-15 has nowhere truthful to live"
        assert sm["wstg"] == ["WSTG-INPV-15"]
        d = yaml.safe_load(
            pathlib.Path("tests_catalog/wstg/INPV-15_hop_by_hop_headers.yaml").read_text())
        assert d["attack_class"] == "smuggling"

    def test_every_class_key_routes(self):
        from orchestrator import capabilities as C
        assert set(c["key"] for c in C.CLASSES) <= C.routing_class_keys()

    def test_the_audit_is_clean_in_both_directions(self):
        from orchestrator import capabilities as C
        assert not any(C.audit().values()), C.audit()

    def test_a_traversal_hint_is_not_handed_an_upload_sheet(self):
        """`path`'s tokens listed `file-upload`, the only one of the three that
        matched a real sheet — so a traversal mission got a cheat-sheet about a
        different bug. Empty is the honest answer when no sheet exists."""
        from orchestrator.skills import select_skill_files
        got = [p.stem for p in select_skill_files("path traversal")]
        assert "hunt-file-upload" not in got, got
        # and the class that legitimately owns that sheet still gets it
        up = [p.stem for p in select_skill_files("unrestricted file upload")]
        assert "hunt-file-upload" in up, up
