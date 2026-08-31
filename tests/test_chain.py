import pytest


class TestChainReferencesResolve:
    """The catalogue held three chain declarations and ZERO working edges.

    One pointed at `WSTG-INPV-05-WAF-BYPASS`, a case nobody ever wrote. One was
    an empty list. One targets a case that always skips for want of
    credentials. Nothing failed, because a chain reference to a case that does
    not exist is not a runtime error — the walker simply never traverses it, so
    the catalogue LOOKED like it had a methodology for as long as nobody
    checked.

    That is why the load-time check matters more than the three edges: it is
    the thing that would have caught this on the day it was written.
    """

    def test_no_case_chains_to_an_unknown_id(self):
        from orchestrator.testcase.loader import load_catalog, dangling_chain_refs
        assert dangling_chain_refs(load_catalog()) == {}

    def test_the_check_detects_a_dangling_reference(self):
        """Guard on the guard — a clean catalogue must not be clean vacuously."""
        from orchestrator.testcase.loader import dangling_chain_refs, load_catalog
        from orchestrator.testcase.schema import ChainRule
        cat = dict(load_catalog())
        victim = cat["WSTG-INFO-02"].model_copy(deep=True)
        victim.chain = ChainRule(always=["WSTG-DOES-NOT-EXIST"])
        cat["WSTG-INFO-02"] = victim
        assert dangling_chain_refs(cat) == {"WSTG-INFO-02": ["WSTG-DOES-NOT-EXIST"]}

    def test_chain_targets_sees_both_declaration_sites(self):
        """An edge can be declared on an EVALUATOR (chain_to) or on the case
        (chain.on_finding / chain.always). A checker that read only one would
        have missed the dangling one, which was on an evaluator."""
        from orchestrator.testcase.loader import load_catalog, chain_targets
        cat = load_catalog()
        assert "WSTG-ERRH-01" in chain_targets(cat["WSTG-INPV-05"])   # evaluator
        assert "WSTG-AUTHZ-04" in chain_targets(cat["WSTG-INPV-05"])  # chain block
        assert "WSTG-INFO-03" in chain_targets(cat["WSTG-INFO-02"])   # chain block

    def test_the_catalogue_has_at_least_one_traversable_edge(self):
        """Every declared edge used to be untraversable. At least one must now
        point at a case whose required fields a bare URL satisfies, or the
        walker is still untested by anything real."""
        from orchestrator.testcase.loader import load_catalog, chain_targets
        cat = load_catalog()
        traversable = [
            (cid, t) for cid, tc in cat.items() for t in chain_targets(tc)
            if t in cat and set(cat[t].target_schema.required) <= {"url", "host", "port"}
        ]
        assert traversable, "no chain edge can be traversed from a bare URL"

    def test_the_dead_reference_is_gone(self):
        import pathlib
        src = (pathlib.Path(__file__).resolve().parents[1] / "tests_catalog"
               / "wstg" / "INPV-05_sqli.yaml").read_text()
        assert "chain_to: [WSTG-INPV-05-WAF-BYPASS]" not in src

    def test_the_empty_always_list_is_gone(self):
        import pathlib
        src = (pathlib.Path(__file__).resolve().parents[1] / "tests_catalog"
               / "wstg" / "INFO-02_fingerprint.yaml").read_text()
        assert "always: []" not in src


class TestTheWalkerActuallyWalks:
    def test_a_chain_runs_more_than_the_root(self):
        """Behavioural, with execution mocked: before this change every chain
        run in erlik's history was one case long."""
        import asyncio
        from unittest.mock import patch
        from orchestrator.testcase.chain import run_chain

        async def fake_exec(*a, **k):
            return {"success": True, "output": "Server: nginx\nDisallow: /admin\n",
                    "error": None}

        with patch("orchestrator.testcase.runner.execute_tool", fake_exec):
            ch = asyncio.run(run_chain(
                "WSTG-INFO-02",
                {"url": "http://t.example", "host": "t.example",
                 "scope": {"allow_hosts": ["t.example"], "allow_ports": [80]}},
                max_depth=3, max_runs=6))
        ran = [r.test_case_id for r in ch.runs]
        assert "WSTG-INFO-02" in ran
        assert "WSTG-INFO-03" in ran, f"the edge did not traverse: {ran}"


class TestParentsRetargetChildren:
    """Before this, `run_chain`'s own docstring said "the same target dict flows
    into every chained test case" — a parent physically could not tell a child
    where to look. That is the deterministic half of the "cannot reach the
    endpoint" bottleneck measured in the agent lane.

    Now a parent that declares `produces:` fans each child out, once per
    discovered value.
    """

    ROBOTS = "User-agent: *\nDisallow: /admin\nDisallow: /backup\nDisallow: /ftp\n"

    @staticmethod
    def _run(root, output, **kw):
        import asyncio
        from unittest.mock import patch
        from orchestrator.testcase.chain import run_chain

        async def fake_exec(*a, **k):
            return {"success": True, "output": output, "error": None}

        with patch("orchestrator.testcase.runner.execute_tool", fake_exec):
            return asyncio.run(run_chain(
                root,
                {"url": "http://t.example", "host": "t.example",
                 # A real scope. An EMPTY one authorises nothing, and the
                 # runner scope-checks every command before executing it — so
                 # with `scope: {}` the step is refused and the mocked executor
                 # is never reached. The safety floor working is what made this
                 # fixture look like a broken fan-out.
                 "scope": {"allow_hosts": ["t.example"], "allow_ports": [80]}},
                max_depth=2, **kw))

    def test_one_child_run_per_discovered_value(self):
        ch = self._run("WSTG-INFO-03", self.ROBOTS, max_runs=12)
        targets = sorted(r.target["url"] for r in ch.runs
                         if r.test_case_id == "WSTG-CONF-04")
        assert targets == ["http://t.example/admin", "http://t.example/backup",
                           "http://t.example/ftp"], targets

    def test_siblings_are_not_dropped_by_the_visited_set(self):
        """A visited set keyed on the case ID alone would run the first fanned
        child and silently discard the rest — the fan-out would look like it
        worked and produce one run."""
        ch = self._run("WSTG-INFO-03", self.ROBOTS, max_runs=12)
        assert len([r for r in ch.runs if r.test_case_id == "WSTG-CONF-04"]) == 3

    def test_a_child_that_consumes_nothing_produced_keeps_the_parent_target(self):
        from orchestrator.testcase.chain import _retarget
        from orchestrator.testcase.loader import find_by_id
        parent = {"url": "http://t.example"}
        got = _retarget(find_by_id("WSTG-CONF-04"), parent,
                        {"jwt": ["a", "b"]}, 10)
        assert got == [parent], "fanned out over a field the child never declared"

    def test_producing_a_field_nobody_consumes_does_not_multiply_work(self):
        from orchestrator.testcase.chain import _retarget
        from orchestrator.testcase.loader import find_by_id
        got = _retarget(find_by_id("WSTG-CONF-04"), {"url": "http://t.example"},
                        {"endpoint": ["/a", "/b", "/c"]}, 10)
        assert len(got) == 1

    def test_fan_out_is_capped(self):
        from orchestrator.testcase.chain import _retarget
        from orchestrator.testcase.loader import find_by_id
        many = {"url": [f"http://t.example/p{i}" for i in range(50)]}
        got = _retarget(find_by_id("WSTG-CONF-04"), {"url": "http://t.example"},
                        many, 5)
        assert len(got) == 5

    def test_max_runs_still_bounds_the_whole_chain(self):
        ch = self._run("WSTG-INFO-03", self.ROBOTS, max_runs=2)
        assert len(ch.runs) <= 2
        assert ch.stopped_reason and "max_runs" in ch.stopped_reason


class TestAProducedUrlCannotLeaveTheTarget:
    """sitemap.xml is written by the target. `<loc>https://evil.example/</loc>`
    in a customer's sitemap must never become a URL erlik connects to — that
    would be scanning a third party nobody authorised, sourced from a file the
    target controls."""

    @pytest.mark.parametrize("value", [
        "https://evil.example/", "//evil.example/x", "http://evil.example:80/",
        "javascript:alert(1)", "data:text/html,x", "file:///etc/passwd",
        "http://t.example:9999/x",
    ])
    def test_off_target_values_are_refused(self, value):
        from orchestrator.testcase.runner import _resolve_url
        assert _resolve_url(value, "http://t.example") is None, value

    @pytest.mark.parametrize("value,expected", [
        ("/admin", "http://t.example/admin"),
        ("http://t.example/x", "http://t.example/x"),
        ("../up", "http://t.example/up"),
    ])
    def test_same_target_values_resolve(self, value, expected):
        from orchestrator.testcase.runner import _resolve_url
        assert _resolve_url(value, "http://t.example") == expected

    def test_a_sitemap_full_of_other_hosts_produces_nothing(self):
        import re
        from orchestrator.testcase.runner import _harvest
        from orchestrator.testcase.schema import Evaluator
        xml = ("<urlset><loc>https://evil.example/a</loc>"
               "<loc>https://cdn.other/b</loc></urlset>")
        ev = Evaluator(type="regex", pattern=r"<loc>\s*([^<\s]+)\s*</loc>",
                       produces={"url": 1})
        got = _harvest(ev, xml, re.MULTILINE, {"url": "http://t.example"})
        assert got == {}

    def test_with_no_base_url_nothing_is_produced(self):
        """Refusing to resolve is the safe default: a produced URL with no
        target to check it against cannot be shown to be in scope."""
        import re
        from orchestrator.testcase.runner import _harvest
        from orchestrator.testcase.schema import Evaluator
        ev = Evaluator(type="regex", pattern=r"^Disallow:\s*(\S+)",
                       produces={"url": 1})
        assert _harvest(ev, "Disallow: /a\n", re.MULTILINE, {}) == {}


class TestDetectionIsUnchanged:
    def test_info_03_still_reports_what_it_always_did(self):
        """The producers were added as SEPARATE evaluators so the detection
        patterns are untouched and every recorded run stays comparable."""
        from orchestrator.testcase.loader import find_by_id
        tc = find_by_id("WSTG-INFO-03")
        robots = next(s for s in tc.steps if s.name == "robots")
        detectors = [e for e in robots.evaluators if e.emit_finding]
        assert len(detectors) == 1
        assert detectors[0].pattern == '^Disallow:|^Allow:|^Sitemap:|^User-agent:'
        assert detectors[0].produces is None, "a detector was turned into a producer"

    def test_the_producers_emit_no_findings(self):
        from orchestrator.testcase.loader import find_by_id
        tc = find_by_id("WSTG-INFO-03")
        for step in tc.steps:
            for e in step.evaluators:
                if e.produces:
                    assert e.emit_finding is None, (
                        "a producing evaluator also reports a finding — it would "
                        "double-count what the detector already reports")
