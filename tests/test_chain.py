

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
                {"url": "http://t.example", "host": "t.example", "scope": {}},
                max_depth=3, max_runs=6))
        ran = [r.test_case_id for r in ch.runs]
        assert "WSTG-INFO-02" in ran
        assert "WSTG-INFO-03" in ran, f"the edge did not traverse: {ran}"
