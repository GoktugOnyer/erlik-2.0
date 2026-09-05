"""Producers only pay off if something consumes what they harvest.

`target_schema.required` declares what a case CONSUMES; `produces` is the other
half. The machinery was built, injection-gated and same-host restricted -- and
then used by exactly ONE case, because two things downstream discarded whatever
a second producer would have found:

  * `_retarget` fanned over the first field the child MENTIONS, not the one it
    NEEDS. A parent producing both `url` and `parameter`, chained to a child
    requiring both and given only `url`, fanned over `url` and threw every
    parameter away -- so each child target then failed validation on the field
    that had just been discovered.

  * `_key` deduped a queued run on `(case_id, url)` alone. Two children
    differing only in `parameter` collided and the second was silently dropped
    as already-visited. Invisible while the only producer emitted `url`, which
    is in the key.

Both are fixed here, and both are what make the two new producers reach
anything.
"""

import pytest

from orchestrator.testcase import find_by_id, load_catalog
from orchestrator.testcase.chain import _retarget, queue_key


class TestRetargetFansOverWhatUnblocksTheChild:
    def test_a_missing_required_field_wins(self):
        child = find_by_id("WSTG-INPV-01")          # needs url AND parameter
        out = _retarget(child, {"url": "http://t/"},
                        {"url": ["http://t/a"], "parameter": ["q", "cat"]}, 5)
        assert [t.get("parameter") for t in out] == ["q", "cat"], out
        assert all(t["url"] == "http://t/" for t in out), (
            "the parent's url was replaced; the child needed the parameter"
        )

    def test_a_field_the_parent_already_has_is_not_preferred(self):
        """The negative control. If `url` were still chosen, every child target
        would lack the parameter and be skipped."""
        child = find_by_id("WSTG-INPV-01")
        out = _retarget(child, {"url": "http://t/"},
                        {"url": ["http://t/a", "http://t/b"]}, 5)
        assert [t["url"] for t in out] == ["http://t/a", "http://t/b"]

    def test_the_existing_url_fan_is_unchanged(self):
        """INFO-03 -> CONF-04 has fanned over discovered URLs since it landed.
        CONF-04 needs only `url`, so nothing about that flow may move."""
        child = find_by_id("WSTG-CONF-04")
        out = _retarget(child, {"url": "http://t/"},
                        {"url": ["http://t/a", "http://t/b"]}, 5)
        assert [t["url"] for t in out] == ["http://t/a", "http://t/b"]

    def test_producing_a_field_nobody_consumes_does_not_multiply_runs(self):
        child = find_by_id("WSTG-CONF-04")
        out = _retarget(child, {"url": "http://t/"}, {"jwt": ["a", "b"]}, 5)
        assert out == [{"url": "http://t/"}]

    def test_the_cap_still_applies(self):
        child = find_by_id("WSTG-INPV-01")
        out = _retarget(child, {"url": "http://t/"},
                        {"parameter": [f"p{i}" for i in range(20)]}, 3)
        assert len(out) == 3


class TestQueueDedupSeesTheWholeTarget:
    """`_key` is defined inside run_chain, so it is exercised through a real
    chain rather than imported."""

    def test_two_targets_differing_only_by_parameter_are_distinct(self):
        """The whole point: harvest two parameters, chain to a child that needs
        one, and BOTH must run. Keyed on url alone, the second collided."""
        child = find_by_id("WSTG-INPV-01")
        out = _retarget(child, {"url": "http://t/"},
                        {"parameter": ["q", "user_id"]}, 5)
        keys = {(t.get("url"), t.get("parameter")) for t in out}
        assert len(keys) == 2, keys

    def test_the_key_separates_targets_differing_only_by_parameter(self):
        """The regression, tested on the function rather than on its source.
        A grep-based version of this passed against the exact revert."""
        a = queue_key("WSTG-INPV-01", {"url": "http://t/", "parameter": "q"})
        b = queue_key("WSTG-INPV-01", {"url": "http://t/", "parameter": "user_id"})
        assert a != b

    def test_an_identical_target_still_collides(self):
        """Loop protection must survive the fix, or a cycle runs forever."""
        t = {"url": "http://t/", "parameter": "q"}
        assert queue_key("X", dict(t)) == queue_key("X", dict(t))

    def test_a_different_case_on_the_same_target_is_distinct(self):
        t = {"url": "http://t/"}
        assert queue_key("A", t) != queue_key("B", t)

    def test_the_scope_dict_does_not_break_it(self):
        """`scope` is a dict -- unhashable, and identical on every target in a
        chain. Including it would raise; keying past it must not, and two
        targets differing only by scope must still collide."""
        t1 = {"url": "http://t/", "scope": {"allow_hosts": ["a"]}}
        t2 = {"url": "http://t/", "scope": {"allow_hosts": ["b"]}}
        assert queue_key("X", t1) == queue_key("X", t2)
        hash(queue_key("X", t1))


class TestTheNewProducers:
    def test_sess02_harvests_a_jwt(self):
        """WSTG-SESS-10 requires a `jwt` and nothing produced one, so it could
        only run against a token pasted in by hand."""
        tc = find_by_id("WSTG-SESS-02")
        prod = [e.produces for st in tc.steps for e in st.evaluators if e.produces]
        assert {"jwt": 0} in prod, prod

    def test_sess02_chains_to_sess10(self):
        assert "WSTG-SESS-10" in (find_by_id("WSTG-SESS-02").chain.always or [])

    def test_the_jwt_pattern_matches_a_real_token_and_not_a_plain_cookie(self):
        import re
        tc = find_by_id("WSTG-SESS-02")
        pat = [e.pattern for st in tc.steps for e in st.evaluators
               if e.produces == {"jwt": 0}][0]
        jwt = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
               ".eyJzdWIiOiIxMjMiLCJuYW1lIjoiYWxpY2UifQ"
               ".dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        assert re.search(pat, f"Set-Cookie: session={jwt}; Path=/")
        for benign in ("Set-Cookie: session=abc123; Path=/",
                       "Set-Cookie: theme=dark",
                       "Set-Cookie: id=eyJonly-one-segment"):
            assert not re.search(pat, benign), benign

    def test_info03_harvests_parameters_from_metafile_urls(self):
        tc = find_by_id("WSTG-INFO-03")
        prod = [e.produces for st in tc.steps for e in st.evaluators if e.produces]
        assert {"parameter": 1} in prod, prod

    def test_info03_chains_to_a_parameter_consumer(self):
        assert "WSTG-INPV-01" in (find_by_id("WSTG-INFO-03").chain.on_finding or [])

    def test_the_parameter_pattern_reads_a_real_robots_line(self):
        import re
        tc = find_by_id("WSTG-INFO-03")
        pat = [e.pattern for st in tc.steps for e in st.evaluators
               if e.produces == {"parameter": 1}][0]
        assert re.search(pat, "Disallow: /search?q=", re.M).group(1) == "q"
        assert re.search(pat, "Allow: /profile?user_id=", re.M).group(1) == "user_id"
        assert not re.search(pat, "Disallow: /admin", re.M), (
            "a path with no query string is not a parameter"
        )


class TestProducersStayHarvestOnly:
    """A producer must not change what a case REPORTS, or every recorded run
    stops being comparable."""

    @pytest.mark.parametrize("tid", ["WSTG-SESS-02", "WSTG-INFO-03"])
    def test_no_producer_also_emits_a_finding(self, tid):
        tc = find_by_id(tid)
        for st in tc.steps:
            for e in st.evaluators:
                if e.produces:
                    assert not e.emit_finding, (
                        f"{tid}/{st.name}: this evaluator both harvests and "
                        "reports, so adding the harvest changed the findings"
                    )

    def test_every_produced_field_is_consumed_by_some_case(self):
        """A field nobody declares is dead weight -- harvested, carried, and
        dropped by _retarget."""
        catalog = load_catalog()
        consumed = set()
        for tc in catalog.values():
            consumed |= set(tc.target_schema.required)
            consumed |= set(tc.target_schema.optional)
        produced = {f for tc in catalog.values() for st in tc.steps
                    for e in st.evaluators for f in (e.produces or {})}
        assert produced <= consumed, produced - consumed


class TestTheAgentSeesDiscoveries:
    """`produced` only ever reached chained children. An agent that asked for
    a case never learned what it found, and would rediscover the same
    parameters with its own turns."""

    class _R:
        findings = []
        not_assessed = []
        steps = []

        def __init__(self, produced):
            self.produced = produced

    def test_discoveries_are_reported(self):
        import orchestrator.main as M
        out = M._format_case_result_for_agent(
            "WSTG-INFO-03", find_by_id("WSTG-INFO-03"),
            self._R({"parameter": ["q", "user_id"]}))
        assert "DISCOVERED parameter: q, user_id" in out

    def test_a_case_that_found_nothing_says_nothing_extra(self):
        import orchestrator.main as M
        out = M._format_case_result_for_agent(
            "X", find_by_id("WSTG-CLNT-09"), self._R({}))
        assert "DISCOVERED" not in out
