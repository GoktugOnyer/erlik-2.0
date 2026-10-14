"""Freeze-safe case tiering.

A new coverage case must not silently change what a recorded arm's prompt says.
`{case_catalogue}` is rendered from every YAML the loader globs, so dropping a
file into tests_catalog/wstg/ changes the prompt for every session -- including
the frozen ai_only/guided_ai arms. Tiering fixes that: a case is `tier: ext`
until `coverage_cases` is turned on, and until then it is invisible to the agent
in ALL THREE places that must agree -- the prompt catalogue, the runnable-id
list, and the run_case resolver.
"""

import orchestrator.main as M
# Aliased so pytest does not try to collect the pydantic models as test classes.
from orchestrator.testcase.schema import TestCase as _Case, TestStep as _Step

_STEP = [_Step(name="s", tool="curl", command="curl {{url}}")]
CORE = _Case(id="WSTG-CORE-01", name="Core case", category="X", steps=_STEP)
EXT = _Case(id="WSTG-EXT-99", name="Ext case", category="X", tier="ext",
            steps=_STEP)


class TestGatePredicate:
    def test_core_is_always_visible(self):
        assert M._case_gated_out(CORE, coverage_cases=False) is False
        assert M._case_gated_out(CORE, coverage_cases=True) is False

    def test_ext_is_hidden_until_coverage_is_on(self):
        assert M._case_gated_out(EXT, coverage_cases=False) is True
        assert M._case_gated_out(EXT, coverage_cases=False) is not False
        assert M._case_gated_out(EXT, coverage_cases=True) is False

    def test_a_case_with_no_tier_field_defaults_to_core(self):
        # Every case shipped before tiering has no `tier:` in its YAML.
        assert _Case(id="X", name="n", category="c", steps=_STEP).tier == "core"


class TestAgentFacingSurfacesAgree:
    """The prompt catalogue, the runnable ids and the resolver must show the
    SAME set, or the interface offers a case it will not run."""

    def _catalog(self, monkeypatch):
        monkeypatch.setattr(M, "load_catalog",
                            lambda: {CORE.id: CORE, EXT.id: EXT})

    def test_prompt_catalogue_hides_ext_when_off(self, monkeypatch):
        self._catalog(monkeypatch)
        off = M._case_catalogue_for_prompt(coverage_cases=False)
        assert CORE.id in off and EXT.id not in off

    def test_prompt_catalogue_shows_ext_when_on(self, monkeypatch):
        self._catalog(monkeypatch)
        on = M._case_catalogue_for_prompt(coverage_cases=True)
        assert CORE.id in on and EXT.id in on

    def test_runnable_ids_hide_ext_when_off(self, monkeypatch):
        self._catalog(monkeypatch)
        assert M._runnable_case_ids(coverage_cases=False) == [CORE.id]

    def test_runnable_ids_show_ext_when_on(self, monkeypatch):
        self._catalog(monkeypatch)
        assert set(M._runnable_case_ids(coverage_cases=True)) == {CORE.id, EXT.id}


class TestFreezeSafety:
    """Nothing SHIPPED today is hidden by the default (off), so the frozen-arm
    prompt is unchanged: every current case is core."""

    def test_no_currently_shipped_case_is_hidden_by_default(self):
        from orchestrator.testcase.loader import load_catalog
        shipped = load_catalog()
        assert shipped, "the catalogue is empty; this guard would be vacuous"
        runnable = set(M._runnable_case_ids(coverage_cases=False))
        hidden = [cid for cid in shipped if cid not in runnable]
        assert hidden == [], f"tiering hid shipped cases from the frozen arms: {hidden}"


def test_the_run_case_resolver_consults_the_gate():
    """Wiring guard: find_by_id has no tier check, so the handler must apply the
    gate itself, or a directly-named ext case runs with coverage off."""
    import pathlib
    src = (pathlib.Path(__file__).resolve().parents[1]
           / "orchestrator" / "main.py").read_text()
    # In the run_case action, after the case is resolved.
    assert "if _case_gated_out(tc, _cov):" in src
