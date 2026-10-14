"""The warm-start experiment cannot be RUN here (no orchestrator/Ollama/target),
but its VALIDITY can be checked statically: the two measured arms must differ in
exactly one lever, both must pin the recorded inference path, and the seed must
be configured to actually harvest. A confound here would silently invalidate the
result the same way `9 of the 29` outlived a grown catalogue.
"""

import importlib.util
import pathlib


def _load():
    p = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "warm_start_experiment.py"
    spec = importlib.util.spec_from_file_location("wse", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class TestWarmStartExperimentIsValid:
    def test_the_two_arms_differ_only_in_learned_playbooks(self):
        m = _load()
        off, on = m.MEASURE_ARMS["learned_off"], m.MEASURE_ARMS["learned_on"]
        diff = {k for k in set(off) | set(on) if off.get(k) != on.get(k)}
        assert diff == {"learned_playbooks"}, diff
        assert off["learned_playbooks"] is False
        assert on["learned_playbooks"] is True

    def test_both_arms_pin_the_recorded_inference_path(self):
        m = _load()
        for name, arm in m.MEASURE_ARMS.items():
            assert arm["provider"] == "ollama", name
            assert arm["safe_mode"] is True, name

    def test_the_seed_is_configured_to_harvest(self):
        m = _load()
        # harvest only sees verified+confirmed findings, which need poc_verify,
        # and only runs when learned_playbooks is on.
        assert m.SEED_CFG["learned_playbooks"] is True
        assert m.SEED_CFG["poc_verify"] is True
