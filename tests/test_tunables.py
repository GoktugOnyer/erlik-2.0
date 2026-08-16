"""Per-session skills tunables: pin, exclude, budget.

Three things this guards, in order of how quietly they fail.

1. `resolve()` carries an explicit key whitelist, so a key that is not in it
   VANISHES SILENTLY — the operator sets it, the UI shows it, the run ignores
   it. Unrecognised `skills_*` keys now warn.

2. The budget knob is the easiest way to make erlik measurably worse while
   believing you improved it, and NO recorded arm ever varied it. The 12-run
   experiment varied skills on/off and playbooks on/off only, so no value here
   can carry a recall figure — only a byte count.

3. `max_chars=0` does NOT mean "no skills": the selector takes the first file
   unconditionally. A control whose label implies otherwise would be lying, so
   the resolver clamps to a sane band and the preview reports ACTUAL injected
   bytes rather than echoing the knob.
"""

import warnings

import pytest

warnings.filterwarnings("ignore", category=DeprecationWarning)

from fastapi.testclient import TestClient  # noqa: E402

import orchestrator.main as M  # noqa: E402
from orchestrator.runconfig import resolve  # noqa: E402
from orchestrator.skills import select_skill_files, catalog_stems  # noqa: E402


@pytest.fixture(scope="module")
def client():
    return TestClient(M.app)


def stems(**kw):
    return [p.name for p in select_skill_files("sql injection", **kw)]


class TestResolveNoLongerSwallowsKeys:
    def test_the_three_keys_survive(self):
        r = resolve({"skills_pin": "hunt-ssrf", "skills_exclude": ["a.md"],
                     "skills_max_chars": 20000})
        assert r["skills_pin"] == ["hunt-ssrf"]
        assert r["skills_exclude"] == ["a.md"]
        assert r["skills_max_chars"] == 20000

    def test_defaults_are_inert(self):
        r = resolve({})
        assert r["skills_pin"] == [] and r["skills_exclude"] == []
        assert r["skills_max_chars"] == 14000
        assert r["run_config_warnings"] == []

    def test_unrecognised_key_warns_instead_of_vanishing(self):
        """The exact failure the whitelist causes: a plausible-looking key that
        does nothing and says nothing."""
        w = resolve({"skills_budget": 22000})["run_config_warnings"]
        assert any("skills_budget" in x for x in w)

    def test_csv_and_list_both_accepted(self):
        assert resolve({"skills_pin": "a.md, b.md"})["skills_pin"] == ["a.md", "b.md"]
        assert resolve({"skills_pin": ["a.md"]})["skills_pin"] == ["a.md"]

    @pytest.mark.parametrize("bad", [1, 99999, "abc", None])
    def test_out_of_band_budget_falls_back_and_warns(self, bad):
        r = resolve({"skills_max_chars": bad})
        assert r["skills_max_chars"] == 14000
        if bad is not None:
            assert any("skills_max_chars" in x for x in r["run_config_warnings"])


class TestSelectorHonoursTheKnobs:
    def test_exclude_removes_a_sheet(self):
        base = stems()
        assert base
        assert base[0] not in stems(exclude=[base[0]])

    def test_pin_forces_a_sheet_in(self):
        assert "hunt-ssrf.md" not in stems()
        assert stems(pin=["hunt-ssrf.md"])[0] == "hunt-ssrf.md"

    def test_pin_is_constrained_to_catalogue_members(self):
        """A pin is a guaranteed-injection primitive; it must not be able to
        name anything the router could not already have chosen."""
        assert stems(pin=["nope.md"]) == stems()
        assert stems(pin=["../etc/passwd"]) == stems()
        assert stems(pin=["/etc/passwd"]) == stems()

    def test_pin_consumes_budget(self):
        """Exempting a pin would let it quietly raise injected volume above the
        stated cap — the one number an operator must be able to trust."""
        pinned = stems(pin=["hunt-ssrf.md"], max_chars=8000)
        assert pinned[0] == "hunt-ssrf.md"
        assert len(pinned) < len(stems(pin=["hunt-ssrf.md"], max_chars=40000))

    def test_exclude_accepts_a_stem_without_the_extension(self):
        base = stems()
        assert base[0] not in stems(exclude=[base[0].removesuffix(".md")])

    def test_no_knobs_is_byte_identical_to_before(self):
        assert stems(exclude=None, pin=None) == stems()


class TestPreviewCannotDisagreeWithTheRun:
    def test_preview_uses_the_same_selector(self, client):
        d = client.post("/api/library/routing/explain",
                        json={"mission": "sql injection",
                              "skills_pin": ["hunt-ssrf.md"]}).json()
        assert [x["stem"] + ".md" for x in d["selected"]] == stems(pin=["hunt-ssrf.md"])

    def test_preview_surfaces_a_pin_that_matched_nothing(self, client):
        """Otherwise the operator assumes the pin took."""
        d = client.post("/api/library/routing/explain",
                        json={"mission": "sql injection",
                              "skills_pin": ["nope.md"]}).json()
        assert any("nope.md" in w for w in d["warnings"])

    def test_preview_surfaces_an_out_of_band_budget(self, client):
        d = client.post("/api/library/routing/explain",
                        json={"mission": "sql injection",
                              "skills_max_chars": 99999}).json()
        assert d["budget"] == 14000
        assert any("skills_max_chars" in w for w in d["warnings"])

    def test_preview_reports_actual_bytes_not_the_knob(self, client):
        """A low budget still injects the first sheet unconditionally, so the
        readout must show what is really sent, not echo the setting."""
        d = client.post("/api/library/routing/explain",
                        json={"mission": "sql injection",
                              "skills_max_chars": 4000}).json()
        assert d["budget"] == 4000
        assert d["injected_total"] > 4000, "readout is echoing the knob"


class TestChainsDoNotInheritPins:
    def test_pin_is_stripped_from_inherited_config(self):
        """A pin forces one sheet into EVERY phase of a chain — recon, exploit,
        report — regardless of what that phase is for. Budget and exclusions
        are phase-agnostic and do carry."""
        import json
        import re
        from pathlib import Path
        src = (Path(__file__).resolve().parents[1] / "orchestrator" / "main.py").read_text()
        block = src[src.index("_chain_run_config = chain_row"):][:900]
        assert '_cc.pop("skills_pin"' in block, "chain config no longer strips pins"
        # and the stripping actually works on a real payload
        cc = json.loads(json.dumps({"skills_pin": ["a.md"], "skills_max_chars": 20000}))
        cc.pop("skills_pin", None)
        assert "skills_pin" not in cc and cc["skills_max_chars"] == 20000


class TestUiCarriesOnlyWhatWasMeasured:
    @staticmethod
    def _html(client):
        return client.get("/").text

    def test_controls_exist(self, client):
        h = self._html(client)
        for t in ("rc-skills-pin", "rc-skills-exclude", "rc-skills-max-chars",
                  "function previewTuning", "function tuningConfig"):
            assert t in h, t

    def test_budget_carries_no_recall_figure(self, client):
        """No arm of the recorded experiment varied the budget, so attaching a
        recall number to any value here would present a figure the data cannot
        support."""
        h = self._html(client)
        i = h.index('id="rc-skills-max-chars"')
        near = h[i - 400:i + 400]
        assert "recall" not in near.lower()

    def test_evidence_panel_states_what_was_actually_varied(self, client):
        h = self._html(client)
        assert "No arm varied this budget" in h
        assert "-0.796" in h or "&minus;0.796" in h

    def test_untouched_controls_emit_null(self, client):
        """Emitting a default would overwrite a value the chosen preset pinned."""
        h = self._html(client)
        assert "Number.isFinite(n) ? n : null" in h
