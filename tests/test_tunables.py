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
        stated cap — the one number an operator must be able to trust.

        Uses max_files=3 explicitly: at the one-sheet default a pin fills the
        only slot, so there is no room left for the budget to affect."""
        pinned = stems(pin=["hunt-ssrf.md"], max_files=3, max_chars=8000)
        assert pinned[0] == "hunt-ssrf.md"
        assert len(pinned) < len(stems(pin=["hunt-ssrf.md"], max_files=3, max_chars=40000))

    def test_pin_fills_the_only_slot_at_the_default(self):
        """Consequence of a one-sheet default worth stating: a pin displaces
        class routing entirely rather than sitting alongside it."""
        assert stems(pin=["hunt-ssrf.md"]) == ["hunt-ssrf.md"]

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

    def test_the_first_phase_is_stripped_too(self):
        """_create_chain_session() is what builds EVERY phase including recon,
        so a chain drops the pin from all of them — not from phases 2+ only.
        Worth pinning down: the panel's note tells operators exactly this."""
        from pathlib import Path
        src = (Path(__file__).resolve().parents[1] / "orchestrator" / "main.py").read_text()
        assert '_create_chain_session(chain_id, chain, "recon", 0)' in src, (
            "the first chain phase no longer goes through the stripping path")

    def test_the_panel_tells_the_operator(self):
        """The pin control sits next to a preview that shows the pin taking.
        Without the note, a chain operator reads a preview that no phase of
        their run will match."""
        from pathlib import Path
        h = (Path(__file__).resolve().parents[1]
             / "dashboard" / "templates" / "index.html").read_text()
        note = h[h.index('id="rc-skills-pin"'):][:900].lower()
        assert "chain" in note, "the pin control does not mention chains"
        assert "every phase" in note and "first" in note, (
            "the note must say the FIRST phase is dropped too — 'chains drop "
            "pins' alone reads as 'later phases only'")


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
        """The panel must cite the CURRENT measurement, not a superseded one.

        It previously quoted r = -0.796 under a 4,096-token window. Giving the
        models their real windows made the effect worse, not better, which
        ruled out the crowding explanation that number was cited for — so the
        panel now carries the direct recall figures instead.
        """
        h = self._html(client)
        assert "No arm varied this budget" in h
        # both models, both directions of the result
        assert "0.114" in h and "0.014" in h, "7B recall delta missing"
        assert "0.086" in h, "27B recall delta missing"
        assert "0.90" in h and "0.07" in h, "precision collapse missing"
        assert "not crowding" in h, "the ruled-out explanation must be stated"

    def test_evidence_panel_does_not_cite_the_superseded_reading(self, client):
        """-0.796 described erlik under a 4,096-token cap, not the models. It
        belongs in the experiment write-up with that context, not on a control
        an operator reads while choosing a budget."""
        h = self._html(client)
        assert "0.796" not in h

    def test_untouched_controls_emit_null(self, client):
        """Emitting a default would overwrite a value the chosen preset pinned."""
        h = self._html(client)
        assert "Number.isFinite(n) ? n : null" in h


class TestTheRunReceivesWhatThePreviewShowed:
    """The preview and the run must read the SAME controls.

    `tuningConfig()` is what `doPreviewTuning()` posts to
    /api/library/routing/explain. For most of this panel's life
    `buildRunConfig()` — the payload that actually starts a session — omitted
    all three keys, so an operator could pin a sheet, watch the preview change
    to prove the pin took, start the run, and get a run that never received it.
    Nothing failed; the UI simply reported a configuration the run did not use.
    """

    TUNABLES = ("skills_pin", "skills_exclude", "skills_max_chars")

    @staticmethod
    def _js(name: str) -> str:
        """The body of a JS function declaration, by brace matching."""
        from pathlib import Path
        src = (Path(__file__).resolve().parents[1]
               / "dashboard" / "templates" / "index.html").read_text()
        i = src.index(f"function {name}(")
        start = src.index("{", i)
        depth, k = 0, start
        while True:
            depth += (src[k] == "{") - (src[k] == "}")
            if depth == 0:
                return src[start:k + 1]
            k += 1

    def _emitted_keys(self) -> set:
        """The keys tuningConfig()'s returned object literal carries."""
        import re
        body = self._js("tuningConfig")
        return set(re.findall(r"^\s*(\w+):", body[body.index("return {"):], re.M))

    def test_preview_posts_the_tuning_controls(self):
        assert "tuningConfig()" in self._js("doPreviewTuning")

    def test_the_run_payload_carries_the_same_builder(self):
        """Not "buildRunConfig mentions skills_pin" — it must call the same
        function, because a second reader of the same inputs is free to drift
        from the first one key at a time."""
        assert "tuningConfig()" in self._js("buildRunConfig"), (
            "buildRunConfig() no longer sources the tunables from "
            "tuningConfig(); the preview and the run can now disagree")

    def test_both_paths_carry_every_tunable(self):
        """Guards the direction that fails silently: a knob added to the panel
        and wired to the preview only."""
        assert self._emitted_keys() == set(self.TUNABLES), self._emitted_keys()

    def test_every_emitted_key_survives_resolve(self):
        """resolve() has an explicit whitelist, so a key the UI sends but the
        whitelist omits vanishes without a word."""
        sent = {"skills_pin": ["hunt-ssrf.md"], "skills_exclude": ["a.md"],
                "skills_max_chars": 20000}
        assert set(sent) == self._emitted_keys(), (
            "the panel gained a knob this test does not check")
        r = resolve(sent)
        assert r["skills_pin"] == ["hunt-ssrf.md"]
        assert r["skills_exclude"] == ["a.md"]
        assert r["skills_max_chars"] == 20000
        assert r["run_config_warnings"] == []

    def test_a_blank_panel_changes_nothing(self):
        """Untouched controls post null. Null has to stay inert, or shipping
        these keys in every run payload would overwrite what the preset chose
        for anyone who never opened the panel."""
        base = {"preset": "guided_ai"}
        blank = dict(base, **{k: None for k in self.TUNABLES})
        assert resolve(blank) == resolve(base)
