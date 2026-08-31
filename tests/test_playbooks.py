"""Exploit playbooks must work on a target that is not Juice Shop.

THE DEFECT THIS GUARDS

`playbooks.py` held six playbooks naming OWASP Juice Shop's exact endpoints —
`POST /profile/image/url`, `GET /redirect?to=`, `PUT /api/Users/:id`. Five of
the six run presets, including the DEFAULT one, set `playbooks: "juiceshop"`.
So an operator pointing erlik at a client target got ~9 KB of instructions to
attack paths that do not exist there, presented as if they did.

Two properties are tested, and they pull in opposite directions:

  * GENERIC playbooks must not assert any path. What transfers between targets
    is how to RECOGNISE a shape, not where it was last seen.
  * The Juice Shop endpoints must still be reachable, because every recorded
    experiment ran with them. They moved to `playbook_catalog/juiceshop.yaml`
    and are now selected by name.

Size is a correctness property here, not tidiness: injected guidance costs
recall dose-dependently (measured 0.1429 / 0.0857 / 0.0714 / 0.0428 for
0/1/2/3 sheets), and `playbook_only` scored 0.1143 against `none` at 0.1429 —
the old block cost recall even on the target it was written for.
"""

import pathlib
import re

import pytest

from orchestrator import playbooks as P
from orchestrator import runconfig

SRC = (pathlib.Path(__file__).resolve().parents[1] / "orchestrator" / "playbooks.py")

# Paths that exist only in Juice Shop. Any of these in a GENERIC playbook means
# the target-specific text leaked back into the default path.
JUICESHOP_ONLY = [
    "/profile/image/url", "/redirect?to=", "/file-upload", "/api/Users/",
    "/rest/products", "/ftp", "juice-shop", "/#/", "/rest/user/login",
]


class TestGenericPlaybooksNameNoTarget:
    def test_no_juiceshop_path_survives_in_generic_text(self):
        blob = "\n".join(P.GENERIC.values()).lower()
        leaked = [p for p in JUICESHOP_ONLY if p.lower() in blob]
        assert leaked == [], f"target-specific paths in generic playbooks: {leaked}"

    def test_generic_playbooks_are_not_empty(self):
        """Guard on the guard — the test above passes trivially on empty text."""
        assert len(P.GENERIC) >= 6
        for k, v in P.GENERIC.items():
            assert len(v) > 200, f"{k} is too short to be useful: {len(v)}"

    def test_each_playbook_says_how_to_confirm(self):
        """A playbook that only lists payloads produces unverified findings —
        which on a real engagement is a wrong client deliverable."""
        for k, v in P.GENERIC.items():
            assert re.search(r"confirms? when|not a finding", v, re.I), k

    def test_each_playbook_says_what_is_NOT_a_finding(self):
        """The false-positive half. Every class here previously produced FPs
        because 'the payload was accepted' read as success."""
        for k, v in P.GENERIC.items():
            assert re.search(r"not (?:by itself )?a finding|not proof|"
                             r"is not (?:stored )?\w+", v, re.I), k

    def test_each_playbook_says_how_to_spot_the_shape(self):
        for k, v in P.GENERIC.items():
            assert "spot it:" in v.lower(), k


class TestRouting:
    def test_mission_selects_only_named_classes(self):
        assert P.select_playbooks("Assess the app for SSRF") == ["ssrf"]

    def test_unrelated_mission_selects_nothing(self):
        assert P.select_playbooks("Check TLS configuration and cipher suites") == []

    def test_selection_is_capped(self):
        m = "ssrf open redirect file upload xxe prototype pollution stored xss"
        assert len(P.select_playbooks(m)) <= P.MAX_PLAYBOOKS

    def test_cap_is_the_dose_lever(self):
        assert len(P.select_playbooks("ssrf and xxe", max_n=1)) == 1


class TestInjectedSize:
    def test_generic_block_is_far_smaller_than_the_old_one(self):
        """The old block was ~9 KB of all six playbooks, every run."""
        out = P.get_playbook_context("http://client.test", mode="auto",
                                     mission="test for ssrf and file upload")
        assert out, "auto mode produced nothing"
        assert len(out) < 3000, f"{len(out)} chars — dose regression"

    def test_block_names_no_path_on_a_foreign_target(self):
        out = P.get_playbook_context("http://client.test", mode="auto",
                                     mission="ssrf, open redirect, xxe, stored xss")
        low = out.lower()
        assert not any(p.lower() in low for p in JUICESHOP_ONLY), out

    def test_block_carries_the_actual_target(self):
        out = P.get_playbook_context("http://client.test:8443", mode="juiceshop",
                                     mission="ssrf")
        assert "juice-shop:3000" not in out


class TestOffByDefault:
    @pytest.mark.parametrize("mode", ["", None, "off", "none", "0", "false"])
    def test_disabled_modes_inject_nothing(self, mode, monkeypatch):
        monkeypatch.delenv("ERLIK_PLAYBOOKS", raising=False)
        assert P.get_playbook_context("http://t", mode=mode) == ""

    def test_env_default_is_off(self, monkeypatch):
        monkeypatch.delenv("ERLIK_PLAYBOOKS", raising=False)
        assert P.get_playbook_context("http://t", mission="ssrf") == ""


class TestTargetProfilesStillWork:
    def test_juiceshop_profile_exists(self):
        assert "juiceshop" in P.available_profiles()

    def test_juiceshop_profile_keeps_its_real_endpoints(self):
        """Every recorded experiment ran with these. Losing them would make the
        measurements unreproducible."""
        pb = P.load_profile("juiceshop")
        assert pb, "juiceshop profile did not load"
        blob = "\n".join(pb.values())
        assert "/profile/image/url" in blob
        assert "/redirect?to=" in blob
        assert "/file-upload" in blob

    def test_profile_is_selected_by_name_never_guessed(self):
        """A URL heuristic would silently attack the wrong app's endpoints."""
        out = P.get_playbook_context("http://localhost:3000", mode="auto",
                                     mission="ssrf")
        assert "/profile/image/url" not in out

    def test_unknown_profile_falls_back_to_generic_not_crash(self):
        out = P.get_playbook_context("http://t", mode="no-such-profile",
                                     mission="ssrf")
        assert "Spot it:" in out

    def test_broken_profile_yaml_does_not_break_a_run(self, tmp_path, monkeypatch):
        bad = tmp_path / "broken.yaml"
        bad.write_text("playbooks: [unclosed\n")
        monkeypatch.setattr(P, "CATALOG", tmp_path)
        assert P.load_profile("broken") == {}


class TestPresetsAreTargetAgnostic:
    def test_no_preset_hardcodes_another_apps_endpoints(self):
        """The actual production defect: the DEFAULT preset shipped Juice Shop's
        endpoints to every client target."""
        for name, preset in runconfig.RUN_PRESETS.items():
            assert preset["config"].get("playbooks") != "juiceshop", name

    def test_default_preset_uses_generic_playbooks(self):
        r = runconfig.resolve({"preset": runconfig.DEFAULT_PRESET})
        assert r["playbooks"] == "auto"

    def test_juiceshop_is_still_selectable_explicitly(self):
        r = runconfig.resolve({"preset": "guided_ai", "playbooks": "juiceshop"})
        assert r["playbooks"] == "juiceshop"


class TestSafeMode:
    def test_generic_playbooks_suggest_no_denied_command(self):
        """Guidance the safe-mode guard would refuse wastes a turn and teaches
        the agent a command it cannot run."""
        from orchestrator import tool_executor as T
        blob = "\n".join(P.GENERIC.values())
        cmds = re.findall(r'((?:curl|sqlmap|ffuf|nmap|gobuster|nuclei)\s[^\n"\']{6,200})',
                          blob)
        denied = [c for c in cmds if T._safe_mode_violation(c)]
        assert denied == [], denied


class TestNoFabricatedRelevance:
    """The fallback used to inject `list(GENERIC)[:2]` — SSRF and open redirect,
    chosen by dict order — for ANY mission naming no class. Alphabetical
    accident presented as routing, and unjustified injected volume is precisely
    what the dose ladder measured as costly."""

    def test_unrelated_mission_injects_nothing_in_auto(self):
        out = P.get_playbook_context(
            "http://client.test", mode="auto",
            mission="Assess for injection, authentication and access-control flaws")
        assert out == "", f"fabricated {len(out)} chars of unrouted guidance"

    def test_the_specific_dict_order_leak(self):
        out = P.get_playbook_context("http://t", mode="auto", mission="check TLS")
        assert "SSRF" not in out and "Open Redirect" not in out

    def test_named_mission_still_injects(self):
        """Guard on the guard: the fix must not silence routing entirely."""
        out = P.get_playbook_context("http://t", mode="auto", mission="test for SSRF")
        assert "SSRF" in out

    def test_explicit_profile_is_honoured_without_a_named_class(self):
        """An operator who typed `juiceshop` chose it for this target."""
        out = P.get_playbook_context("http://t", mode="juiceshop", mission="general assessment")
        assert out, "an explicitly chosen profile injected nothing"


class TestRoutingSpecificity:
    """Ranking was `max(len(phrase))`, and length is a proxy for nothing.

    MEASURED CONSEQUENCE: in the none-vs-auto experiment the mission read
    "...injection, cross-site scripting, SSRF, open redirect...". Lengths were
    'cross-site scripting' 20, 'open redirect' 13, 'ssrf' 4, and the cap was 2 —
    so the SSRF playbook was dropped although the mission named it outright, and
    nothing in the log or the run record said so. All four `auto` runs were
    scored as testing guidance that was never injected.
    """

    MISSION = ("Assess the OWASP Juice Shop instance for injection, cross-site "
               "scripting, SSRF, open redirect, broken access control and "
               "authentication flaws.")

    def test_an_explicitly_named_class_is_not_dropped_for_a_longer_phrase(self):
        sel, dropped = P.route_playbooks(self.MISSION)
        assert "ssrf" in sel, f"SSRF named in the mission but dropped: {dropped}"

    def test_short_precise_acronym_outranks_a_long_generic_phrase(self):
        sel = P.select_playbooks("test for ssrf", max_n=1)
        assert sel == ["ssrf"]

    def test_generic_word_inside_an_identifier_does_not_route(self):
        """'redirect' as a substring matched `redirect_uri`, and 'upload'
        matched `uploaded_at` — a generic word then outranked a named class."""
        assert P.route_playbooks("inspect the redirect_uri parameter")[0] == []
        assert P.route_playbooks("check the uploaded_at column")[0] == []

    def test_a_deliberate_mention_still_routes(self):
        """Guard on the guard: the boundary fix must not silence real requests."""
        assert P.route_playbooks("test for open redirect")[0] == ["open_redirect"]

    def test_selection_is_deterministic_across_calls(self):
        """Ties broke on dict iteration before; the same mission must not route
        differently between two runs of the same arm."""
        runs = {tuple(P.select_playbooks(self.MISSION)) for _ in range(50)}
        assert len(runs) == 1, runs

    def test_the_cap_reports_what_it_discarded(self):
        """A silent cap is how the SSRF drop survived a whole experiment."""
        sel, dropped = P.route_playbooks(self.MISSION, max_n=1)
        assert len(sel) == 1
        assert dropped, "cap discarded classes but reported none"
        assert set(sel) & set(dropped) == set()

    def test_default_cap_covers_a_three_class_mission(self):
        sel, dropped = P.route_playbooks(self.MISSION)
        assert dropped == [], f"ordinary 3-class mission still truncated: {dropped}"


class TestCapIsPinnable:
    """ERLIK_MAX_PLAYBOOKS was read once at module import and was not a
    run_config key, so two runs of the same arm in two server processes could
    receive different treatments with nothing in the record showing it."""

    def test_max_playbooks_is_a_run_config_key(self):
        assert runconfig.resolve({"preset": "custom", "max_playbooks": 1})["max_playbooks"] == 1

    def test_the_cap_actually_changes_what_is_injected(self):
        m = "test for ssrf, cross-site scripting and open redirect"
        one = P.get_playbook_context("http://t", mode="auto", mission=m, max_n=1)
        three = P.get_playbook_context("http://t", mode="auto", mission=m, max_n=3)
        assert 0 < len(one) < len(three)
