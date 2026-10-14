"""The Authorization panel drives E-011's cross-arm checks from the dashboard.

Until this panel, `cross_arm_authorization`, `cross_arm_privileged_function` and
`coverage` were reachable only by POSTing raw JSON at the API — the product's flagship
differentiator had no human surface. These guard the two things that make the surface
safe to ship:

  1. THREAT MODEL (same as test_dashboard_injection). The results rendered here are
     TARGET-authored — urls, asserted owners, reasons, role labels, evidence ids — so the
     panel must render them through text nodes, never through innerHTML with interpolated
     data.

  2. THE CARDINAL PRODUCT RULE. A refusal, or incomplete coverage, must read as NOT a
     clean pass even when the findings list is empty. That is the whole reason the route
     docstrings say "read refused_because before findings"; a panel that showed an empty
     list as green would reintroduce exactly the false assurance the engine refuses to give.

Each assertion names a pre-change shape, so reverting the fix reddens the named test.
"""
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
UI = ROOT / "dashboard" / "templates" / "index.html"
INVENTORY = ROOT / "orchestrator" / "integrations" / "inventory.py"


@pytest.fixture(scope="module")
def src():
    return UI.read_text()


@pytest.fixture(scope="module")
def outcome_body(src):
    """Just the panel's JS, so assertions cannot pass on unrelated code elsewhere."""
    start = src.index("// ===== AUTHORIZATION")
    end = src.index("// ===== ADDRESSABLE STATE")
    assert start < end
    return src[start:end]


class TestPanelIsWired:
    def test_nav_and_view_exist(self, src):
        assert 'id="nav-authz"' in src
        assert 'id="view-authz"' in src
        assert "switchView('authz')" in src

    def test_switchview_knows_authz(self, src):
        assert "'testlab', 'authz'" in src, "authz missing from the switchView toggle list"
        assert "if (view === 'authz') authzInit();" in src, "no loader bound for the authz view"

    def test_the_three_checks_and_the_picker_route_are_called(self, outcome_body):
        assert "/api/integrations/sessions'" in outcome_body  # picker feed
        assert "'/authorization'" in outcome_body
        assert "'/privileged-function'" in outcome_body
        assert "/coverage" in outcome_body


class TestRefusalAndIncompleteAreNotClean:
    def test_refusal_verdict_text(self, outcome_body):
        assert "An empty findings list here is NOT a clean result" in outcome_body

    def test_incomplete_coverage_verdict_text(self, outcome_body):
        assert "NOT a clean pass" in outcome_body

    def test_verdict_checks_refusal_first(self, outcome_body):
        # refused is evaluated before findings in the verdict ladder; swapping the order
        # would let an empty findings list on a refusal read as green.
        assert outcome_body.index("if (refused.length)") < outcome_body.index("else if (findings.length)")

    def test_refusal_block_is_rendered_before_the_findings_block(self, outcome_body):
        render = outcome_body[outcome_body.index("function authzRenderOutcome"):
                              outcome_body.index("function authzFindingCard")]
        assert "refused because:" in render
        assert "findings.forEach(" in render
        assert render.index("refused because:") < render.index("findings.forEach("), \
            "findings are rendered before the refusal reasons"


class TestEmptyIsNotCleanSignals:
    # The caveat keys the UI reads MUST be keys the engine actually returns, or an empty
    # result would silently read clean when coverage was in fact incomplete.
    CAVEAT_KEYS = [
        "contradicting_findings", "operations_the_other_arm_did_not_probe",
        "arms_with_unfinished_stages", "not_comparable", "urls_not_shared_by_both_arms",
        "ambiguous_evidence", "skipped_reflected_marker", "skipped_anonymous_was_redirected",
        "skipped_url_names_the_caller", "skipped_indistinct_response",
        "declared_access_that_matched_nothing", "caller_own_records_not_excluded",
    ]

    def test_ui_reads_each_caveat_key(self, outcome_body):
        for key in self.CAVEAT_KEYS:
            assert f"'{key}'" in outcome_body, f"the panel does not read caveat key {key!r}"

    def test_each_caveat_key_is_a_real_outcome_field(self):
        inv = INVENTORY.read_text()
        for key in self.CAVEAT_KEYS:
            assert f'"{key}"' in inv, \
                f"{key!r} is not a field cross_arm_* returns — UI/engine drift, the caveat would never fire"


class TestTargetDataGoesThroughTextNodes:
    def test_authzText_assigns_textContent(self, outcome_body):
        block = outcome_body[outcome_body.index("function authzText"):
                             outcome_body.index("function authzText") + 400]
        assert "textContent = text" in block, "authzText no longer builds a text node"

    def test_evidence_link_label_is_text_and_id_is_encoded(self, outcome_body):
        card = outcome_body[outcome_body.index("function authzFindingCard"):
                            outcome_body.index("function authzRunCoverage")]
        assert "a.textContent = arm" in card, "evidence link label is not a text node"
        assert "encodeURIComponent(eid)" in card, "evidence id is not URL-encoded into the href"

    def test_innerHTML_is_only_ever_cleared_never_given_data(self, outcome_body):
        # Within the panel, innerHTML is assigned ONLY the empty string (a clear). Any
        # data-bearing assignment is the sink this test exists to catch.
        for m in re.finditer(r"\.innerHTML\s*=\s*([^;]+);", outcome_body):
            assert m.group(1).strip() in ("''", '""'), \
                f"authz panel assigns data to innerHTML: {m.group(0)[:80]}"


class TestGuardIsNotVacuous:
    def test_authzText_is_used_widely(self, outcome_body):
        # If authzText vanished (rendering moved to innerHTML), the text-node assertions
        # above would pass vacuously. It is the panel's only rendering primitive.
        assert outcome_body.count("authzText(") > 15, "authzText barely used — check the render path"
