"""A case that declined to assess must never render as clean.

The deterministic lane's cases print an in-band canary for their verdict, and
the dashboard classifies it: a canary meaning "I could not conclude" renders
amber as "not assessed", anything else renders as a result. That classification
is one regex in one file, and the canaries live in twenty-nine others.

It had drifted. `ERLIK_\\w*(?:NOT_ASSESSED|NO_RESPONSE|INCONCLUSIVE)\\w*`
required an UNDERSCORE after ERLIK, and two of the catalogue's declines did not
match it:

  * `ERLIK-AUTHZ-INCONCLUSIVE` (AUTHZ-04) -- hyphens, so the `ERLIK_` prefix
    never matched. The case says "the low-privilege session got the same
    response as an anonymous request, so it was not authenticated here and this
    says nothing about access control", and that rendered GREEN.
  * `ERLIK_HBH_UNSTABLE_BASELINE` (INPV-15) -- right separator, but the word
    was not in the alternation. The case says the baseline moved between
    adjacent samples, so the probe means nothing, and that rendered GREEN too.

Both are the failure this codebase treats as equal to a crash: an interface
describing something that did not happen. The table below is the fix that
cannot drift, because a canary added later and left out of it fails
`test_the_table_covers_every_canary_in_the_catalogue`.
"""

import glob
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "dashboard" / "templates" / "index.html"

# Every canary the catalogue emits, and whether it means "could not conclude".
# Read off each case's own text. Adding a canary without a row here fails.
NOT_ASSESSED = {
    "ERLIK-AUTHZ-INCONCLUSIVE",
    "ERLIK_ATHN_NO_RESPONSE",
    "ERLIK_BUSL_NO_SUCCESS",
    "ERLIK_FRAMING_NOT_ASSESSED_REDIRECT",
    "ERLIK_FRAMING_NO_RESPONSE",
    "ERLIK_HBH_NO_RESPONSE",
    "ERLIK_HBH_UNSTABLE_BASELINE",
}
A_RESULT = {
    "ERLIK-AUTHZ-IDOR", "ERLIK-AUTHZ-OK",
    "ERLIK-LFI-ENCODED", "ERLIK-LFI-SOURCE", "ERLIK-LFI-TRAVERSAL",
    "ERLIK-LFI-WINDOWS", "ERLIK-UPLOAD-EXECUTED-CANARY",
    "ERLIK_ATHN_ACTION_OVER_HTTP", "ERLIK_ATHN_FORM_OVER_HTTP",
    "ERLIK_ATHN_NO_FORM", "ERLIK_ATHN_OK",
    "ERLIK_BUSL_RACE", "ERLIK_BUSL_SINGLE_SUCCESS",
    "ERLIK_FRAMING_HEADER_ABSENT", "ERLIK_FRAMING_HEADER_PRESENT",
    "ERLIK_HBH_NO_CHANGE", "ERLIK_HBH_STATUS_CHANGED",
    "ERLIK_LDAP_BLIND_DIFFERENTIAL", "ERLIK_LDAP_SECOND_PROBE",
    "ERLIK_LDAP_WILDCARD_INTERPRETED",
    "ERLIK_NOSQL_OPERATOR_PARSED", "ERLIK_OPERATOR_RESPONSE",
}


def _dashboard_regex() -> str:
    m = re.search(r"const TL_NOT_ASSESSED = /([^/]+)/", UI.read_text())
    assert m, "the dashboard's not-assessed marker regex moved or was renamed"
    return m.group(1)


def _catalogue_canaries() -> set[str]:
    found = set()
    for f in glob.glob(str(ROOT / "tests_catalog" / "wstg" / "*.yaml")):
        found |= set(re.findall(r"ERLIK[_-][A-Z0-9_-]+", Path(f).read_text()))
    return found


class TestTheClassificationIsRight:
    @pytest.mark.parametrize("canary", sorted(NOT_ASSESSED))
    def test_a_decline_renders_as_not_assessed(self, canary):
        assert re.search(_dashboard_regex(), canary), (
            f"{canary} means the case could not conclude, and the dashboard "
            "would render that row as a clean result"
        )

    @pytest.mark.parametrize("canary", sorted(A_RESULT))
    def test_a_real_verdict_is_not_swallowed(self, canary):
        """The other direction, and it matters as much: a finding or a clean
        verdict misread as 'not assessed' hides a real result behind an amber
        row nobody acts on."""
        assert not re.search(_dashboard_regex(), canary), (
            f"{canary} is a verdict, but the dashboard would render it as "
            "'not assessed'"
        )


class TestTheTableCannotDrift:
    def test_the_table_covers_every_canary_in_the_catalogue(self):
        """Guard on the guard. Without this, a case added later emits a canary
        no row classifies, and the two tests above pass while the dashboard
        renders it green."""
        declared = NOT_ASSESSED | A_RESULT
        actual = _catalogue_canaries()
        missing = actual - declared
        assert not missing, (
            f"these canaries are emitted by the catalogue and classified "
            f"nowhere: {sorted(missing)}. Decide whether each means the case "
            "could not conclude, and add it to NOT_ASSESSED or A_RESULT."
        )

    def test_the_table_does_not_describe_canaries_that_are_gone(self):
        declared = NOT_ASSESSED | A_RESULT
        stale = declared - _catalogue_canaries()
        assert not stale, (
            f"these are classified here but no case emits them: {sorted(stale)}"
        )

    def test_the_extractor_actually_finds_things(self):
        """If the YAML format changed so the extraction regex stopped matching,
        both drift tests above would pass against an empty set."""
        found = _catalogue_canaries()
        assert len(found) >= 20, found

    def test_the_two_classes_are_disjoint(self):
        assert not (NOT_ASSESSED & A_RESULT)


class TestBothSeparatorsAreHandled:
    """The specific regression. The catalogue uses `_` and `-` and both are
    load-bearing, so a regex that assumes one silently drops the other."""

    def test_hyphenated_and_underscored_declines_both_match(self):
        rx = _dashboard_regex()
        assert re.search(rx, "ERLIK-AUTHZ-INCONCLUSIVE")
        assert re.search(rx, "ERLIK_FRAMING_NO_RESPONSE")

    def test_both_separators_really_are_in_use(self):
        """Guard on that guard: if the catalogue were normalised to one
        separator, the test above would stop proving anything."""
        found = _catalogue_canaries()
        assert any(c.startswith("ERLIK-") for c in found), found
        assert any(c.startswith("ERLIK_") for c in found), found
