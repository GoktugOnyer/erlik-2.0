"""The dashboard renders bytes chosen by the target being attacked.

THREAT MODEL. erlik probes hosts and shows what came back. `steps[].output` is
raw stdout from curl/nmap/etc. with no sanitisation, and `findings[].evidence`
is a slice of it. So the ATTACKED HOST authors much of what the operator's
browser renders — and the dashboard origin can launch attacks, read every
engagement, and reach the API. Script execution there is a privilege boundary
crossed, not a cosmetic bug.

THE DEFECT THIS GUARDS. `tlRunOne` serialised the whole run object into a
single-quoted `onclick` attribute:

    <button onclick='tlDetail(${JSON.stringify(d).replace(/'/g, "&#39;")})'>

That `.replace` is a ROUND-TRIP, not an escape: it protects the attribute
delimiter, and the browser decodes `&#39;` back to `'` in the JS source. It does
nothing about character references already in the target's bytes. `JSON.stringify`
escapes a literal `"`, but a target emitting the six characters `&quot;` yields
JSON containing that text, which the HTML parser decodes into a real `"` inside
the attribute — closing the JSON string literal and executing arbitrary JS.

Confirmed by execution in a browser, both directions: the old expression ran the
payload, the replacement does not.

The rule these tests encode: NEVER serialise target-derived data through the
HTML parser. Hold the parsed object in JS, reference it by an id we minted, and
bind handlers with addEventListener.
"""

import pathlib
import re

import pytest

UI = (pathlib.Path(__file__).resolve().parents[1]
      / "dashboard" / "templates" / "index.html")


@pytest.fixture(scope="module")
def src():
    return UI.read_text()


class TestNoTargetDataReachesTheHtmlParser:
    def test_no_json_stringify_into_an_attribute(self, src):
        """The exact pre-fix shape. JSON.stringify of a server response
        interpolated into markup is the sink."""
        assert "JSON.stringify(d).replace" not in src
        for m in re.finditer(r"onclick='[^']*JSON\.stringify", src):
            pytest.fail(f"JSON serialised into an onclick attribute: {m.group(0)[:90]}")

    def test_run_results_are_held_in_js_not_markup(self, src):
        assert "const tlRuns = {}" in src, "no JS-side store for run results"
        assert "tlRuns[id] = d" in src
        assert "data-tlrun" in src

    def test_the_detail_handler_is_bound_not_inlined(self, src):
        assert "addEventListener('click', () => tlDetail(tlRuns[" in src

    def test_the_replace_round_trip_is_gone(self, src):
        """`.replace(/'/g, "&#39;")` reads like escaping and is not: the browser
        decodes it straight back to an apostrophe in the JS source."""
        assert '.replace(/\'/g, "&#39;")' not in src


class TestEscapingCoversTheContextsUsed:
    def test_tlEsc_escapes_the_apostrophe(self, src):
        """Several sinks interpolate into single-quoted attribute values, where
        a bare apostrophe closes the attribute."""
        block = src[src.index("function tlEsc"):src.index("function tlEsc") + 400]
        assert "&#39;" in block, "tlEsc does not escape the apostrophe"
        for ch in ("&amp;", "&lt;", "&gt;", "&quot;"):
            assert ch in block, f"tlEsc no longer escapes {ch}"

    def test_engagement_handlers_carry_no_interpolated_data(self, src):
        """Engagement rows render DB-stored operator input and DISCOVERED
        hostnames — neither belongs inside an inline handler."""
        for bad in ("onclick=\"engApprove('${", "onclick=\"engOpen('${",
                    "onclick=\"engToTestLab('${"):
            assert bad not in src, f"data interpolated into a handler: {bad}"
        for good in ("data-engapprove", "data-engopen", "data-engtestlab"):
            assert good in src, f"missing the data-attribute form: {good}"

    def test_step_output_is_rendered_through_the_escaper(self, src):
        """tlDetail shows raw target stdout. It must go through tlEsc."""
        d = src[src.index("function tlDetail"):]
        d = d[:d.index("\n        }\n")]
        assert "tlEsc(s.command)" in d
        assert "tlEsc((s.output" in d or "tlEsc(s.output" in d

    def test_llm_authored_critique_is_escaped(self, src):
        """renderRunReview shows model-written text stored in the DB."""
        r = src[src.index("async function renderRunReview"):]
        r = r[:r.index("\n        }\n")]
        assert "tlEsc(t)" in r, "critique list items are not escaped"
        assert "tlEsc(r.recommended_next_run)" in r


class TestGuardIsNotVacuous:
    def test_the_escaper_actually_exists_and_is_used_widely(self, src):
        """If tlEsc vanished, every assertion above about it would pass
        vacuously on a file that simply stopped calling it."""
        assert src.count("tlEsc(") > 25, "tlEsc is barely used — check the sinks"
