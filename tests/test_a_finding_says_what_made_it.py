"""E-016: "package each finding with ... tool/image version".

A reviewer handed one finding should be able to reproduce it without being handed the lane as
well. The facts existed and were scattered across three modules — ZAP's image in
`runtime.IMAGES`, katana's `"version": "1.2.2"` and Schemathesis's `"version": "4.0.14"`
inlined in their own adapters' stage metadata — and none of them reached the finding, which is
the one thing that leaves the building.

STAMPED FROM `source`, NOT PASSED BY EACH PRODUCER. There are five construction sites and the
failure mode is a sixth that forgets; filling in the first five does not prevent that. Every
site already declares `source`, so the model derives the provenance and a new producer cannot
be silent about the question a reviewer starts from.

Lane-authored findings name no image on purpose. `cross-arm` and `testcase` evaluations run
over stored evidence — no container ran, so naming one would be inventing it, and what
reproduces them is the cited artifacts and the rule, which the finding already carries.
"""
import inspect

import pytest

from orchestrator.integrations.contracts import IntegrationFinding
from orchestrator.integrations.runtime import IMAGES, LANE_AUTHORED, TOOL_VERSIONS, produced_by


def finding(source, **kw):
    return IntegrationFinding(fingerprint="f", title="t", url="http://app.test/x", rule="r",
                              source=source, basis="b", **kw)


# ------------------------------------------------------------------- it is always stamped


@pytest.mark.parametrize("source", ["zap", "schemathesis", "katana", "interactsh",
                                    "cross-arm", "testcase", "a-new-producer"])
def test_every_finding_says_what_made_it(source):
    """Including a source nobody has written yet — the failure mode is the producer that
    forgets, so the default must be informative rather than empty."""
    assert finding(source).produced_by, source


def test_a_scanner_finding_names_the_image_that_ran():
    assert finding("zap").produced_by == IMAGES["zap"]
    assert IMAGES["worker"] in finding("schemathesis").produced_by
    assert TOOL_VERSIONS["schemathesis"] in finding("schemathesis").produced_by


def test_a_lane_authored_finding_names_no_image():
    """No container ran. Naming one would be inventing it, and a reviewer who went looking
    for that image would be chasing something that never executed."""
    for source in LANE_AUTHORED:
        provenance = finding(source).produced_by
        assert "no scanner image ran" in provenance, provenance
        assert IMAGES["worker"] not in provenance and IMAGES["zap"] not in provenance
        assert "cited evidence" in provenance, (
            "it does not say what DOES reproduce the finding")


def test_an_explicit_value_still_wins():
    """A caller that knows better than the map — a pinned digest, a rebuilt image — must be
    able to say so."""
    assert finding("zap", produced_by="ghcr.io/zaproxy/zaproxy@sha256:abc").produced_by == (
        "ghcr.io/zaproxy/zaproxy@sha256:abc")


# ------------------------------------------------ and there is one source for the versions


def test_the_adapters_and_the_finding_cannot_disagree():
    """Three copies of one fact is what this closes. A stage's recorded version and its
    findings' provenance now read the same constant, so they cannot drift apart."""
    from orchestrator.integrations import adapters

    source = inspect.getsource(adapters)
    for tool, version in TOOL_VERSIONS.items():
        assert f'"version": "{version}"' not in source, (
            f"{tool}'s version is inlined again; it belongs in runtime.TOOL_VERSIONS")
        assert f'TOOL_VERSIONS["{tool}"]' in source, tool


def test_every_producer_of_a_finding_is_covered_by_the_stamp():
    """The structural guard. `produced_by` is derived in the model rather than at the five
    construction sites precisely so this cannot rot — this asserts the construction sites
    still all declare a `source`, which is what the derivation reads.
    """
    import pathlib

    def call_body(text, start):
        """The argument list, matched by counting parentheses.

        A regex stopping at the first `)` reads the nested `fingerprint(...)` call as the end
        of the construction and never sees `source=` — which an earlier version of this test
        did, and it failed for that reason rather than finding anything.
        """
        depth, i = 0, start
        while i < len(text):
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                depth -= 1
                if depth == 0:
                    return text[start + 1:i]
            i += 1
        raise AssertionError("unbalanced call")

    root = pathlib.Path(__file__).resolve().parents[1] / "orchestrator" / "integrations"
    sites = 0
    for module in root.glob("*.py"):
        text = module.read_text()
        cursor = 0
        while (found := text.find("IntegrationFinding(", cursor)) != -1:
            cursor = found + 1
            if text[max(0, found - 6):found] == "class ":
                continue                    # the class definition, not a construction
            body = call_body(text, found + len("IntegrationFinding"))
            sites += 1
            assert "source=" in body, (
                f"{module.name}: a finding is constructed without a `source`, so it cannot "
                f"say what made it:\n{body[:200]}")
    assert sites >= 4, f"only found {sites} construction sites; this test has stopped looking"


def test_an_unknown_source_falls_back_to_the_worker_rather_than_nothing():
    """The worker image is where every non-ZAP tool runs, so it is the honest default — and
    an empty string would be the silent answer this exists to remove."""
    assert produced_by("something-new") == IMAGES["worker"]
