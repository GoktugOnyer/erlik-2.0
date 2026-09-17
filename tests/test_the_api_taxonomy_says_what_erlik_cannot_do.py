"""Coverage against the OWASP API Security Top 10 2023 — E-011's unmet acceptance clause.

E-011 asks for coverage mapped to "relevant WSTG and API Security categories". The WSTG
half existed throughout the codebase; the API half did not exist anywhere — not in
`orchestrator/`, not in `tests_catalog/`, not in the docs. Measured before building it.

THE TAXONOMIES ARE NOT THE SAME LIST. `CLASSES[*]["owasp"]` is the WEB Top 10 (A01:2021);
this is the API Top 10 2023. The difference that earns the mapping its place: the web list
has ONE "Broken Access Control", while the API list splits OBJECT level (API1) from
FUNCTION level (API5) — and erlik already runs those as two different checks,
`cross_arm_authorization` and `cross_arm_privileged_function`. The mapping reports a split
the product already makes.

WHAT THIS FILE IS REALLY GUARDING is the honest-absence property. A coverage report that
lists only what it found reads as complete when it is not, so every category appears and
an uncovered one must carry a REASON. `audit()` fails on a category that is neither
claimed nor declared uncovered — which is the only way "8 of 10" can mean eight of ten
rather than a complete list of eight.
"""
import inspect

import pytest

from orchestrator.capabilities import (
    API_CATEGORIES, API_NOT_COVERED, API_UNMAPPED_REASON, CLASSES, api_coverage, audit)


# ------------------------------------------------------------------ the join is sound


def test_every_declared_category_is_a_real_one():
    declared = {a for c in CLASSES for a in c["api"]}
    assert declared <= set(API_CATEGORIES), sorted(declared - set(API_CATEGORIES))
    assert audit()["api_declared_missing"] == []


def test_every_category_is_either_claimed_or_declared_uncovered():
    """The direction that does the work. A category nothing claims and nothing explains is
    a hole in the guide, not an absence of risk."""
    assert audit()["api_unaccounted"] == []


def test_a_category_cannot_be_both_claimed_and_declared_uncovered():
    assert audit()["api_claimed_yet_declared_uncovered"] == []


def test_the_contradiction_check_can_actually_fire(monkeypatch):
    """The guard has never fired in this tree, which is exactly when a guard needs a
    positive control — an assertion that only ever sees an empty list proves nothing about
    the code that fills it."""
    monkeypatch.setitem(API_NOT_COVERED, "API1:2023", "pretend nothing covers this")
    assert audit()["api_claimed_yet_declared_uncovered"] == ["API1:2023"]


def test_an_unaccounted_category_is_caught(monkeypatch):
    """The other guard, given something to find."""
    monkeypatch.delitem(API_NOT_COVERED, "API4:2023")
    assert audit()["api_unaccounted"] == ["API4:2023"]


def test_a_class_that_drops_its_mapping_is_reported_not_raised(monkeypatch):
    """Found by the EXISTING join-integrity test, not by this file. `audit()` read
    `c["api"]` directly and a class dict without the key raised a KeyError from inside the
    audit — and `/api/library/classes/audit` turns this dict into an `ok` verdict, so an
    exception is a 500 rather than a verdict.

    Tolerating the absence quietly is the other wrong answer: `jwt` dropping API2 while
    `authn` still claims it leaves every other direction clean, so the omission has to be
    its own finding.
    """
    from orchestrator import capabilities as C

    monkeypatch.setattr(C, "CLASSES", [{"key": "x", "label": "x", "owasp": "x",
                                        "wstg": [], "detectors": []}])
    a = C.audit()
    assert a["classes_missing_api"] == ["x"]
    assert not all(not v for v in a.values()), "a malformed class still read as ok"


def test_no_class_is_missing_its_mapping_here():
    assert audit()["classes_missing_api"] == []


def test_the_two_taxonomies_are_not_mixed_up():
    """A web id in the API field, or an API id in the web field, is the failure mode of
    having two numbered OWASP lists in one table."""
    for c in CLASSES:
        assert not any(a.startswith("A0") or a.startswith("A1:") for a in c["api"]), c["key"]
        assert "API" not in c["owasp"], c["key"]


# ------------------------------------------------- the report does not flatter itself


def test_uncovered_categories_are_listed_rather_than_omitted():
    report = api_coverage()
    assert len(report["categories"]) == len(API_CATEGORIES) == 10
    assert report["covered"] == 8 and report["total"] == 10
    uncovered = [c for c in report["categories"] if not c["covered"]]
    assert {c["id"] for c in uncovered} == {"API4:2023", "API10:2023"}


def test_an_uncovered_category_always_carries_a_reason():
    """"Not covered" with no reason is indistinguishable from "not yet mapped"."""
    for c in api_coverage()["categories"]:
        if not c["covered"]:
            assert c["not_covered_reason"], c["id"]
            assert len(c["not_covered_reason"]) > 40, c["id"]


def test_a_covered_category_carries_no_stale_reason():
    for c in api_coverage()["categories"]:
        if c["covered"]:
            assert c["not_covered_reason"] is None, c["id"]


def test_each_category_keeps_the_two_verdicts_rather_than_one_badge():
    """The module header's rule: `agent_session` and `wstg_engine` are separate execution
    paths and a single merged verdict would assert coverage no run can deliver."""
    for c in api_coverage()["categories"]:
        for cls in c["classes"]:
            assert set(cls["verdicts"]) >= {"agent_session", "wstg_engine"}, cls["key"]


# --------------------------------------------- the authorization claim is behavioural


def test_the_object_and_function_split_is_a_real_split_not_a_label():
    """E-011 already recorded the failure this prevents: cross-tenant "had only a LABEL
    test", where the product reported a class it had never been shown to recover.

    `authz` claims TWO categories, so two distinct checks must exist. If either is
    deleted or collapsed into the other, the class is claiming a category it cannot
    demonstrate — and nothing else in the suite compares the claim to the code.
    """
    from orchestrator.integrations.inventory import (
        cross_arm_authorization, cross_arm_privileged_function)

    authz = next(c for c in CLASSES if c["key"] == "authz")
    assert authz["api"] == ["API1:2023", "API5:2023"]
    assert cross_arm_authorization is not cross_arm_privileged_function
    assert inspect.iscoroutinefunction(cross_arm_authorization)
    assert inspect.iscoroutinefunction(cross_arm_privileged_function)


def test_the_acceptance_exercises_both_categories_it_claims():
    """The claim is only worth something if the acceptance actually runs both checks. This
    reads the acceptance file rather than re-running it: the point is that the two claimed
    categories are the two the demonstration covers, not that they pass here."""
    from pathlib import Path

    body = (Path(__file__).resolve().parents[0]
            / "test_the_authorization_acceptance.py").read_text()
    assert "cross_arm_authorization" in body, "API1 is claimed but not demonstrated"
    assert "cross_arm_privileged_function" in body, "API5 is claimed but not demonstrated"
    assert "test_a_privileged_function_violation_is_recovered" in body


# --------------------------------------------------------------- injection is not a gap


def test_injection_declares_no_category_and_says_why():
    """Six classes map to nothing, and that is the taxonomy's doing rather than erlik's:
    injection was API8:2019 and was REMOVED in 2023. Filing them under "API8 Security
    Misconfiguration" because the number looks familiar is the confidently-wrong
    relationship this module refuses to auto-generate."""
    for key in ("sqli", "xss", "cmdi", "ssti", "ldap", "nosql", "injection_generic"):
        assert next(c for c in CLASSES if c["key"] == key)["api"] == [], key
    assert "2019" in API_UNMAPPED_REASON and "removed" in API_UNMAPPED_REASON.lower()
    assert api_coverage()["injection_note"] == API_UNMAPPED_REASON


def test_an_unmapped_class_is_not_reported_as_an_uncovered_category():
    """`sqli` having no API category does not mean erlik cannot test SQL injection. The
    coverage report is about the taxonomy's boxes, not about erlik's capability, and
    conflating the two would understate the product."""
    sqli = next(c for c in CLASSES if c["key"] == "sqli")
    assert sqli["api"] == [] and sqli["wstg"] and sqli["detectors"]


# ------------------------------------------------------------------------ over the wire


def test_the_route_serves_it():
    from fastapi.testclient import TestClient

    from orchestrator.main import app

    r = TestClient(app).get("/api/library/api-coverage")
    assert r.status_code == 200
    assert r.json()["covered"] == 8
    assert r.json()["reference"] == "https://github.com/OWASP/API-Security"


def test_the_api_field_reaches_the_class_listing():
    from fastapi.testclient import TestClient

    from orchestrator.main import app

    classes = TestClient(app).get("/api/library/classes").json()["classes"]
    assert next(c for c in classes if c["key"] == "authz")["api"] == ["API1:2023", "API5:2023"]


def test_the_audit_endpoint_still_reports_ok():
    """`ok` is `all(not v for v in audit().values())`, so a new audit key that is non-empty
    in a healthy tree would flip the endpoint to not-ok forever."""
    from fastapi.testclient import TestClient

    from orchestrator.main import app

    assert TestClient(app).get("/api/library/classes/audit").json()["ok"] is True
