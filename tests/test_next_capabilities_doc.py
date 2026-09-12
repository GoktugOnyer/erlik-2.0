"""Drift tests for docs/next-pentesting-capabilities.md.

`tests/test_security_doc.py` already states the standard: "A security-posture
document is worse than useless once it is wrong: it states defaults a reader will
rely on without checking." An implementation guide is the same shape — it names
files a reader will open, defaults they will budget against, and tool names they
will call — so the claims it makes about THIS repository are re-asserted here
against live code, and every repo-relative path it names must resolve.

Three references in the guide as received did not resolve: the future-development
plan under a different filename, and two documents that are not in this
repository at all. The first was repointed; the second two were de-linked with an
editor's note, because a dead link in a document whose purpose is to be followed
is the defect this file exists to prevent.

What is NOT asserted here: the guide's proposals. Sections 5 onward describe
tables, routes and tools that do not exist yet, and a test that demanded them
would fail on a correct repository. Only the statements about what is already
here are checked.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "next-pentesting-capabilities.md"


def text():
    return DOC.read_text()


def test_the_guide_exists():
    assert DOC.exists()


# ------------------------------------------------------------------ its own links

def test_every_repo_relative_path_it_names_resolves():
    """The standard `test_security_doc` applies to SECURITY.md. A guide that sends a
    reader to a file which is not there has wasted their time and lost their trust in
    the rest of it."""
    dead = []
    for label, target in re.findall(r"\[([^\]]+)\]\(([^)]+)\)", text()):
        if target.startswith(("http://", "https://", "#")):
            continue
        if not (DOC.parent / target).resolve().exists():
            dead.append((label, target))
    assert dead == [], f"dead repo-relative links: {dead}"


def test_it_does_not_link_documents_this_repository_lacks():
    """Both were kept as prose deliberately. If they land, link them — and this
    assertion is where to notice."""
    body = text()
    for absent in ("code-review-2026-09-12.md", ".specify/memory/constitution.md"):
        assert f"]({absent})" not in body, (
            f"{absent} is linked again; either it now exists, in which case remove it "
            f"from this list, or the link is dead")
        assert absent in body, f"the reference to {absent} was dropped rather than de-linked"


def test_the_editors_note_records_what_it_reconciled():
    body = text()
    assert "Editor's note" in body
    assert "future-plan.md" in body


# ---------------------------------------------------- what it says is already here

def test_the_existing_files_it_tells_a_reader_to_extend_are_real():
    """Section 3's table is the guide's most-followed part: it claims each path exists
    in the working tree."""
    section = text().split("## 3. Existing code to extend")[1].split("## 4.")[0]
    missing = [target for _, target in re.findall(r"\[([^\]]+)\]\(([^)]+)\)", section)
               if not (DOC.parent / target).resolve().exists()]
    assert missing == []


def test_the_mcp_server_name_and_tools_are_as_described():
    """Section 18 tells the reader to keep these working, so they have to be the
    names that are actually registered — and the `erlik_` prefix it proposes has to
    still be collision-free."""
    source = (ROOT / "mcp_servers" / "cve" / "server.py").read_text()
    assert 'Server("erlik-cve")' in source
    registered = set(re.findall(r'name="([a-z_]+)"', source))
    for tool in ("enrich_cve", "bulk_enrich_cves", "get_cached_cve", "cache_stats"):
        assert tool in registered, tool
        assert tool in text(), f"{tool} is registered but the guide no longer names it"
    assert not [t for t in registered if t.startswith("erlik_")], (
        "an erlik_-prefixed tool now exists; section 18's collision argument needs "
        "rechecking against it")


def test_the_default_budgets_it_tells_a_reader_to_retain_are_the_defaults():
    from orchestrator.integrations.contracts import Budget

    budget = Budget()
    assert (budget.requests_per_second, budget.concurrency) == (5, 2)
    assert (budget.stage_seconds, budget.assessment_seconds) == (600, 1800)
    section = text().split("### Contracts and scheduling")[1].split("### Data model")[0]
    for figure in ("five target requests/second", "two concurrent requests",
                   "600 seconds/stage", "1,800 seconds/assessment"):
        assert figure in section, figure


def test_the_stage_outcomes_it_lists_are_the_real_vocabulary():
    """Section 18's job contract enumerates them, and a client would code against it."""
    from typing import get_args

    from orchestrator.integrations.contracts import StageStatus

    listed = re.search(r"Use the backend's existing stage outcomes: (.+?), with a reason\.",
                       text(), re.S).group(1)
    named = set(re.findall(r"`([a-z_]+)`", listed))
    assert named == set(get_args(StageStatus)), (
        f"the guide lists {sorted(named)} against {sorted(get_args(StageStatus))}")


def test_the_closed_stage_list_constraint_still_holds():
    """Section 3 warns that registering an adapter class is not enough because
    `AssessmentConfig.stages` is a closed literal. If that stops being true the warning
    becomes misleading advice."""
    from typing import get_args

    from orchestrator.integrations.contracts import AssessmentConfig

    annotation = AssessmentConfig.model_fields["stages"].annotation
    inner = get_args(annotation)[0]
    assert set(get_args(inner)) == {"zap", "schemathesis", "interactsh", "katana"}
    assert "`AssessmentConfig.stages` is a closed literal list" in text()


# ------------------------------------------- and the baseline it calls outstanding is not

def test_phase_zero_is_marked_done_rather_than_outstanding():
    """THE REASON THIS FILE WAS WRITTEN. Section 4 asks for six repairs that are all
    already closed — E-001 to E-006 in the plan — and a guide that opens with six
    finished tasks sends the reader to redo them. The note says so; this keeps it said.
    """
    plan = (ROOT / "docs" / "future-plan.md").read_text()
    for item in ("E-001", "E-002", "E-003", "E-004", "E-005", "E-006"):
        row = next(line for line in plan.splitlines() if line.startswith(f"| {item} |"))
        assert "**CLOSED**" in row, f"{item} is no longer closed; section 4's note is wrong"
    section = text().split("## 4. Phase zero")[1].split("## 5.")[0]
    assert "Already done" in section
    assert "E-001" in section and "E-006" in section


def test_the_stale_test_count_is_flagged_not_quietly_restated():
    """The guide's "161 passing network-free tests" is kept as a record of that review,
    and the note carries the current figure so a reader does not take 161 as today's."""
    body = text()
    assert "161 passing network-free tests" in body
    readme = (ROOT / "README.md").read_text()
    stated = re.search(r"\*\*(\d+) passed, \d+ skipped\*\* on its first run", readme).group(1)
    assert stated in body, (
        f"the README's fresh-clone figure is {stated} and the guide's editor's note no "
        f"longer carries it; update the note when the figure moves")
