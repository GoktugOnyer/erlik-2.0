"""Tests for the skill-library router (orchestrator/skills.py).

These pin two defects that made the *guided* experimental condition inject the
wrong knowledge — which silently degrades the guided-vs-AI-solo comparison the
thesis rests on:

1. RANKING. Scoring summed topical overlap and a filename-shape bonus into one
   number, so a "-quickstart" file (+3) beat a file that matched more query
   tokens (+1 each). Because the category directories "client-side" and
   "server-side" both tokenise to "side", an `ssrf` hint selected client-side
   clickjacking/CORS sheets and zero server-side content.

2. BUDGET. The selection loop did `break` when a candidate overflowed the
   character budget, abandoning the remaining budget entirely instead of trying
   the next (smaller) candidate. An `sqli` hint returned a single file with
   ~6 KB of the 14 KB budget left unused.

The corpus-backed tests below are deliberately coupled to the vendored
skills_catalog/ — that coupling is the point, since the regressions were only
visible against real filenames and real file sizes. The synthetic tests pin the
mechanics independently of corpus contents.
"""

import pytest

import orchestrator.skills as S


def _rel(paths):
    return [str(p.relative_to(S.SKILLS_ROOT)) for p in paths]


# --- corpus-backed regressions -------------------------------------------

def test_ssrf_selects_server_side_not_client_side():
    """The headline regression: 'ssrf' must not return client-side sheets."""
    picked = _rel(S.select_skill_files("ssrf"))
    assert picked, "ssrf should match something in the corpus"
    assert all(p.startswith("server-side/") for p in picked), picked
    assert not any("clickjacking" in p or "cors" in p for p in picked), picked


def test_xss_prefers_dom_xss_sheets_over_unrelated_quickstart():
    """'xss' previously spent half its budget on clickjacking-quickstart."""
    picked = _rel(S.select_skill_files("xss"))
    assert any("dom-xss" in p for p in picked), picked
    assert not any("clickjacking" in p for p in picked), picked


def test_sqli_uses_the_budget_instead_of_stopping_at_the_first_overflow():
    """An oversized rank-2 candidate must not truncate the selection to one."""
    picked = S.select_skill_files("sqli")
    assert len(picked) > 1, _rel(picked)
    assert any("sql-injection" in str(p) for p in picked), _rel(picked)


@pytest.mark.parametrize(
    "hint, expected_category",
    [
        ("jwt", "authentication"),
        ("idor", "web-app-logic"),
        ("sqli", "injection"),
        ("ssrf", "server-side"),
    ],
)
def test_hint_routes_to_the_expected_category(hint, expected_category):
    picked = _rel(S.select_skill_files(hint))
    assert picked, hint
    assert picked[0].startswith(f"{expected_category}/"), (hint, picked)


def test_selection_respects_the_character_budget():
    for hint in ("sqli", "xss", "ssrf", "jwt", "idor"):
        picked = S.select_skill_files(hint, max_chars=14000)
        total = sum(p.stat().st_size for p in picked)
        # The first pick is always taken (never return empty on a real match),
        # so only a multi-file selection is required to fit.
        if len(picked) > 1:
            assert total <= 14000, (hint, total, _rel(picked))


def test_no_match_returns_empty():
    assert S.select_skill_files("zzzz-nothing-matches-this") == []


def test_empty_hint_returns_empty():
    assert S.select_skill_files("") == []
    assert S.select_skill_files("   ") == []


# --- synthetic corpus: mechanics, independent of vendored content ---------

@pytest.fixture
def fake_corpus(tmp_path, monkeypatch):
    """Build a throwaway corpus and point the router at it."""

    def _build(files):
        for relpath, size in files.items():
            p = tmp_path / relpath
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("x" * size, encoding="utf-8")
        monkeypatch.setattr(S, "SKILLS_ROOT", tmp_path)
        return tmp_path

    return _build


def test_overlap_outranks_filename_boost(fake_corpus):
    """Two matched tokens must beat one matched token + a '-quickstart' bonus."""
    fake_corpus({
        # matches only "side" (1 token) but carries the +3 quickstart boost
        "client-side/decoy-quickstart.md": 100,
        # matches "server" and "side" (2 tokens), no boost
        "server-side/real-resources.md": 100,
    })
    picked = S.select_skill_files("server side", max_files=1)
    assert [p.name for p in picked] == ["real-resources.md"]


def test_boost_still_breaks_ties_at_equal_overlap(fake_corpus):
    """With overlap equal, the action-oriented file should still win."""
    fake_corpus({
        "alpha/topic-quickstart.md": 100,   # boost 3
        "alpha/topic-principles.md": 100,   # boost 1
    })
    picked = S.select_skill_files("alpha topic", max_files=1)
    assert [p.name for p in picked] == ["topic-quickstart.md"]


def test_oversized_candidate_is_skipped_not_fatal(fake_corpus):
    """Rank 2 overflowing must not prevent rank 3 from being selected."""
    fake_corpus({
        "alpha/topic-quickstart.md": 1000,    # rank 1 (boost 3), fits
        "alpha/topic-advanced.md": 50_000,    # rank 2 (boost 1), way too big
        "alpha/topic-principles.md": 1000,    # rank 3 (boost 1), fits
    })
    picked = S.select_skill_files("alpha topic", max_files=3, max_chars=5000)
    names = [p.name for p in picked]
    assert "topic-quickstart.md" in names
    assert "topic-principles.md" in names, names   # the regression
    assert "topic-advanced.md" not in names, names


def test_first_match_is_taken_even_when_it_alone_exceeds_the_budget(fake_corpus):
    """Never return empty for a real match — the pre-existing guard."""
    fake_corpus({"alpha/topic-quickstart.md": 99_000})
    picked = S.select_skill_files("alpha topic", max_chars=1000)
    assert [p.name for p in picked] == ["topic-quickstart.md"]


def test_max_files_is_respected(fake_corpus):
    fake_corpus({f"alpha/topic-{i}-quickstart.md": 10 for i in range(10)})
    assert len(S.select_skill_files("alpha topic", max_files=3, max_chars=99_000)) == 3


def test_index_and_skill_stubs_are_never_selected(fake_corpus):
    """SKILL.md / INDEX.md are navigation, not injectable knowledge."""
    fake_corpus({
        "alpha/SKILL.md": 100,
        "alpha/INDEX.md": 100,
        "alpha/alpha-quickstart.md": 100,
    })
    picked = [p.name for p in S.select_skill_files("alpha", max_files=5)]
    assert picked == ["alpha-quickstart.md"]
