"""Tests for the environment-aware technique router.

The router exists to answer a different question from skills.py: not "what is the
mission about" but "what is this target actually running". A Nettacker pre-scan
reports open ports, and a detected 27017 should pull MongoDB techniques.

Two properties matter beyond plain routing:

LICENCE SEPARATION. HackTricks is CC BY-NC 4.0 and erlik is MIT, so the committed
index carries facts only — environment, ports, title, tags, citation URL — and
never upstream prose. Body text is read at run time from the reader's own clone
via ERLIK_HACKTRICKS_PATH. The tests below pin that the router degrades to
citations-only when no clone is configured, because that is the behaviour that
keeps the repository redistributable.

RANKING. Ranked on (port hit, tag overlap) as an ordered pair, never a summed
score — the summed form is exactly what made the skills router return client-side
sheets for an `ssrf` hint.
"""

import pytest

import orchestrator.techniques as T


@pytest.fixture(autouse=True)
def _no_clone(monkeypatch):
    """Default every test to 'no local corpus' unless it opts in."""
    monkeypatch.delenv("ERLIK_HACKTRICKS_PATH", raising=False)
    monkeypatch.delenv("ERLIK_TECHNIQUES", raising=False)


# --- the index ------------------------------------------------------------

def test_index_loads():
    idx = T.load_index()
    assert idx, "techniques_catalog/index.yaml should be committed and parseable"
    assert len(idx) > 500


def test_index_entries_are_well_formed():
    for t in T.load_index()[:200]:
        assert t.get("id") and t.get("env") and t.get("title")
        assert t.get("source", "").startswith("https://")
        assert isinstance(t.get("tags"), list)


def test_index_carries_no_upstream_prose():
    """The licence separation, pinned. Facts only — nothing long enough to be
    authored expression."""
    for t in T.load_index():
        assert set(t) <= {"id", "env", "title", "path", "ports", "protocol",
                          "tags", "source"}, t
        title = t.get("title", "")
        assert len(title) <= 160, t
        # A heading is a few words; a sentence is authored expression. Some
        # upstream pages open with prose that parses as an H1, so the generator
        # falls back to the filename for those.
        assert len(title.split()) <= 14, t


def test_service_entries_are_mostly_port_keyed():
    """Port routing is the whole point of the service environment."""
    svc = [t for t in T.load_index() if t["env"] == "service"]
    keyed = [t for t in svc if t.get("ports")]
    assert len(keyed) / len(svc) > 0.9


# --- routing --------------------------------------------------------------

@pytest.mark.parametrize("port, expect", [
    (27017, "mongodb"),
    (6379, "redis"),
    (3306, "mysql"),
    (5432, "postgresql"),
    (11211, "memcache"),
])
def test_open_port_routes_to_its_service(port, expect):
    picked = T.select_techniques(open_ports=[port], max_items=3)
    assert picked, port
    assert any(expect in t["id"] or expect in t["title"].lower() for t in picked), \
        [t["title"] for t in picked]


def test_port_hit_outranks_tag_overlap():
    """An exact port match must never be displaced by a weak keyword overlap —
    the ordered-pair ranking, pinned."""
    picked = T.select_techniques(open_ports=[27017], tech=["nginx", "express"],
                                 hint="injection xss redirect", max_items=1)
    assert picked
    assert 27017 in (picked[0].get("ports") or [])


def test_multiple_ports_each_contribute():
    picked = T.select_techniques(open_ports=[27017, 6379], max_items=6)
    titles = " ".join(t["title"].lower() for t in picked)
    assert "mongo" in titles and "redis" in titles


def test_hint_routes_when_no_ports_are_known():
    picked = T.select_techniques(hint="deserialization", max_items=5)
    assert picked
    assert any("deserial" in t["id"] for t in picked), [t["id"] for t in picked]


def test_environment_filter_restricts_results():
    picked = T.select_techniques(hint="injection", environments=["web"], max_items=10)
    assert picked
    assert all(t["env"] == "web" for t in picked)


def test_unmatched_environment_returns_nothing():
    assert T.select_techniques(open_ports=[64999], max_items=5) == []
    assert T.select_techniques() == []
    assert T.select_techniques(hint="") == []


def test_max_items_is_respected():
    assert len(T.select_techniques(hint="injection", max_items=3)) <= 3


def test_selection_is_deterministic():
    """A research instrument must not reorder between runs."""
    a = [t["id"] for t in T.select_techniques(open_ports=[27017, 6379], max_items=6)]
    b = [t["id"] for t in T.select_techniques(open_ports=[27017, 6379], max_items=6)]
    assert a == b


# --- rendering without a local corpus -------------------------------------

def test_render_without_clone_gives_citations_only():
    """No clone configured -> titles and URLs, never upstream text."""
    out = T.render_techniques(open_ports=[27017])
    assert out
    assert "book.hacktricks.wiki" in out
    assert "Set ERLIK_HACKTRICKS_PATH" in out
    assert "Basic Information" not in out       # a body heading — must be absent


def test_render_always_attributes_the_source():
    out = T.render_techniques(open_ports=[6379])
    assert "CC BY-NC 4.0" in out
    assert "Carlos Polop" in out


def test_render_is_empty_when_nothing_matches():
    assert T.render_techniques(open_ports=[64999]) == ""


def test_body_read_returns_nothing_without_a_clone():
    t = T.select_techniques(open_ports=[27017], max_items=1)[0]
    assert T.read_technique_body(t) == ""


def test_missing_clone_path_is_ignored(monkeypatch):
    monkeypatch.setenv("ERLIK_HACKTRICKS_PATH", "/nonexistent/path/xyz")
    assert T.hacktricks_root() is None
    assert T.render_techniques(open_ports=[27017])   # still renders citations


# --- gating ---------------------------------------------------------------

def test_context_is_empty_unless_enabled():
    assert T.get_techniques_context(open_ports=[27017]) == ""


def test_context_renders_when_enabled(monkeypatch):
    monkeypatch.setenv("ERLIK_TECHNIQUES", "1")
    assert T.get_techniques_context(open_ports=[27017])


@pytest.mark.parametrize("value, on", [
    ("1", True), ("true", True), ("YES", True), ("on", True),
    ("0", False), ("false", False), ("", False),
])
def test_enable_flag_parsing(monkeypatch, value, on):
    monkeypatch.setenv("ERLIK_TECHNIQUES", value)
    assert T.techniques_enabled() is on


# --- budget ---------------------------------------------------------------

def test_oversized_entry_is_skipped_not_fatal(monkeypatch):
    """Same defect class as the skills router's budget loop: an entry that does
    not fit must be skipped, not abandon the remaining budget."""
    monkeypatch.setattr(T, "read_technique_body", lambda t, **kw: "x" * 50_000)
    out = T.render_techniques(open_ports=[27017, 6379], max_chars=2000)
    assert out                       # first entry always lands
    assert len(out) < 60_000
