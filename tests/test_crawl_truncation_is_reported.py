"""E-030: the page-visit cap hid arm asymmetry instead of merely truncating.

The rendered crawl visits one level past the landing page for forms, bounded by
`form_pages` (default 20). The bound was silent, and silence is the wrong default
twice over:

  - two arms publishing DIFFERENT menus truncate at different places, so the cap
    MANUFACTURES a surface difference;
  - two arms publishing the SAME menu truncate identically and the cap HIDES a real
    one. Measured on DVWA: changing only the crawl root from `/index.php` to `/`
    moved the boundary by one link and revealed `/vulnerabilities/cryptography/`, a
    GET form at `security=impossible` and not at `low`. An earlier audit had called
    the cap benign precisely because both arms truncated identically.

The second is the worse case, so the count travels with the result. This does not
change the cap — raising it is an execution-policy decision — it stops the cap being
invisible.
"""
import json

import pytest

from orchestrator.integrations.adapters import ADAPTERS
from orchestrator.integrations.contracts import AssessmentConfig


def test_the_worker_reports_how_many_links_it_did_not_visit():
    """The worker is what applies the bound, so it is what must count.

    Asserted against the source because the loop runs inside the worker image and a
    unit test cannot reach it; the end-to-end behaviour is checked by the Docker
    suite. What matters here is that the field exists, is derived from the links the
    crawl actually skipped, and is emitted.
    """
    from pathlib import Path
    source = Path("orchestrator/integrations/worker.py").read_text()
    action = source[source.index('elif action == "browser"'):source.index('elif action == "baseline_browser"')]
    assert "pages_not_visited" in action, "the browser action does not report the cap"
    assert "capped = sum(" in action, "the count is asserted rather than measured"
    # Counted over same-origin links the crawl had not reached — not simply
    # len(links), which would include off-origin and already-visited ones.
    assert "u.startswith(origin)" in action and "u not in seen_pages" in action


def test_a_truncated_crawl_produces_an_observation():
    """A reader of the stage result can see the cap fired, and by how much."""
    from orchestrator.integrations.adapters import crawl_truncation

    observation = crawl_truncation({"pages_visited": 21, "pages_not_visited": 9})
    assert observation["type"] == "crawl_truncated"
    assert observation["pages_visited"] == 21
    assert observation["pages_not_visited"] == 9


def test_the_observation_names_the_remedy_and_the_hazard():
    """An observation that does not say why it matters reads as trivia."""
    from orchestrator.integrations.adapters import crawl_truncation

    detail = crawl_truncation({"pages_visited": 21, "pages_not_visited": 9})["detail"]
    assert "form_pages" in detail, "it does not name the remedy"
    assert "not the same surface" in detail, (
        "it does not say that differently-truncated arms cannot be compared")
    assert "hiding" in detail, (
        "it does not say that IDENTICAL truncation can hide a difference too — the "
        "reading an earlier audit actually made")
    assert "21" in detail and "9" in detail, "the counts are not in the text"


def test_an_untruncated_crawl_adds_no_observation():
    """Noise on every run is how an observation stops being read."""
    from orchestrator.integrations.adapters import crawl_truncation

    assert crawl_truncation({"pages_visited": 21, "pages_not_visited": 0}) is None
    assert crawl_truncation({"pages_visited": 21}) is None
    assert crawl_truncation({}) is None


def test_the_adapter_attaches_it_to_the_stage_result():
    from pathlib import Path
    source = Path("orchestrator/integrations/adapters.py").read_text()
    assert "browser_truncation = crawl_truncation(browser)" in source
    assert "result.observations.append(browser_truncation)" in source
