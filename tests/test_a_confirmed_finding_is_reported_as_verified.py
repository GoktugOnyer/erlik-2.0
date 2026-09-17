"""278 confirmed findings were reported to a client as unverified.

`verified` was `confidence == "confirmed"` — an exact, case-sensitive match against a
column an LLM pass writes. Measured on the recorded corpus, 462 findings:

    'Confirmed'     251        'CONFIRMED'      15
    '** Confirmed'   12        'confirmed'      10
    'Demonstrated'   19        'Potential'      15        None  140

288 are graded confirmed by any reading. TEN matched. The other 278 — including twelve
carrying `** `, markdown bold that leaked out of a model response — were told to a client
as unverified.

THE CODEBASE ALREADY LEARNED THIS, one column over. `normalise_severity` says it outright:
`calibrated_severity` is written by an LLM pass and the corpus holds `'** CRITICAL'`, and
returned raw those become distinct buckets so a filter for critical silently misses the
starred rows. `confidence` is written by the same pass and never got the same treatment.

THE DIRECTION OF THE ERROR IS THE SAFE ONE and it is still wrong. erlik understated what it
had established rather than overstating it — but a report contradicting the product's own
data is not one anyone can act on, and the same comparison decides `verified` on a client's
DefectDojo tracker.

WHAT IS NOT DONE HERE: the stored values are not migrated. `normalise_severity` reads rather
than rewrites, for the reason that the column records what a pass actually produced, and a
migration would erase the evidence that it produced `'** Confirmed'` at all.
"""
import pathlib
import sqlite3

import pytest

from orchestrator.reporting import (
    CONFIDENCE_VALUES, model_confidence, normalise_confidence)

from tests import corpus


# ------------------------------------------------------------------ what it normalises


@pytest.mark.parametrize("stored", ["confirmed", "Confirmed", "CONFIRMED", "** Confirmed",
                                    "  confirmed  ", "**confirmed**"])
def test_every_spelling_of_confirmed_reads_as_confirmed(stored):
    assert normalise_confidence(stored) == "confirmed", stored


@pytest.mark.parametrize("stored,expected", [("likely", "likely"), ("Likely", "likely"),
                                             ("suspected", "suspected"),
                                             ("** SUSPECTED", "suspected")])
def test_the_other_grades_normalise_too(stored, expected):
    assert normalise_confidence(stored) == expected


@pytest.mark.parametrize("stored", ["Demonstrated", "Potential", "very sure", "high"])
def test_a_word_outside_the_vocabulary_grades_at_the_floor(stored):
    """`normalise_severity`'s rule — "anything unrecognised is 'info', never invented" — in
    its equivalent. `Demonstrated` READS stronger than suspected, and mapping it upward is
    how a model's vocabulary quietly becomes erlik's."""
    assert normalise_confidence(stored) == "suspected"
    assert normalise_confidence(stored) != "confirmed"


@pytest.mark.parametrize("stored", [None, "", "   ", "**", "  ** "])
def test_nothing_recorded_is_not_a_grade(stored):
    """None, not "suspected". A finding nobody graded has no confidence, and giving it the
    floor would invent a judgement to report."""
    assert normalise_confidence(stored) is None


# ------------------------------------------------- the two places that decide `verified`


def test_the_report_uses_the_normalised_value():
    import inspect

    from orchestrator import reporting

    source = inspect.getsource(reporting)
    assert 'normalise_confidence(f.get("confidence")) == "confirmed"' in source
    assert '(f.get("confidence") == "confirmed")' not in source, "the exact match is back"


def test_the_tracker_export_uses_it_too():
    """DefectDojo is where `verified` stops being a word in a report and becomes a flag a
    human trusts. It had the identical exact comparison."""
    import inspect

    from orchestrator.integrations import defectdojo

    source = inspect.getsource(defectdojo)
    assert 'normalise_confidence(finding["confidence"]) == "confirmed"' in source
    assert 'finding["confidence"] == "confirmed"' not in source


# ------------------------------------------ reading and writing are different questions


def test_reading_grades_at_the_floor_and_writing_declines():
    """The asymmetry, asserted because it looks like an inconsistency until you need it.
    Reading an unrecognised word means "grade it low". WRITING one must mean "write
    nothing", or a model inventing a word would overwrite a `confirmed` that a differential
    earned, with `suspected`, and call it normalisation."""
    assert normalise_confidence("Demonstrated") == "suspected"
    assert model_confidence("Demonstrated") is None


def test_a_model_still_cannot_write_confirmed_however_it_spells_it():
    """The clamp and the cleaner share one implementation now, so the markdown spelling is
    clamped rather than dropped — `'** Confirmed'` used to fall out of the vocabulary check
    and write nothing at all."""
    for spelling in ("confirmed", "Confirmed", "** Confirmed", "**CONFIRMED**"):
        assert model_confidence(spelling) == "likely", spelling


# ---------------------------------------------------------- against the recorded corpus


def test_the_corpus_is_what_this_was_measured_on():
    """The evidence, re-derived rather than quoted. If a future change to the reader drops
    one of these spellings, this says so in the terms the defect was found in."""
    corpus.require("findings")
    db = pathlib.Path(__file__).resolve().parents[1] / "data" / "pentest.db"
    rows = sqlite3.connect(f"file:{db}?mode=ro", uri=True).execute(
        "SELECT confidence, COUNT(*) FROM findings GROUP BY confidence").fetchall()

    exact = sum(n for value, n in rows if value == "confirmed")
    normalised = sum(n for value, n in rows if normalise_confidence(value) == "confirmed")
    assert normalised > exact, (
        "the corpus no longer contains the mixed spellings this guard exists for")
    assert normalised - exact >= 100, (
        f"only {normalised - exact} findings recovered; the measurement said 278")


def test_no_corpus_value_normalises_to_something_outside_the_vocabulary():
    corpus.require("findings")
    db = pathlib.Path(__file__).resolve().parents[1] / "data" / "pentest.db"
    for (value,) in sqlite3.connect(f"file:{db}?mode=ro", uri=True).execute(
            "SELECT DISTINCT confidence FROM findings"):
        graded = normalise_confidence(value)
        assert graded is None or graded in CONFIDENCE_VALUES, (value, graded)
