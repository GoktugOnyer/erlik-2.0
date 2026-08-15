"""Tests for model-availability reporting.

The health check decided availability with `target.split(":")[0] in m`, which
compares only the family name. A configured "qwen2.5-coder:7b-instruct-q4_K_M"
was therefore reported available because an unrelated "qwen2.5-coder:7b" was
installed — Ollama needs the exact tag, so the dashboard showed "Ollama ready"
while every generation 404'd on its first call. That is the worst shape of bug
this project keeps producing: a confident green light over a path that cannot
work.
"""

import pytest

from orchestrator.llm_client import model_installed, suggest_models

INSTALLED = [
    "qwen2.5vl:7b",
    "llama3.1:70b",
    "nomic-embed-text:latest",
    "qwen2.5:7b",
    "qwen2.5-coder:7b",
    "qwen3.5:35b",
]


# --- the regression -------------------------------------------------------

def test_family_match_is_not_enough():
    """The exact bug: a different tag in the same family must NOT count."""
    assert model_installed("qwen2.5-coder:7b-instruct-q4_K_M", INSTALLED) is False


def test_exact_tag_is_available():
    assert model_installed("qwen2.5-coder:7b", INSTALLED) is True
    assert model_installed("llama3.1:70b", INSTALLED) is True


@pytest.mark.parametrize("target", [
    "qwen2.5-coder:7b-instruct-q4_K_M",   # right family, wrong quantisation
    "qwen2.5-coder:14b",                  # right family, wrong size
    "llama3.1:8b",                        # right family, wrong size
    "mistral:7b",                         # absent entirely
])
def test_missing_models_are_reported_missing(target):
    assert model_installed(target, INSTALLED) is False


# --- Ollama's :latest rule ------------------------------------------------

def test_bare_name_resolves_to_latest():
    """Ollama serves a bare name as :latest, so that one case is genuinely fine."""
    assert model_installed("nomic-embed-text", INSTALLED) is True


def test_bare_name_without_a_latest_tag_is_missing():
    assert model_installed("qwen2.5-coder", INSTALLED) is False


def test_a_tagged_target_does_not_fall_back_to_latest():
    assert model_installed("nomic-embed-text:v2", INSTALLED) is False


# --- edges ----------------------------------------------------------------

@pytest.mark.parametrize("target, models", [
    ("", INSTALLED),
    (None, INSTALLED),
    ("qwen2.5-coder:7b", []),
    ("qwen2.5-coder:7b", None),
])
def test_edges_do_not_raise_and_report_missing(target, models):
    assert model_installed(target, models) is False


# --- suggestions ----------------------------------------------------------

def test_suggests_installed_tags_from_the_same_family():
    assert suggest_models("qwen2.5-coder:7b-instruct-q4_K_M", INSTALLED) == \
        ["qwen2.5-coder:7b"]


def test_suggestion_does_not_bleed_across_families():
    """'qwen2.5' and 'qwen2.5-coder' are different families — a prefix match
    would wrongly offer one for the other."""
    assert suggest_models("qwen2.5:32b", INSTALLED) == ["qwen2.5:7b"]
    assert "qwen2.5-coder:7b" not in suggest_models("qwen2.5:32b", INSTALLED)


def test_no_suggestion_when_the_family_is_absent():
    assert suggest_models("mistral:7b", INSTALLED) == []
    assert suggest_models("", INSTALLED) == []


def test_suggestions_are_capped():
    many = [f"foo:{i}b" for i in range(10)]
    assert len(suggest_models("foo:99b", many, limit=3)) == 3
