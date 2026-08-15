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


# --- the configured default must be usable --------------------------------

def test_default_model_is_a_plain_pullable_tag():
    """The default was "qwen2.5-coder:7b-instruct-q4_K_M", which is not what
    `ollama pull qwen2.5-coder:7b` installs, so every run on the default died on
    its first generation."""
    import orchestrator.llm_client as L
    assert L.OLLAMA_DEFAULT_MODEL == "qwen2.5-coder:7b"


def test_stale_default_is_gone_from_the_shipped_defaults():
    """It was hard-coded in eight places; a survivor would reintroduce the bug."""
    import pathlib
    stale = "qwen2.5-coder:7b-instruct-q4_K_M"
    root = pathlib.Path(__file__).resolve().parents[1]
    for rel in ("orchestrator/database.py", "orchestrator/models.py",
                "dashboard/templates/index.html", "setup.sh"):
        text = (root / rel).read_text(encoding="utf-8", errors="replace")
        assert stale not in text, f"{rel} still defaults to a model that is not installed"


# --- fail fast, never substitute ------------------------------------------

def _run(coro):
    import asyncio
    return asyncio.run(coro)


def test_available_model_passes_through(monkeypatch):
    import orchestrator.llm_client as L

    async def fake_list():
        return ["qwen2.5-coder:7b", "qwen3.5:35b"]
    monkeypatch.setattr(L, "_ollama_list_models", fake_list)
    monkeypatch.setattr(L, "PROVIDER", "ollama")
    assert _run(L.ensure_model_available("qwen2.5-coder:7b")) == "qwen2.5-coder:7b"


def test_missing_model_raises_before_the_run_with_a_usable_message(monkeypatch):
    import orchestrator.llm_client as L

    async def fake_list():
        return ["qwen2.5-coder:7b", "qwen2.5-coder:7b-juicy2"]
    monkeypatch.setattr(L, "_ollama_list_models", fake_list)
    monkeypatch.setattr(L, "PROVIDER", "ollama")

    with pytest.raises(L.ModelUnavailable) as e:
        _run(L.ensure_model_available("qwen2.5-coder:7b-instruct-q4_K_M"))
    msg = str(e.value)
    assert "not installed" in msg
    assert "qwen2.5-coder:7b" in msg          # names the near miss
    assert "ollama pull" in msg               # tells you how to fix it


def test_a_fine_tune_is_never_silently_substituted(monkeypatch):
    """This machine carries qwen2.5-coder:7b-juicy2 and -cipher beside the base
    model. Falling back to a target-tuned variant would corrupt a baseline run
    while looking entirely normal, so the only safe behaviour is to refuse."""
    import orchestrator.llm_client as L

    async def fake_list():
        return ["qwen2.5-coder:7b-juicy2", "qwen2.5-coder:7b-cipher"]
    monkeypatch.setattr(L, "_ollama_list_models", fake_list)
    monkeypatch.setattr(L, "PROVIDER", "ollama")

    with pytest.raises(L.ModelUnavailable):
        _run(L.ensure_model_available("qwen2.5-coder:7b"))


def test_unreachable_ollama_does_not_block_the_run(monkeypatch):
    """An empty list means the daemon did not answer, not that nothing is
    installed — let the request surface the transport error instead."""
    import orchestrator.llm_client as L

    async def fake_list():
        return []
    monkeypatch.setattr(L, "_ollama_list_models", fake_list)
    monkeypatch.setattr(L, "PROVIDER", "ollama")
    assert _run(L.ensure_model_available("anything:1b")) == "anything:1b"


def test_remote_provider_is_not_checked_against_ollama(monkeypatch):
    import orchestrator.llm_client as L
    monkeypatch.setattr(L, "PROVIDER", "openai")
    assert _run(L.ensure_model_available("gpt-4o")) == "gpt-4o"
