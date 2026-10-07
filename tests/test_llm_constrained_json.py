"""Constrained / structured JSON decoding (ERLIK_CONSTRAINED_JSON).

The tool interface is a JSON action protocol over the model's text channel, and
small local models frequently emit malformed JSON. The knob lets an operator
ask the provider's own decoder to guarantee valid JSON — Ollama `format`,
OpenAI `response_format`.

Two properties are load-bearing and each has a mutation guard here:

1. OFF by default → the request body is byte-for-byte what it was before the
   knob existed. Delete the `_constrained_json_enabled()` check and
   `test_ollama_off_is_byte_for_byte_unchanged` /
   `test_openai_off_is_byte_for_byte_unchanged` fail.
2. Only JSON-shaped calls are constrained → a plain prose `chat()` (the session
   review, the executive summary) is never forced into JSON even with the knob
   on. Delete the `want_json and` half of the guard and
   `test_ollama_on_but_plain_chat_is_untouched` fails.

The bodies asserted here are the ACTUAL dicts handed to httpx, captured at the
transport boundary — not a re-implementation of request assembly (CLAUDE.md #3).
"""

import asyncio

import pytest

import orchestrator.llm_client as L


# --- transport capture ----------------------------------------------------

CONTENT = '{"action": "noop"}'


class _FakeResp:
    # One payload satisfies both the Ollama and the OpenAI content paths.
    _PAYLOAD = {
        "message": {"content": CONTENT},
        "choices": [{"message": {"content": CONTENT}}],
    }

    def raise_for_status(self):
        return None

    def json(self):
        return dict(self._PAYLOAD)


class _CaptureClient:
    """Stand-in for httpx.AsyncClient that records every POST body."""

    calls: list = []

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, json=None, headers=None):
        _CaptureClient.calls.append({"url": url, "json": json, "headers": headers})
        return _FakeResp()


@pytest.fixture
def capture(monkeypatch):
    _CaptureClient.calls = []
    monkeypatch.setattr(L.httpx, "AsyncClient", _CaptureClient)
    # No hosted-provider pacing in the tests.
    monkeypatch.setattr(L, "LLM_RPM", 0)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    return _CaptureClient


def _last_body():
    return _CaptureClient.calls[-1]["json"]


def _run(coro):
    return asyncio.run(coro)


# --- the flag parser -------------------------------------------------------

@pytest.mark.parametrize("val", ["1", "true", "TRUE", "Yes", "on", " on "])
def test_flag_truthy_values_enable(monkeypatch, val):
    monkeypatch.setenv("ERLIK_CONSTRAINED_JSON", val)
    assert L._constrained_json_enabled() is True


@pytest.mark.parametrize("val", ["", "0", "false", "no", "off", "maybe"])
def test_flag_falsy_values_stay_off(monkeypatch, val):
    monkeypatch.setenv("ERLIK_CONSTRAINED_JSON", val)
    assert L._constrained_json_enabled() is False


def test_flag_absent_is_off(monkeypatch):
    monkeypatch.delenv("ERLIK_CONSTRAINED_JSON", raising=False)
    assert L._constrained_json_enabled() is False


# --- Ollama ---------------------------------------------------------------

def test_ollama_off_is_byte_for_byte_unchanged(capture, monkeypatch):
    """Knob off: the body is exactly model/messages/stream, no `format`."""
    monkeypatch.delenv("ERLIK_CONSTRAINED_JSON", raising=False)
    msgs = [{"role": "user", "content": "hi"}]
    _run(L.chat(msgs, model="qwen2.5-coder:7b", provider="ollama", want_json=True))
    body = _last_body()
    assert body == {"model": "qwen2.5-coder:7b", "messages": msgs, "stream": False}
    assert "format" not in body


def test_ollama_on_and_want_json_adds_format_json(capture, monkeypatch):
    monkeypatch.setenv("ERLIK_CONSTRAINED_JSON", "1")
    _run(L.chat([{"role": "user", "content": "hi"}],
                model="qwen2.5-coder:7b", provider="ollama", want_json=True))
    assert _last_body()["format"] == "json"


def test_ollama_on_with_schema_sends_the_schema(capture, monkeypatch):
    monkeypatch.setenv("ERLIK_CONSTRAINED_JSON", "1")
    schema = {"type": "object", "properties": {"action": {"type": "string"}},
              "required": ["action"]}
    _run(L.chat([{"role": "user", "content": "hi"}], model="qwen2.5-coder:7b",
                provider="ollama", want_json=True, json_schema=schema))
    assert _last_body()["format"] == schema


def test_ollama_on_but_plain_chat_is_untouched(capture, monkeypatch):
    """The guard's `want_json` half: a prose call (session review, exec summary)
    must NOT be forced into JSON even with the knob on."""
    monkeypatch.setenv("ERLIK_CONSTRAINED_JSON", "1")
    _run(L.chat([{"role": "user", "content": "write prose"}],
                model="qwen2.5-coder:7b", provider="ollama"))
    assert "format" not in _last_body()


def test_ollama_constraint_coexists_with_num_ctx(capture, monkeypatch):
    """`format` sits beside `options`, it does not clobber the context budget."""
    monkeypatch.setenv("ERLIK_CONSTRAINED_JSON", "1")
    _run(L.chat([{"role": "user", "content": "hi"}], model="qwen2.5-coder:7b",
                provider="ollama", want_json=True, num_ctx=8192))
    body = _last_body()
    assert body["format"] == "json"
    assert body["options"]["num_ctx"] == 8192


# --- OpenAI / OpenAI-compatible -------------------------------------------

def test_openai_off_is_byte_for_byte_unchanged(capture, monkeypatch):
    monkeypatch.delenv("ERLIK_CONSTRAINED_JSON", raising=False)
    msgs = [{"role": "user", "content": "hi"}]
    _run(L.chat(msgs, model="gpt-4o", provider="openai", want_json=True))
    body = _last_body()
    assert body == {"model": "gpt-4o", "messages": msgs}
    assert "response_format" not in body


def test_openai_on_and_want_json_adds_json_object(capture, monkeypatch):
    monkeypatch.setenv("ERLIK_CONSTRAINED_JSON", "1")
    _run(L.chat([{"role": "user", "content": "hi"}],
                model="gpt-4o", provider="openai", want_json=True))
    assert _last_body()["response_format"] == {"type": "json_object"}


def test_openai_on_with_schema_uses_json_schema(capture, monkeypatch):
    monkeypatch.setenv("ERLIK_CONSTRAINED_JSON", "1")
    schema = {"name": "action", "schema": {"type": "object"}}
    _run(L.chat([{"role": "user", "content": "hi"}], model="gpt-4o",
                provider="openai", want_json=True, json_schema=schema))
    assert _last_body()["response_format"] == {
        "type": "json_schema", "json_schema": schema}


def test_openai_on_but_plain_chat_is_untouched(capture, monkeypatch):
    monkeypatch.setenv("ERLIK_CONSTRAINED_JSON", "1")
    _run(L.chat([{"role": "user", "content": "write prose"}],
                model="gpt-4o", provider="openai"))
    assert "response_format" not in _last_body()


# --- chat_json wires want_json through ------------------------------------

def test_chat_json_declares_want_json_ollama(capture, monkeypatch):
    """chat_json always wants JSON, so turning the knob on constrains it with no
    caller change."""
    monkeypatch.setenv("ERLIK_CONSTRAINED_JSON", "1")
    out = _run(L.chat_json([{"role": "user", "content": "hi"}],
                           model="qwen2.5-coder:7b", provider="ollama"))
    assert _last_body()["format"] == "json"
    assert out == {"action": "noop"}       # the canned reply still parses


def test_chat_json_off_still_parses_and_sends_no_format(capture, monkeypatch):
    monkeypatch.delenv("ERLIK_CONSTRAINED_JSON", raising=False)
    out = _run(L.chat_json([{"role": "user", "content": "hi"}],
                           model="qwen2.5-coder:7b", provider="ollama"))
    assert "format" not in _last_body()
    assert out == {"action": "noop"}


# --- the README documents what the code does (CLAUDE.md #7) ---------------

import pathlib

_README = (pathlib.Path(__file__).resolve().parents[1] / "README.md"
           ).read_text(encoding="utf-8", errors="replace")


def test_readme_documents_the_knob_and_its_default():
    assert "ERLIK_CONSTRAINED_JSON" in _README
    # The default-off promise is the load-bearing claim; if the code default
    # ever flips, this and the next test disagree and the suite breaks.
    assert "default off" in _README.lower()


def test_readme_default_matches_the_code(monkeypatch):
    """Doc says off by default; the code must agree with no env set."""
    monkeypatch.delenv("ERLIK_CONSTRAINED_JSON", raising=False)
    assert L._constrained_json_enabled() is False


def test_readme_names_both_provider_mechanisms():
    """Guard the guard (CLAUDE.md #5): if the README stops naming the real
    request fields, this parse fails rather than passing vacuously."""
    assert 'format: "json"' in _README        # Ollama
    assert "response_format" in _README        # OpenAI-compatible
