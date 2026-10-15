"""A transient 5xx from the inference provider is retried, a 4xx is not.

A provider hiccup (502/503 from a gateway, a brief 500) is transient: one agent
run makes up to ~30 LLM calls, and surfacing the first 5xx would kill the run
partway through over an error that clears in seconds. These lock the retry path
for both the Ollama and OpenAI-compatible clients. A 4xx (a real client error)
must still surface immediately — retrying it only wastes the budget.
"""

import httpx
import pytest

from orchestrator import llm_client as L

OLLAMA_OK = {"message": {"content": "ok"}}
OPENAI_OK = {"choices": [{"message": {"content": "ok"}}]}


class FakeResp:
    def __init__(self, status, body=None, headers=None):
        self.status_code = status
        self._body = body or {}
        self.headers = headers or {}
        self.request = httpx.Request("POST", "http://inference.test")

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                f"HTTP {self.status_code}", request=self.request, response=self)

    def json(self):
        return self._body


class FakeClient:
    """One stateful client shared across attempts, so its call counter persists
    even though each retry opens a new `httpx.AsyncClient(...)`."""
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, **kw):
        r = self._responses[min(self.calls, len(self._responses) - 1)]
        self.calls += 1
        return r


@pytest.fixture(autouse=True)
def _no_backoff_sleep(monkeypatch):
    async def _instant(_):
        return None
    monkeypatch.setattr(L.asyncio, "sleep", _instant)


def _install(monkeypatch, responses):
    client = FakeClient(responses)
    monkeypatch.setattr(L.httpx, "AsyncClient", lambda *a, **k: client)
    return client


# --------------------------------------------------------------------- Ollama

async def test_ollama_retries_a_5xx_then_succeeds(monkeypatch):
    client = _install(monkeypatch, [FakeResp(503), FakeResp(200, OLLAMA_OK)])
    out = await L._ollama_chat([{"role": "user", "content": "hi"}], "m", max_retries=3)
    assert out == "ok"
    assert client.calls == 2, "the 503 must have been retried exactly once"


async def test_ollama_does_not_retry_a_4xx(monkeypatch):
    client = _install(monkeypatch, [FakeResp(400), FakeResp(200, OLLAMA_OK)])
    with pytest.raises(httpx.HTTPStatusError):
        await L._ollama_chat([{"role": "user", "content": "hi"}], "m", max_retries=3)
    assert client.calls == 1, "a 4xx must surface immediately, not retry"


async def test_ollama_gives_up_after_max_retries_on_persistent_5xx(monkeypatch):
    client = _install(monkeypatch, [FakeResp(500)])
    with pytest.raises(httpx.HTTPStatusError):
        await L._ollama_chat([{"role": "user", "content": "hi"}], "m", max_retries=3)
    assert client.calls == 3, "it must try exactly max_retries times, then raise"


# ------------------------------------------------------------ OpenAI-compatible

async def test_openai_retries_a_5xx_then_succeeds(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    client = _install(monkeypatch, [FakeResp(502), FakeResp(200, OPENAI_OK)])
    out = await L._openai_chat([{"role": "user", "content": "hi"}], "m", max_retries=3)
    assert out == "ok"
    assert client.calls == 2


async def test_openai_does_not_retry_a_4xx(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    client = _install(monkeypatch, [FakeResp(401), FakeResp(200, OPENAI_OK)])
    with pytest.raises(httpx.HTTPStatusError):
        await L._openai_chat([{"role": "user", "content": "hi"}], "m", max_retries=3)
    assert client.calls == 1
