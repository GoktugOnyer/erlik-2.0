import asyncio
import httpx
import json
import re

OLLAMA_BASE = "http://localhost:11434"
DEFAULT_MODEL = "qwen2.5-coder:7b-instruct-q4_K_M"


async def list_models() -> list[str]:
    """Fetch available models from Ollama."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{OLLAMA_BASE}/api/tags")
            resp.raise_for_status()
            return [m["name"] for m in resp.json().get("models", [])]
    except Exception:
        return []


async def chat(messages: list[dict], model: str | None = None, max_retries: int = 3) -> str:
    """Call Ollama chat API with exponential backoff retry on transient failures.

    Retries on timeout and connection errors with escalating timeouts:
    attempt 1: 120s, attempt 2: 180s, attempt 3: 240s
    Non-retryable errors (4xx, parse errors) fail immediately.
    """
    use_model = model or DEFAULT_MODEL
    last_error = None

    for attempt in range(max_retries):
        timeout = 120.0 + (attempt * 60.0)  # 120s, 180s, 240s
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(
                    f"{OLLAMA_BASE}/api/chat",
                    json={"model": use_model, "messages": messages, "stream": False},
                )
                resp.raise_for_status()
                return resp.json()["message"]["content"]
        except (httpx.TimeoutException, httpx.ConnectError) as e:
            last_error = e
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt  # 1s, 2s backoff
                await asyncio.sleep(wait_time)
                continue
            raise
        except Exception:
            raise  # Non-retryable errors fail immediately

    raise last_error


async def chat_json(messages: list[dict], model: str | None = None) -> dict | None:
    content = await chat(messages, model=model)
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass
    match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", content, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    return None


async def health_check() -> dict:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{OLLAMA_BASE}/api/tags")
            resp.raise_for_status()
            models = [m["name"] for m in resp.json().get("models", [])]
            has_model = any(DEFAULT_MODEL.split(":")[0] in m for m in models)
            return {
                "ollama": "connected",
                "models": models,
                "target_model": DEFAULT_MODEL,
                "model_available": has_model,
            }
    except Exception as e:
        return {"ollama": "disconnected", "error": str(e)}
