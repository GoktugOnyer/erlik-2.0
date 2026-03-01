import httpx
import json
import re

OLLAMA_BASE = "http://localhost:11434"
MODEL = "qwen2.5-coder:7b-instruct-q4_K_M"


async def chat(messages: list[dict]) -> str:
    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(
            f"{OLLAMA_BASE}/api/chat",
            json={"model": MODEL, "messages": messages, "stream": False},
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"]


async def chat_json(messages: list[dict]) -> dict | None:
    content = await chat(messages)
    # Try direct parse
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass
    # Try extracting from markdown code block
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
            has_model = any(MODEL.split(":")[0] in m for m in models)
            return {
                "ollama": "connected",
                "models": models,
                "target_model": MODEL,
                "model_available": has_model,
            }
    except Exception as e:
        return {"ollama": "disconnected", "error": str(e)}
