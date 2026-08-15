import asyncio
import os
import httpx
import json
import re

# Provider selection via env. Default keeps existing local Ollama behaviour.
#   ERLIK_LLM_PROVIDER = ollama | openai
#   ERLIK_LLM_MODEL    = model id override (provider-specific)
#
# Cloud / remote inference:
#   openai → OPENAI_API_KEY, optional OPENAI_BASE_URL for any OpenAI-compatible
#            gateway (OpenRouter, Groq, Together, a self-hosted vLLM, etc.)
PROVIDER = os.environ.get("ERLIK_LLM_PROVIDER", "ollama").lower()

OLLAMA_BASE = os.environ.get("OLLAMA_BASE", "http://localhost:11434")
# Must be a tag Ollama can actually serve. This was
# "qwen2.5-coder:7b-instruct-q4_K_M", which is not what `ollama pull
# qwen2.5-coder:7b` installs — every run on the default 404'd on its first
# generation while /api/health reported the model as available.
OLLAMA_DEFAULT_MODEL = "qwen2.5-coder:7b"

OPENAI_BASE = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
OPENAI_DEFAULT_MODEL = os.environ.get("OPENAI_DEFAULT_MODEL", "gpt-4o")


def _default_model() -> str:
    override = os.environ.get("ERLIK_LLM_MODEL")
    if override:
        return override
    if PROVIDER == "openai":
        return OPENAI_DEFAULT_MODEL
    return OLLAMA_DEFAULT_MODEL


# Back-compat: external callers still import DEFAULT_MODEL.
DEFAULT_MODEL = _default_model()


def _get_inference_seed() -> int | None:
    val = os.environ.get("ERLIK_OLLAMA_SEED")
    if val is None or val == "":
        return None
    try:
        return int(val)
    except ValueError:
        return None


# ---------- Ollama (local inference) ----------

async def _ollama_chat(messages: list[dict], model: str, max_retries: int) -> str:
    body = {"model": model, "messages": messages, "stream": False}
    seed = _get_inference_seed()
    if seed is not None:
        body["options"] = {"seed": seed}

    last_error = None
    for attempt in range(max_retries):
        timeout = 120.0 + (attempt * 60.0)
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(f"{OLLAMA_BASE}/api/chat", json=body)
                resp.raise_for_status()
                return resp.json()["message"]["content"]
        except httpx.HTTPStatusError as e:
            # Retry transient server errors (5xx); surface 4xx immediately.
            last_error = e
            if e.response.status_code >= 500 and attempt < max_retries - 1:
                await asyncio.sleep(2 ** attempt)
                continue
            raise
        except (httpx.TimeoutException, httpx.ConnectError) as e:
            last_error = e
            if attempt < max_retries - 1:
                await asyncio.sleep(2 ** attempt)
                continue
            raise
    raise last_error


async def _ollama_list_models() -> list[str]:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{OLLAMA_BASE}/api/tags")
            resp.raise_for_status()
            return [m["name"] for m in resp.json().get("models", [])]
    except Exception:
        return []


def model_installed(target: str, models: list[str]) -> bool:
    """Whether Ollama can actually serve `target`.

    Must be an EXACT tag match. The previous check compared only the family name
    (`target.split(":")[0] in m`), so a configured
    "qwen2.5-coder:7b-instruct-q4_K_M" was reported available because an
    unrelated "qwen2.5-coder:7b" was installed — the dashboard showed green while
    every generation 404'd on the first call.

    The one exception is Ollama's own rule that a bare name resolves to :latest.
    """
    if not target:
        return False
    names = set(models or [])
    if target in names:
        return True
    return ":" not in target and f"{target}:latest" in names


def suggest_models(target: str, models: list[str], limit: int = 3) -> list[str]:
    """Installed tags in the same family as `target` — what the operator probably
    meant. Surfaced so a near-miss like a wrong quantisation suffix is obvious."""
    if not target:
        return []
    family = target.split(":")[0].strip().lower()
    if not family:
        return []
    return sorted(m for m in (models or [])
                  if m.split(":")[0].strip().lower() == family)[:limit]


async def _ollama_health() -> dict:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{OLLAMA_BASE}/api/tags")
            resp.raise_for_status()
            models = [m["name"] for m in resp.json().get("models", [])]
            target = _default_model()
            available = model_installed(target, models)
            out = {
                "provider": "ollama",
                "ollama": "connected",
                "models": models,
                "target_model": target,
                "model_available": available,
            }
            if not available:
                out["model_suggestions"] = suggest_models(target, models)
                out["hint"] = f"ollama pull {target}"
            return out
    except Exception as e:
        return {"provider": "ollama", "ollama": "disconnected", "error": str(e)}


# ---------- OpenAI / OpenAI-compatible (remote inference) ----------

async def _openai_chat(messages: list[dict], model: str, max_retries: int) -> str:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set")

    body = {"model": model, "messages": messages}
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    last_error = None
    for attempt in range(max_retries):
        timeout = 120.0 + (attempt * 60.0)
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(
                    f"{OPENAI_BASE}/chat/completions", json=body, headers=headers
                )
                resp.raise_for_status()
                data = resp.json()
                return data["choices"][0]["message"]["content"] or ""
        except httpx.HTTPStatusError as e:
            # Retry transient server errors (5xx); surface 4xx (incl. 401/429) immediately.
            last_error = e
            if e.response.status_code >= 500 and attempt < max_retries - 1:
                await asyncio.sleep(2 ** attempt)
                continue
            raise
        except (httpx.TimeoutException, httpx.ConnectError) as e:
            last_error = e
            if attempt < max_retries - 1:
                await asyncio.sleep(2 ** attempt)
                continue
            raise
    raise last_error


async def _openai_list_models() -> list[str]:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return []
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"{OPENAI_BASE}/models",
                headers={"Authorization": f"Bearer {api_key}"},
            )
            resp.raise_for_status()
            return [m["id"] for m in resp.json().get("data", [])]
    except Exception:
        return []


async def _openai_health() -> dict:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return {"provider": "openai", "status": "disconnected", "error": "OPENAI_API_KEY not set"}
    return {
        "provider": "openai",
        "status": "configured",
        "base_url": OPENAI_BASE,
        "target_model": _default_model(),
    }


# ---------- Public API (unchanged signatures) ----------

async def list_models() -> list[str]:
    if PROVIDER == "openai":
        return await _openai_list_models()
    return await _ollama_list_models()


class ModelUnavailable(RuntimeError):
    """The requested model is not installed, raised BEFORE a run starts."""


async def ensure_model_available(model: str | None = None) -> str:
    """Check the model can be served, and return the tag that will be used.

    Deliberately raises instead of substituting a near neighbour. The model is an
    experimental variable, and this machine has `qwen2.5-coder:7b-juicy2` and
    `-cipher` installed alongside the base `qwen2.5-coder:7b` — quietly falling
    back to a target-tuned variant would corrupt a baseline run while looking
    perfectly normal in the logs. Fail loudly, name the near misses, let the
    operator choose.

    Only meaningful for Ollama; a remote provider validates at request time.
    """
    use_model = model or _default_model()
    if PROVIDER != "ollama":
        return use_model

    installed = await _ollama_list_models()
    if not installed:
        # Ollama unreachable — let the request itself produce the transport error
        # rather than blocking a run on a health probe that may just have raced.
        return use_model
    if model_installed(use_model, installed):
        return use_model

    near = suggest_models(use_model, installed)
    hint = f" Closest installed: {', '.join(near)}." if near else ""
    raise ModelUnavailable(
        f"Model '{use_model}' is not installed in Ollama.{hint} "
        f"Pull it with `ollama pull {use_model}`, or set ERLIK_LLM_MODEL "
        f"(or pick a model in the dashboard) to one that is installed.")


async def chat(messages: list[dict], model: str | None = None, max_retries: int = 3) -> str:
    use_model = model or _default_model()
    if PROVIDER == "openai":
        return await _openai_chat(messages, use_model, max_retries)
    return await _ollama_chat(messages, use_model, max_retries)


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
    if PROVIDER == "openai":
        return await _openai_health()
    return await _ollama_health()
