"""erlik CVE enrichment MCP server (Phase 4).

A stdio MCP server that exposes erlik's NVD CVE enrichment
(`orchestrator/enrichment/nvd.py`) as MCP tools, so an MCP-capable agent can
look up CVSS / severity / CWE for CVE ids.

Server shell (Server / @list_tools / @call_tool / stdio bootstrap, the
sliding-window RateLimiter, and the disk cache) is adapted from
transilienceai/communitytools (MIT), mcp/transilience-vuln/server.py — with the
hosted-SaaS backend swapped for erlik's free, no-key NVD core. See
THIRD_PARTY_LICENSES.md and licenses/communitytools-MIT.txt.

This module deliberately lives OUTSIDE the `orchestrator` package and is the
only place that imports `mcp`, so the core FastAPI orchestrator never depends on
it. Install its extra dep with:  pip install -r requirements-mcp.txt
Run with:  python -m mcp_servers.cve.server
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections import deque
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

# Make `orchestrator` importable regardless of the launcher's working directory
# (Claude Code's MCP config has no cwd option), so this server can be registered
# by absolute path from any project: python /abs/path/mcp_servers/cve/server.py
import sys  # noqa: E402
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from orchestrator.enrichment.nvd import CVE_RE, lookup_cve  # noqa: E402

log = logging.getLogger("erlik-cve-mcp")

# Project-local cache dir (NOT ~/). Override with ERLIK_CVE_CACHE_DIR.
CACHE_DIR = Path(
    os.environ.get(
        "ERLIK_CVE_CACHE_DIR",
        str(Path(__file__).resolve().parents[2] / "data" / "cve_cache"),
    )
)
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# NVD without a key allows ~5 req / 30s. Stay comfortably under that.
RATE_LIMIT_PER_MIN = int(os.environ.get("ERLIK_CVE_RATE_LIMIT", "8"))


class RateLimiter:
    """Sliding-window rate limiter, asyncio-safe.

    Adapted from communitytools/mcp/transilience-vuln/server.py (MIT).
    """

    def __init__(self, max_per_min: int):
        self.max = max_per_min
        self.window = 60.0
        self.calls: deque[float] = deque()
        self.lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self.lock:
            now = time.monotonic()
            while self.calls and now - self.calls[0] >= self.window:
                self.calls.popleft()
            if len(self.calls) >= self.max:
                wait = self.window - (now - self.calls[0]) + 0.05
                log.info("Rate limit reached, sleeping %.2fs", wait)
                await asyncio.sleep(wait)
                now = time.monotonic()
                while self.calls and now - self.calls[0] >= self.window:
                    self.calls.popleft()
            self.calls.append(time.monotonic())


limiter = RateLimiter(RATE_LIMIT_PER_MIN)


# --- disk cache (adapted from communitytools, MIT) ------------------------- #

def cache_path(cve_id: str) -> Path:
    return CACHE_DIR / f"{cve_id.upper()}.json"


def cache_get(cve_id: str) -> dict | None:
    p = cache_path(cve_id)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError) as e:
        log.warning("Cache read failed for %s: %s", cve_id, e)
        return None


def cache_put(cve_id: str, payload: dict) -> None:
    try:
        cache_path(cve_id).write_text(json.dumps(payload))
    except OSError as e:
        log.warning("Cache write failed for %s: %s", cve_id, e)


async def fetch(cve_id: str, *, use_cache: bool = True) -> tuple[dict, str]:
    """Return (nvd_summary, source) where source is cache|api|validation.

    nvd_summary is exactly what orchestrator.enrichment.nvd.lookup_cve returns:
    {cve_id, cvss_score, cvss_vector, severity, cwes, status}.
    """
    cve_id = (cve_id or "").strip().upper()
    if not CVE_RE.fullmatch(cve_id):
        return ({"cve_id": cve_id, "cvss_score": None, "cvss_vector": None,
                 "severity": "UNKNOWN", "cwes": [], "status": "invalid"}, "validation")
    if use_cache:
        cached = cache_get(cve_id)
        if cached is not None:
            return cached, "cache"
    await limiter.acquire()
    result = await lookup_cve(cve_id)
    if result.get("status") != "error":
        cache_put(cve_id, result)
    return result, "api"


# --------------------------------------------------------------------------- #
# MCP server
# --------------------------------------------------------------------------- #

server = Server("erlik-cve")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="enrich_cve",
            description=(
                "Look up a single CVE on NVD and return CVSS score, severity, "
                "CVSS vector and CWE ids. Cached on disk so repeated lookups of "
                "the same CVE don't re-hit NVD. No API key required."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string", "description": "e.g. CVE-2021-44228"},
                    "force_refresh": {
                        "type": "boolean",
                        "description": "Bypass cache and re-fetch from NVD",
                        "default": False,
                    },
                },
                "required": ["cve_id"],
            },
        ),
        Tool(
            name="bulk_enrich_cves",
            description=(
                "Enrich a list of CVE ids. De-duplicates and respects the NVD "
                "rate limit automatically; uncached lookups are slow (~6s each "
                "without an API key)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "cve_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of CVE ids",
                    },
                    "force_refresh": {"type": "boolean", "default": False},
                },
                "required": ["cve_ids"],
            },
        ),
        Tool(
            name="get_cached_cve",
            description="Read a previously-fetched CVE from local cache without calling NVD.",
            inputSchema={
                "type": "object",
                "properties": {"cve_id": {"type": "string"}},
                "required": ["cve_id"],
            },
        ),
        Tool(
            name="cache_stats",
            description="Show CVE cache size, location, and a few sample entries.",
            inputSchema={"type": "object", "properties": {}},
        ),
    ]


def _text(obj: Any) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps(obj, indent=2, default=str))]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        if name == "enrich_cve":
            payload, source = await fetch(
                arguments.get("cve_id", ""),
                use_cache=not arguments.get("force_refresh", False),
            )
            return _text({"source": source, "data": payload})

        if name == "bulk_enrich_cves":
            cve_ids = arguments.get("cve_ids") or []
            if not isinstance(cve_ids, list) or not cve_ids:
                return _text({"error": "cve_ids must be a non-empty list"})
            force = arguments.get("force_refresh", False)
            seen: set[str] = set()
            unique: list[str] = []
            for c in cve_ids:
                u = str(c).upper().strip()
                if u not in seen:
                    seen.add(u)
                    unique.append(u)
            results: dict[str, dict] = {}
            counts = {"cache": 0, "api": 0, "validation": 0, "error": 0}
            for cve_id in unique:
                payload, source = await fetch(cve_id, use_cache=not force)
                counts[source] = counts.get(source, 0) + 1
                if payload.get("status") == "error":
                    counts["error"] += 1
                results[cve_id] = payload
            return _text({
                "summary": {
                    "requested": len(unique),
                    "from_cache": counts["cache"],
                    "from_api": counts["api"],
                    "errors": counts["error"],
                },
                "results": results,
            })

        if name == "get_cached_cve":
            cve_id = arguments.get("cve_id", "").upper().strip()
            if not CVE_RE.fullmatch(cve_id):
                return _text({"error": "invalid_format", "cve": cve_id})
            cached = cache_get(cve_id)
            if cached is None:
                return _text({"cve": cve_id, "cached": False})
            return _text({"cve": cve_id, "cached": True, "data": cached})

        if name == "cache_stats":
            files = list(CACHE_DIR.glob("CVE-*.json"))
            return _text({
                "cache_dir": str(CACHE_DIR),
                "cached_cve_count": len(files),
                "sample_entries": sorted(f.stem for f in files)[:10],
                "rate_limit_per_min": RATE_LIMIT_PER_MIN,
            })

        return _text({"error": f"unknown tool: {name}"})

    except Exception as e:  # noqa: BLE001 — surface unexpected errors to the caller
        log.exception("Tool %s failed", name)
        return _text({"error": "tool_exception", "tool": name, "detail": str(e)})


async def main() -> None:
    log.info("Starting erlik-cve MCP server on stdio")
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def cli() -> None:
    """Sync entry point."""
    asyncio.run(main())


if __name__ == "__main__":
    cli()
