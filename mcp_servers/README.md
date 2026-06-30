# MCP Tool Servers

MCP servers that wrap erlik capabilities so an MCP-capable agent (Claude
Desktop, Claude Code, or any MCP client) can call them over stdio.

The core FastAPI orchestrator does **not** depend on `mcp` — these servers are
the only place it's imported. Install the extra dependency separately:

```bash
pip install -r requirements-mcp.txt
```

## `cve/` — CVE enrichment (NVD)

Exposes erlik's free, no-API-key NVD enrichment
(`orchestrator/enrichment/nvd.py`) as MCP tools.

Run it:

```bash
python -m mcp_servers.cve.server
```

Tools:

| Tool | Purpose |
|------|---------|
| `enrich_cve` | CVSS score / severity / vector / CWE for one CVE (disk-cached) |
| `bulk_enrich_cves` | Enrich a de-duplicated list, rate-limit aware |
| `get_cached_cve` | Read a CVE from the local cache without hitting NVD |
| `cache_stats` | Cache size, location, sample entries |

Config (all optional):

- `ERLIK_CVE_CACHE_DIR` — cache location (default `data/cve_cache/`)
- `ERLIK_CVE_RATE_LIMIT` — requests/min (default `8`)
- `NVD_API_KEY` — raises the NVD rate limit (never required)

Example Claude Desktop entry (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "erlik-cve": {
      "command": "python",
      "args": ["-m", "mcp_servers.cve.server"],
      "cwd": "/path/to/erlik-2.0"
    }
  }
}
```

The server shell (Server / list_tools / call_tool / stdio bootstrap, the
rate limiter and disk cache) is adapted from the MIT-licensed
[transilienceai/communitytools](https://github.com/transilienceai/communitytools)
`mcp/transilience-vuln` server, with its hosted backend replaced by the NVD
core. See `THIRD_PARTY_LICENSES.md`.
