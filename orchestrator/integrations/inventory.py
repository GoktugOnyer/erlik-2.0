"""Identity-specific inventory shared by discovery and downstream testing."""
from urllib.parse import urldefrag
from . import persistence as db
from .egress_policy import EgressPolicy


async def seeds(context, policy):
    rows = await db.rows("SELECT url,method FROM integration_endpoints WHERE session_id=? AND identity_id=? ORDER BY url,method",
                         (context.session_id, context.identity_id))
    candidates = [{"url": context.target, "method": "GET"}, *rows]
    selected, seen = [], set()
    for item in candidates:
        url = urldefrag(item["url"])[0]
        method = item["method"].upper()
        if method not in ("GET", "HEAD", "OPTIONS") or url in seen:
            continue
        if not EgressPolicy(policy).check(url, method)[0]:
            continue
        seen.add(url)
        selected.append(url)
    return selected[:context.config.max_urls]


def eligible_test_cases(url, method="GET"):
    # These catalogue checks have a supported deterministic HTTP execution path.
    return ["WSTG-SESS-02", "WSTG-CONF-06", "WSTG-CLNT-07"] if method == "GET" else []
