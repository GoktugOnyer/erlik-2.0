"""NVD CVE enrichment for erlik-2.0.

Adapted from transilienceai/communitytools (MIT), tools/nvd-lookup.py:
    https://github.com/transilienceai/communitytools
See THIRD_PARTY_LICENSES.md and licenses/communitytools-MIT.txt.

Changes from the original:
  * Reworked the synchronous urllib CLI tool into an async, importable
    ``lookup_cve(cve_id) -> dict`` built on ``httpx`` (matching the retry /
    timeout style used in ``orchestrator/llm_client.py``).
  * Added an in-process TTL cache and a CVE-id regex guard so non-CVE
    findings are skipped cheaply and repeated lookups don't re-hit NVD.
  * Dropped the human-readable formatter / ``JSON_SUMMARY`` stdout contract.

The CVSS / CWE / severity extraction logic is retained from the original.

NVD's free API needs no key (rate-limited to ~5 req/30s). Set ``NVD_API_KEY``
for a higher limit. All network access is gated by ``ERLIK_ENRICH_CVE``.
"""

from __future__ import annotations

import asyncio
import html as html_module
import os
import re
import time
import urllib.parse

import httpx

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_WEB_URL = "https://nvd.nist.gov/vuln/detail"

# Strict CVE id form: CVE-YYYY-NNNN(+)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

_API_KEY = os.environ.get("NVD_API_KEY") or None
_CACHE_TTL = float(os.environ.get("ERLIK_CVE_CACHE_TTL", "86400"))  # 24h default

# cve_id -> (monotonic_ts, result_dict)
_CACHE: dict[str, tuple[float, dict]] = {}


def enrichment_enabled() -> bool:
    """True when CVE enrichment (and its outbound calls) is opted in via env."""
    return os.environ.get("ERLIK_ENRICH_CVE", "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def find_cve_ids(*texts: str) -> list[str]:
    """Extract unique, upper-cased CVE ids from arbitrary text fragments."""
    seen: dict[str, None] = {}
    for t in texts:
        if not t:
            continue
        for m in CVE_RE.findall(t):
            seen[m.upper()] = None
    return list(seen.keys())


# --- extraction helpers (retained from communitytools/tools/nvd-lookup.py) ---


def severity_label(score: float | None) -> str:
    """Map a CVSS base score to a severity label."""
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def extract_cvss(metrics: dict) -> dict:
    """Extract the best available CVSS scores from an NVD metrics object."""
    result: dict[str, dict] = {}
    for version_key, label in [
        ("cvssMetricV31", "CVSS v3.1"),
        ("cvssMetricV30", "CVSS v3.0"),
        ("cvssMetricV2", "CVSS v2.0"),
    ]:
        entries = metrics.get(version_key, [])
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        cvss = entry.get("cvssData", {})
        result[label] = {
            "score": cvss.get("baseScore"),
            "severity": cvss.get("baseSeverity", entry.get("baseSeverity", "UNKNOWN")),
            "vector": cvss.get("vectorString"),
        }
    for entry in metrics.get("cvssMetricV40", []):
        cvss = entry.get("cvssData", {})
        result["CVSS v4.0"] = {
            "score": cvss.get("baseScore"),
            "severity": cvss.get("baseSeverity", "UNKNOWN"),
            "vector": cvss.get("vectorString"),
        }
    return result


def extract_cwes(weaknesses: list) -> list[str]:
    """Extract deduplicated CWE ids from NVD weakness data."""
    cwes: list[str] = []
    for w in weaknesses:
        for desc in w.get("descriptions", []):
            val = desc.get("value", "")
            if val.startswith("CWE-") or val == "NVD-CWE-noinfo":
                cwes.append(val)
    return list(dict.fromkeys(cwes))  # dedupe, preserve order


def _parse_nvd_html(html: str) -> dict:
    """Best-effort scrape of CVSS/CWE from the NVD detail page (fallback)."""
    result: dict = {"cvss3_score": None, "cvss3_severity": None,
                    "cvss3_vector": None, "cwes": []}
    m = re.search(r'data-testid="vuln-cvss3-\w+-panel-score"[^>]*>([^<]+)', html)
    if m:
        text = m.group(1).strip()
        score_match = re.search(r"(\d+\.?\d*)", text)
        if score_match:
            result["cvss3_score"] = float(score_match.group(1))
            upper = text.upper()
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                if sev in upper:
                    result["cvss3_severity"] = sev
                    break
    m = re.search(r'v3-calculator\?[^"]*vector=([^&"]+)', html)
    if m:
        vector = urllib.parse.unquote(m.group(1))
        result["cvss3_vector"] = (
            vector if vector.startswith("CVSS:") else f"CVSS:3.1/{vector}"
        )
    for m in re.finditer(r'data-testid="vuln-CWEs-link-\d+"[^>]*>([^<]+)', html):
        val = html_module.unescape(m.group(1).strip())
        if val.startswith("CWE-"):
            result["cwes"].append(val)
    return result


# --- async fetchers (httpx, erlik-style retry/timeout) ---


async def _fetch_api(cve_id: str, *, max_retries: int = 3) -> dict:
    url = f"{NVD_API_URL}?cveId={urllib.parse.quote(cve_id)}"
    headers = {"User-Agent": "erlik-2.0-nvd-enrichment/1.0"}
    if _API_KEY:
        headers["apiKey"] = _API_KEY
    last_error: Exception | None = None
    for attempt in range(max_retries):
        timeout = 30.0 + attempt * 15.0
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(url, headers=headers)
                resp.raise_for_status()
                return resp.json()
        except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError) as e:
            last_error = e
            if attempt < max_retries - 1:
                await asyncio.sleep(2 ** attempt)
                continue
        except Exception as e:  # noqa: BLE001 — never let enrichment crash a session
            last_error = e
            break
    return {"error": str(last_error) if last_error else "unknown API error"}


async def _fetch_web(cve_id: str) -> dict:
    """Scrape the NVD website as a fallback and shape it like the API result."""
    url = f"{NVD_WEB_URL}/{urllib.parse.quote(cve_id)}"
    headers = {"User-Agent": "Mozilla/5.0 (compatible; erlik-2.0-nvd-enrichment/1.0)"}
    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            parsed = _parse_nvd_html(resp.text)
    except Exception as e:  # noqa: BLE001
        return {"error": f"website fallback failed: {e}"}

    if parsed["cvss3_score"] is None:
        return {"vulnerabilities": []}  # nothing usable scraped
    severity = parsed["cvss3_severity"] or severity_label(parsed["cvss3_score"])
    weaknesses = (
        [{"descriptions": [{"lang": "en", "value": c} for c in parsed["cwes"]]}]
        if parsed["cwes"] else []
    )
    return {
        "_source": "website",
        "vulnerabilities": [{
            "cve": {
                "id": cve_id,
                "vulnStatus": "N/A (scraped)",
                "metrics": {
                    "cvssMetricV31": [{
                        "type": "Primary",
                        "cvssData": {
                            "baseScore": parsed["cvss3_score"],
                            "baseSeverity": severity,
                            "vectorString": parsed["cvss3_vector"] or "N/A",
                        },
                    }]
                },
                "weaknesses": weaknesses,
            }
        }],
    }


def _summarize(cve_id: str, data: dict) -> dict:
    """Reduce an NVD response to the fields erlik stores on a finding."""
    base = {
        "cve_id": cve_id,
        "cvss_score": None,
        "cvss_vector": None,
        "severity": "UNKNOWN",
        "cwes": [],
        "status": "not_found",
    }
    if "error" in data:
        base["status"] = "error"
        base["error"] = data["error"]
        return base
    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return base
    cve = vulns[0].get("cve", {})
    metrics = extract_cvss(cve.get("metrics", {}))
    best_score = None
    best_sev = "UNKNOWN"
    best_vec = None
    for info in metrics.values():
        s = info.get("score")
        if s is not None and (best_score is None or s > best_score):
            best_score = s
            best_sev = info.get("severity") or severity_label(s)
            best_vec = info.get("vector")
    base.update({
        "cvss_score": best_score,
        "cvss_vector": best_vec,
        "severity": best_sev if best_score is not None else "UNKNOWN",
        "cwes": extract_cwes(cve.get("weaknesses", [])),
        "status": cve.get("vulnStatus", "found"),
    })
    return base


async def lookup_cve(cve_id: str) -> dict:
    """Look up a single CVE on NVD and return a normalized summary dict.

    Returns ``{cve_id, cvss_score, cvss_vector, severity, cwes, status}``.
    Never raises — failures surface as ``status`` of ``"invalid"``,
    ``"not_found"`` or ``"error"``. Tries the NVD API first, then falls back
    to scraping the NVD detail page. Results are cached in-process (TTL).
    """
    cve_id = (cve_id or "").strip().upper()
    if not CVE_RE.fullmatch(cve_id):
        return {
            "cve_id": cve_id, "cvss_score": None, "cvss_vector": None,
            "severity": "UNKNOWN", "cwes": [], "status": "invalid",
        }

    now = time.monotonic()
    cached = _CACHE.get(cve_id)
    if cached and (now - cached[0]) < _CACHE_TTL:
        return cached[1]

    data = await _fetch_api(cve_id)
    if "error" in data or not data.get("vulnerabilities"):
        web = await _fetch_web(cve_id)
        if "error" not in web and web.get("vulnerabilities"):
            data = web

    result = _summarize(cve_id, data)
    # Cache everything except hard errors so transient failures can retry.
    if result["status"] != "error":
        _CACHE[cve_id] = (now, result)
    return result
