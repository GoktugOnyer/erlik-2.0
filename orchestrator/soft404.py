"""Measure a target's catch-all response size instead of hardcoding one.

erlik hardcodes `--exclude-length 3748` in five prompt sites. 3748 is the body
size of OWASP Juice Shop's catch-all page — a value specific to ONE target, in a
tool used on real client engagements. All 39 recorded gobuster invocations carry
it, which means a soft-404 control ALREADY runs universally at the tool
boundary; it is just calibrated to the wrong app everywhere except Juice Shop.

Two ways that is wrong on someone else's target:
  - the target has an honest 404, and the flag filters nothing (harmless but
    misleading), or worse, a genuine 3748-byte page is silently suppressed;
  - the target has a catch-all of a different size, so every path "found" is
    the same echoed page, and content discovery reports dozens of paths that
    do not exist.

This measures it per origin instead.

NOTE ON SCOPE: soft-404 SUPPRESSION of findings was deliberately NOT built.
Measured against the recorded corpus, all 60 `Content discovery:` rows score as
TRUE positives against ground truth, so suppressing them lowers precision
(0.903 -> 0.865) and costs recall on GT #23 (robots.txt). Suppressing a true
positive lowers precision whenever precision < 1. Only the measurement survives.

`classify()` is a pure function over probe samples with no I/O, so the state
machine is testable without a network.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

# Paths no real application serves. Fixed rather than random so a verdict is
# reproducible and two runs against the same host are comparable.
PROBE_PATHS = (
    "/erlik-probe-a9f31c2e",
    "/erlik-probe-4d7b0e15/nested",
    "/erlik-probe-c02a88f6.html",
    "/erlik-probe-71e5da39.json",
)

CATCHALL = "catchall"
HONEST_404 = "honest_404"
INDETERMINATE = "indeterminate"

# What erlik used before this module existed. An indeterminate verdict must
# render byte-identically to that, so the change is provably a no-op wherever
# the probe cannot reach a confident answer.
LEGACY_SIZE = 3748


@dataclass(frozen=True)
class Sample:
    path: str
    status: int
    length: int


@dataclass(frozen=True)
class Verdict:
    state: str
    size: int | None = None
    detail: str = ""

    @property
    def confident(self) -> bool:
        return self.state in (CATCHALL, HONEST_404)


def classify(samples: list[Sample]) -> Verdict:
    """Decide how an origin answers a path that does not exist.

    Pure. No I/O, so every branch is reachable in a unit test.

    catchall      every probe answered 2xx/3xx with the SAME body size
    honest_404    every probe answered 4xx
    indeterminate anything else — mixed statuses, or 200s of differing size

    Indeterminate is not a failure state, it is a refusal to guess: the caller
    keeps today's behaviour rather than acting on a shaky measurement.
    """
    if len(samples) < 2:
        return Verdict(INDETERMINATE, None, "need at least two probes")

    statuses = {s.status for s in samples}

    if all(400 <= s.status < 500 for s in samples):
        return Verdict(HONEST_404, None, f"all probes 4xx ({sorted(statuses)})")

    if all(200 <= s.status < 400 for s in samples):
        sizes = {s.length for s in samples}
        if len(sizes) == 1:
            size = sizes.pop()
            return Verdict(CATCHALL, size, f"all probes {sorted(statuses)}, {size} bytes")
        return Verdict(INDETERMINATE, None,
                       f"non-404 but sizes differ: {sorted(sizes)}")

    return Verdict(INDETERMINATE, None, f"mixed statuses {sorted(statuses)}")


def agree(a: Verdict, b: Verdict) -> Verdict:
    """Twin-probe stability check.

    A host that answers differently to two identical rounds is not stable
    enough to calibrate against, and a wrong catch-all size is worse than no
    filter — it silently suppresses real pages of that size.
    """
    if a.state != b.state or a.size != b.size:
        return Verdict(INDETERMINATE, None,
                       f"twin probes disagree: {a.state}/{a.size} vs {b.state}/{b.size}")
    return a


def filter_flag(verdict: Verdict | None, tool: str = "gobuster") -> str:
    """The size-filter flag for a discovery command, or "" when none applies.

    honest_404    -> "" — nothing to filter, and a flag here can suppress a
                     genuine page that happens to be that size
    catchall      -> filter on the MEASURED size
    indeterminate -> the legacy literal, byte-identical to erlik's old output
    """
    if verdict is None or verdict.state == INDETERMINATE:
        size = LEGACY_SIZE
    elif verdict.state == HONEST_404:
        return ""
    else:
        size = verdict.size

    if tool == "ffuf":
        return f"-fs {size}"
    return f"--exclude-length {size}"


def cache_key(target_url: str) -> str:
    return hashlib.sha256((target_url or "").encode("utf-8", "replace")).hexdigest()[:16]


_CACHE: dict[str, Verdict] = {}


def remember(target_url: str, verdict: Verdict) -> None:
    _CACHE[cache_key(target_url)] = verdict


def recall(target_url: str) -> Verdict | None:
    return _CACHE.get(cache_key(target_url))


def reset_cache() -> None:
    _CACHE.clear()


async def probe_origin(target_url: str, client=None) -> Verdict:
    """Request the probe paths twice and return a stability-checked verdict.

    Never raises: a target that cannot be probed is INDETERMINATE, which keeps
    erlik's existing behaviour rather than degrading it.
    """
    import httpx
    from urllib.parse import urlparse

    try:
        p = urlparse(target_url if "://" in target_url else f"http://{target_url}")
        origin = f"{p.scheme}://{p.netloc}"
    except ValueError:
        return Verdict(INDETERMINATE, None, "unparseable target")
    if not origin or origin.endswith("://"):
        return Verdict(INDETERMINATE, None, "no origin in target")

    owns = client is None
    if owns:
        client = httpx.AsyncClient(timeout=10.0, follow_redirects=False)
    try:
        rounds = []
        for _ in range(2):
            samples = []
            for path in PROBE_PATHS:
                try:
                    r = await client.get(origin + path)
                    samples.append(Sample(path, r.status_code, len(r.content)))
                except Exception:
                    return Verdict(INDETERMINATE, None, "probe request failed")
            rounds.append(classify(samples))
        verdict = agree(rounds[0], rounds[1])
    finally:
        if owns:
            await client.aclose()

    remember(target_url, verdict)
    return verdict
