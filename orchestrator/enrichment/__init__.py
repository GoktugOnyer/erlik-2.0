"""CVE / vulnerability enrichment for erlik-2.0.

Currently provides NVD-backed CVE enrichment (`nvd.py`). All enrichment is
gated behind the ``ERLIK_ENRICH_CVE`` env flag (default off) so the core
orchestrator makes no outbound calls unless explicitly enabled.
"""

from .nvd import enrichment_enabled, find_cve_ids, lookup_cve

__all__ = ["enrichment_enabled", "find_cve_ids", "lookup_cve"]
