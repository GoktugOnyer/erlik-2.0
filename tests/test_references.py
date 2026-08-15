"""Tests for deterministic reference / ATT&CK derivation.

The `mitre` and `ref_links` columns existed on the findings table, were declared
on the model, and were read by the report builder — but nothing ever wrote them.
`mitre` received a hardcoded None from the only UPDATE that touched it, and
`ref_links` had no writer at all, so ReportFinding.references was always empty
and the HTML report's References section (gated on `if refs:`) never rendered.

The derivation is deterministic by design: every URL is constructed from data
already on the row, so it is correct by construction rather than recalled by a
model. The URL-shape tests below therefore pin real, verifiable formats — a
fabricated citation in a client-ready security report is worse than none.
"""

import asyncio

import pytest

import orchestrator.database as db_mod
import orchestrator.main as main_mod
from orchestrator.references import (build_ref_links, cve_url, cwe_url, mitre_for,
                                     owasp_url, serialise_ref_links)


# --- URL construction -----------------------------------------------------

@pytest.mark.parametrize("cwe, expected", [
    ("CWE-89", "https://cwe.mitre.org/data/definitions/89.html"),
    ("cwe-79", "https://cwe.mitre.org/data/definitions/79.html"),
    ("918", "https://cwe.mitre.org/data/definitions/918.html"),
    (None, None),
    ("", None),
    ("not-a-cwe", None),
])
def test_cwe_url(cwe, expected):
    assert cwe_url(cwe) == expected


@pytest.mark.parametrize("cve, expected", [
    ("CVE-2021-44228", "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"),
    ("cve-2021-44228", "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"),
    ("CVE-2023-123456", "https://nvd.nist.gov/vuln/detail/CVE-2023-123456"),
    (None, None),
    ("CVE-bad", None),
])
def test_cve_url(cve, expected):
    assert cve_url(cve) == expected


@pytest.mark.parametrize("category, tail", [
    ("A03:2021 - Injection", "A03_2021-Injection/"),
    ("A01:2021 - Broken Access Control", "A01_2021-Broken_Access_Control/"),
    ("A07:2021", "A07_2021-Identification_and_Authentication_Failures/"),
    ("A10:2021 - SSRF", "A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"),
])
def test_owasp_url(category, tail):
    assert owasp_url(category) == f"https://owasp.org/Top10/{tail}"


def test_owasp_url_rejects_unknown_ranks():
    assert owasp_url("A99:2021 - Nonsense") is None
    assert owasp_url("Injection") is None
    assert owasp_url(None) is None


def test_every_owasp_rank_maps():
    """All ten 2021 categories must resolve — a missing slug is a silent gap."""
    for n in range(1, 11):
        assert owasp_url(f"A{n:02d}:2021") is not None, n


# --- assembly -------------------------------------------------------------

def test_build_ref_links_combines_available_sources():
    urls = build_ref_links(cwe="CWE-89", cve_id="CVE-2021-44228",
                           owasp_category="A03:2021 - Injection")
    assert len(urls) == 3
    assert any("cwe.mitre.org" in u for u in urls)
    assert any("nvd.nist.gov" in u for u in urls)
    assert any("owasp.org" in u for u in urls)


def test_build_ref_links_skips_missing_sources():
    assert build_ref_links(cwe="CWE-79") == [
        "https://cwe.mitre.org/data/definitions/79.html"]


def test_build_ref_links_is_empty_when_nothing_is_derivable():
    assert build_ref_links() == []
    assert build_ref_links(cwe=None, cve_id=None, owasp_category=None) == []


def test_build_ref_links_dedupes():
    urls = build_ref_links(cwe="CWE-89", cve_id=None, owasp_category="A03:2021")
    assert len(urls) == len(set(urls))


def test_serialised_form_round_trips_through_the_report_reader():
    """_build_report_json splits ref_links on ',' — the storage form must survive."""
    urls = build_ref_links(cwe="CWE-89", cve_id="CVE-2021-44228",
                           owasp_category="A03:2021 - Injection")
    stored = serialise_ref_links(urls)
    assert [x.strip() for x in stored.split(",") if x.strip()] == urls


def test_no_generated_url_contains_a_comma():
    """A comma would break the storage format the report reader parses."""
    urls = build_ref_links(cwe="CWE-918", cve_id="CVE-2021-44228",
                           owasp_category="A10:2021 - SSRF")
    assert all("," not in u for u in urls)


# --- ATT&CK ---------------------------------------------------------------

@pytest.mark.parametrize("vuln_type, technique_id", [
    ("SQL Injection", "T1190"),
    ("Reflected Cross-Site Scripting", "T1059.007"),
    ("Command Injection", "T1059"),
    ("JSON Web Token Flaws", "T1550.001"),
    ("Insecure Direct Object References", "T1190"),
    ("Sensitive Data Exposure", "T1213"),
    ("Open Redirect", "T1204.001"),
])
def test_mitre_mapping(vuln_type, technique_id):
    got = mitre_for(vuln_type)
    assert got and got.startswith(technique_id), got


def test_unmapped_class_returns_none_rather_than_a_guess():
    assert mitre_for("Quantum Flux Anomaly") is None
    assert mitre_for(None) is None
    assert mitre_for("") is None


def test_longest_match_wins():
    """'sql injection' must not be shadowed by a shorter overlapping needle."""
    assert mitre_for("SQL Injection").startswith("T1190")
    assert mitre_for("Command Injection").startswith("T1059 ")


# --- persistence ----------------------------------------------------------

@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db_mod, "DB_PATH", tmp_path / "t.db")
    monkeypatch.setattr(db_mod, "DB_DIR", tmp_path)
    asyncio.run(db_mod.init_db())
    return tmp_path


def _add(vuln_type, cwe=None, cve_id=None, owasp=None, mitre=None, ref_links=None):
    async def go():
        db = await db_mod.get_db()
        try:
            await db.execute("INSERT INTO sessions (id, target_url) VALUES (?, ?)",
                             ("s1", "http://juice-shop:3000"))
        except Exception:
            pass
        cur = await db.execute(
            "INSERT INTO findings (session_id, vuln_type, severity, url, cwe, cve_id, "
            "owasp_category, mitre, ref_links) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("s1", vuln_type, "high", "http://juice-shop:3000/x", cwe, cve_id,
             owasp, mitre, ref_links))
        await db.commit()
        fid = cur.lastrowid
        await db.close()
        return fid
    return asyncio.run(go())


def _row(fid):
    async def go():
        db = await db_mod.get_db()
        cur = await db.execute("SELECT mitre, ref_links FROM findings WHERE id = ?", (fid,))
        r = await cur.fetchone()
        await db.close()
        return dict(r)
    return asyncio.run(go())


def _persist():
    return asyncio.run(main_mod._persist_derived_references("s1"))


def test_columns_are_populated(temp_db):
    """The whole point: both used to stay NULL forever."""
    fid = _add("SQL Injection", cwe="CWE-89", owasp="A03:2021 - Injection")
    assert _persist() == 1
    row = _row(fid)
    assert row["mitre"].startswith("T1190")
    assert "cwe.mitre.org/data/definitions/89.html" in row["ref_links"]
    assert "owasp.org/Top10/A03_2021-Injection/" in row["ref_links"]


def test_findings_the_model_skipped_still_get_references(temp_db):
    """Derivation runs outside the `if structured:` guard, so a finding with no
    LLM block is still enriched."""
    fid = _add("Command Injection", cwe="CWE-78")
    _persist()
    row = _row(fid)
    assert row["mitre"].startswith("T1059")
    assert "definitions/78.html" in row["ref_links"]


def test_existing_values_are_not_overwritten(temp_db):
    fid = _add("SQL Injection", cwe="CWE-89", mitre="T9999 — hand-set",
               ref_links="https://example.test/manual")
    _persist()
    row = _row(fid)
    assert row["mitre"] == "T9999 — hand-set"
    assert row["ref_links"] == "https://example.test/manual"


def test_unmappable_finding_is_left_null_not_filled_with_noise(temp_db):
    fid = _add("Quantum Flux Anomaly")
    _persist()
    row = _row(fid)
    assert row["mitre"] is None
    assert row["ref_links"] is None


def test_persist_is_idempotent(temp_db):
    _add("SQL Injection", cwe="CWE-89")
    assert _persist() == 1
    assert _persist() == 0        # nothing left to change


def test_persist_never_raises(monkeypatch, tmp_path):
    monkeypatch.setattr(db_mod, "DB_PATH", tmp_path / "nope" / "x.db")
    assert asyncio.run(main_mod._persist_derived_references("s1")) == 0
