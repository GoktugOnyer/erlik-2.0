"""The thesis export is redacted, by column type rather than by field list.

Every table is fetched with `SELECT *`, so a column added anywhere reaches this
export the moment it exists. A hand-listed set of fields TO mask therefore omits
whatever nobody thought of — the original design's list missed
`steps.model_response` (where the model quotes the token it just captured),
`recon_context.value` and `sessions.system_prompt`, and measured on the recorded
corpus those carry secrets in rows that would have shipped in the clear while
the artifact claimed `"redaction": {"applied": true}`. A false attestation is
worse than none.

So the allowlist is inverted: everything is masked unless a column is declared
STRUCTURAL. A column added later is redacted until someone deliberately says
otherwise.

The other half is that the export has to stay analysable. Redaction that
corrupts `run_config` or renames a severity has destroyed the artifact it was
protecting.
"""

import json
import re
import sqlite3
import warnings
from pathlib import Path

import pytest

warnings.filterwarnings("ignore", category=DeprecationWarning)

from fastapi.testclient import TestClient  # noqa: E402

import orchestrator.main as M  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "data" / "pentest.db"
JWT_RX = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}")
PLACEHOLDER_RX = re.compile(r"<[a-z_]+:redacted:[0-9a-f]{4}>")


@pytest.fixture(scope="module")
def export():
    """The recorded corpus, or a skip.

    data/ is gitignored — it holds client findings — so a fresh clone has no
    database. Without this guard these tests ERROR on the export endpoint and
    read as product failures rather than as "there is nothing here to check".
    """
    import sqlite3
    try:
        r = TestClient(M.app).get("/api/thesis/export")
    except sqlite3.OperationalError as e:
        # TestClient re-raises server exceptions, so a schema-less database
        # never reaches a status code — the request raises straight out of the
        # fixture and nine tests ERROR rather than skip.
        pytest.skip(f"no recorded corpus in this checkout ({e})")
    if r.status_code != 200:
        pytest.skip(f"no recorded corpus in this checkout (export -> {r.status_code})")
    d = r.json()
    if not (d.get("tables") or d.get("rows") or d.get("findings")):
        pytest.skip("corpus present but empty")
    return d


class TestPolicyIsDefaultDeny:
    def test_unknown_column_is_masked(self):
        """The property that makes this survive schema growth."""
        counts: dict = {}
        rows = M._mask_export_rows(
            [{"id": 1, "a_column_nobody_declared":
              'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjF9.abcdEFGH'}],
            counts)
        assert "eyJhbGciOiJIUzI1NiJ9" not in rows[0]["a_column_nobody_declared"]
        assert counts

    def test_structural_columns_pass_through(self):
        counts: dict = {}
        row = {"id": 7, "severity": "high", "vuln_type": "SQL Injection",
               "created_at": "2026-08-17", "status": "completed", "denied": 1}
        assert M._mask_export_rows([row], counts)[0] == row
        assert counts == {}

    def test_non_strings_are_untouched(self):
        counts: dict = {}
        row = {"whatever": 42, "other": None, "flag": True}
        assert M._mask_export_rows([row], counts)[0] == row

    def test_the_columns_a_field_list_forgets_are_covered(self):
        """steps.model_response, recon_context.value, sessions.system_prompt —
        none of them appeared in the original design's list."""
        for col in ("model_response", "value", "system_prompt", "prompt_sent",
                    "tool_output", "evidence", "triage_note", "impact"):
            assert col not in M._EXPORT_STRUCTURAL, col

    def test_url_columns_stay_parseable(self):
        """A masked URL is still an artifactLocation and an endpoint."""
        from urllib.parse import urlparse
        counts: dict = {}
        row = {"url": "http://juice-shop:3000/rest/x?token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjF9.abcdEFGH&p=1"}
        out = M._mask_export_rows([row], counts)[0]["url"]
        u = urlparse(out)
        assert u.scheme == "http" and u.hostname == "juice-shop" and u.port == 3000
        assert u.path == "/rest/x"
        assert "p=1" in out
        assert "eyJhbGciOiJIUzI1NiJ9" not in out


class TestAgainstTheRealCorpus:
    def test_no_raw_jwt_survives(self, export):
        if not DB.exists():
            pytest.skip("no recorded corpus")
        blob = json.dumps(export)
        assert JWT_RX.findall(blob) == []

    def test_something_was_actually_masked(self, export):
        """Guard on the guard: 'no JWTs found' is also true of an empty export."""
        if not DB.exists():
            pytest.skip("no recorded corpus")
        assert export["redaction"]["total"] > 0
        assert PLACEHOLDER_RX.search(json.dumps(export))
        assert export["steps"] and export["findings"]

    def test_only_secret_bearing_columns_changed(self, export):
        """Redaction must not quietly rewrite anything else."""
        if not DB.exists():
            pytest.skip("no recorded corpus")
        con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        raw = {r["id"]: dict(r) for r in con.execute("SELECT * FROM steps")}
        changed = set()
        for st in export["steps"]:
            r = raw.get(st["id"])
            if not r:
                continue
            for c, v in st.items():
                if c in r and r[c] != v:
                    changed.add(c)
        assert changed <= {"tool_input", "tool_output", "model_response",
                           "prompt_sent"}, changed

    def test_structural_cells_are_byte_identical(self, export):
        if not DB.exists():
            pytest.skip("no recorded corpus")
        con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        raw = {r["id"]: dict(r) for r in con.execute("SELECT * FROM sessions")}
        for s in export["sessions"]:
            r = raw.get(s["id"])
            if not r:
                continue
            for c in M._EXPORT_STRUCTURAL:
                if c in r and c in s:
                    assert r[c] == s[c], f"{c} was altered"


class TestExportStaysAnalysable:
    def test_run_config_still_parses(self, export):
        """Reproducibility depends on it: run_config is JSON in a TEXT column,
        so it is masked like any other free text and must survive intact."""
        if not DB.exists():
            pytest.skip("no recorded corpus")
        vals = [s["run_config"] for s in export["sessions"] if s.get("run_config")]
        assert vals
        for v in vals:
            json.loads(v)

    def test_severity_and_type_vocabulary_is_intact(self, export):
        if not DB.exists():
            pytest.skip("no recorded corpus")
        sevs = {f["severity"] for f in export["findings"] if f.get("severity")}
        assert sevs <= {"critical", "high", "medium", "low", "info"}, sevs
        assert any(f["vuln_type"] == "SQL Injection" for f in export["findings"])

    def test_row_counts_are_unchanged(self, export):
        """Masking must not drop rows — this is a research corpus."""
        if not DB.exists():
            pytest.skip("no recorded corpus")
        con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
        for table, key in (("sessions", "sessions"), ("findings", "findings"),
                           ("steps", "steps")):
            n = con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            assert len(export[key]) == n, table


class TestDeclarationIsHonest:
    def test_applied_and_total_are_separate_facts(self, export):
        r = export["redaction"]
        assert r["applied"] is True
        assert isinstance(r["total"], int)
        assert "by_kind" in r and "policy" in r

    def test_total_matches_the_kind_breakdown(self, export):
        r = export["redaction"]
        assert r["total"] == sum(r["by_kind"].values())

    def test_export_is_still_declared_ungated_for_the_right_reason(self):
        """It stays outside the deliverable boundary because it exports the
        whole corpus, not because it is unredacted."""
        reason = M.ALLOWED_UNGATED_REPORT_PATHS["/api/thesis/export"]
        assert "redacted" in reason.lower()
        assert "raw corpus by design" not in reason
