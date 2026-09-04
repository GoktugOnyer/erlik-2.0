"""Drift tests for REPRODUCIBILITY.md's provenance table.

The table states, per data file, whether a reader can regenerate it or is
taking a committed number on trust. That claim decays silently: a new JSON
lands in docs/ and is simply absent from the table, or a file is regenerated
and its pinned hash goes stale, and in both cases the document still reads as
authoritative. So every row is re-asserted here against the tree.

The load-bearing test is `test_power_analysis_constants_match_the_data`.
`scripts/power_analysis.py` hard-codes the discordance counts rather than
reading them, so if the coverage data is ever corrected the script will keep
reporting power for the superseded effect without failing. The document says
so; this test is what makes the statement enforceable rather than decorative.
"""

import hashlib
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "REPRODUCIBILITY.md"
METHODOLOGY = ROOT / "docs" / "METHODOLOGY.md"

# Files the table pins that live outside the repository (gitignored corpora).
NOT_IN_REPO = {"training_data/juicy3_train.jsonl", "training_data/juicy3_val.jsonl"}

# Paths the document names that are gitignored by design, so they exist in a
# working checkout and not in a clean clone. Exempt from the path-resolution
# test — but the exemption is not free: `test_exempt_paths_are_really_ignored`
# asserts each one is genuinely gitignored, so this cannot become a place to
# park a typo. CI caught the original omission here: the document claimed a
# "tracked data/pentest.db" when nothing under data/ is tracked at all.
GITIGNORED_BY_DESIGN = {"data/pentest.db"}


def _doc() -> str:
    return DOC.read_text()


def _pinned() -> dict[str, str]:
    """{repo-relative path: sha256} for every row of the provenance table."""
    out = {}
    for line in _doc().splitlines():
        m = re.match(r"\|\s*`([^`]+)`\s*\|\s*`([0-9a-f]{64})`\s*\|", line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def _tracked_data_files() -> set[str]:
    """Data files committed under docs/ — what the table must account for."""
    return {
        f"docs/{p.name}"
        for p in (ROOT / "docs").iterdir()
        if p.suffix in {".json", ".csv"} and p.is_file()
    }


def test_doc_exists():
    assert DOC.exists()


class TestProvenanceTable:
    def test_the_table_parses_at_all(self):
        """A guard on the guard: if the table is reformatted so the regex stops
        matching, every other test here would pass vacuously."""
        assert len(_pinned()) >= 7, _pinned()

    def test_every_tracked_data_file_has_a_row(self):
        missing = _tracked_data_files() - set(_pinned())
        assert not missing, (
            f"data files in docs/ with no provenance row: {sorted(missing)}. "
            "A reader cannot tell whether these are regenerable."
        )

    def test_every_pinned_hash_matches(self):
        stale = []
        for rel, want in _pinned().items():
            if rel in NOT_IN_REPO:
                continue
            f = ROOT / rel
            assert f.exists(), f"table pins {rel}, which does not exist"
            got = hashlib.sha256(f.read_bytes()).hexdigest()
            if got != want:
                stale.append(f"{rel}: pinned {want[:12]}…, actual {got[:12]}…")
        assert not stale, stale

    def test_files_declared_absent_really_are(self):
        """The negative control. If training_data/ were ever committed, the
        table's 'Not in the repo' rows would be wrong in the other direction."""
        for rel in NOT_IN_REPO:
            assert not (ROOT / rel).exists(), f"{rel} is present; the table says it is not"


class TestRegenerationClaims:
    """The document tells a reader which scripts run from a clean clone and
    which do not. Both halves are checkable."""

    NEEDS_RUNS = [
        "scripts/recompute_gt_coverage.py",
        "scripts/recompute_all_thesis_tables.py",
    ]

    def test_scripts_declared_unrunnable_do_depend_on_runs(self):
        for rel in self.NEEDS_RUNS:
            src = (ROOT / rel).read_text()
            assert re.search(r'["\']runs/', src), (
                f"{rel} is documented as needing runs/, but does not reference it"
            )

    def test_the_runnable_recompute_reads_only_tracked_inputs(self):
        """recompute_statistical_tests.py is the one pipeline the document
        offers as verifiable, so it must not reach into runs/ on the default
        path. It may *mention* runs/ in its carried-forward message."""
        src = (ROOT / "scripts" / "recompute_statistical_tests.py").read_text()
        for name in ("orchestrator", "main.py", "recomputed_gt_coverage.json"):
            assert name in src
        reads = re.findall(r'(?:open|read_text|load)\([^)]*["\']([^"\']+)["\']', src)
        assert not [r for r in reads if r.startswith("runs/")], reads

    def test_runs_is_gitignored_as_the_doc_states(self):
        assert re.search(r"^runs/\s*$", (ROOT / ".gitignore").read_text(), re.M)

    def test_the_corpus_really_is_empty(self):
        """The document's headline claim: where a database exists at all, it
        holds ground truth and nothing else. `data/` is gitignored, so CI has
        no database and skips; this fires in a working checkout, where a
        restored corpus would falsify the framing above it ('the raw evidence
        is not in this repository')."""
        import sqlite3

        db = ROOT / "data" / "pentest.db"
        if not db.exists():
            pytest.skip("no data/pentest.db in this checkout")
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            for table in ("findings", "sessions", "steps"):
                try:
                    n = con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                except sqlite3.OperationalError:
                    continue
                assert n == 0, (
                    f"{table} has {n} rows; REPRODUCIBILITY.md tells readers the "
                    "tracked database holds only ground truth"
                )
        finally:
            con.close()


class TestUnattributedFile:
    def test_no_script_generates_recomputed_gt_coverage_all(self):
        """The document says this file has no generator. If one is ever
        written or recovered, that paragraph must come out."""
        hits = [
            p.name
            for p in (ROOT / "scripts").glob("*.py")
            if "recomputed_gt_coverage_all" in p.read_text()
        ]
        assert not hits, (
            f"{hits} now writes recomputed_gt_coverage_all.json; "
            "REPRODUCIBILITY.md still calls it unattributed"
        )


class TestPowerAnalysisDrift:
    def test_power_analysis_constants_match_the_data(self):
        """power_analysis.py transcribes the discordance table instead of
        deriving it. REPRODUCIBILITY.md states the two currently agree; this is
        what makes that statement hold or fail loudly."""
        src = (ROOT / "scripts" / "power_analysis.py").read_text()
        observed = {
            k: int(v)
            for k, v in re.findall(r'"(baseline_only|ftv3_only|both|neither)":\s*(\d+)', src)
        }
        n_gt = int(re.search(r"^N_GT\s*=\s*(\d+)", src, re.M).group(1))
        assert len(observed) == 4, observed

        cov = json.loads((ROOT / "docs" / "recomputed_gt_coverage.json").read_text())
        base = set(cov["results"]["baseline_7b_apr17"]["gt_hit_ids"])
        ft = set(cov["results"]["ft_v3_7b_apr17"]["gt_hit_ids"])
        total = cov["gt_total"]

        derived = {
            "both": len(base & ft),
            "baseline_only": len(base - ft),
            "ftv3_only": len(ft - base),
            "neither": total - len(base | ft),
        }
        assert n_gt == total, f"N_GT={n_gt} but gt_total={total}"
        assert observed == derived, (
            f"power_analysis.py hard-codes {observed}, but the tracked coverage "
            f"data gives {derived}. The published power figures describe an "
            "effect the repository no longer reports."
        )


class TestCrossReferences:
    def test_backticked_repo_paths_exist(self):
        missing = []
        for path in re.findall(r"`((?:docs|scripts|orchestrator|tests|data)/[\w./{}-]+)`", _doc()):
            if "{" in path or "*" in path:  # brace/glob patterns are illustrative
                continue
            if path in GITIGNORED_BY_DESIGN:
                continue
            if not (ROOT / path).exists():
                missing.append(path)
        assert not missing, missing

    def test_exempt_paths_are_really_ignored(self):
        """The exemption above must cost something. Each path skipped by the
        resolution test has to be gitignored for real, so a mistyped path
        cannot be waved through by adding it to the set."""
        ignore = (ROOT / ".gitignore").read_text().splitlines()
        patterns = {ln.strip() for ln in ignore if ln.strip() and not ln.startswith("#")}
        for path in GITIGNORED_BY_DESIGN:
            covered = any(
                p.rstrip("/") == path.split("/")[0] or p == f"*{Path(path).suffix}"
                for p in patterns
            )
            assert covered, (
                f"{path} is exempted from path resolution but nothing in "
                ".gitignore covers it — it is just missing"
            )

    def test_methodology_sections_named_here_exist(self):
        meth = METHODOLOGY.read_text()
        for sec in set(re.findall(r"Section (\d+\.\d+(?:\.\d+)?)", _doc())):
            assert re.search(rf"^#{{2,4}} {re.escape(sec)}\s", meth, re.M), (
                f"REPRODUCIBILITY.md cites Section {sec}, which METHODOLOGY.md "
                "does not define"
            )
