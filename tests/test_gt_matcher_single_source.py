"""The ground-truth matcher must have exactly one implementation.

`scripts/recompute_gt_coverage.py` carried its own copy, introduced with the
comment "verbatim from orchestrator's _match_finding_to_ground_truth_scored".
It was not verbatim, and it was being cited as a proof that a change had not
moved the numbers — a second implementation cannot prove anything about the
first.

By the time anyone checked, the copy had drifted past drift into broken:

  * `_TYPE_ALIASES` was a module-level table in the script, while the canonical
    matcher keeps its aliases LOCAL to the function — so `main` has no
    `_TYPE_ALIASES` at all and the two could never be compared.
  * `match_finding` returned `best_gt["id"]`, but ground-truth rows have no
    `id` key. Every call against JUICE_SHOP_GROUND_TRUTH raised KeyError, so
    the script could not have produced a thesis number in that state.

These tests pin the single-source property, and they check what the script
EXECUTES rather than what it mentions — the module docstring names the deleted
constants on purpose, and a naive grep would fail the file for documenting its
own history.
"""

import ast
import importlib.util
import sqlite3
import sys
from pathlib import Path

import pytest

from tests import corpus  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "recompute_gt_coverage.py"


@pytest.fixture(scope="module")
def script():
    sys.path.insert(0, str(ROOT))
    spec = importlib.util.spec_from_file_location("rgc", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _code_lines(path: Path) -> list[tuple[int, str]]:
    """Source lines that are neither docstrings nor comments."""
    text = path.read_text()
    doc: set[int] = set()
    for node in ast.walk(ast.parse(text)):
        body = getattr(node, "body", None)
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                 ast.AsyncFunctionDef)) or not body:
            continue
        first = body[0]
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) \
                and isinstance(first.value.value, str):
            doc.update(range(first.lineno, (first.end_lineno or first.lineno) + 1))
    return [(n, l) for n, l in enumerate(text.splitlines(), 1)
            if n not in doc and not l.lstrip().startswith("#")]


class TestNoSecondImplementation:
    def test_script_imports_the_canonical_matcher(self, script):
        import orchestrator.main as M
        assert script._canonical_match is M._match_finding_to_ground_truth_scored

    def test_no_private_matcher_constants_in_executable_code(self):
        """The docstring names the deleted tables deliberately; only code counts."""
        offenders = [f"line {n}: {l.strip()[:70]}" for n, l in _code_lines(SCRIPT)
                     if "_TYPE_ALIASES" in l or "_EVIDENCE_CONFIRMATION_KEYWORDS" in l]
        assert offenders == [], offenders

    def test_no_reimplemented_scoring_in_executable_code(self):
        """The 2.0 threshold belongs to the canonical matcher alone."""
        offenders = [f"line {n}: {l.strip()[:70]}" for n, l in _code_lines(SCRIPT)
                     if "best_score" in l or ">= 2.0" in l]
        assert offenders == [], offenders

    def test_the_check_above_can_actually_fail(self, tmp_path):
        """Guard on the guard: prove the docstring exclusion does not blind it."""
        f = tmp_path / "x.py"
        f.write_text('"""mentions _TYPE_ALIASES harmlessly."""\n'
                     "# and _TYPE_ALIASES in a comment\n"
                     "_TYPE_ALIASES = {'a': 1}\n")
        hits = [n for n, l in _code_lines(f) if "_TYPE_ALIASES" in l]
        assert hits == [3], f"guard missed the real assignment (found {hits})"


class TestScriptAgreesWithTheCanonicalMatcher:
    def test_identical_verdicts_over_the_whole_corpus(self, script):
        """Trivially true now that it IS the same function — which is the point.
        Before, this comparison could not even run: the copy raised KeyError."""
        import orchestrator.main as M
        db = ROOT / "data" / "pentest.db"
        if not db.exists():
            pytest.skip("no recorded corpus")
        corpus.require("findings")
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        rows = [dict(r) for r in con.execute(
            "SELECT vuln_type,severity,url,parameter,evidence FROM findings")]
        assert rows
        for f in rows:
            a = script.match_finding(f, M.JUICE_SHOP_GROUND_TRUTH)
            b = M._match_finding_to_ground_truth_scored(f, M.JUICE_SHOP_GROUND_TRUTH)
            assert a["match"] == bool(b.get("match"))
            if a["match"]:
                assert a["gt_id"] == b.get("gt_index")

    def test_matcher_does_not_raise_on_real_ground_truth(self, script):
        """The regression that made the script unusable: ground-truth rows have
        no `id` key, and the copy indexed one."""
        import orchestrator.main as M
        script.match_finding(
            {"vuln_type": "SQL Injection", "severity": "high",
             "url": "http://juice-shop:3000/rest/user/login",
             "parameter": "email", "evidence": "injection point found, payload 1=1"},
            M.JUICE_SHOP_GROUND_TRUTH)

    def test_coverage_summary_is_computable(self, script):
        import orchestrator.main as M
        db = ROOT / "data" / "pentest.db"
        if not db.exists():
            pytest.skip("no recorded corpus")
        corpus.require("findings")
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        rows = [dict(r) for r in con.execute(
            "SELECT vuln_type,severity,url,parameter,evidence FROM findings")]
        cov = script.compute_gt_coverage(rows, M.JUICE_SHOP_GROUND_TRUTH)
        assert cov["findings"] == len(rows)
        assert cov["tp_findings"] + cov["fp_findings"] == len(rows)
        assert 0.0 <= cov["precision"] <= 1.0


class TestGroundTruthShapeIsWhatCallersAssume:
    def test_rows_have_no_id_field(self):
        """Pins the fact the copy got wrong. If an `id` is ever added, the
        adapter's index-based gt_id should be revisited."""
        import orchestrator.main as M
        assert "id" not in M.JUICE_SHOP_GROUND_TRUTH[0]
        assert "vuln_type" in M.JUICE_SHOP_GROUND_TRUTH[0]

    def test_canonical_matcher_returns_an_index(self):
        import orchestrator.main as M
        r = M._match_finding_to_ground_truth_scored(
            {"vuln_type": "SQL Injection", "severity": "high",
             "url": "http://juice-shop:3000/rest/user/login",
             "parameter": "email", "evidence": "injection point found, payload 1=1"},
            M.JUICE_SHOP_GROUND_TRUTH)
        assert "gt_index" in r and "match" in r and "score" in r
