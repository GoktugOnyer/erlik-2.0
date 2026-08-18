"""Load YAML test cases from the catalog directory."""

from pathlib import Path
import yaml

from orchestrator.testcase.schema import TestCase

CATALOG_ROOT = Path(__file__).resolve().parents[2] / "tests_catalog"


def _yaml_files() -> list[Path]:
    if not CATALOG_ROOT.exists():
        return []
    # Only directories that actually hold test cases. rglob over the whole
    # catalogue root swept in tests_catalog/cleanroom/corpus.yaml — the
    # false-positive fixture corpus, which is not a TestCase — and printed four
    # pydantic validation errors on every `list` and every run. A loader that
    # cries wolf on a file that was never meant for it trains the operator to
    # ignore its errors, which is where a genuinely malformed case hides.
    roots = [d for d in (CATALOG_ROOT / "wstg",) if d.exists()] or [CATALOG_ROOT]
    files: list[Path] = []
    for root in roots:
        files += sorted(root.rglob("*.yaml")) + sorted(root.rglob("*.yml"))
    return files


def load_test_case(path: Path | str) -> TestCase:
    """Parse and validate a single YAML test case file."""
    p = Path(path)
    with p.open("r") as f:
        data = yaml.safe_load(f)
    return TestCase(**data)


def load_catalog() -> dict[str, TestCase]:
    """Load every YAML test case under tests_catalog/, keyed by test case id."""
    out: dict[str, TestCase] = {}
    errors: list[tuple[Path, Exception]] = []
    for path in _yaml_files():
        try:
            tc = load_test_case(path)
            out[tc.id] = tc
        except Exception as e:
            errors.append((path, e))
    if errors:
        for p, e in errors:
            print(f"[testcase.loader] failed to load {p}: {e}")
    return out


def find_by_id(test_id: str) -> TestCase | None:
    catalog = load_catalog()
    return catalog.get(test_id)
