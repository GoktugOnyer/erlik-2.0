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


def chain_targets(tc: TestCase) -> list[str]:
    """Every test case id this one can schedule after itself."""
    ids: list[str] = []
    for step in tc.steps:
        for ev in step.evaluators:
            ids += ev.chain_to or []
    if tc.chain:
        ids += tc.chain.on_finding + tc.chain.always
    return ids


def dangling_chain_refs(catalog: dict[str, TestCase]) -> dict[str, list[str]]:
    """{case_id: [ids it chains to that do not exist]}.

    A chain reference to a case nobody wrote is not a runtime error — the
    walker simply never traverses it — so it survives indefinitely while the
    catalogue LOOKS like it has a methodology. The whole catalogue held three
    chain declarations and zero working edges: one pointed at
    `WSTG-INPV-05-WAF-BYPASS`, which was never written, one at a case that
    always skips for want of credentials, and one was an empty list.

    Reported rather than raised: a dangling edge must not stop the other 21
    cases from loading.
    """
    known = set(catalog)
    out: dict[str, list[str]] = {}
    for cid, tc in catalog.items():
        missing = sorted({t for t in chain_targets(tc) if t not in known})
        if missing:
            out[cid] = missing
    return out


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
    for cid, missing in dangling_chain_refs(out).items():
        print(f"[testcase.loader] {cid} chains to unknown case(s): "
              f"{', '.join(missing)}", flush=True)
    return out


def find_by_id(test_id: str) -> TestCase | None:
    catalog = load_catalog()
    return catalog.get(test_id)
