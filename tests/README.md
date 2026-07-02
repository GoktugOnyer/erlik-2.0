# Tests — scientific-instrument guardrails

This suite pins the behaviour of the functions every thesis metric is derived
from. Their job is to make the detection/scoring code **safe to refactor**: if a
change (or a recall-roadmap patch) moves a number in the paper, a test here
turns red first.

## What is covered

| Function (`orchestrator/main.py`) | What it does | Coverage |
|---|---|---|
| `_auto_detect_findings` | Programmatic, evidence-gated finding emitter (why precision is model-independent) | 100% of lines |
| `_match_finding_to_ground_truth_scored` | Fuzzy finding↔ground-truth scorer (type=1, url=1, param=1, evidence=1; TP at score ≥ 2.0) | 100% |
| `_sound_confusion_matrix` | One-to-one greedy scorer behind `sound_metrics` | 100% |

Also guards the recall denominator: `JUICE_SHOP_GROUND_TRUTH` must stay at 35
entries with the keys the matcher reads.

## Running

```bash
pip install -r requirements-dev.txt
pytest                       # from the repo root
python -m coverage run -m pytest && python -m coverage report --include="*/orchestrator/main.py"
```

`pytest` must be run from the repo root — `orchestrator.main` builds a Jinja2
templates object with a path relative to the working directory (`conftest.py`
anchors CWD at the root so imports work regardless of where you invoke it).

## Documented defects (strict `xfail`)

Three real defects found while writing the suite are encoded as
`@pytest.mark.xfail(strict=True)`. They assert the **desired** behaviour, so
they xfail today (suite stays green) and will xpass — failing the strict marker
and prompting removal of the marker — the moment the bug is fixed:

1. **dalfox/xsstrike `[POC]`/`[VULN]`/`[G]` markers ignored** — confirmed XSS is
   dropped unless the output literally contains `vulnerable`/`confirmed`
   (recall-roadmap Wave 1 #3).
2. **jwt_tool bare `found` false positive** — ordinary banner text like
   "Token found in header" emits a phantom Broken Authentication finding
   (Wave 1 #11).
3. **`/api/orders` `totalPrice` dead clause** — `main.py:858` compares the
   mixed-case literal `"totalPrice"` against already-lowercased output, so that
   IDOR signal never fires; only a `"products"` key works.

These are the first fixes the recall roadmap should land — each flips its test
from xfail to pass.
