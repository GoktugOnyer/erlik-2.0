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

## Defects found by the suite — now fixed (regression tests)

Three real defects surfaced while writing the suite. They have been fixed in
`_auto_detect_findings`, and each is pinned by a regression test plus a
companion guard so the change cannot regress in the opposite direction:

1. **dalfox/xsstrike `[POC]`/`[VULN]`/`triggered` markers ignored** — confirmed
   XSS used to be dropped unless the output literally said `vulnerable`/
   `confirmed`. Now recognised (recall win, Wave 1 #3). Guard:
   `test_benign_output_still_does_not_trigger`.
2. **jwt_tool bare `found` false positive** — banner text like "Token found in
   header" emitted a phantom Broken Authentication finding. The trigger now
   requires a real crack signal (precision win, Wave 1 #11). Guard:
   `test_correct_key_crack_is_detected`.
3. **`/api/orders` `totalPrice` dead clause** — `main.py:858` compared the
   mixed-case literal `"totalPrice"` against already-lowercased output, so that
   IDOR signal never fired. The literal is now lowercased (recall win).

> Note: fixes #1 and #3 make the detector emit *more* findings and #2 emits
> *fewer* false ones. They change detection behaviour intentionally, so runs
> produced after this commit are not directly comparable to the recorded
> pre-fix baselines — re-run baselines before comparing.
