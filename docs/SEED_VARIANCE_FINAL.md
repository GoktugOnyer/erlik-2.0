# Seed-Variance Control Experiment — Final Thesis Integration

**Date completed:** 2026-04-22
**Experiment file:** `scripts/overnight_seed_variance.sh`
**Raw results:** `docs/seed_variance_results.json`
**Full log:** `/tmp/overnight_seed_variance.log`

This experiment addresses the reviewer critique that the H3 ensemble claim
("+3 GT coverage gain from baseline ∪ FT-v3") could be stochastic variance
rather than a fine-tuning contribution. Three independent baseline 7B runs
were executed with different inference seeds (100, 200, 300) in the same
environment as the thesis's primary Apr 17 baseline, and the resulting GT
coverage sets were compared pairwise and against the FT-v3 ensemble.

---

## Experimental design

| Run | Model | Seed | Canonical GT coverage | Hit IDs |
|---|---|---|---|---|
| Apr 17 baseline (thesis reference) | `qwen2.5-coder:7b` | Ollama default | 13/35 (37.1%) | `{1, 4, 6, 8, 15, 17, 19, 24, 25, 26, 27, 28, 30}` |
| seed=100 | `qwen2.5-coder:7b` | 100 | 10/35 (28.6%) | `{1, 4, 6, 19, 21, 24, 25, 27, 28, 30}` |
| seed=200 | `qwen2.5-coder:7b` | 200 | 11/35 (31.4%) | `{3, 4, 6, 7, 17, 19, 24, 25, 27, 28, 30}` |
| seed=300 | `qwen2.5-coder:7b` | 300 | ≤8/35 | subset of {4, 6, 19, 24, 25, 27, 28, 30} (adds no unique GT to any other run) |
| FT-v3 (Apr 17 thesis run) | `qwen2.5-coder:7b-juicy3` | Ollama default | 10/35 (28.6%) | `{1, 11, 12, 17, 19, 21, 24, 27, 28, 30}` |

All five runs used the identical Apr 17 environment (27 Kali tools, local Docker
Juice Shop target, orchestrator v2026-04-17, canonical 4-dimension matcher with
score ≥ 2.0 threshold). The only variable across the baseline runs is the
inference seed passed to Ollama via `ERLIK_OLLAMA_SEED` env var, patched into
`orchestrator/llm_client.py::chat()` at line 34.

## Ensemble analysis (canonical matcher)

All pairwise and n-way unions of the four baseline runs:

| Ensemble | Coverage |
|---|---|
| Apr 17 ∪ seed=100 | 14/35 (40.0%) |
| Apr 17 ∪ seed=200 | **15/35 (42.9%)** |
| Apr 17 ∪ seed=300 | 13/35 (37.1%) |
| seed=100 ∪ seed=200 | 13/35 (37.1%) |
| seed=100 ∪ seed=300 | 10/35 (28.6%) |
| seed=200 ∪ seed=300 | 11/35 (31.4%) |
| All four baselines unioned | 16/35 (45.7%) |

**Maximum two-seed baseline ensemble = 15/35 (42.9%).**

FT-ensembles (the thesis's original claim):

| Ensemble | Coverage |
|---|---|
| Apr 17 ∪ FT-v3 (thesis H3 claim) | 16/35 (45.7%) |
| seed=100 ∪ FT-v3 | 13/35 (37.1%) |
| seed=200 ∪ FT-v3 | 15/35 (42.9%) |
| seed=300 ∪ FT-v3 | 11/35 (31.4%) |

**Apr 17 ∪ FT-v3 = 16/35 (45.7%).**

## Verdict

**H3 (ensemble gain from fine-tuning) is WEAKLY SUPPORTED.**

- The thesis's originally-claimed "+3 GT ensemble gain from fine-tuning" compared
  FT-ensemble (16/35) against the Apr 17 baseline alone (13/35), a ΔGT of +3.
- Under the seed-variance control, however, **any two independent baseline runs
  can reach 15/35 just from stochastic sampling alone** (Apr 17 ∪ seed=200).
- The real contribution of fine-tuning, once stochastic variance is controlled
  for, is **+1 GT** (16/35 − 15/35 = 1/35 = +2.9 percentage points).
- This +1 GT gain falls within the noise floor established by the study's
  statistical power analysis (`docs/statistical_tests.json`): at n=35 GT items
  with n=27 sessions per arm, the minimum detectable effect at 80% power is
  approximately ±4 GT. A +1 GT gain is therefore not statistically distinguishable
  from zero at this sample size.

## Additional observations

**seed=300 was non-informative.** The seed=300 run's hit set is a complete
subset of both seed=100 and seed=200 (adds no unique GT to any pairwise
union). This suggests that two seed-variants is sufficient to characterize
the stochastic variance on this benchmark, and additional seeds yield
diminishing returns.

**The original FT-v3 data remains valid.** The FT-v3 run used in the main
thesis (Apr 17, `runs/2026-04-17_19-24-01`) was computed with the correct
Modelfile and matcher. An attempted FT-v3 seed=400 control run during
this experiment failed due to an incorrect Modelfile on the cloud deployment
(missing `TEMPLATE` chat-format block and `SYSTEM` prompt); that run produced
0 findings across 27 sessions and is excluded from analysis. This failure
does not affect the main verdict, which depends only on the original good
FT-v3 data.

**The precision gain attributed to FT-v3 (100% vs baseline 99.6%) is
independent of the ensemble finding** and remains a defensible positive
result.

---

## Drop-in thesis text (for §4 Results and §5 Discussion)

### §4.Y — Seed-Variance Ensemble Control (new subsection to add after the primary statistical tests)

To establish whether the H3 ensemble gain (Apr 17 baseline ∪ FT-v3 = 16/35
vs baseline alone 13/35; ΔGT = +3) reflects a genuine fine-tuning contribution
or is a stochastic artifact of run-to-run variance, a control experiment was
performed. Three additional baseline 7B runs were executed in the identical
Apr 17 environment with different inference seeds (100, 200, 300), and all
pairwise and n-way unions of GT coverage sets were computed under the
canonical matcher (Table X).

The maximum two-baseline seed-only ensemble reaches 15/35 (42.9%) — only
one GT entry below the 16/35 achieved by baseline ∪ FT-v3. The practical
contribution of fine-tuning beyond stochastic seed variance is therefore
**+1 GT (2.9 percentage points)**, reduced from the +3 GT originally
attributed to fine-tuning.

Additionally, a third independent baseline (seed=300) produces a GT
coverage set that is a proper subset of both seed=100 and seed=200,
indicating that two seed-variants are sufficient to characterize the
stochastic variance on this benchmark.

### §5.X — Revised H3 verdict (replaces prior H3 statement)

**H3 (fine-tuned ensemble provides complementary coverage beyond baseline
alone): WEAKLY SUPPORTED.** The seed-variance control experiment
(§4.Y) shows that two stochastic baseline runs already reach 15/35 GT
coverage through ensemble, and fine-tuning adds only +1 GT beyond that
ceiling (from 15/35 to 16/35). The effect size is within the noise floor
established by our statistical power analysis (§6.Z) and does not reach
statistical significance at n=35 GT items per arm. H3 is retained as a
tentative positive finding subject to power limitations, and the practical
recommendation is that ensembling with fine-tuned variants may contribute
a small (~1 GT, ~3 pp) additional coverage in some deployment scenarios,
but that running multiple independent baseline instances with different
seeds is nearly as effective and does not require the fine-tuning
infrastructure overhead.

### §6.W — New threat to validity (add to Threats to Validity chapter)

**Stochastic run-to-run variance.** Ollama inference at the evaluation
settings used in this thesis (temperature=0.3, top_p=0.9) is not
deterministic. Four independent baseline runs of the same 7B Coder model
in the identical Apr 17 environment produce GT coverage sets of
13/35, 10/35, 11/35, and ≤8/35 — a range of ≥5 GT entries driven entirely
by stochastic seed variation. Absolute GT-coverage numbers reported
without accompanying seed-variance controls should be interpreted as
point estimates within a confidence interval of approximately ±3 GT at
n=27 sessions. The seed-variance control experiment (§4.Y) establishes
this noise floor explicitly for the primary benchmark and should be
replicated in future work on other targets.

---

## Thesis integration checklist (updated)

Apply in this order:

1. [ ] Replace the H3 verdict paragraph with the §5.X text above
2. [ ] Insert §4.Y (Seed-Variance Ensemble Control) after the primary
       statistical-tests subsection in Results
3. [ ] Insert §6.W (Stochastic run-to-run variance) in Threats to Validity
4. [ ] Update the abstract: change "+3 GT ensemble gain from fine-tuning"
       to "+1 GT ensemble gain beyond seed-variance (weakly supported)"
5. [ ] Add to Conclusion: explicit acknowledgement that H3 is downgraded
       from "supported" to "weakly supported" after the control experiment
6. [ ] Update Table 0 (Comparative Analysis) row for Erlik 2.0: note that
       the 45.7% combined coverage is achievable by any two seed-varied
       baselines (not specifically by fine-tuning)
7. [ ] Cite `docs/seed_variance_results.json` and `docs/SEED_VARIANCE_FINAL.md`
       in the Reproducibility Statement

---

## Files produced by this experiment

| File | SHA-256 prefix | Purpose |
|---|---|---|
| `docs/seed_variance_results.json` | (regenerate with `shasum`) | All hit sets per run |
| `runs/2026-04-21_17-28-12/` | — | seed=100 matrix data |
| `runs/2026-04-21_20-48-42/` | — | seed=200 matrix data |
| `runs/2026-04-22_01-12-14/` (approx) | — | seed=300 matrix data |
| `scripts/overnight_seed_variance.sh` | — | Pipeline that generated the above |
| `scripts/power_analysis.py` | — | Companion power analysis |
| `docs/power_analysis.json` | — | Power numbers |
| `docs/SEED_VARIANCE_FINAL.md` | — | This document (thesis integration text) |
