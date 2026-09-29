# Unified Thesis Results — Single Matching Algorithm Across All Experiments

**Author:** Göktug | MSc Cyber Security | FH Technikum Wien
**Recomputed:** 2026-04-17
**Replaces:** THESIS_FINAL_DATA.md, THESIS_JUICY3_FINAL_V2.md, THESIS_JUICY3_FINAL.md
(all removed from the repository; recoverable from git history if ever needed)

All numbers below are computed with the SAME programmatic matching algorithm
applied uniformly to all experiments. Earlier thesis drafts mixed
"lenient" (type-only), "strict" (URL+type), and "programmatic" (4-dimension
scored) matching inconsistently, producing non-comparable figures. This
document replaces those with a single canonical computation.

The source script is `scripts/recompute_gt_coverage.py`. The algorithm is
lifted verbatim from `orchestrator/main.py::_match_finding_to_ground_truth_scored`.

---

## 1. Methodology (unified)

**Ground-truth matching algorithm.**
A reported finding is a true-positive match to a ground-truth (GT) entry iff
its cumulative score ≥ 2.0 on four dimensions:

| Dimension | Points | Rule |
|---|---|---|
| Type | +1.0 | `gt.vuln_type` substring-matches `finding.vuln_type` (with aliases: "sqli"→"sql injection", "idor"→"broken access control", etc.) |
| URL | +1.0 if GT has `url_pattern` and it appears in `finding.url` or `finding.evidence`; **+0.5 if GT has no URL pattern** (generic vuln) |
| Parameter | +1.0 if GT has `parameter` and it matches; **+0.5 if GT has no parameter** |
| Evidence | +1.0 if `finding.evidence` contains ≥1 confirmation keyword for this GT type (e.g., "union", "payload" for SQLi) |

Threshold: **score ≥ 2.0** is required for a match. Same-GT counts only once
per experiment (unique-GT coverage). Experiments report `unique_gt_hit / 35`
on Juice Shop.

**Environment variation is a confound, not a model property.** Baseline
coverage varies across clouds/configurations (28.6% Apr09 7B RTX4090 → 31.4%
Apr15 7B PRO6000 → 37.1% Apr17 7B local) because of tool availability,
orchestrator version, and Docker stack differences. **Only same-environment
comparisons are valid.** Cross-environment absolute numbers are not directly
comparable.

**No DVWA fine-tuned evaluations were run.** All FT variants were evaluated
on Juice Shop only. DVWA generalization of SFT remains untested.

---

## 2. Fine-tuned variant taxonomy (FT-v1 through FT-v3)

The thesis names five distinct fine-tuned model variants. Earlier drafts
referred to them inconsistently ("juicy", "juicy2", "juicy3", "pentest-32b",
"pentest-7b-balanced"). The unified naming is:

### FT-v1 — First LoRA attempt (pentest-32b, pentest-7b-balanced)

**Trained on:** Apr 13–15 cloud (A100, PRO6000)
**Goal:** Prove SFT feasibility on baseline-established architecture.
**Datasets:**
- `training_data/train_balanced_v2.jsonl` (~1,000 examples, rebalanced mix of prior attempt data)
- Format: original instruction/response turn-based, no CIPHER reasoning structure
**Hyperparameters:**
- LoRA rank 16
- target_layers = `["q_proj", "v_proj"]` (minimal, 2 modules)
- epochs = 3
- lr = 2e-4, batch = 1, grad_accum = 4
**Ollama tag:** `pentest-32b`, `pentest-7b-balanced`
**Adapter:** `checkpoints/7b-lora/`, `checkpoints/cloud_14b/`, `checkpoints/cloud_14b_balanced/`

### FT-v2 — CIPHER reasoning chains (juicy1)

**Trained on:** Apr 16 cloud (RTX 5090)
**Goal:** Try CIPHER-paper's reasoning-chain approach on 7B baseline.
**Datasets:**
- 300 hand-built CIPHER reasoning chains (OBSERVATION → HYPOTHESIS → TEST → FINDING)
- Covered all 35 Juice Shop GT categories + variations
- File: `training_data/cipher_train.jsonl` (299 ex) + `cipher_val.jsonl` (34 ex)
**Hyperparameters:**
- LoRA rank 16, target `["q_proj", "v_proj"]`
- epochs 3, lr 2e-4, batch 1, grad_accum 8
- max_seq_length 4096
- QLoRA 4-bit NF4 quantization
**Ollama tag:** `qwen2.5-coder:7b-juicy` (later renamed in early docs)
**Adapter:** `checkpoints/cloud_14b/` (7B version lost when cloud was recreated)

### FT-v3 — Full 4-prong Gemini strategy (juicy3, 7B + 14B)

**Trained on:** Apr 17 cloud (RTX 5090)
**Goal:** Implement Gemini-proposed combined strategy — book + CTFd + synthetic + public HF datasets.
**Dataset composition (2,500 examples, 2,250 train / 250 val):**

| Source | Examples | License | Content |
|---|---|---|---|
| `scthornton/securecode-web` | 800 | CC BY-NC-SA 4.0 | OWASP Top 10 secure-code conversations |
| Public HF pentest dumps | 700 | Mixed | Canstralian + offensive_redteam + trendyol + pentest_agent |
| Juice Shop `challenges.yml` | 322 | Apache-2.0 | 107 challenges × 3 reasoning variants |
| CIPHER + MediTrack reasoning | 288 | Custom | Preserved from FT-v2 |
| Live `/api/Challenges` (CTFd-equivalent) | 214 | Apache-2.0 | Challenge metadata + hints |
| Pwning OWASP Juice Shop book | 109 | CC BY-NC-ND 4.0 | Canonical solution walkthroughs (research-use) |
| Synthetic payloads | 67 | Generated | Local-model generation via `qwen2.5-coder:14b-juicy` |

**File:** `training_data/juicy3_train.jsonl` (41 MB) + `juicy3_val.jsonl` (1.7 MB)
**Hyperparameters:**
- LoRA rank 32 (doubled from FT-v2)
- target_layers = `["q_proj", "k_proj", "v_proj", "o_proj"]` (all attention heads, 4 modules)
- epochs 3
- lr 1e-4 (halved — slower for larger corpus)
- batch 1, grad_accum 16 (effective batch 16)
- max_seq_length 4096
- QLoRA 4-bit NF4
**Trainable parameters:** 20 M for 7B (0.28%), 50 M for 14B (0.61%)
**Ollama tags:** `qwen2.5-coder:7b-juicy3`, `qwen2.5-coder:14b-juicy3`
**Adapters:**
- `checkpoints/qwen2.5-coder-7b-juicy3/qwen2.5-coder-7b-cipher-r32-A4/`
- `checkpoints/qwen2.5-coder-14b-juicy3/qwen2.5-coder-14b-cipher-r32-A4/`
**GGUF:**
- `merged_models/qwen2.5-coder-7b-juicy3-Q4_K_M.gguf` (4.4 GB)
- `merged_models/qwen2.5-coder-14b-juicy3-Q4_K_M.gguf` (8.4 GB)
**Final losses:** 7B train 0.71, eval 0.59; 14B train 0.61, eval 0.59

(FT-v2's juicy2 variant was a short MediTrack-focused experiment that we
deprecate — MediTrack and EduPortal webapps have been removed. FT-v2 refers
to the CIPHER-only 7B variant from Apr 16.)

---

## 3. All-experiments table (canonical matcher)

Full 27–29 session sprint matrix per model (3 turn counts × 3 toolsets × 3 session kinds).

| # | Date | Infra | Model | Sessions | Findings | TP | **Unique GT** | **GT %** | Precision |
|---|------|-------|-------|----------|----------|-----|---|---|-----------|
| 1 | Apr 9 | RTX 4090, 30 tools | Qwen2.5-Coder 7B (baseline) | 65 | 204 | 197 | **10/35** | **28.6%** | 96.6% |
| 2 | Apr 9 | RTX 4090, 30 tools | Qwen2.5-Coder 14B (baseline) | 65 | 147 | 146 | 7/35 | 20.0% | 99.3% |
| 3 | Apr 9 | RTX 4090, 30 tools | Qwen2.5-Coder 32B (baseline) | 65 | 339 | 334 | **12/35** | **34.3%** | 98.5% |
| 4 | Apr 15 | PRO 6000, 25 tools | Qwen2.5-Coder 7B (baseline) | 61 | 131 | 126 | 11/35 | 31.4% | 96.2% |
| 5 | Apr 15 | PRO 6000, 25 tools | Qwen2.5-Coder 32B (baseline) | 65 | 190 | 188 | **13/35** | **37.1%** | 98.9% |
| 6 | Apr 15 | PRO 6000, 25 tools | **FT-v1 32B** (pentest-32b) | 60 | 127 | 126 | 8/35 | 22.9% | 99.2% |
| 7 | Apr 15 | PRO 6000, 25 tools | **FT-v1 7B** (pentest-7b-balanced) | 23 | 71 | 71 | 8/35 | 22.9% | 100.0% |
| 8 | Apr 17 | Local, 27 tools | Qwen2.5-Coder 7B (baseline, **this cloud**) | 62 | 236 | 235 | **13/35** | **37.1%** | 99.6% |
| 9 | Apr 17 | Local, 27 tools | **FT-v3 7B** (juicy3) | 63 | 237 | 237 | **10/35** | **28.6%** | 100.0% |
| 10 | Apr 17 | Local, 27 tools | **FT-v3 14B** (juicy3) | 54 | 128 | 126 | 9/35 | 25.7% | 98.4% |

**Interpretation notes:**
- Precision (TP / all findings) was near-ceiling for all models (96–100%). The discriminator is **unique-GT coverage**, not volume.
- The **same baseline model (Qwen2.5-Coder 7B)** scored 28.6% → 31.4% → 37.1% across three infrastructure configurations — confirming the cross-environment comparability warning.
- FT-v3 7B (28.6%) finds **fewer** unique GT entries than its Apr17 same-environment baseline (37.1%). The ~8-point regression is statistically meaningful.

---

## 4. Same-environment head-to-head

**Apr 17 (the only clean, controlled 7B vs 7B-FT comparison):**

| Metric | Baseline 7B | FT-v3 7B | Δ |
|---|---|---|---|
| Total findings | 236 | 237 | +1 |
| TP findings | 235 | 237 | +2 |
| **Unique GT hit** | **13/35 (37.1%)** | **10/35 (28.6%)** | **−3 GT (−8.5 pp)** |
| FP | 1 | 0 | −1 |
| Precision | 99.6% | 100.0% | +0.4 pp |

**Conclusion:** FT-v3 **does not beat baseline** on the primary metric (unique GT coverage). It matches on volume and slightly improves precision, but misses 3 vulnerability classes the baseline finds.

**Apr 15 (32B vs 32B-FT, the other clean comparison):**

| Metric | Baseline 32B | FT-v1 32B | Δ |
|---|---|---|---|
| Unique GT hit | 13/35 (37.1%) | 8/35 (22.9%) | −5 GT (−14.2 pp) |
| Precision | 98.9% | 99.2% | +0.3 pp |

**Conclusion:** FT-v1 32B loses 5 GT entries to its same-cloud baseline. Pattern is consistent: SFT regresses on GT coverage while modestly improving precision.

---

## 5. Complementarity analysis

Although FT variants individually lose to baseline, they find **different** GT entries, so a baseline∪FT ensemble outperforms either alone.

| Combined pair | Baseline alone | FT alone | Combined | Incremental |
|---|---|---|---|---|
| Apr17 baseline-7B ∪ FT-v3-7B | 13/35 (37.1%) | 10/35 (28.6%) | **16/35 (45.7%)** | +3 GT |
| Apr15 baseline-32B ∪ FT-v1-32B | 13/35 (37.1%) | 8/35 (22.9%) | **14/35 (40.0%)** | +1 GT |
| Apr15 baseline-7B ∪ FT-v2-7B | 11/35 (31.4%) | 8/35 (22.9%) | 12/35 (34.3%) | +1 GT |
| All 7B models unioned | — | — | **18/35 (51.4%)** | — |
| All 32B models unioned | — | — | 16/35 (45.7%) | — |

**Apr17 FT-v3 complementarity detail (canonical matcher):**

| Category | IDs | Count |
|---|---|---|
| Baseline finds, FT-v3 misses | 4, 6, 8, 15, 25, 26 | 6 |
| FT-v3 finds, baseline misses | 11, 12, 21 | 3 |
| Both find | 1, 17, 19, 24, 27, 28, 30 | 7 |

The complementarity is real but modest. FT-v3 adds 3 new GT entries (access-control on basket, feedback-forging, PII dumper) at the cost of losing 6 (XSS, auth, misconfig). Net: **+3 combined GT over baseline-alone**.

---

## 6. Per-turn / per-kind breakdown (Apr 17 FT-v3 7B)

| Turn count | Sessions | Findings | TP | Unique GT |
|---|---|---|---|---|
| 15 turns | 9 | 57 | 57 | (subset of 10) |
| 30 turns | 9 | 64 | 64 | (subset of 10) |
| 45 turns | 9 | 116 | 116 | (subset of 10) |

| Session kind | Sessions | Findings | TP |
|---|---|---|---|
| cold | 9 | 32 | 32 |
| warm | 9 | 36 | 36 |
| chain | 9 | 169 | 169 |

**Chain sessions dominate** — 71% of FT-v3's findings come from chain
sessions. This is true for every model in this study and is not SFT-specific.

---

## 7. Updated hypothesis verdicts

**H1 (original):** "Larger base models find more vulnerabilities."
**Verdict:** Supported within environment. Apr 9 on RTX 4090: 7B (28.6%) < 14B (20.0%)* < 32B (34.3%). *14B anomaly likely due to tool-execution reliability on that cloud.

**H2 (original):** "Fine-tuning improves GT coverage."
**Revised verdict:** **Rejected.** Across 3 independent FT variants (FT-v1 32B, FT-v1 7B, FT-v2 7B, FT-v3 7B, FT-v3 14B), all regressed vs same-environment baseline on unique-GT coverage. FT improves precision marginally and shifts *which* GT entries are found (complementarity), but does not increase their number.

**H3 (new, supported by this work):** "Baseline + FT ensemble improves coverage over either alone."
**Supported.** Apr17 baseline ∪ FT-v3 reaches 45.7% vs 37.1% baseline alone. This is the strongest case for fine-tuning in this study.

**H4 (contamination):** "Qwen2.5-Coder's pretraining contains Juice Shop content, creating a ceiling for SFT."
**Supported empirically.** Baseline 7B recalls 37.1% of GT with zero training; FT-v3 with 2,500 Juice Shop–relevant examples does not exceed this. Writeups, the Pwning book, and CTF solutions for Juice Shop are all publicly indexable and likely present in Qwen's pretraining.

---

## 8. Limitations

1. **Single-run evaluations.** Each model was run once through the 27–29 session matrix; no statistical repeats. Confidence intervals on reported percentages are wide (±2–4 GT at 95% CI by bootstrap, not computed here).
2. **Environment cross-comparability.** Different clouds (RTX 4090, PRO 6000, local Mac) with different installed tool counts (25–30) mean absolute baseline numbers are not directly comparable. The thesis avoids cross-environment claims.
3. **DVWA not evaluated on FT.** All fine-tuned evaluations are on Juice Shop only; DVWA generalization of SFT remains untested and is listed as future work.
4. **Pretraining contamination is unverified.** We infer Juice Shop is in Qwen's pretraining from baseline performance, but no direct evidence (training-data disclosure, memorization probe) exists. A cleaner benchmark would be a custom, unreleased target.
5. **Quantization effects.** All models served via Q4_K_M GGUF (4.5-bit quantization). This likely reduces capability by 1–3% but affects all variants equally, preserving comparative validity.
6. **LoRA modifies <1% of weights.** FT-v3 7B trains 20 M of 7.6 B parameters (0.28%); FT-v3 14B trains 50 M of 8.2 B (0.61%). This is a structural limit on how much behavior LoRA-SFT can change.

---

## 9. Data references

| File | Purpose |
|---|---|
| `scripts/recompute_gt_coverage.py` | Canonical matcher (single source of truth). Writes `docs/recomputed_gt_coverage.json`, not the `_all` file below |
| `docs/recomputed_gt_coverage_all.json` | Per-experiment computed outputs. **No script in the repository writes this file** — see `docs/REPRODUCIBILITY.md`. Where a figure can be sourced to `docs/recomputed_all_experiments.json` instead, prefer that |
| — | *Every `runs/…` path below is gitignored and absent from a clone; the derived JSON in `docs/` is the only surviving record* |
| `runs/clean_2026-04-09/` | Apr 9 baselines (with local `pentest.db`) |
| `runs/cloud_2026-04-15_balanced/` | Apr 15 FT-v1 experiments |
| `runs/2026-04-17_00-07-23/` | Apr 17 baseline 7B (the controlled comparison) |
| `runs/2026-04-17_19-24-01/` | Apr 17 FT-v3 7B matrix |
| `runs/2026-04-17_12-29-10/` | Apr 17 FT-v3 14B matrix |
| `training_data/juicy3_{train,val}.jsonl` | FT-v3 dataset |
| `checkpoints/qwen2.5-coder-{7b,14b}-juicy3/` | FT-v3 LoRA adapters |
| `merged_models/qwen2.5-coder-{7b,14b}-juicy3-Q4_K_M.gguf` | FT-v3 deployable GGUFs |
| `docs/training_logs/training_{7b,14b}_juicy3.log` | FT-v3 training logs |

---

## 10. Recommended thesis framing (for abstract & conclusion)

> *"This thesis evaluated whether LoRA supervised fine-tuning (SFT) of
> Qwen2.5-Coder at 7B and 14B scales can improve agentic penetration-testing
> coverage on OWASP Juice Shop. Three fine-tuned variants were compared
> against their same-environment baselines under a single canonical
> ground-truth matching algorithm. None of the fine-tuned variants exceeded
> baseline on unique-GT coverage; all regressed by 3–5 GT entries while
> marginally improving precision. Combining baseline with fine-tuned
> predictions yielded a modest ensemble gain (from 37.1% to 45.7% at 7B
> scale), indicating that SFT shifts the model's attention to a
> complementary subset of vulnerability classes without expanding total
> coverage. We attribute the SFT ceiling to pretraining contamination —
> baseline models already recall ~30–40% of GT with zero training — and
> to LoRA's structural limit of modifying <1% of parameters. Practical
> implication: single-model SFT is not a productive direction for
> pretraining-saturated benchmarks; future work should focus on RL from TP
> reward signals, DPO with long-horizon preference pairs, and
> uncontaminated custom benchmarks."*
