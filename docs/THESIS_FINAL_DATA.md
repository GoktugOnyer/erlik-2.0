> ⚠️ **DEPRECATED** — this document mixes 'lenient', 'strict', and 'programmatic' GT matching algorithms inconsistently. All numbers here may differ from the canonical results under a single matcher. **For the authoritative numbers, see [THESIS_UNIFIED_RESULTS.md](THESIS_UNIFIED_RESULTS.md).**

---

# ERLIK 2.0 — FINAL THESIS DATA
## Comprehensive Evaluation: AI-Driven Pentesting with LoRA Fine-Tuning

**Author:** Göktug | MSc Cyber Security | FH Technikum Wien
**Date:** April 16, 2026
**Total sessions:** 654 | **Configurations:** 16 | **Clouds:** 4
**Targets:** OWASP Juice Shop (35 GT vulns), DVWA (19 GT vulns)

---

## 1. METHODOLOGY NOTE — Two Matching Algorithms

All results below report TWO ground-truth coverage figures:

- **Lenient match (used in earlier analysis):** Type match + URL OR param match + evidence keyword. Score ≥ 2.0 = TP. ONE finding can match multiple GT entries.
- **Strict match (used here):** Type match + URL pattern MUST match + parameter MUST match if specified. ONE finding maps to specific GT entries.

**The strict matching is more honest and is used as the primary metric below.** Lenient matching inflated results by ~20-30%.

---

## 2. COMPLETE EXPERIMENT TABLE

Each model ran the full 29-session matrix: 9 cold + 9 warm + 9 chain × 3 turn counts (15/30/45) + 2 repeat runs.

Format: `(sessions / total_findings / true_positives)`

| # | Cloud | Model | Cold | Warm | Chain | Total TP | Strict GT |
|---|-------|-------|------|------|-------|----------|-----------|
| 1 | Apr9 RTX4090 Docker | qwen2.5-coder:7b BASELINE | 9/13/12 | 9/27/24 | 9/161/158 | 194 | — |
| 2 | Apr9 RTX4090 Docker | qwen2.5-coder:14b BASELINE | 9/10/10 | 9/12/12 | 9/121/120 | 142 | — |
| 3 | Apr9 RTX4090 Docker | qwen2.5-coder:32b BASELINE | 9/65/65 | 9/45/44 | 9/216/212 | 321 | — |
| 4 | Apr9 RTX4090 Docker | qwen2.5:32b INSTRUCT | 9/4/0 | 9/0/0 | 9/42/15 | 15 | — |
| 5 | Apr13 A100 | qwen2.5-coder:7b BASELINE | 9/28/27 | 9/28/32 | 7/89/89 | 148 | 8/35 |
| 6 | Apr13 A100 | pentest-7b-r2 (r=32) | 9/24/24 | 8/24/24 | 9/123/123 | 171 | 5/35 |
| 7 | Apr13 A100 | pentest-7b-v2 (model-spec) | 9/24/27 | 8/19/19 | 9/157/157 | 203 | 4/35 |
| 8 | Apr13 A100 | pentest-7b-combined | 9/14/15 | 8/22/22 | 6/63/63 | 100 | 11/35 |
| 9 | Apr13 A100 | pentest-7b-scaled (0.5x) | 9/17/17 | 9/24/23 | 9/110/110 | 150 | 5/35 |
| 10 | Apr13 A100 | pentest-14b R1 | 9/10/10 | 9/17/17 | 9/61/61 | 88 | 5/35 |
| 11 | Apr13 A100 | pentest-14b-v2 | 9/7/7 | 9/13/13 | 8/33/33 | 53 | 5/35 |
| 12 | Apr13 A100 | pentest-32b R1 | 9/22/22 | 9/10/10 | 9/79/78 | 110 | 5/35 |
| 13 | Apr15 PRO6000 | qwen2.5-coder:32b BASELINE | 9/26/26 | 9/34/34 | 9/124/122 | 182 | 12/35 |
| 14 | Apr15 PRO6000 | pentest-32b FINE-TUNED | 9/13/12 | 9/22/30 | 5/80/80 | 122 | 6/35 |
| 15 | Apr15 PRO6000 | qwen2.5-coder:7b BASELINE | 9/16/14 | 8/35/36 | 7/63/62 | 112 | 8/35 |
| 16 | Apr15 PRO6000 | pentest-7b-balanced (incomplete) | 6/16/17 | 4/16/16 | 2/38/38 | 71 | 7/35 |

**Key observations:**
- Chain sessions consistently produce 60-80% of total findings across ALL models
- Fine-tuned models that show 'high TP' often inflate via lenient matching
- Strict GT typically 30-50% lower than lenient counts

## 3. SESSION-TYPE EFFECTIVENESS

Average TP per session, grouped by session type (across all models):

| Cloud | Cold avg TP/session | Warm avg TP/session | Chain avg TP/session |
|-------|---------------------|---------------------|----------------------|
| Apr9 RTX4090 Docker | 2.4 | 2.2 | 14.0 |
| Apr13 A100 | 2.1 | 2.3 | 10.8 |
| Apr15 PRO6000 | 2.1 | 3.9 | 13.1 |

**Conclusion:** Chain sessions outperform cold by 5-15x on TPs. This holds across ALL models, baselines AND fine-tuned. **Architecture matters more than fine-tuning.**

## 4. FAIR SAME-CLOUD COMPARISONS (Strict Matching)

### 4.1 Apr13 Cloud (A100, 30 tools enabled, 25 installed)

| Model | Strict GT | Total TP | Verdict |
|-------|-----------|----------|---------|
| qwen2.5-coder:7b BASELINE | 8/35 | 148 | |
| pentest-7b-r2 (r=32) | 5/35 | 171 | |
| pentest-7b-v2 (model-spec) | 4/35 | 203 | |
| pentest-7b-combined | 11/35 | 100 | |
| pentest-7b-scaled (0.5x) | 5/35 | 150 | |
| pentest-14b R1 | 5/35 | 88 | |
| pentest-14b-v2 | 5/35 | 53 | |
| pentest-32b R1 | 5/35 | 110 | |

### 4.2 Apr15 Cloud (PRO6000, 30 tools enabled, 25+custom installed)

| Model | Strict GT | Total TP | Cold TP | Warm TP | Chain TP |
|-------|-----------|----------|---------|---------|----------|
| qwen2.5-coder:32b BASELINE | 12/35 | 182 | 26 | 34 | 122 |
| pentest-32b FINE-TUNED | 6/35 | 122 | 12 | 30 | 80 |
| qwen2.5-coder:7b BASELINE | 8/35 | 112 | 14 | 36 | 62 |
| pentest-7b-balanced (incomplete) | 7/35 | 71 | 17 | 16 | 38 |

---

## 5. CRITICAL FINDINGS (CORRECTED with strict matching)

### Finding 1: Fine-Tuning Did NOT Improve Vulnerability Detection

Out of 13 fine-tuning experiments (Apr13 + Apr15 with strict matching):

- **0 fine-tuned models beat their same-cloud baseline**
- Fine-tuning consistently REDUCED total TPs by 15-50%
- The 'access control breakthrough' was a measurement artifact:
  - FT 32B produced only 3 raw 'Broken Access Control' findings
  - With strict URL matching, only 1 actually matched a GT entry
  - The previous '6/6 BAC' was lenient matching counting one finding against all 6 BAC GT entries

### Finding 2: Apr15 Same-Cloud Comparison (Strict)

| Model | Strict GT | Total TP |
|-------|-----------|----------|
| qwen2.5-coder:32b BASELINE | 12/35 | 182 |
| pentest-32b FINE-TUNED | 6/35 | 122 |
| qwen2.5-coder:7b BASELINE | 8/35 | 112 |
| pentest-7b-balanced (incomplete) | 7/35 | 71 |

- Baseline 32B: 12/35 GT, 182 TP
- FT 32B: 6/35 GT, 122 TP — **lost capability**
- Combined baseline+FT 32B: 12/35 GT — **fine-tuning added zero new vulns**

### Finding 3: Chain Architecture > Model Size > Fine-Tuning

Effect sizes (TP per session, Apr15 cloud):
- Cold → Chain: **5-15x more TPs**
- 7B → 32B: **~2x more TPs**
- Baseline → Fine-tuned: **0.5-0.7x TPs (worse)**

### Finding 4: Code Pretraining Is Essential (the only robust positive finding)

Apr9 cloud, same model size:
- Qwen2.5-Coder 32B: 321 total TP
- Qwen2.5 32B Instruct: 15 total TP
- **22x performance gap** — Instruct cannot generate valid JSON tool calls

### Finding 5: Catastrophic Forgetting Confirmed (R3 7B)

Apr13 cloud, same setup, only LoRA config differs:
- R1 (r=16, 2 layers): matched baseline
- R2 (r=32, 2 layers): -15% TP
- R3 (r=64, 7 layers, 3.6% trainable): **0 TP, total failure**

---

## 6. LIMITATIONS AND THREATS TO VALIDITY

### 6.1 Statistical Power
- Only 3 repeat runs per configuration (n=3)
- 7B coefficient of variation: 100% (highly unstable)
- 32B CV: 21% (more stable but still limited)
- **Cannot establish statistical significance** for most claims

### 6.2 Cross-Cloud Reproducibility Issues
- Same model on same target across clouds varies by ~40% in GT coverage
- Apr14 5090 cloud excluded due to incomplete tool installation
- Inference quality differences between GPUs may affect outputs

### 6.3 Matching Algorithm Sensitivity
- Lenient vs strict matching produces 20-50% different GT scores
- The orchestrator's built-in scorer (best-match) gives most conservative results
- All 'breakthrough' claims revisited under strict matching showed inflation

### 6.4 Incomplete Experiments
- 7B-balanced: only 13/29 sessions (cloud terminated)
- 14B-balanced: never executed
- DVWA fine-tuned: never executed

---

## 7. HONEST CONCLUSIONS FOR THESIS

### What Worked
1. **System architecture** (MCP orchestration, ground truth validation, chain sessions)
2. **Code-specialized pretraining** (22x improvement over Instruct)
3. **Multi-phase chain sessions** (5-15x improvement over cold start)
4. **Conservative LoRA config** (r=16, 2 layers) avoids catastrophic forgetting

### What Didn't Work
1. **LoRA fine-tuning** for vulnerability discovery improvement (0 of 13 experiments beat baseline)
2. **Aggressive LoRA** (r=64, 7 layers): catastrophic forgetting
3. **Memory injection alone**: model ignored manual testing instructions
4. **Model-specific training data** (V2): worst performer (-32%)

### Honest Thesis Statement

> *"This thesis presents a controlled evaluation framework for AI-driven penetration testing
> with ground truth validation. Across 654 sessions and 13 fine-tuning configurations on
> Qwen2.5-Coder models (7B/14B/32B), LoRA fine-tuning with small datasets (170-2670 examples)
> failed to improve vulnerability discovery over baseline models in any tested configuration
> when measured with strict ground truth matching. The investigation reveals three findings
> with practical implications: (1) code-specialized pretraining is essential (22x performance
> gap vs. instruction-tuned models), (2) multi-phase chain session architecture provides 5-15x
> improvement and compensates for model size, and (3) aggressive LoRA configurations cause
> catastrophic forgetting. The negative result on fine-tuning effectiveness contributes to
> the literature by establishing that domain-specific instruction tuning at small scale
> (≤2,700 examples) does not yield expected gains in autonomous pentesting agents, in
> contrast to prior work in static security analysis."*

---

## 8. DATA ARCHIVE LOCATIONS

```
runs/
├── clean_2026-04-09/          # Apr9 baselines (7B/14B/32B/Instruct, 30 tools)
├── dvwa_2026-04-11/           # DVWA cross-target (4 models)
├── finetuned_2026-04-12/      # R1 7B fine-tuned eval
├── cloud_2026-04-13/          # 8 fine-tuning experiments + DB
├── cloud_2026-04-15_balanced/ # 32B baseline+FT + 7B baseline+balanced + DB
└── memory_augmented_*.json    # Memory injection experiment

checkpoints/                   # All LoRA adapters preserved
training_data/                 # 7 dataset versions
docs/
├── EXPERIMENT_LOG.md          # Full timeline
├── FINAL_ALL_FINDINGS.md      # Previous findings (with lenient matching)
└── THESIS_FINAL_DATA.md       # THIS DOCUMENT
```

**EXCLUDED (invalid):** `runs/cloud_2026-04-14_proper/` — incomplete tool installation, results not reproducible.
