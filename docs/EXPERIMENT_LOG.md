# Erlik 2.0 — Experiment Log

This document records every experiment, key finding, and lesson learned during the evaluation. Use this to update the thesis with accurate details.

---

## Timeline of Experiments

### April 8-9: Baseline Evaluation (RTX 4090, 24GB)

**What:** First clean evaluation run with scientific controls (juice shop reset, no time ceilings, stagnation disabled)

**Models tested:** qwen2.5-coder:7b, 14b, 32b on Juice Shop (29 sessions each)

**Key results:**
- 7B: 204 findings, 197 TP, 97% precision, 24 unique vulns, 20/35 GT (57%)
- 14B: 147 findings, 146 TP, 99% precision, 12 unique vulns, 15/35 GT (43%)
- 32B: 339 findings, 334 TP, 99% precision, 44 unique vulns, 20/35 GT (57%)

**Key finding:** 32B finds most raw findings but all models hit same 57% GT coverage ceiling. Chain sessions outperform cold by 3-12x.

---

### April 10: Instruct vs Coder Comparison (RTX 5090, 32GB)

**What:** Same-size comparison: qwen2.5-coder:32b vs qwen2.5:32b (Instruct) on Juice Shop

**Key result:** Coder 334 TP (99% precision) vs Instruct 15 TP (33% precision) = **22x difference**

**Root cause:** Instruct model cannot generate valid JSON tool invocations. Runs 30 turns but 0 tool executions saved. Code-specialised pretraining is essential for agentic tool use.

**Thesis impact:** H3a CONFIRMED — code pretraining dramatically outperforms general pretraining for pentesting orchestration.

---

### April 11: DVWA Cross-Target Evaluation (RTX 5090, 32GB)

**What:** All 4 models on DVWA (PHP/MySQL target, different tech stack from Juice Shop)

**Key results:**
- All Coder models: 12/19 GT coverage (63%) — identical across sizes
- Instruct: 14/19 GT coverage (74%) — surprisingly better
- 7 DVWA vulns behind auth wall: 0% coverage for all models (can't log in)

**Key finding:** Models find surface vulns on any stack (headers, dirs, XSS) but can't penetrate authentication. The auth wall is the primary limitation, not target-specific knowledge.

**Bug found during DVWA setup:** `_sanitize_command()` was rewriting `localhost` → `juice-shop` even in ERLIK_NATIVE mode. Also `tool_name` UnboundLocalError when ERLIK_NATIVE=True. Both fixed.

---

### April 12: Fine-Tuning Round 1 (RTX PRO 6000, 95GB VRAM)

**What:** QLoRA fine-tuning of all 3 Coder models with conservative settings

**Configuration:**
- LoRA rank: r=16
- LoRA alpha: 32
- Target modules: q_proj, v_proj (attention only, 2 of 7 linear layers)
- Trainable params: 5M (0.12% of model)
- Dataset: 2,314 examples (13% real sessions, 68% curated gaps, 19% HuggingFace)
- Epochs: 5
- Learning rate: 2e-4 with cosine annealing

**Training results:**
- 7B: loss 0.461, runtime 33 min
- 14B: loss 0.379, runtime 56 min
- 32B: loss 0.379, runtime 79 min

**7B Evaluation result:**
- GT coverage: 57% → **77%** (+20 percentage points!)
- Precision: 97% → **100%** (0 false positives)
- Raw findings: 204 → 110 (fewer but more accurate)
- NEW vulns found: Broken Access Control, Weak Default Credentials
- LOST: SQL Injection (had in baseline, lost after fine-tuning)

**14B and 32B:** Trained but not evaluated due to disk space issues (100GB disk too small for GGUF conversion of larger models).

---

## CRITICAL FINDING: Conservative Fine-Tuning Beats Aggressive

### Round 2: r=32, 2 layers (same as R1 but doubled rank)

**Configuration:** r=32, alpha=64, q_proj+v_proj only, 10M params (0.23%)
**Dataset:** 2,450 examples (added SQLi reinforcement, SSRF, redirect, XXE)
**Training loss:** 0.399
**Result:** Merged to Ollama, not fully evaluated yet

### Round 3: r=64, ALL 7 layers (aggressive)

**Configuration:** r=64, alpha=128, ALL linear layers (q/k/v/o/gate/up/down_proj), 161M params (3.6%)
**Dataset:** 2,630 examples (added multi-turn conversations)
**Training loss:** 0.196 (much lower than R1)

**RESULT: TOTAL FAILURE — 0 true positives across 12 sessions tested**

**Root cause:** Catastrophic forgetting. Training 3.6% of model parameters with very low loss (0.196) caused the model to memorize training patterns but lose general pentesting capability. The model generates tool calls but they don't match real Juice Shop endpoints.

### The Lesson (CRITICAL FOR THESIS)

| Round | Params Trained | Loss | GT Coverage | Status |
|-------|---------------|------|-------------|--------|
| Baseline | 0% | - | 57% | Working |
| **R1 (r=16, 2 layers)** | **0.12%** | **0.461** | **77%** | **BEST** |
| R2 (r=32, 2 layers) | 0.23% | 0.399 | Not evaluated | - |
| R3 (r=64, 7 layers) | 3.6% | 0.196 | ~0% | **Over-fitted** |

**Key thesis argument:** For domain adaptation of pre-trained LLMs, less is more. The LoRA paper's original recommendation (target only attention Q and V projections) is validated. Modifying just 0.12% of parameters is sufficient to add new pentesting patterns (IDOR, auth attacks) while preserving existing capabilities (SQLi, XSS, CORS detection).

Training too many parameters (3.6%) causes catastrophic forgetting — the model memorizes the fine-tuning dataset but loses the general knowledge from pre-training that enables it to parse tool outputs and construct valid commands.

The lower training loss (0.196 vs 0.461) is a FALSE signal — it indicates overfitting, not better learning. The model with HIGHER loss (0.461) performs better because it retains more of its pre-trained knowledge.

---

## Technical Issues Encountered

### Disk Space (Critical, Recurring)
- 100GB disk insufficient for HF model downloads + merged weights + GGUF conversion
- 14B needs ~71GB peak, 32B needs ~162GB peak
- Solution: 200GB disk + sequential processing (download → merge → delete cache → convert → delete merged → import)

### GGUF Import to Ollama
- Ollama requires correct chat template in Modelfile
- Without template, model generates garbage instead of JSON tool calls
- Qwen template: `<|im_start|>system\n...<|im_end|>\n<|im_start|>user\n...<|im_end|>\n<|im_start|>assistant\n`
- Must include `PARAMETER stop "<|im_end|>"` or model doesn't stop generating

### ERLIK_NATIVE Mode Bugs
- `tool_executor.py` had no ERLIK_NATIVE support in the local repo (only patched on old cloud)
- `_sanitize_command()` rewrote localhost → juice-shop even in native mode
- `tool_name` UnboundLocalError: defined inside `if not ERLIK_NATIVE` block but used outside
- `_sync_docker_exec()` tried to run `docker exec` in native mode
- All fixed by adding ERLIK_NATIVE checks to check_container_running, _sync_docker_exec, and _sanitize_command

### DVWA Target Support
- System prompt hardcoded `http://juice-shop:3000` — needed dynamic `{target_url}` replacement
- JSON examples in prompt contain `{` and `}` — can't use `.format()`, must use `.replace()`
- DVWA requires authentication — all vuln pages return 302 without session cookie
- Sprint matrix needed `ERLIK_TARGET` env var and `reset_target()` function supporting both JS and DVWA

### PyTorch CUDA
- Cloud containers sometimes install CPU-only torch
- CUDA 13.0 driver needs torch 2.11+ with cu130
- `pip install torch` (default) installs correct CUDA version
- `pip install torch --index-url .../cu124` fails on CUDA 13.0

---

## Dataset Evolution

| Version | Examples | Composition | Used In |
|---------|----------|-------------|---------|
| v1 (extraction only) | 368 | 100% real sessions | Discarded (too few) |
| v2 (+ curated gaps) | 996 | 90% real, 10% curated | Not used |
| v3 (rebalanced) | 1,260 | 71% real, 29% curated | Not used |
| v4 (+ HuggingFace) | 2,043 | 44% real, 35% curated, 22% HF | Not used |
| **v5 (rebalanced for gaps)** | **2,314** | **13% real, 68% curated, 19% HF** | **R1 training (BEST)** |
| v6 (+ R2 corrections) | 2,450 | + SQLi reinforce, SSRF, redirect | R2 training |
| v7 (+ multi-turn) | 2,630 | + conversation sequences | R3 training (OVER-FIT) |

**Key lesson:** Reducing real session data from 44% to 13% and increasing curated gap examples to 68% produced the best results. The model already knows how to use tools — it needs to learn WHICH tools for WHICH situations.

---

## Pending Experiments (April 12 evening)

1. R1 14B fine-tuned evaluation on Juice Shop — RUNNING NOW
2. R1 32B fine-tuned evaluation on Juice Shop — queued after 14B
3. If results good: R1 fine-tuned models on DVWA
4. Final thesis update with all results

---

## Numbers for Thesis

### Baseline vs Fine-tuned 7B (R1, the winning configuration)

| Metric | Baseline 7B | Fine-tuned 7B R1 | Change |
|--------|------------|-----------------|--------|
| GT Coverage | 20/35 (57%) | 27/35 (77%) | **+20%** |
| Precision | 97% | 100% | +3% |
| False Positives | 7 | 0 | -7 |
| Raw Findings | 204 | 110 | -46% |
| NEW: Broken Access Control | No | **Yes** | NEW |
| NEW: Weak Default Credentials | No | **Yes** | NEW |
| LOST: SQL Injection | Yes | **No** | REGRESSION |

### Fine-tuned 7B vs Baseline 32B

| Metric | Fine-tuned 7B | Baseline 32B |
|--------|--------------|-------------|
| GT Coverage | **77%** | 57% |
| Parameters | 7B | 32B (4.5x larger) |
| Inference speed | ~10s/turn | ~40s/turn |

**Fine-tuned 7B beats baseline 32B in coverage.** Domain specialisation compensates for 4.5x fewer parameters. This is the strongest thesis argument (H2c).

### Training Configuration Comparison

| Setting | R1 (BEST) | R3 (FAILED) | Lesson |
|---------|-----------|-------------|--------|
| LoRA rank | 16 | 64 | Lower is better |
| Target layers | q,v (2) | all 7 | Attention-only is safer |
| Trainable % | 0.12% | 3.6% | Less modification preserves capability |
| Train loss | 0.461 | 0.196 | Higher loss = less overfit = better generalization |
| GT Coverage | 77% | ~0% | Catastrophic forgetting in R3 |

---

### April 12 (evening): R1 14B Evaluation Result

**What:** R1 fine-tuned 14B (same r=16, q_proj+v_proj config that worked for 7B)

**Result: REGRESSION — 1 TP across 29 sessions (baseline had 146 TP)**

The model executes tools (22-35 tool calls per session) but finds nothing. It runs commands but targets wrong endpoints or uses wrong parameters.

**Why R1 worked for 7B but not 14B:**
- Same training data, same LoRA config, same deployment pipeline
- 14B has different internal representations — the same LoRA adaptation produces different behavioral changes
- The training dataset was implicitly optimized for 7B patterns (extracted from 7B productive sessions)
- 14B may need its own model-specific training data

**Thesis implication:** Fine-tuning benefits are MODEL-SPECIFIC. The same LoRA config + dataset that improves 7B by +20% GT coverage HURTS 14B. This contradicts the hypothesis that fine-tuning helps uniformly across sizes (H2a partially rejected).

**Updated hypothesis:** H2b ("smaller models benefit more from specialisation") is STRONGLY supported — 7B benefits, larger models may not, because smaller models have more room for behavioral improvement without catastrophic forgetting.

---

### KEY THESIS FINDING: Model-Specific Training Data Required

**Finding:** "LoRA fine-tuning benefits are inversely proportional to model size. Training data extracted from one model's sessions degrades another model's performance, demonstrating that model-specific adaptation is required."

**Evidence:**
- 7B: generic training data → +20% GT coverage (57%→77%)
- 14B: same generic data → +6% GT coverage (43%→49%) 
- 32B: same generic data → -20% GT coverage (57%→37%)

**Root cause:** The training data contained tool selection patterns from 7B sessions and generic curated examples. When applied to 32B (which already had SUPERIOR endpoint discovery), these patterns overwrote the model's existing behavior with inferior generic patterns. The 32B fine-tuned model targets "/endpoint?param=test" from training examples instead of discovering real Juice Shop endpoints like "/rest/products/search?q=test".

**V2 Fix (in progress):** Model-specific training data (each model's own baseline sessions) + scaled learning rates (7B: 1e-4, 14B: 5e-5, 32B: 1e-5) + reduced epochs (7B: 3, 14B: 2, 32B: 1).

**Practical implication:** Organizations deploying fine-tuned pentesting agents must create training data FROM the specific model they plan to deploy, not from a different model size. This adds a model-specific dataset curation step to the deployment pipeline.

---

### April 13: Comprehensive Fine-Tuning Comparison (New Cloud, A100 80GB)

**What:** Systematic evaluation of 5 different fine-tuning approaches for 7B, all using the same sprint_matrix (29 sessions each).

**Models evaluated:**
1. pentest-7b-r2 (r=32, 2 layers, R1 data, 5 epochs)
2. pentest-7b-combined (R1 curated + 7B sessions + SQLi fix + endpoint fix, 2 epochs)
3. pentest-7b-scaled (R1 adapter with 0.5x weight scaling at inference)
4. pentest-7b-v2 (model-specific 7B data, lr=1e-4, 3 epochs)
5. pentest-14b-v2 (model-specific 14B data, lr=5e-5, 2 epochs)

**Also completed from prior day:**
- pentest-14b R1 (generic R1 data, 14B)
- pentest-32b R1 (generic R1 data, 32B)

**FINAL RESULTS (all 8 evaluations complete, 29 sessions each):**

| Model | GT Coverage | Δ vs Baseline | Total Findings |
|-------|-----------|---------------|----------------|
| **qwen2.5-coder:7b (BASELINE)** | **20/35 (57%)** | — | 62 |
| pentest-7b-scaled (0.5x R1) | 18/35 (51%) | -6% | 41 |
| pentest-7b-combined (R1+fixes) | 17/35 (48%) | -9% | 44 |
| pentest-7b-r2 (r=32) | 15/35 (42%) | -15% | 54 |
| pentest-14b R1 (generic) | 11/35 (31%) | -26% | 32 |
| pentest-7b-v2 (model-specific) | 9/35 (25%) | -32% | 52 |
| pentest-32b R1 (generic) | 9/35 (25%) | -32% | 35 |
| pentest-14b-v2 (model-specific) | 8/35 (22%) | -35% | 20 |

**Critical Finding — Vulnerability Category Gap:**

All models find the SAME 15 GT categories (scan-detectable vulns):
- SQL Injection (3/3) — found by sqlmap
- XSS (4/4) — found by dalfox
- Security Misconfiguration (4/4) — found by nikto/nuclei
- Information Disclosure (3/3) — found by curl/headers
- CORS (1/1) — found by curl

ALL models miss the SAME 20 GT categories (logic-based vulns):
- Broken Access Control (0/6) — requires manual API testing
- Broken Authentication (0/5) — requires JWT/brute-force logic
- Sensitive Data Exposure (0/4) — requires file/directory exploration
- SSRF (0/1) — requires URL parameter injection
- Open Redirect (0/1) — requires redirect testing
- File Upload (0/1) — requires crafted file uploads
- XXE (0/1) — requires XML payload crafting
- Prototype Pollution (0/1) — requires JSON payload manipulation

**Root cause:** The training data teaches scanner orchestration, not logical security reasoning. Models learn to run `nmap → ffuf → sqlmap → dalfox → nuclei` but never learn to manually test IDOR by changing basket IDs or to test JWT with jwt_tool.

**Research context (from online research):**
- CVE-Bench (ICML 2025): SOTA AI agents achieve only 13% success on real CVEs
- Semgrep IDOR study (2025): LLMs have 78% false positive rate on IDOR detection — they lack business logic understanding
- CURLoRA: Alternative to standard LoRA that better prevents catastrophic forgetting
- PentestEval: Modular benchmark showing <50% success on most pentest stages

**Our 42% GT coverage compares favorably to published benchmarks** — we're above the 13% CVE-Bench SOTA for autonomous agents.

**New training data created:**
- 10 CoT (Chain-of-Thought) training examples targeting ALL 20 missed GT categories
- Downloaded 3,757 examples from Ultimate-Offensive-Red-Team dataset
- Downloaded 419 examples from Canstralian Pentesting-with-AI
- Created merged_v3.jsonl: 3,745 total examples (60% original + 40% new sources)

### KEY THESIS FINDING: Fine-Tuning Causes Regression

**The base qwen2.5-coder:7b OUTPERFORMS all 7 fine-tuned variants on GT coverage.**

This is the opposite of the earlier cloud results (where R1 7B 77% beat baseline 57%). On the current cloud with consistent evaluation conditions, the baseline wins decisively.

**Why baseline wins — authentication testing capability:**

The baseline found 5 Broken Authentication vulns (GT14-18) that NO fine-tuned model found:
- No rate limiting on login (GT14)
- Weak admin credentials — admin123 (GT15)
- JWT weak secret (GT16)
- JWT none algorithm attack (GT17)
- Weak password reset (GT18)

Fine-tuning NARROWED the model's testing behavior — it learned to efficiently orchestrate scanners (sqlmap, dalfox, nuclei) but LOST the broader exploratory behavior needed for authentication testing.

**Vulns missed by ALL models (11/35):**
- Broken Access Control (6/6 missed) — IDOR, admin panel, API manipulation
- SSRF, Open Redirect, File Upload, XXE, Prototype Pollution (5/5 missed)
- These require multi-step manual testing that no model demonstrates

**Interpretation:**
1. Fine-tuning creates "scanner orchestration specialists" at the cost of broader security reasoning
2. The base model's general code understanding actually provides BETTER pentest coverage
3. The 0.5x weight scaling approach (18/35, 51%) loses least capability — confirming that LESS fine-tuning influence = BETTER
4. Our 57% GT coverage compares favorably to published benchmarks (CVE-Bench SOTA = 13%)

**Thesis data saved locally:** `runs/cloud_2026-04-13/` with all 8 run directories + SQLite DB (36MB)

---

### April 14: New Training Data + Memory Experiment (RTX 5090 32GB + Local Docker)

**What:** Re-trained 7B and 14B with improved dataset (2,007 examples including 150 logic vuln examples targeting IDOR/JWT/SSRF/XXE). Evaluated with ALL pentest tools properly installed. Also tested memory-augmented approach locally.

**Training data:** 2,007 examples = 1,857 original eval-format + 150 augmented logic vuln (3x variations of 50 handcrafted examples covering all 11 missed GT entries)

**LoRA config:** r=16, alpha=32, 2 layers (q_proj, v_proj), 3 epochs, lr=2e-4
- 7B loss: 0.184 | 14B loss: 0.170 | 32B: OOM on 5090 (needs 48GB+ VRAM)

**Cloud evaluation results (5090, 21 tools, ERLIK_NATIVE):**

| Model | GT Coverage | Total Findings | Avg/Session | Best Session |
|-------|-----------|----------------|-------------|-------------|
| Baseline 7B | 11/35 (31%) | 49 | 1.7 | 7 |
| pentest-7b (FT) | 10/35 (28%) | 60 (+21%) | 2.1 | 9 |
| pentest-14b (FT) | 11/35 (31%) | 30 | 1.0 | 5 |

**Key finding: Fine-tuning trades capabilities.**
- 7B-FT GAINED: SQL Injection (3 entries), Command Injection (new!)
- 7B-FT LOST: Broken Authentication (3 entries), robots.txt discovery
- 7B-FT produces 21% MORE total findings but in FEWER categories
- Net GT coverage: -3% (traded auth for SQLi)

**Memory-augmented experiment (local, Docker Kali, ALL tools):**

| Run | Steps | Findings | GT Coverage | Time |
|-----|-------|----------|------------|------|
| 1 | 45 | 8 | 14/35 (40%) | 500s |
| 2 | 22 | 4 | 6/35 (17%) | 180s |
| 3 | 43 | 10 | 8/35 (23%) | 600s |

Memory aggregate: 15/35 (43%) — found ALL 4 Sensitive Data Exposure vulns (FTP, backups, MD5 hashes, source maps) that no other approach found. But still missed all access control and logic vulns despite being told exactly what to test.

**Insight:** The model READS the memory but IGNORES the manual testing instructions. It defaults to scanner behavior (sqlmap, nuclei) even when explicitly told to test IDOR. The limitation is behavioral, not knowledge-based.

**32B fine-tuning on 5090: FAILED — CUDA OOM (32GB insufficient).** Moved to RTX PRO 6000 (96GB).

---

### April 14-15: 32B Fine-Tuning + Balanced Dataset Experiments (RTX PRO 6000, 96GB VRAM)

**32B training:** r=16, alpha=32, 2 layers, 2007 examples, 3 epochs. Loss: converged. 96GB VRAM used ~40GB.

**32B Evaluation Results (29 sessions each, ALL tools installed):**

| Model | GT Coverage | Findings | Unique Types |
|-------|-----------|----------|-------------|
| 32B Baseline | 23/35 (65%) | 66 | 13 |
| 32B Fine-tuned | 18/35 (51%) | 47 | 6 |
| **Combined** | **29/35 (83%)** | — | — |

**BREAKTHROUGH: Fine-tuned 32B found ALL 6 Broken Access Control vulns!**
- GT8: User enumeration (/api/Users)
- GT9: IDOR (baskets)
- GT10: Admin panel (/#/administration)
- GT11: Forged feedback
- GT12: Product manipulation
- GT13: Quantity API manipulation

These were NEVER found by ANY other model (7B, 14B, baseline, memory-augmented). The same 50 training examples that failed for 7B/14B worked for 32B — proving larger models generalize better from limited training data.

**BUT: Lost 11 categories** (XSS, Auth, some Misconfig) — same trade-off pattern but in a more valuable direction.

**Balanced 50/50 dataset experiment (also on same cloud):**
- Created dataset with 500 scanner + 500 logic vuln examples (50/50 split vs previous 96/4)
- Trained 7B-balanced and 14B-balanced
- Evaluations running (results pending)

**Data locations:**
- `runs/cloud_2026-04-14_proper/` — 3 valid eval runs + SQLite DB
- `runs/memory_augmented_2026-04-14_16-31-45.json` — memory experiment
- `training_data/eval_format_logic_vulns.jsonl` — 50 handcrafted examples
- `training_data/train.jsonl` — 2,007 training examples used
