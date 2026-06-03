> ⚠️ **DEPRECATED** — this document mixes 'lenient', 'strict', and 'programmatic' GT matching algorithms inconsistently. All numbers here may differ from the canonical results under a single matcher. **For the authoritative numbers, see [THESIS_UNIFIED_RESULTS.md](THESIS_UNIFIED_RESULTS.md).**

---


================================================================================
ERLIK 2.0 — FINAL THESIS FINDINGS
Comprehensive Evaluation of LoRA Fine-Tuning for AI-Driven Penetration Testing
================================================================================

Author: Göktug | MSc Cyber Security | FH Technikum Wien
Date: April 15, 2026
Total: 654 evaluation sessions | 15 valid configurations | 7 training datasets
       5 GPU clouds | 2 target applications | 1 memory-augmented experiment

================================================================================
1. COMPLETE EXPERIMENT TABLE (valid runs only)
================================================================================

Excluded: Apr14 5090 cloud (only 21/30 tools — invalid comparison)
Excluded: R3 7B (0/35 catastrophic failure — dead model)
Excluded: 32B Instruct (3/35 — cannot invoke tools, different category)

 #  Model                    Cloud    GT Coverage  Find  Types  Dataset           Tools
--- ------------------------ -------- ------------ ----- ------ ----------------- -----
 1  32B Baseline             Apr15    23/35 (65%)    66    13   —                 25
 2  7B Baseline              Apr9     20/35 (57%)   204    24   —                 30
 3  32B Baseline             Apr9     20/35 (57%)   339    44   —                 30
 4  7B Baseline              Apr13    20/35 (57%)    62    10   —                 25+
 5  R1 7B (r=16)             Apr13    20/35 (57%)*    —     —   Generic 2314      25+
 6  Scaled 0.5x 7B           Apr13    18/35 (51%)    41     8   R1 scaled         25+
 7  FT 32B (new data)        Apr15    18/35 (51%)    47     6   New 2007          25
 8  Combined 7B              Apr13    17/35 (48%)    44     7   Mixed 2670        25+
 9  14B Baseline             Apr9     15/35 (43%)   147    12   —                 30
10  R2 7B (r=32)             Apr13    15/35 (42%)    54     8   R2 2450           25+
11  7B Baseline              Apr15    15/35 (42%)    58     —   —                 25
12  7B-balanced (50/50)      Apr15    15/35 (42%)    33     —   Balanced 1000     25†
13  Memory 7B                Local    15/35 (43%)    22     8   Memory inject     30
14  R1 14B                   Apr13    11/35 (31%)    32     4   Generic 2314      25+
15  R1 32B                   Apr13     9/35 (25%)    35     6   Generic 2314      25+
16  V2 7B (model-specific)   Apr13     9/35 (25%)    52     4   7B-only 227       25+
17  V2 14B                   Apr13     8/35 (22%)    20     4   14B-only 170      25+

* R1 7B 57% from Apr12 eval — no raw DB data available to verify
† 7B-balanced only 13/29 sessions completed (cloud terminated early)

================================================================================
2. VULNERABILITY CATEGORIES — WHO FOUND WHAT
================================================================================

Only including models with valid, complete runs on comparable setups.

Category                   Base   Base   Base   FT     FT     FT       Mem
                           7B     14B    32B    R1-7B  32B    7B-Bal   7B
                           Apr9   Apr9   Apr15  Apr13  Apr15  Apr15†   Local
-------------------------- ------ ------ ------ ------ ------ ------   -----
SQL Injection (3)           ✅     ✅     ✅     ✅     ✅     ❌       ✅
XSS (4)                     ✅     ❌     ✅     ✅     ❌     ❌       ❌
Broken Access Control (6)   ❌     ❌     ❌     ❌     ✅★    ✅★†    ❌
Broken Authentication (5)   ✅     ✅     ✅     ✅     ❌     ❌       ❌
Sensitive Data Exp (4)      ❌     ❌     ✅     ❌     ✅     ✅       ✅
Security Misconfig (4)      ✅     ✅     ✅     ✅     ✅     ✅       ✅
Info Disclosure (3)         ✅     ✅     ✅     ✅     ✅     ✅       ✅
CORS (1)                    ✅     ✅     ✅     ✅     ✅     ✅       ✅
SSRF (1)                    ❌     ❌     ❌     ❌     ❌     ❌       ❌
Open Redirect (1)           ❌     ❌     ❌     ❌     ❌     ❌       ❌
File Upload (1)             ❌     ❌     ❌     ❌     ❌     ❌       ❌
XXE (1)                     ❌     ❌     ❌     ❌     ❌     ❌       ❌
Prototype Pollution (1)     ❌     ❌     ❌     ❌     ❌     ❌       ❌

★ = FIRST TIME EVER FOUND — only by fine-tuned models
† = Incomplete run (13/29 sessions — cloud terminated)

================================================================================
3. FAIR COMPARISONS (same cloud, same tools only)
================================================================================

A) Apr9 Cloud — RTX 4090, Docker Kali, ALL 30 tools:
   7B:  20/35 (57%)  |  14B: 15/35 (43%)  |  32B: 20/35 (57%)
   → 7B matches 32B; 14B is worst

B) Apr13 Cloud — A100, native, 25+ tools:
   7B Baseline:     20/35 (57%)
   R1 7B (FT):      20/35 (57%)  → TIED with baseline (best FT result ever)
   R2 7B (r=32):    15/35 (42%)  → -15% ❌
   V2 7B (227 ex):   9/35 (25%)  → -32% ❌
   Combined 7B:     17/35 (48%)  → -9% ❌
   Scaled 0.5x 7B:  18/35 (51%)  → -6% ❌
   R1 14B:          11/35 (31%)  → vs 14B base 43% = -12% ❌
   V2 14B:           8/35 (22%)  → vs 14B base 43% = -21% ❌
   R1 32B:           9/35 (25%)  → vs 32B base 57% = -32% ❌

C) Apr15 Cloud — RTX PRO 6000, native, 25 tools:
   32B Baseline:     23/35 (65%)
   FT 32B:           18/35 (51%)  → -14% on GT BUT found 6 NEW vulns ★
   7B Baseline:      15/35 (42%)
   7B-balanced:      15/35 (42%)  → TIED on GT BUT found 6 NEW vulns ★†
   COMBINED 32B:     29/35 (83%)  → baseline + FT together

D) Local — Docker Kali, 30 tools:
   Memory 7B:        15/35 (43%)  → found 4 Sensitive Data vulns

================================================================================
4. KEY FINDINGS
================================================================================

FINDING 1: Fine-Tuning Discovers Previously Invisible Vulnerabilities
─────────────────────────────────────────────────────────────────────
Broken Access Control (6 vulns: IDOR, user enumeration, admin panel,
forged feedback, product manipulation, quantity API) was NEVER found
by ANY baseline model across 654 sessions on 5 clouds.

Fine-tuned 32B found ALL 6 on Apr15 cloud (same cloud as its baseline).
7B-balanced also found ALL 6 on the same cloud (13/29 sessions†).

This is the strongest evidence that fine-tuning teaches NEW testing
behaviors that base models never exhibit, regardless of session count.

FINDING 2: Fine-Tuning Trades Capabilities — Never Strictly Improves
────────────────────────────────────────────────────────────────────
On the same cloud with same tools, every fine-tuned model that gained
new categories lost others. Out of 10 valid same-cloud comparisons:
0 beat baseline on GT count, 2 tied, 8 scored lower.

Same-cloud evidence (Apr15):
  FT 32B: +6 Access Control, +4 Sensitive Data, -3 XSS, -5 Auth, -3 Misconfig
  Net: gained 10 GT entries, lost 11 GT entries = -1 overall

Root cause: LoRA creates behavioral specialisation. The model can
learn new testing patterns but loses existing ones in the process.

FINDING 3: Combined Baseline + Fine-Tuned = 83% (Best Result)
─────────────────────────────────────────────────────────────
On Apr15 cloud (same setup, fair comparison):
  Baseline 32B alone:    23/35 (65%)
  Fine-tuned 32B alone:  18/35 (51%)
  COMBINED:              29/35 (83%)

Only 6 vulns remain unfound by any approach: SSRF, Open Redirect,
File Upload, XXE, Prototype Pollution, Stored XSS.

FINDING 4: Catastrophic Forgetting Is Predictable
─────────────────────────────────────────────────
All on Apr13 cloud (same setup):
  R1 (r=16, 2 layers, 0.12% params): 57% — matched baseline
  R2 (r=32, 2 layers, 0.23% params): 42% — degradation
  R3 (r=64, 7 layers, 3.60% params):  0% — total failure

More trainable parameters = more forgetting. Lower training loss
(0.196 for R3) does NOT mean better task performance.

FINDING 5: Model Size Scaling Is Non-Linear
───────────────────────────────────────────
Apr9 cloud (all 30 tools, fairest comparison):
  7B:  20/35 (57%) — matches 32B
  14B: 15/35 (43%) — WORST
  32B: 20/35 (57%) — same as 7B

14B is consistently the worst performer across all clouds.
Model size alone does not predict pentesting capability.

FINDING 6: Code Pretraining Is Essential (22x Gap)
──────────────────────────────────────────────────
Apr9 cloud (same model size, same setup):
  32B Coder:    334 TP, 99% precision
  32B Instruct:  15 TP, 33% precision

22x performance gap. Instruct model cannot generate valid JSON
tool invocations. Code pretraining is a prerequisite.

FINDING 7: Memory Injection Helps Discovery, Not Exploitation
────────────────────────────────────────────────────────────
Local experiment (Docker Kali, all 30 tools):
  Best session: 14/35 (40%) GT in single session
  Aggregate:    15/35 (43%) across 3 sessions
  NEW: Found all 4 Sensitive Data Exposure vulns

But model ignored explicit manual testing instructions for IDOR,
JWT, SSRF. Knowledge ≠ behavior change. Fine-tuning changes
behavior; memory provides knowledge. Both are needed.

FINDING 8: Cross-Target Generalisation Works
───────────────────────────────────────────
Apr11 DVWA evaluation (same cloud, same tools):
  All Coder models: 12/19 GT (63%) — identical across sizes
  Auth wall blocks 7/19 vulns for all models

Scanner-based testing generalises across tech stacks (Node.js → PHP).

FINDING 9: Our Results vs Published Benchmarks
─────────────────────────────────────────────
  CVE-Bench (ICML 2025):  13% SOTA
  AutoPenBench:           21% autonomous
  PentestEval:            <50% per stage
  Our baseline 32B:       65% GT coverage
  Our combined approach:  83% GT coverage

================================================================================
5. TRAINING DATA EVOLUTION
================================================================================

  Version     Examples  Used In           Key Change
  ----------  --------  ----------------  ----------------------------------
  R1 Generic    2,314   R1 7B/14B/32B     13% real + 68% curated + 19% HF
  R2 +SQLi      2,450   R2 7B             Added SQLi reinforcement
  R3 Multi      2,630   R3 7B (FAILED)    Added multi-turn, caused forgetting
  Model-spec  170-570   V2 7B/14B         Only that model's own sessions
  Combined      2,670   Combined 7B       R1 + model sessions + fixes
  New (+logic)  2,007   FT 32B Apr15      1857 scanner + 150 logic vuln (3x)
  Balanced      1,000   7B-balanced       500 scanner + 500 logic vuln (10x)

================================================================================
6. LoRA CONFIGURATION COMPARISON (all on Apr13 cloud — fair)
================================================================================

  Config     r    Layers  Params   Epochs  Loss   GT     Verdict
  ---------  ---  ------  -------  ------  -----  -----  --------
  R1         16   2       0.12%    5       0.461  57%    Best (matched base)
  Scaled     16   2       0.12%    5       0.461  51%    0.5x weight at inference
  Combined   16   2       0.12%    2       0.37   48%    OK but below base
  R2         32   2       0.23%    5       0.399  42%    Moderate degradation
  V2 7B      16   2       0.12%    3       0.42   25%    Bad data → bad result
  R3         64   7       3.60%    5       0.196  0%     Catastrophic forgetting

  Best: r=16, 2 attention layers (q_proj, v_proj), 0.12% trainable params

================================================================================
7. PRACTICAL RECOMMENDATIONS
================================================================================

  1. DUAL-RUN STRATEGY: Run baseline then fine-tuned, merge findings.
     Achieves 83% vs 65% best single model.

  2. CONSERVATIVE LoRA: r=16, 2 attention layers only.
     Higher ranks cause catastrophic forgetting.

  3. USE 32B WHEN POSSIBLE: Larger models generalise better from
     limited training data for learning new testing behaviors.

  4. MEMORY + FINE-TUNING: Inject target knowledge for discovery,
     fine-tune for exploitation. Neither alone is sufficient.

  5. CODE MODELS ONLY: Instruct models cannot perform tool invocation.

================================================================================
8. UNSOLVABLE VULNS (6/35) — No approach found these
================================================================================

  SSRF             — Needs crafted POST with internal URL
  Open Redirect    — Needs allowlist bypass technique
  File Upload      — Needs crafted filename with null byte
  XXE              — Needs crafted XML entity payload
  Prototype Poll.  — Needs JS-specific __proto__ injection
  Stored XSS       — Needs multi-step: register → inject → trigger

  These require multi-step exploit crafting beyond current LLM capability.

================================================================================
9. DATA ARCHIVE
================================================================================

  runs/clean_2026-04-09/          — Baselines (7B/14B/32B/Instruct, 30 tools)
  runs/dvwa_2026-04-11/           — DVWA cross-target
  runs/finetuned_2026-04-12/      — R1 7B eval
  runs/cloud_2026-04-13/          — 8 fine-tuning experiments + DB
  runs/cloud_2026-04-15_balanced/ — 32B + balanced experiments + DB
  runs/memory_augmented_*.json    — Memory experiment
  checkpoints/                    — All LoRA adapters
  training_data/                  — 7 dataset versions

  EXCLUDED (invalid): runs/cloud_2026-04-14_proper/ (only 21 tools)

================================================================================
