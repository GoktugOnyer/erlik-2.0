# Fine-Tuning Dataset and Training Methodology

This document describes the fine-tuning dataset construction, composition, and training procedure for updating the thesis.

---

## 1. Dataset Construction

### 1.1 Overview

The fine-tuning dataset was constructed from three sources:

| Source | Examples | Percentage | Purpose |
|--------|----------|-----------|---------|
| Real session data | 300 | 13% | Reinforce effective tool selection patterns from baseline evaluation |
| Curated expert demonstrations | 1,573 | 68% | Teach new attack patterns the baseline models cannot perform |
| Public HuggingFace datasets | 441 | 19% | Add general pentesting knowledge and security reasoning |
| **Total** | **2,314** | **100%** | |

### 1.2 Data Split

| Split | Examples | Percentage |
|-------|----------|-----------|
| Training | 1,966 | 85% |
| Validation | 186 | 8% |
| Test | 162 | 7% |

### 1.3 Format

Each example follows the Qwen chat template with three roles:

```json
{
  "messages": [
    {"role": "system", "content": "You are an autonomous penetration testing agent targeting {target_url}. Respond with ONLY a JSON object. Available tools: curl, nmap, nuclei, sqlmap, ..."},
    {"role": "user", "content": "Tools run so far: nmap (1x), gobuster (1x)\nPrevious tool: gobuster\nOutput: /api (500) /ftp (200) /rest (500)..."},
    {"role": "assistant", "content": "{\"action\": \"run_tool\", \"command\": \"sqlmap -u \\\"http://juice-shop:3000/rest/products/search?q=test\\\" --batch --level=3\", \"reason\": \"Found parameterised endpoint. Testing SQL injection.\"}"}
  ]
}
```

The system prompt specifies the target URL and available tools. The user message provides the current context (tools run, previous output). The assistant message is the correct action — either a tool invocation, a vulnerability finding report, or a session completion signal.

---

## 2. Source 1: Real Session Data (300 examples, 13%)

### 2.1 Origin

Extracted from the 232 baseline evaluation sessions across both Juice Shop and DVWA targets. The extraction script (`scripts/extract_training_data.py`) reads the orchestrator's SQLite database and selects steps from sessions that produced 3 or more true positive findings.

### 2.2 Selection Criteria

- Only steps from "high-finding" sessions (total_findings >= 3)
- Only steps where the tool actually executed and produced output (tool_output length > 20 characters)
- Balanced by tool: maximum 60 examples per tool to prevent any single tool from dominating
- Reduced from the original 895 extracted examples to 300 to rebalance the dataset toward curated examples

### 2.3 Why Only 13%

The real session data teaches the model to repeat its existing behaviour — the same tool chains that produced the baseline results. Since the goal of fine-tuning is to IMPROVE beyond baseline performance (especially on the 43% of ground truth vulnerabilities that all models miss), the majority of the training signal must come from examples that demonstrate NEW patterns the model has never performed.

### 2.4 What These Examples Teach

- Effective gobuster → curl → sqlmap chaining patterns
- Productive tool selection in chain sessions (phase-appropriate tools)
- How to construct correct command-line arguments for each tool
- When to report findings vs continue scanning

---

## 3. Source 2: Curated Expert Demonstrations (1,573 examples, 68%)

### 3.1 Construction Method

Written manually by the researcher based on known Juice Shop and DVWA vulnerabilities, correct pentesting methodology, and the specific gaps identified in the baseline evaluation. Each example represents what an expert human penetration tester would do in the given context.

### 3.2 Category Breakdown

| Category | Examples | What It Teaches | Gap Addressed |
|----------|----------|-----------------|---------------|
| Tool selection & chaining | 75 | When to switch tools, discovery→exploitation chains | General improvement |
| IDOR / Broken Access Control | 138 | Login → probe baskets/orders → diff-view → report finding | A01: 13% → target 50%+ |
| SQL Injection (deep) | 90 | Login bypass variants, UNION extraction, blind SQLi, authentication bypass | A03 confirmation |
| XSS (all types) | 78 | Reflected, DOM, stored, WAF bypass, DVWA 3 types | A03 XSS gap |
| JWT / Authentication attacks | 72 | Weak secret cracking, none algorithm, password spray, reset abuse, rate limiting | A07 inconsistency |
| DVWA authenticated testing | 264 | Login flow → navigate vuln pages → SQLi/CmdInj/LFI/XSS/upload/CSRF | DVWA auth wall (7 missed vulns) |
| Juice Shop full chains | 132 | Complete 4-phase recon→discovery→vuln_scan→exploitation sequences | Chain methodology |
| Output interpretation | 66 | How to read nmap/gobuster/sqlmap/nuclei/nikto output and decide next action | Output parsing gap |
| Error recovery | 48 | What to do when tools fail, timeout, or produce no results | Resilience |
| Strategic decisions | 72 | Turn budget management, phase transitions, dig deeper vs move on | Decision quality |
| Negative corrections | 106 | Stop repeating nmap, don't call done early, diversify tools, use arjun for params | 14B premature termination |
| Advanced injection (XXE, prototype pollution, SSTI) | 78 | NoSQL injection, XXE via file upload, prototype pollution, SSTI, CRLF, path traversal | A03/A05 expansion |
| Advanced recon (.git, backups, phpinfo) | 54 | Exposed git repositories, backup files, phpinfo, Dockerfile, source maps | A02/A05 discovery |
| API abuse | 48 | Mass assignment, negative quantity, price manipulation, method tampering | A01 business logic |
| File inclusion / discovery | 48 | LFI path traversal, null byte bypass, backup file enumeration | DVWA LFI gap |
| Payload crafting | 36 | SQLi bypass variants, XSS evasion, command injection separators, SSRF metadata | Payload diversity |
| Reporting & findings | 42 | Correct severity classification, evidence formatting, when to call done | Report quality |
| SSRF | 18 | Profile image URL fetch, file:// protocol, cloud metadata | A10: 0% → target detected |
| Browser testing | 24 | Playwright crawl for SPA routes, interactive-pw login flow, admin panel access | SPA-specific discovery |
| Headers & config | 30 | Missing security headers, Swagger exposure, TLS analysis, Prometheus metrics | A05 coverage |
| Generic target (non-Juice-Shop) | 18 | Tomcat, WordPress, Apache/PHP — generalisation beyond training targets | Generalisation |
| Open redirect | 12 | /redirect?to= abuse, allowlist bypass | A01 expansion |

### 3.3 Tripling Strategy

Critical gap examples (IDOR, DVWA auth, full chains, advanced injection) are tripled (3x) in the dataset to increase their influence during training. This is a standard oversampling technique for imbalanced datasets — the model sees these patterns 3 times more often, making them more likely to be learned.

### 3.4 Validation of Curated Examples

All curated examples use:
- Real Juice Shop endpoint URLs verified against the v17.1.1 API
- Real DVWA vulnerability page paths verified against the installed instance
- Correct tool syntax verified by manual testing
- Realistic tool output based on actual captured outputs from baseline sessions
- Proper JSON response format matching the orchestrator's expected schema

---

## 4. Source 3: Public HuggingFace Datasets (441 examples, 19%)

### 4.1 Datasets Used

| Dataset | Source | Examples Used | Total Available | Purpose |
|---------|--------|-------------|----------------|---------|
| preemware/pentesting-eval | HuggingFace | 241 | 241 | Pentesting knowledge Q&A — teaches WHY attacks work |
| AlicanKiraz0/Cybersecurity-Dataset-Fenrir-v2.0 | HuggingFace | 200 | 83,920 | Offensive security reasoning (filtered to pentest-relevant) |

### 4.2 pentesting-eval (241 examples)

Multiple-choice questions about penetration testing concepts with explanations. Converted to our format as knowledge-enrichment examples. Covers topics including: dynamic analysis techniques, memory forensics, network exploitation, web application attacks, and defensive evasion.

These examples do not teach specific tool commands but improve the model's understanding of security concepts, enabling better reasoning about which attack vector to pursue.

### 4.3 Cybersecurity-Dataset-Fenrir-v2.0 (200 of 83,920)

A large-scale cybersecurity training dataset containing system/user/assistant triples. Filtered from 83,920 entries to 200 using keyword matching for offensive security relevance: SQL injection, XSS, IDOR, command injection, file inclusion, SSRF, CSRF, JWT, brute force, privilege escalation, penetration testing, exploit, vulnerability scanning, and specific tool names (nmap, sqlmap, nuclei, etc.).

The filtered subset provides deep technical explanations of attack techniques that supplement our curated action-based examples with theoretical knowledge.

---

## 5. Tool Distribution

The dataset covers all 30 tools in the Erlik 2.0 toolset:

| Tool | Examples | Percentage | Role |
|------|----------|-----------|------|
| curl | 709 | 30.6% | Primary interaction tool (probing, verification, exploitation) |
| knowledge | 441 | 19.1% | HuggingFace knowledge examples (no tool action) |
| finding | 309 | 13.4% | Vulnerability reporting examples |
| sqlmap | 96 | 4.1% | SQL injection detection |
| gobuster | 71 | 3.1% | Directory enumeration |
| nmap | 57 | 2.5% | Port scanning and service ID |
| jwt_tool | 56 | 2.4% | JWT analysis and attacks |
| done | 54 | 2.3% | Session completion signals |
| dalfox | 50 | 2.2% | XSS detection |
| nuclei | 48 | 2.1% | Template-based scanning |
| whatweb | 44 | 1.9% | Technology fingerprinting |
| pw-crawl | 42 | 1.8% | JavaScript-aware crawling |
| ffuf | 38 | 1.6% | Web fuzzing |
| xsstrike | 35 | 1.5% | XSS detection |
| arjun | 34 | 1.5% | Hidden parameter discovery |
| zap-cli | 30 | 1.3% | Automated scanning |
| login-helper | 27 | 1.2% | Authentication helper |
| commix | 23 | 1.0% | Command injection |
| nikto | 21 | 0.9% | Server scanning |
| crlfuzz | 20 | 0.9% | CRLF injection |
| diff-view | 19 | 0.8% | IDOR response comparison |
| wafw00f | 17 | 0.7% | WAF detection |
| sslyze | 13 | 0.6% | TLS analysis |
| hydra | 11 | 0.5% | Brute force |

curl dominates (30.6%) because it is the primary tool for manual probing, IDOR testing, CORS checking, header analysis, and API interaction — it is the most versatile tool in the pentesting workflow. The "finding" category (13.4%) teaches the model when and how to correctly report discovered vulnerabilities.

---

## 6. Training Configuration

### 6.1 QLoRA Hyperparameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Quantisation | 4-bit NF4 (NormalFloat) | Fits 32B model in GPU memory |
| LoRA rank (r) | 16 | Balance between capacity and overfitting |
| LoRA alpha (α) | 32 | Effective learning rate multiplier α/r = 2 |
| LoRA dropout | 0.05 | Regularisation |
| Target modules | q_proj, v_proj | Attention-focused adaptation (per LoRA paper) |
| Trainable parameters | ~0.05-0.1% of total | Parameter-efficient fine-tuning |

### 6.2 Training Hyperparameters

| Parameter | Value |
|-----------|-------|
| Learning rate | 2e-4 with cosine annealing |
| Warmup ratio | 10% |
| Batch size | 1 (gradient accumulation 4 = effective batch 4) |
| Epochs | 5 (with early stopping, patience 2) |
| Max sequence length | 8,192 tokens |
| Loss function | Cross-entropy on assistant tokens only |
| Precision | bfloat16 |
| Weight decay | 0.01 |

### 6.3 Models Fine-Tuned

| Model | Base | VRAM Required | Estimated Training Time |
|-------|------|-------------|------------------------|
| qwen2.5-coder:7b | Qwen/Qwen2.5-Coder-7B-Instruct | ~16 GB | ~30 min |
| qwen2.5-coder:14b | Qwen/Qwen2.5-Coder-14B-Instruct | ~24 GB | ~60 min |
| qwen2.5-coder:32b | Qwen/Qwen2.5-Coder-32B-Instruct | ~40 GB | ~90 min |

All three models are fine-tuned with identical dataset, hyperparameters, and LoRA configuration. The only variable is the base model size. This enables direct comparison of fine-tuning effect across model sizes (RQ2/H2b).

### 6.4 Deployment Pipeline

After training:
1. LoRA adapter weights saved as checkpoint (~50-200 MB per model)
2. Adapter merged with base model weights
3. Merged model quantised to GGUF Q4_K_M format
4. Imported into Ollama via Modelfile
5. Evaluated using identical 29-session matrix on Juice Shop and DVWA

---

## 7. Expected Improvements

Based on the dataset composition targeting specific baseline gaps:

| Baseline Gap | Training Examples | Expected Improvement |
|-------------|------------------|---------------------|
| A01 Broken Access Control (13%) | 138 IDOR + 48 API abuse | 13% → 40-60% coverage |
| A03 XSS (missed by 14B/32B) | 78 XSS examples | More consistent XSS detection |
| A07 Authentication (missed by 14B) | 72 JWT/auth examples | 14B 0% → 60%+ coverage |
| A10 SSRF (0%) | 18 SSRF examples | 0% → detected |
| DVWA authenticated vulns (0/7) | 264 DVWA examples | 0/7 → 3-5/7 vulns |
| Premature session termination (14B) | 106 negative corrections | Fewer early stops |
| Tool repetition (nmap 3x) | 106 phase transition examples | More diverse tool usage |

---

## 8. Iterative Training Plan

### Round 1 (Current)
- Dataset: 2,314 examples as described above
- Train all 3 Coder models
- Evaluate on Juice Shop + DVWA
- Compare with baseline: TP count, unique vulns, GT coverage, precision

### Round 2 (After Round 1 Evaluation)
- Analyse what the fine-tuned models STILL fail on
- Create targeted corrections for new failures
- Add real session data from fine-tuned model runs (active learning)
- Re-train with expanded dataset

### Round 3 (If Needed)
- Further corrections and HuggingFace data expansion
- Hyperparameter tuning (try r=32 or r=64)
- Dataset size ablation (25%, 50%, 100%)

This iterative approach is scientifically stronger than a single training run — improvement per round can be reported, and the active learning component demonstrates that the system can self-improve.

---

## 9. Ethical Considerations for Training Data

### 9.1 Data Provenance
- Real session data: generated by the researcher's own system against self-hosted vulnerable applications
- Curated examples: written by the researcher targeting known, documented vulnerabilities
- HuggingFace datasets: publicly available under open licenses (Apache 2.0, MIT)

### 9.2 No Harmful Knowledge
All training examples target intentionally vulnerable applications (Juice Shop, DVWA) designed for security training. No real-world targets, production systems, or private data are included. The payloads and techniques taught are standard pentesting methodology documented in OWASP, PTES, and public security resources.

### 9.3 Reproducibility
The complete dataset, extraction script, and training configuration are version-controlled and archived. The random seed (42) ensures identical splits across reproductions.
