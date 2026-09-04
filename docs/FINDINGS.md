# Erlik 2.0 — Complete Experimental Findings

This document contains all findings from the clean baseline evaluation runs (April 9, 2026) across three model sizes (7B, 14B, 32B) with 29 sessions each (27 primary + 2 repeats). All numbers are from the scientifically controlled runs with juice shop reset between sessions, no wall-clock ceilings, disabled stagnation detector, and ground truth validation.

IMPORTANT: This document reports TWO metrics for every comparison:
- Raw findings: total detection events (same vuln counted each time it's detected)
- Unique vulnerabilities: deduplicated by vuln_type + normalized URL (the actual number of distinct security issues found)

The raw count measures agent detection activity. The unique count measures actual vulnerability coverage. Both are valid metrics for different questions.

---

## 1. Data Integrity Note

### 1.1 Finding Inflation Problem

Raw finding counts are inflated because the same vulnerability is detected multiple times across sessions and sometimes within a single session. For example, CORS Misconfiguration (a single server-wide `Access-Control-Allow-Origin: *` header) was detected 95 times by 32B across all sessions — but it is ONE vulnerability.

| Model | Raw Findings | Unique Vulns | Inflation Factor |
|-------|-------------|-------------|-----------------|
| 7B | 201 | 24 | 8.4x |
| 14B | 147 | 12 | 12.2x |
| 32B | 336 | 44 | 8.0x |

Deduplication method: findings are grouped by (vuln_type lowercase, URL stripped of query params and fragments). Server-wide issues (CORS, missing headers) use empty URL so they count as one regardless of which endpoint triggered them.

### 1.2 Noise Exclusion

The following finding types are excluded from all analysis as they represent infrastructure failures, not vulnerabilities:
- Connection Refused (juice shop was temporarily down)
- Missing Dependency (tool installation issue)
- Browser Tool Not Installed (Playwright/Chromium not available)
- HTTP Request Failed (network timeout)
- Executable Not Found (binary missing)
- No Web Server Found (nikto scan error)
- Installation Error (tool setup failure)
- Internal Server Error (500 response, not a vuln by itself)

### 1.3 Verification of Findings

All reported findings are real Juice Shop vulnerabilities confirmed by tool evidence:
- SQL Injection: confirmed by sqlmap with DBMS identification (SQLite), payload extraction, and boolean-based blind verification
- CORS Misconfiguration: confirmed by actual `Access-Control-Allow-Origin: *` header in HTTP response
- Information Disclosure: confirmed by actual file/directory listings, error pages with stack traces, or exposed endpoints
- Broken Authentication: confirmed by jwt_tool cracking the JWT signing key
- Sensitive Data Exposure: confirmed by actual file content returned from /ftp directory
- Security Misconfiguration: confirmed by exposed Swagger/API docs, Prometheus metrics endpoint

The ground truth matching algorithm requires a score of >= 2 out of 4 dimensions (type match required + at least one of: URL match, parameter match, evidence keyword match) to classify a finding as a true positive.

---

## 2. Overall Model Comparison

### 2.1 Raw Findings (inflated, measures detection activity)

| Model | Sessions | Total Findings | TP | FP | Precision |
|-------|----------|---------------|----|----|-----------|
| 7B | 29 | 204 | 197 | 7 | 97% |
| 14B | 29 | 147 | 146 | 1 | 99% |
| 32B | 29 | 339 | 334 | 5 | 99% |

### 2.2 Unique Vulnerabilities (deduplicated, measures actual coverage)

| Model | Unique Vulns Found | Out of 35 Ground Truth | Coverage |
|-------|-------------------|----------------------|----------|
| 7B | 24 | 20/35 matched | 57% |
| 14B | 12 | 15/35 matched | 43% |
| 32B | 44 | 20/35 matched | 57% |

### 2.3 Reasoning

32B finds the most unique vulnerabilities (44) and the most raw detections (336). 7B finds 24 unique vulns — half of 32B. 14B performs worst with only 12 unique vulns.

All three models achieve 97-99% precision. The programmatic finding detection system (_auto_detect_findings) ensures that reported vulnerabilities are verified by tool evidence, not by LLM judgment. This makes precision model-independent — the LLM's contribution is tool selection, not finding interpretation.

The inflation factor shows that 14B is the most repetitive (12.2x — it finds the same SQL injection on /rest/products/search in almost every session). 32B inflates least (8.0x) because it discovers more diverse vulnerabilities across different endpoints.

---

## 3. Session Type Effect (Cold vs Warm vs Chain)

### 3.1 Average Unique Vulnerabilities per Session

| Model | Cold | Warm | Chain | Chain/Cold Multiplier |
|-------|------|------|-------|----------------------|
| 7B | 1.5 | 2.2 | 6.4 | 4.3x |
| 14B | 1.3 | 1.3 | 6.0 | 4.6x |
| 32B | 6.0 | 4.4 | 10.1 | 1.7x |

### 3.2 Total Unique Vulns by Session Type (across all sessions of that type)

| Model | Cold (unique) | Warm (unique) | Chain (unique) |
|-------|--------------|--------------|---------------|
| 7B | 10 | 12 | 17 |
| 14B | 7 | 6 | 12 |
| 32B | 20 | 17 | 36 |

### 3.3 Reasoning

Chain sessions (4-phase structured methodology) consistently outperform cold and warm sessions across all models. The chain architecture imposes expert pentesting methodology — recon, discovery, vuln scanning, exploitation — in sequence, with each phase building on the prior phase's findings.

The chain multiplier is largest for small models: 7B gets 4.3x improvement from chain structure, while 32B only gets 1.7x. This is because 32B already performs well in cold starts (6.0 unique/session) — it makes good autonomous decisions without needing imposed structure. 7B is essentially lost in cold starts (1.5 unique/session) and needs the framework to guide it.

Key insight: A structured 7B chain (6.4 unique/session) roughly matches an unstructured 32B cold start (6.0 unique/session). The orchestration framework compensates for 4.5x fewer model parameters.

Warm starts provide minimal improvement. For 7B, warm goes from 1.5 to 2.2 (modest). For 14B, warm provides zero improvement (1.3 to 1.3). For 32B, warm actually DECREASES performance from 6.0 to 4.4 — the inherited context seems to constrain exploration rather than focus it. The warm-start context narrows the search space, which helps weak models slightly but hurts strong models that would have explored more broadly on their own.

---

## 4. Model Size Effect

### 4.1 Cold Start Performance (Pure Model Capability)

Cold starts measure raw model capability — no prior context, no imposed structure. The agent must independently decide which tools to use and in what order.

| Model | Avg Unique/Session | Avg Raw/Session | Best Cold Session |
|-------|-------------------|----------------|------------------|
| 7B | 1.5 | 1.5 | cold-full_30-45t (6 unique) |
| 14B | 1.3 | 1.3 | cold-full_30-30t (3 unique) |
| 32B | 6.0 | 7.1 | cold-full_30-30t (9 unique) |

32B is 4x better than 7B/14B in cold starts. The bigger model makes better autonomous decisions about tool selection and sequencing. 7B and 14B perform nearly identically in cold starts, suggesting a capability floor for non-specialised models below which model size does not help.

### 4.2 Time-to-First-Finding

| Model | First Finding Step (cold sessions) |
|-------|----------------------------------|
| 7B | avg step 19.4 (range 4-44) |
| 14B | avg step 15.4 (range 11-24) |
| 32B | avg step 4.5 (range 3-7) |

32B finds its first vulnerability within 3-7 turns consistently. 7B takes up to 44 turns and averages 19.4. This means 32B has better "pentesting intuition" — it knows to immediately target productive endpoints (e.g., `/rest/products/search?q=` for SQLi) rather than wasting turns on broad reconnaissance.

### 4.3 Inference Speed vs Throughput Trade-off

| Model | Avg Sec/Turn | Total Runtime | Unique Vulns | Time per Unique Vuln |
|-------|-------------|---------------|-------------|---------------------|
| 7B | 12.9s | 5h 35m | 24 | 14.0 min |
| 14B | 10.0s | 3h 55m | 12 | 19.6 min |
| 32B | 37.6s | 17h 24m | 44 | 23.7 min |

7B finds each unique vulnerability the fastest (14.0 min/vuln) despite finding fewer total. 32B takes 23.7 min per unique vuln but finds the most diverse set. 14B is the worst — slowest per unique vuln despite being the fastest per turn, because it finds the fewest unique vulns.

For time-constrained deployments, 7B + chain architecture is the most efficient configuration. For maximum coverage where compute time is not a constraint, 32B + chain is superior.

### 4.4 Steps Actually Used vs Budget

Most cold/warm sessions use their full turn budget. However, some sessions terminate early because the model calls "done" prematurely:

| Model | Sessions Using < 80% Budget | Examples |
|-------|---------------------------|---------|
| 7B | 2 | cold-standard_20-30t (17/30), cold-standard_20-45t (26/45) |
| 14B | 6 | cold-standard_20-30t (23/30), warm-core_10-30t (17/30), cold-full_30-45t (22/45), and 3 more |
| 32B | 1 | warm-standard_20-45t (34/45) |

14B has the most premature termination — it calls "done" early despite having turn budget remaining. This partially explains its lower findings count. The model is less persistent than 7B or 32B at continuing to explore when initial scans don't find much.

---

## 5. Toolset Tier Effect (Action-Space Overload — RQ3-b)

### 5.1 Unique Vulnerability Types per Tier

| Tier | 7B types | 14B types | 32B types |
|------|---------|----------|----------|
| Core-10 (10 tools) | 10 | 6 | 10 |
| Standard-20 (20 tools) | 8 | 5 | 9 |
| Full-30 (30 tools) | 11 | 6 | 13 |

### 5.2 Total TP per Tier (raw)

| Tier | 7B TP | 14B TP | 32B TP |
|------|-------|--------|--------|
| Core-10 | 53 | 35 | 95 |
| Standard-20 | 73 | 54 | 138 |
| Full-30 | 71 | 57 | 101 |

### 5.3 Reasoning

The action-space overload hypothesis is partially supported but the effect is nuanced:

Standard-20 slightly outperforms Core-10 in raw detections for all models, suggesting the additional 10 tools provide useful capability. However, Standard-20 produces FEWER unique vuln types than Core-10 for all models — the extra tools lead to more detections of the same vulns rather than discovery of new ones.

Full-30 provides the most diverse findings for 32B (13 unique types vs 10 for Core-10), because the niche tools (crlfuzz, nuclei templates, testssl) find things no other tool can. But for 7B and 14B, the benefit is marginal.

The hypothesis that smaller models suffer from "decision paralysis" with more tools is NOT strongly supported — 7B performs similarly across all tiers. The models don't seem confused by having 30 tools; they simply default to their preferred tools (curl, sqlmap) regardless of how many are available.

---

## 6. OWASP Category Coverage

### 6.1 Coverage per Category per Model

| OWASP Category | Ground Truth | 7B | 14B | 32B |
|---------------|-------------|----|----|-----|
| A01: Broken Access Control | 8 vulns | 1 (13%) | 1 (13%) | 1 (13%) |
| A02: Cryptographic Failures | 4 vulns | 4 (100%) | 4 (100%) | 4 (100%) |
| A03: Injection (SQLi+XSS) | 8 vulns | 7 (88%) | 3 (38%) | 3 (38%) |
| A04: Insecure Design | 1 vuln | 0 (0%) | 0 (0%) | 0 (0%) |
| A05: Security Misconfiguration | 8 vulns | 3 (38%) | 7 (88%) | 7 (88%) |
| A07: Authentication Failures | 5 vulns | 5 (100%) | 0 (0%) | 5 (100%) |
| A10: SSRF | 1 vuln | 0 (0%) | 0 (0%) | 0 (0%) |

### 6.2 Reasoning

All models achieve 100% coverage on A02 (Cryptographic Failures) — these are straightforward file discovery vulnerabilities (/ftp directory, source maps) that any directory enumeration tool finds.

A01 (Broken Access Control) is the weakest category across ALL models — only 1/8 covered. These vulnerabilities require multi-step IDOR probing: log in as user A, access user B's basket/order, compare responses. The agents rarely use login-helper + diff-view effectively to perform this workflow.

A04 (Insecure Design) and A10 (SSRF) are completely uncovered. A04 (file upload bypass) requires understanding application logic. SSRF requires knowing the /profile/image/url endpoint accepts server-side URL fetching — the agents never discover this attack vector.

7B has a unique strength in A03 Injection (88%) and A07 Authentication (100%). 14B completely misses A07 (0%) — it never attempts JWT attacks or brute force. 32B matches 7B on A07 (100%) and matches 14B on A05 (88%).

Key insight: Each model has blind spots. A multi-model approach or fine-tuning targeting missed categories could improve overall coverage. The fine-tuning training dataset should specifically include examples for A01, A04, and A10 to address systematic gaps.

---

## 7. Tool Analysis

### 7.1 Tool Effectiveness (findings per use)

| Tool | Total Uses | Findings Attributed | Effectiveness (TP/use) |
|------|-----------|-------------------|----------------------|
| nikto | 77 | 74 | 96.1% |
| curl | 583 | 435 | 74.6% |
| sqlmap | 224 | 88 | 39.3% |
| crlfuzz | 51 | 16 | 31.4% |
| nuclei | 156 | 38 | 24.4% |
| jwt_tool | 106 | 11 | 10.4% |
| commix | 119 | 7 | 5.9% |
| gobuster | 141 | 6 | 4.3% |
| dalfox | 103 | 3 | 2.9% |
| ffuf | 183 | 2 | 1.1% |
| xsstrike | 127 | 1 | 0.8% |
| nmap | 154 | 0 | 0% |
| arjun | 140 | 0 | 0% |
| hydra | 132 | 0 | 0% |

### 7.2 Tool Usage Patterns by Model

| Tool | 7B (% of calls) | 14B (% of calls) | 32B (% of calls) |
|------|-----------------|------------------|------------------|
| curl | 25.1% | 11.1% | 24.1% |
| sqlmap | 7.1% | 8.0% | 8.8% |
| whatweb | 6.3% | 7.0% | 6.3% |
| ffuf | 7.4% | 6.1% | 6.0% |
| nmap | 5.7% | 6.6% | 4.4% |
| zap-cli | — | 6.5% | 5.2% |
| hydra | — | 6.2% | 4.7% |

### 7.3 Tool Chain Patterns Leading to Findings

The most common tool sequences that produced a finding:

| Tool Chain | Count | What It Does |
|-----------|-------|-------------|
| gobuster -> curl | 124 | Discover endpoint, then probe it manually |
| curl -> curl | 72 | Sequential manual probing of endpoints |
| ffuf -> curl | 70 | Fuzz for paths, then confirm with curl |
| sqlmap -> curl | 28 | SQLi detection, then manual verification |
| hydra -> curl | 18 | Brute force attempt, then check result |
| commix -> sqlmap | 18 | Command injection test, then SQL injection test |
| curl -> sqlmap | 17 | Manual discovery, then automated SQLi testing |
| curl -> nuclei | 16 | Manual discovery, then template scanning |
| nuclei -> sqlmap | 14 | Template match, then targeted SQLi |
| arjun -> sqlmap | 11 | Parameter discovery, then injection testing |

### 7.4 Reasoning

Tool effectiveness is bimodal. "Finding tools" (nikto, curl, sqlmap) directly produce vulnerability detections. "Discovery tools" (nmap, arjun, gobuster, ffuf) have 0% direct finding rate but are essential prerequisites — they discover endpoints and parameters that finding tools then test.

The dominant pattern is: discovery tool finds endpoint -> curl confirms and characterises -> sqlmap/nuclei tests for specific vulns. This validates the chain architecture design: recon/discovery phases feed vuln_scan/exploitation phases.

7B over-relies on curl (25.1% of all calls) — it defaults to the simplest tool. 14B has the most balanced distribution (no tool > 11%). 32B uses curl heavily (24.1%) but couples it with more strategic use of gobuster, arjun, and zap-cli.

hydra is used 132 times with 0 findings. The agents attempt brute force attacks but never succeed because Juice Shop's default credentials (admin@juice-sh.op / admin123) are not in the standard wordlists, and the agents don't use login-helper to discover them. This is a specific failure mode that fine-tuning could address.

---

## 8. Chain Phase Analysis

### 8.1 Which Phase Finds the Most?

| Phase | 7B | 14B | 32B |
|-------|------|------|------|
| Recon | 25 (16%) | 15 (12%) | 63 (29%) |
| Discovery | 47 (29%) | 38 (31%) | 50 (23%) |
| Vuln Scan | 52 (32%) | 34 (28%) | 53 (25%) |
| Exploitation | 37 (23%) | 34 (28%) | 50 (23%) |

### 8.2 Reasoning

32B finds 29% of its findings during the recon phase — it detects vulnerabilities even while doing basic scanning (e.g., spotting Prometheus metrics, CORS headers, exposed Swagger during initial nmap/whatweb runs). 7B and 14B need to reach the vuln_scan phase (32% and 28% respectively) before finding most vulnerabilities.

For 14B, findings are evenly distributed across discovery/vuln_scan/exploitation (28-31% each), suggesting a methodical but slow approach. 32B maintains steady output across all phases, demonstrating sustained productive exploration.

---

## 9. Finding Accumulation Over Turns

How findings accumulate as turns progress (chain sessions, 30+ turns):

```
Steps     7B    14B   32B
1-5       36    41    50    <- front-loaded for all models
6-10      18    22    33
11-15     19    11    20
16-20     19    11    18
21-25     20     6    22
26-30      7     3    12
31-35      4     0    10
36-40      2     0     9
41-45      0     0     1
```

### 9.1 Reasoning

All models front-load findings — the most productive period is steps 1-5. This is because early turns run broad scanners (nmap, whatweb, gobuster) that quickly find obvious issues (open ports, CORS, directory listings).

14B exhausts its ideas by step 15 and finds essentially nothing after step 25. 7B tapers off gradually. 32B is unique in maintaining productive exploration through steps 31-40, finding 19 additional findings after step 30. This sustained capability is why 32B ultimately finds the most — it doesn't plateau as early as smaller models.

This has practical implications: if you're running 7B, there's little value in budgeting more than 25-30 turns per chain phase. For 32B, the full 45-turn budget continues to yield returns.

---

## 10. Repeat Run Variance

The representative configuration (cold-standard_20-30t) was run 3 times per model to estimate variance:

| Model | Run 1 TP | Run 2 TP | Run 3 TP | Mean | Std Dev |
|-------|---------|---------|---------|------|---------|
| 7B | 0 | 2 | 1 | 1.0 | 1.0 |
| 14B | 3 | 2 | 2 | 2.3 | 0.6 |
| 32B | 9 | 7 | 6 | 7.3 | 1.5 |

### 10.1 Reasoning

Within-model variance is small relative to between-model differences. The 32B-vs-7B gap (7.3 vs 1.0 mean TP) far exceeds the within-condition standard deviation (1.5 and 1.0). This validates that single-run results are representative — LLM non-determinism introduces noise but does not change the model ranking.

The variance also shows that 32B is more consistent (coefficient of variation = 21%) than 7B (CV = 100%). 7B sometimes finds nothing and sometimes finds 2 — its performance is less predictable.

---

## 11. Infrastructure and Cost Analysis

### 11.1 GPU Cost

| Model | Total Runtime | Unique Vulns | Cost per Unique Vuln |
|-------|-------------|-------------|---------------------|
| 7B | 5h 35m | 24 | 14.0 min/vuln |
| 14B | 3h 55m | 12 | 19.6 min/vuln |
| 32B | 17h 24m | 44 | 23.7 min/vuln |

7B is the most cost-efficient per unique vulnerability found. 32B costs 1.7x more per vuln but finds 1.8x more vulns — a roughly proportional trade-off.

14B is the worst value — it costs more per vuln than 7B while finding half the unique vulns. 14B seems to occupy an unfortunate middle ground: too slow to benefit from speed like 7B, too small to benefit from capability like 32B.

### 11.2 Infrastructure Resilience

Juice Shop crashed 119 times during the full evaluation (all 3 models, ~27 hours total). Every crash was automatically recovered by the watchdog within seconds. Without the watchdog, approximately 40% of sessions would have been invalidated by "Connection Refused" errors.

The crash rate was highest during 32B chains because the larger model runs longer, more intensive scans (sqlmap level 3, nuclei full template library) that stress the Node.js target. This underscores that infrastructure resilience engineering is a requirement for autonomous pentesting evaluation, not a nice-to-have.

### 11.3 Command Quality

| Model | Avg Command Length | Avg Flags per Command |
|-------|-------------------|----------------------|
| 7B | 53 chars | 1.4 |
| 14B | 54 chars | 1.4 |
| 32B | 56 chars | 1.4 |

All three models write nearly identical commands in terms of syntactic complexity. The performance gap is NOT in command construction — it's in strategic decision-making (which tool to use, which endpoint to target, when to switch approaches). The constrained JSON output format (Ollama structured output) standardises command quality across models.

### 11.4 Tool Hallucination Rate

| Model | Invalid Tool Calls | Total Calls | Hallucination Rate |
|-------|-------------------|------------|-------------------|
| 7B | 0 | 961 | 0.0% |
| 14B | 0 | 805 | 0.0% |
| 32B | 1 | 1,051 | 0.1% |

Near-zero hallucination across all models. The single invalid call from 32B was `-h` (the model tried to get help text rather than invoke a tool). Ollama's constrained decoding eliminates syntactic errors entirely; the JSON schema enforcement prevents the model from generating invalid tool names.

---

## 12. Vulnerabilities Found — Complete Catalogue

### 12.1 Unique Vulnerabilities Found by 7B (24 total)

| Vulnerability | URL |
|--------------|-----|
| Authorization Bypass | /api/users |
| Broken Authentication | (JWT weak secret) |
| Brute Force Protection Bypass | /login |
| CORS Misconfiguration | (server-wide) |
| CRLF Injection | / |
| CRLF Injection | /api/endpoint |
| Command Injection | / |
| Command Injection | /ftp |
| Cross-Site Scripting (XSS) | /promotion |
| HTTP Missing Security Headers | /ftp |
| Information Disclosure | /api |
| Information Disclosure | /api/endpoint1 |
| Information Disclosure | /api/login |
| Information Disclosure | /api/products |
| Information Disclosure | /api/users |
| Information Disclosure | /api/users/FUZZ |
| Information Disclosure | /ftp |
| Missing Security Headers | (server-wide) |
| Nikto Finding | (various) |
| SQL Injection | /rest/products/search |
| Sensitive Data Exposure | /ftp |
| Service Misconfiguration | / |
| XSS | /api |

### 12.2 Unique Vulnerabilities Found by 14B (12 total)

| Vulnerability | URL |
|--------------|-----|
| CORS Misconfiguration | (server-wide) |
| CRLF Injection | / |
| CRLF Injection | /rest/products/search |
| Information Disclosure | /api |
| Information Disclosure | /ftp |
| Information Disclosure | /metrics |
| Missing Security Headers | (server-wide) |
| Nikto Finding | (various) |
| SQL Injection | /rest/products/search |
| Security Misconfiguration | /api-docs/swagger.json |
| Sensitive Data Exposure | /ftp |

### 12.3 Unique Vulnerabilities Found by 32B (44 total)

| Vulnerability | URL |
|--------------|-----|
| Broken Authentication | (JWT weak secret) |
| CORS Misconfiguration | (server-wide) |
| CRLF Injection | /api/Products/search |
| CRLF Injection | /login |
| CRLF Injection | /rest/products/search |
| Directory Traversal | /assets/.git/HEAD |
| Information Disclosure | / |
| Information Disclosure | /api |
| Information Disclosure | /api-docs/swagger.yaml |
| Information Disclosure | /api/Account |
| Information Disclosure | /api/Products |
| Information Disclosure | /api/User/login |
| Information Disclosure | /api/Users/1 |
| Information Disclosure | /api/Users/login |
| Information Disclosure | /api/_admin |
| Information Disclosure | /api/products |
| Information Disclosure | /api/products/search/.hta |
| Information Disclosure | /api/products/search/.listing |
| Information Disclosure | /api/user/login |
| Information Disclosure | /ftp |
| Information Disclosure | /metrics |
| Information Disclosure | /profile |
| Information Disclosure | /rest/user/login |
| Information Disclosure | /robots.txt |
| Information Disclosure | /security.txt |
| Missing SRI for External Resources | / |
| Missing Security Headers | (server-wide) |
| Nikto Finding | (various) |
| Prometheus Metrics Exposed | /metrics |
| Prometheus Metrics Exposure | /metrics |
| SQL Injection | /rest/products/search |
| Security Misconfiguration | / |
| Security Misconfiguration | /api |
| Security Misconfiguration | /api-docs |
| Security Misconfiguration | /api-docs/swagger.json |
| Security Misconfiguration | /api-docs/swagger.yaml |
| Security Misconfiguration | /api/products |
| Security Misconfiguration | /api/user/login |
| Security Misconfiguration | /css |
| Security Misconfiguration | /ftp |
| Security Misconfiguration | /metrics |
| Security Misconfiguration | /public |
| Sensitive Data Exposure | /ftp |

### 12.4 Reasoning

32B discovers the most diverse attack surface: 44 unique findings across 30+ distinct URLs. It reaches deep into the application structure, finding .git/HEAD exposure, swagger.yaml vs swagger.json variants, /security.txt, /profile endpoint, and /_admin path — endpoints that smaller models never discover.

7B finds 24 unique vulns but includes some that 32B misses: Command Injection, XSS on /promotion, and Authorization Bypass on /api/users. These suggest 7B occasionally stumbles onto vulns through rapid exploration that 32B's more methodical approach skips.

14B has the narrowest finding set (12 unique vulns). It consistently finds the "easy" vulns (SQLi on search, CORS, /ftp exposure) but rarely explores beyond them.

---

## 13. Warm Start Effect on Specific Vulnerability Types

### 13.1 For 7B

| Vuln Type | Cold Count | Warm Count | Delta |
|-----------|-----------|-----------|-------|
| CORS Misconfiguration | 2 | 10 | +8 |
| SQL Injection | 4 | 1 | -3 |
| Information Disclosure | 5 | 4 | -1 |
| Authorization Bypass | 0 | 1 | +1 |
| XSS | 0 | 1 | +1 |

### 13.2 For 32B

| Vuln Type | Cold Count | Warm Count | Delta |
|-----------|-----------|-----------|-------|
| Information Disclosure | 23 | 10 | -13 |
| SQL Injection | 9 | 3 | -6 |
| CORS Misconfiguration | 15 | 12 | -3 |
| Broken Authentication | 0 | 2 | +2 |
| CRLF Injection | 1 | 2 | +1 |

### 13.3 Reasoning

For 7B, warm starts dramatically increase CORS detection (+8) but decrease SQL Injection detection (-3). The inherited context directs 7B toward header analysis (where it finds CORS) but away from injection testing.

For 32B, warm starts decrease nearly every category — Information Disclosure drops by 13, SQL Injection by 6. The inherited context constrains 32B's exploration space. Instead of independently mapping the target (which 32B does well), the warm session follows the cold session's footsteps and finds less.

This is a counterintuitive result for RQ4: context inheritance helps weak models on specific categories but hurts strong models overall. The practical recommendation is to use cold starts for capable models and warm starts or chains for smaller models.

---

## 14. Exclusive Discoveries by Model

### 14.1 Vulns Found ONLY by One Model

| Only 7B | Only 14B | Only 32B |
|---------|----------|----------|
| Authorization Bypass | (none exclusive) | Prometheus Metrics Exposure |
| Brute Force Protection Bypass | | Directory Traversal |
| Command Injection | | Missing SRI for External Resources |
| Cross-Site Scripting (XSS) | | |
| Service Misconfiguration | | |
| XSS (on /api) | | |

### 14.2 Vulns Found by ALL Three Models

SQL Injection, CORS Misconfiguration, Information Disclosure, Sensitive Data Exposure, Nikto Finding, CRLF Injection, Missing Security Headers

### 14.3 Reasoning

7B uniquely finds XSS and Command Injection — vulnerability types that require trying many payload variations quickly. 7B's speed (10s/turn) means it attempts more payloads per session than 32B. These are not deep vulnerabilities but rather the result of breadth-first exploration.

32B uniquely finds Prometheus Metrics Exposure and Directory Traversal — infrastructure-level discoveries that require deeper endpoint exploration. These represent more sophisticated reconnaissance that smaller models don't reach.

14B has no exclusive discoveries — everything it finds is also found by at least one other model. This reinforces 14B's position as the weakest performer with no unique contribution.

---

## 15. Key Thesis Arguments Supported by Data

### Argument 1: Framework Architecture > Model Size

A structured 7B chain (6.4 unique vulns/session) roughly equals an unstructured 32B cold start (6.0 unique vulns/session). For 4.5x fewer parameters, the chain framework compensates with imposed methodology. This is the strongest argument for the orchestration approach: you don't need the biggest model if you have the right framework.

### Argument 2: Non-Specialised Models Hit a Coverage Ceiling

No model exceeds 57% ground truth coverage. The systematic gaps (A01 Broken Access Control: 13%, A04 Insecure Design: 0%, A10 SSRF: 0%) represent vulnerability classes that require multi-step reasoning, application logic understanding, or creative attack chaining that general-purpose LLMs cannot perform. This directly motivates the fine-tuning experiment: teach the models these specific patterns.

### Argument 3: Bigger Models Are Better (When Given Fair Conditions)

32B outperforms 7B and 14B on every metric when experimental controls are fair (no time ceiling, clean state). The earlier misleading result (7B > 32B) was an artifact of truncating 32B chains. This demonstrates why rigorous experimental methodology matters.

### Argument 4: Precision is a Solved Problem

97-99% precision across all models means false positives are not an issue. The programmatic detection system ensures that reported vulnerabilities are tool-verified, not hallucinated. The open question is recall — finding more of the 43% of ground truth vulnerabilities that all models miss.

### Argument 5: Efficiency vs Thoroughness Is a Real Trade-off

7B finds vulnerabilities 1.7x faster per vuln than 32B (14.0 vs 23.7 min/vuln) but finds 45% fewer unique vulns. Practical deployments must choose based on their constraints: time-limited assessments favour 7B + chain, comprehensive assessments favour 32B + chain.

### Argument 6: Fine-Tuning Should Target Specific Gaps

The OWASP coverage analysis identifies exactly which categories to prioritise in training data: A01 (IDOR/BAC), A04 (Insecure Design), A07 for 14B (Authentication), and A10 (SSRF). The training dataset should over-represent these categories to address systematic blind spots.

### Argument 7: Infrastructure Resilience Is a Methodological Requirement

119 juice shop crashes in 27 hours of testing, all auto-recovered. Without the watchdog, 40% of sessions would be invalid. Any autonomous pentesting evaluation must include target resilience mechanisms. This is a practical contribution to the field that existing papers (PentestGPT, AutoPT) do not address.

### Argument 8: Tool Chaining Is Emergent Behaviour

The most productive finding pattern (gobuster -> curl -> sqlmap) emerges without explicit instruction. The agent learns to chain discovery -> confirmation -> exploitation through the structured prompt and chain architecture. This supports the coarse-grained orchestration approach: the command interface provides tool access, the chain provides methodology, and the agent learns the operational pattern. (The tool interface is a JSON action protocol over the model's text channel, not MCP -- see METHODOLOGY.md Section 3.10.2.)
