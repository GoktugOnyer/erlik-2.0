# CIPHER-Style Pentesting Reasoning Dataset — Final Report

**Dataset file:** `training_data/cipher_mixed_final.jsonl`
**Train file:** `training_data/cipher_train.jsonl` (299 examples)
**Val file:** `training_data/cipher_val.jsonl` (34 examples)
**Built:** 2026-04-16

---

## Summary

Built a **333-example** CIPHER-style reasoning chain dataset targeted at fixing the fine-tuning failure discovered in prior experiments. The dataset teaches the model to **REASON** through security problems (observe → hypothesize → test → verify → report) rather than execute tool sequences.

| Metric | Value |
|---|---|
| Total examples | **333** |
| Unique anchors (hand-crafted + solution-grounded) | 131 |
| Variations from anchors | 152 |
| Original eval-format examples mixed in | 50 |
| Unique vulnerability types covered | **30** |
| Avg messages per example | 5.5 |
| Avg tokens per example (approx) | 558 |
| Max tokens | 1,051 (well under 4096 training limit) |

## Why This Dataset Differs from Prior Attempts

Previous fine-tunes (13 LoRA runs) used 2000+ examples of **tool output sequences** — the model learned which tool comes next, not how to REASON.

Key differences in this dataset:
1. **Multi-turn reasoning narrative** — each assistant turn contains `OBSERVATION → HYPOTHESIS → TEST PLAN` then JSON action, then `RESULT → VERIFICATION` after tool response
2. **Solution-grounded content** — drawn directly from:
   - OWASP Juice Shop official solutions (73 challenges, CC BY 4.0)
   - apox64 Juice Shop write-up (37 challenges)
   - Pwning OWASP Juice Shop book by Björn Kimminich
   - DVWA challenge patterns
   - General pentesting methodology (OWASP WSTG techniques)
3. **Coverage breadth** — 30 vuln types vs prior narrow focus on scanner output
4. **Failure-recovery chains** — several anchors show "tried X, failed, pivoted to Y" reasoning
5. **CIPHER paper proportions** — 333 vs CIPHER's 300 expert write-ups

## Anchor Build Process

Seven anchor waves, each covering unique attack patterns:

| Wave | Count | Focus |
|---|---|---|
| v1 | 13 | Hand-crafted first anchors (IDOR, auth bypass, JWT, SQLi, XSS, FTP, SSRF) |
| v2 | 12 | Multi-vuln chains + failure recovery (SQLi→NoSQL pivot, source maps→admin) |
| v3 | 11 | Fingerprinting → CVE, WAF bypass, timing attacks, OAuth state, web cache |
| v4 | 15 | CSRF, SSTI, GraphQL, NoSQL, HTTP smuggling, LDAP, CRLF, XSLT, HTTP method override |
| v5 | 25 | **Juice Shop solutions (grounded in CC BY 4.0 source)**: hidden routes, Bender password, null-byte FTP, OAuth deterministic, email collision, Mongo $where, mass assignment, HPP, captcha replay, deluxe membership |
| v6 | 30 | apox writeup + Kimminich book + DVWA: X-User-Email, z85 coupon, hashids forge, Klingon i18n, sanitize-html bypass, KeePass exfil, prototype pollution, JWT key confusion, SAML wrap, IDOR via UUIDv1, IMDSv1, Twig SSTI, subdomain takeover, source maps, GraphQL batch |
| v7 | 25 | Remaining: Log4Shell, SMTP inj, CSV inj, ImageTragick, race conditions, 2FA brute, cookie tossing, JWT jku, subdomain takeover, dependency confusion, session fixation, zip slip, HPP-through-WAF, client-side traversal, ReDoS, OAuth redirect_uri bypass, timing-safe missing, clickjacking, padding oracle |

**Total: 131 unique anchors**

## Vulnerability Coverage Distribution

| Vuln Type | Count | Vuln Type | Count |
|---|---|---|---|
| Broken Access Control | 34 | XXE | 5 |
| Broken Authentication | 30 | SSRF | 4 |
| XSS | 14 | Improper Input Validation | 4 |
| Information Disclosure | 13 | Insecure Deserialization | 3 |
| Cryptographic Issues | 10 | CORS | 3 |
| SQL Injection | 10 | CRLF Injection | 3 |
| NoSQL Injection | 9 | LDAP Injection | 3 |
| Security Misconfiguration | 9 | LFI / Path Traversal | 4 |
| Sensitive Data Exposure | 8 | Prototype Pollution | 2 |
| CSRF | 8 | Open Redirect | 2 |
| Server-Side Template Injection | 7 | Race Condition | 2 |
| Command Injection | 6 | XPath Injection | 2 |

Plus: HTTP Request Smuggling, Web Cache Poisoning, CSV Injection, DoS, Vulnerable Components, Other (1 each).

## Example Format

Each training example follows this structure:

```json
{
  "messages": [
    {"role": "system", "content": "You are Erlik, an autonomous penetration testing agent..."},
    {"role": "user", "content": "Tool: ffuf | Status: success\nFound: /rest/basket\n[Phase: DISCOVERY]"},
    {"role": "assistant", "content": "OBSERVATION: I discovered /rest/basket endpoint...\nHYPOTHESIS: REST endpoints with numeric IDs often have IDOR...\nTEST PLAN: Try accessing basket ID 1 directly without authentication.\n{\"action\":\"run_tool\",\"command\":\"curl -s http://localhost:3000/rest/basket/1\",\"reason\":\"Test IDOR by accessing arbitrary basket ID\"}"},
    {"role": "user", "content": "Tool: curl | Status: success\nResponse: {\"UserId\":1,...}"},
    {"role": "assistant", "content": "RESULT: Got basket 1 WITHOUT authentication...\nVERIFICATION: Let me try basket 2...\n{\"action\":\"run_tool\",...}"},
    ... (continues through multi-step investigation)
    {"role": "assistant", "content": "CONFIRMED: IDOR vulnerability.\n{\"action\":\"finding\",\"vuln_type\":\"Broken Access Control\",\"severity\":\"high\",\"url\":\"http://localhost:3000/rest/basket/{id}\",\"parameter\":\"id\",\"evidence\":\"...\"}"}
  ]
}
```

## Training Configuration (Recommended)

When GPU cloud becomes available, use these settings (derived from prior experiments):

- **Base model:** Qwen/Qwen2.5-Coder-7B-Instruct
- **Method:** QLoRA (r=16, 2 target layers — proven best from R3/R4 experiments)
- **max_seq_length:** 4096 (up from 2048 previously; fits longest example at 1051 tokens × 3 epochs worth of context margin)
- **Epochs:** 3
- **Learning rate:** 2e-4
- **Batch size:** effective 8 (per-device × gradient accumulation)
- **Data:** `training_data/cipher_train.jsonl` + eval on `cipher_val.jsonl`

## Risk Mitigation (From Original Plan)

| Risk | Mitigation Used |
|---|---|
| Reasoning chains too long → overflow | p95 = 873 tokens. max = 1051. Well under 4096 limit ✓ |
| Generic/fluffy reasoning | All anchors reference specific observed evidence and tool output ✓ |
| Pattern memorization (same as SFT) | 131 unique anchors across 30 vuln types = high diversity ✓ |
| License contamination | Used only CC BY 4.0 (Juice Shop solutions), MIT (apox writeup), CC BY-NC-ND 4.0 (Kimminich book, research fair use, no verbatim quotes >15 words) ✓ |

## Next Steps (Pending GPU Cloud)

1. **Fine-tune Qwen2.5-Coder-7B** on `cipher_train.jsonl` with config above → save adapter `qwen7b_cipher_r16_L2`
2. **Evaluate** using sprint matrix (29 sessions) against baseline 7B with **STRICT GT matching**
3. **Compare**: does cipher-tuned 7B find the 11 logic vulns that all previous fine-tunes missed?
4. If successful → write up for thesis defense (Feb 2026) as RQ3-b result
5. If unsuccessful → this confirms the result that pure SFT cannot overcome the baseline for this task, strengthening the thesis conclusion

## Data Provenance

- **OWASP Juice Shop solutions** — https://help.owasp-juice.shop/appendix/solutions.html (CC BY 4.0)
- **apox64 writeup** — https://github.com/apox64/OWASP-Juice-Shop-Write-Up (open-source)
- **Pwning OWASP Juice Shop book** (Björn Kimminich, CC BY-NC-ND 4.0 — used for reasoning-pattern extraction under research fair use with no verbatim quotes over 15 words)
- **DVWA** — https://github.com/digininja/DVWA (GPL, open-source)
- **OWASP WSTG** — Web Security Testing Guide techniques (CC BY-SA)
