# Do generic exploit playbooks help? — none vs auto vs profile

**Date** 2026-08-18 · **Commit** `cd21179` · **Target** OWASP Juice Shop
(35 ground-truth items) · **Model** `qwen2.5-coder:7b` · **n=4 per arm,
interleaved** · **Data** `data/playbook_arms.jsonl`

## Why this ran

`orchestrator/playbooks.py` was rewritten to be target-agnostic: generic
technique playbooks routed to the classes a mission names, replacing a ~9 KB
block of OWASP Juice Shop's exact endpoints that five of six presets injected
by default. The rewrite was justified by a prior measurement (guidance costs
recall dose-dependently) but was itself **unmeasured**. This is that
measurement.

| arm | what is injected | bytes |
|---|---|---|
| `none` | nothing | 0 |
| `auto` | generic playbooks, routed to the mission's classes | 1289 |
| `playbook_only` | Juice Shop profile, routed and capped | 3402 |

`playbook_only` is **not** the historical 9 KB block — it is the same profile
routed under the new cap. The three arms therefore isolate *content* at
comparable volume (nothing / generic / target-specific), not the old volume
difference.

## Controls

Every previously recorded generation (`context_test_v2/v3.jsonl`) has
`injected_chars = -1`, because `--server-log` was never passed. **Nothing in
that corpus proves the arms ever differed in what reached the model.** Had the
injection path been broken, both arms would have run the same condition and the
result would have read as a confident null.

This run verified it per-row from the server's own log:

```
none           [0, 0, 0, 0]
auto           [1289, 1289, 1289, 1289]
playbook_only  [3402, 3402, 3402, 3402]
```

Single mission (`4a91b4ea`), single commit (`cd21179`), no `ERLIK_*` set on the
server process, arms **interleaved within each rep** so Juice Shop's
accumulating state does not become a property of an arm.

## Results

| arm | n | recall (mean) | sd | min–max | precision | findings | turns | sec |
|---|---|---|---|---|---|---|---|---|
| `none` | 4 | **0.0571** | 0.0233 | 0.0286–0.0857 | 0.857 | 3.00 | 28.8 | 298 |
| `auto` | 4 | **0.0286** | 0.0233 | 0.0000–0.0571 | 0.500 | 1.75 | 26.2 | 430 |
| `playbook_only` | 4 | **0.0500** | 0.0142 | 0.0286–0.0571 | 0.875 | 2.25 | 23.0 | 265 |

Exact permutation test, all C(8,4)=70 splits, two-sided:

| comparison | \|Δmean\| | p |
|---|---|---|
| `none` vs `auto` | 0.0285 | 0.286 |
| `none` vs `playbook_only` | 0.0071 | 0.857 |
| `auto` vs `playbook_only` | 0.0214 | 0.371 |

**Nothing here is distinguishable from noise.**

## The targeted test — and why it matters more than the aggregate

`auto` injected XSS and open-redirect guidance, 1289 chars, on all four runs.
What it found on those classes:

| class | `none` | `auto` | `playbook_only` |
|---|---|---|---|
| XSS | 0 | **0** | 1 |
| open redirect | 0 | **0** | 0 |

Zero. The only XSS found in the whole experiment came from the arm carrying a
**concrete endpoint**, not a description of a shape.

Ground truth actually matched, all 12 runs:

| GT class | `none` | `auto` | `playbook_only` |
|---|---|---|---|
| Information Disclosure | 7 | 4 | 5 |
| Security Misconfiguration | 1 | 0 | 1 |
| XSS | 0 | 0 | 1 |

Recall on this target is **almost entirely one class**, and it is not a class
any playbook addresses.

## Two reasons this experiment could not have found a benefit

**1. The router dropped the class the mission asked for.** Ranking was
`max(len(phrase))`. The mission named `cross-site scripting` (20), `open
redirect` (13) and `SSRF` (4); the cap was 2. SSRF was silently discarded. All
four `auto` runs were scored as a test of guidance that was never injected.
Found by adversarial audit, not by reading the output. Fixed in `763c464`'s
successor: weighted whole-word matching, cap 2 → 3, and the cap now logs what
it discards.

**2. The metric has ~3 distinguishable levels.** Across all 12 runs only 7 of
35 GT items were ever matched — a ceiling of 0.2000, with a best single run of
0.0857. One true positive is 0.0286 of recall, and the largest difference
observed between any two arms was 0.0285. **The entire aggregate effect is one
finding.**

Power, resampled from the observed distributions:

| n per arm | power | cost |
|---|---|---|
| **4 (this run)** | **0.14** | 48 min |
| 8 | 0.60 | 96 min |
| 12 | 0.90 | 144 min |

At n=4 a null was near-guaranteed whether or not the effect is real.

## What can and cannot be claimed

**Can:** there is no evidence generic playbooks improve recall; the point
estimate is worse (0.0286 vs 0.0571), precision is lower (0.500 vs 0.857) and
runs are 44% slower. On the two classes the guidance actually addressed it
produced nothing across four runs.

**Cannot:** that generic playbooks do not work. The arm never received the SSRF
sheet, the metric is dominated by a class no playbook targets, and the design
had 0.14 power.

## Follow-up: rerun at n=8 with the routing fixed (commit `7270326`)

The SSRF drop and the cap were fixed, `max_playbooks` pinned to 3, the server
restarted, and both arms re-run at n=8 into a **fresh file** (reusing the old
rows under the same `arm` label was the audit's top-severity trap). `auto` now
injects 1834 bytes and the server log confirms the CONTENT, not just the size:
`classes=['ssrf', 'open_redirect', 'stored_xss'] dropped=[]`.

| arm | n | recall | sd | median | min–max | precision | findings | sec |
|---|---|---|---|---|---|---|---|---|
| `none` | 8 | 0.0464 | 0.0372 | 0.0286 | 0.0000–0.1143 | 0.812 | 1.75 | 325 |
| `auto` | 8 | **0.0643** | 0.0253 | 0.0571 | 0.0286–0.1143 | 0.854 | 3.00 | 308 |

Exact permutation over all C(16,8)=12870 splits: |Δ| = 0.0178, **p = 0.3854**.
Bootstrap 95% CI on `none − auto`: **[−0.0464, +0.0107]** — spans zero, width
2.0 findings.

**The direction reversed.** At n=4 with SSRF dropped, `auto` was *worse*
(0.0286 vs 0.0571). At n=8 with SSRF routed, `auto` is *better* (0.0643 vs
0.0464). Neither is significant. Two things I reported from the first run —
that `auto` cost precision (0.500 vs 0.857) and ran 44% slower — both reversed
here (0.854 vs 0.812; 308s vs 325s). They were noise, and I should have said so
with less confidence the first time.

### The noise floor, measured directly

`none` is the *same treatment* in both experiments — 0 bytes, same mission,
same model, and the intervening commits touched only playbook routing, which
`none` never reaches. So the gap between its two means is pure noise:

| | |
|---|---|
| same-condition drift (`none` exp1 vs exp2) | **0.0107** |
| the effect being chased (exp2 `none` vs `auto`) | **0.0178** |

The effect is 1.7× the drift of a comparison known to be null. That is the
honest size of what this instrument can see.

### Targeted classes — the sharper test

`auto` injected SSRF, open-redirect and stored-XSS guidance on all 8 runs.

| GT class | `none` | `auto` |
|---|---|---|
| XSS | 0 | **1** |
| open redirect | 0 | 0 |
| SSRF | 0 | 0 |
| Broken Authentication | 2 | 0 |
| Information Disclosure | 10 | 15 |

One XSS in 8 runs against none in 8 (Fisher exact p = 1.0) is not evidence.
SSRF and open redirect produced nothing even with the guidance correctly
routed. Distinct GT items reached: `none` 5, `auto` 4 — `auto` scored more
total matches but reached *fewer distinct* items, because Information
Disclosure repeats.

**Verdict: no detectable effect in either direction, across two experiments and
28 runs.** `auto` has a higher median (0.0571 vs 0.0286), a higher floor (it
never scored 0; `none` did) and lower variance — but all of that sits inside
the interval.

## Class-restricted scoring — the sharper question

Aggregate recall averages over 35 items, most of them classes no playbook
targets. Restricting the denominator to the routed classes asks what the
guidance was actually about. Rescore only, no new runs:
`scripts/score_by_class.py`.

Denominator: **6 items** — XSS ×4 (`/rest/products/search`, `/#/search`,
`/#/track-result`, `/api/Users`), SSRF ×1 (`/profile/image/url`), Open
Redirect ×1 (`/redirect`). One finding = 0.1667.

| arm | n | restricted recall | runs that hit anything |
|---|---|---|---|
| `none` | 12 | 0.0000 | **0 / 12** |
| `auto` | 12 | 0.0139 | 1 / 12 |
| `playbook_only` | 4 | 0.0417 | 1 / 4 |

`auto` vs `none`: p = 1.0000. Pooling any guidance vs none — 2/16 vs 0/12 —
gives p = 0.4921. At these sample sizes guidance would need **≥5/12** hits
against 0/12 to reach p<0.05.

Across all 28 runs there were exactly **two** routed-class hits, both XSS at
`/rest/products/search`. **SSRF and Open Redirect were never found by any arm**,
including the eight `auto` runs that carried correctly-routed SSRF guidance and
the four `playbook_only` runs that named `/profile/image/url` outright.

### The denominator is reachable — this is a positive control, not a dead metric

Across the whole database, **19 of 102** sessions with findings did hit one of
these six items: XSS `/rest/products/search` ×14, `/#/track-result` ×2,
`/api/Users` ×2, `/#/search` ×1, and SSRF `/profile/image/url` ×1. So erlik can
reach them; this experimental configuration mostly does not (2/28 = 7% against
a 22% hit-rate for the 7B overall).

Every one of the 19 was `qwen2.5-coder:7b`. The 27B hit **0 of 15** — consistent
with the earlier finding that it is 7× slower and no better.

### What this actually says

The bottleneck is not knowing what to do at the endpoint. It is **reaching the
endpoint at all**. Generic playbooks describe technique; they do not help the
agent navigate to `/profile/image/url` in the first place, and neither, in
practice, did naming it — `playbook_only` states that exact path and still
never produced an SSRF finding in four runs.

That reframes the product question. Guidance content is not the lever worth
tuning next; endpoint discovery is.

## Next

1. Re-run `auto` with the routing fix, so the arm tests what the mission asks.
2. n≥8 per arm, or the result is not interpretable either way.
3. Consider scoring on the routed classes only. Aggregate recall over 35 items
   dominated by Information Disclosure cannot detect a playbook effect at all.

The presets shipping `playbooks: "auto"` remain unproven — but after 28 runs the
honest reading is that the effect is smaller than this instrument resolves, not
that it is absent. Resolving it needs a better metric, not more reps.

## Reproduce

```bash
./run.sh > /tmp/erlik.log 2>&1 &            # MUST be a fresh server
python scripts/context_test.py \
  --arms none,auto,playbook_only --reps 4 \
  --model qwen2.5-coder:7b \
  --out data/playbook_arms.jsonl \
  --server-log /tmp/erlik.log               # without this the control is dead
```
