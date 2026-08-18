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

## Next

1. Re-run `auto` with the routing fix, so the arm tests what the mission asks.
2. n≥8 per arm, or the result is not interpretable either way.
3. Consider scoring on the routed classes only. Aggregate recall over 35 items
   dominated by Information Disclosure cannot detect a playbook effect at all.

Until (1) and (2) land, the presets shipping `playbooks: "auto"` are shipping
something unmeasured — the honest options are to default it off or to finish
the measurement.

## Reproduce

```bash
./run.sh > /tmp/erlik.log 2>&1 &            # MUST be a fresh server
python scripts/context_test.py \
  --arms none,auto,playbook_only --reps 4 \
  --model qwen2.5-coder:7b \
  --out data/playbook_arms.jsonl \
  --server-log /tmp/erlik.log               # without this the control is dead
```
