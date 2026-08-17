# Context allocation and injected guidance

**Date:** 17 Aug 2026 · **Code:** `3d91f85` · **Target:** OWASP Juice Shop ·
**Raw data:** `data/context_test_v3.jsonl` (gitignored; `v2` = same code, 4,096-token allocation)

Supersedes the interpretation recorded in earlier runs. It does **not** overturn
the earlier measurement — it explains it, and finds the opposite of what was
expected.

## The bug this started from

erlik trimmed every conversation to `MAX_ESTIMATED_TOKENS = 3600`, sized for a
4,096-token window. It also never sent `num_ctx`, and **Ollama allocates its own
default (4096) regardless of what the model supports**:

| model | window | erlik used |
|---|---|---|
| `qwen2.5-coder:7b` | 32,768 | 4,096 (12%) |
| `qwen3.8:27b` | 262,144 | 4,096 (1.6%) |

So the original finding — recall falls as injected bytes rise, r = −0.796 — was
measured where the 18,166-char skills block (~4,540 tokens) **exceeded the entire
conversation budget**. Injecting it necessarily evicted tool output every turn.
That is a real effect, but it is a fact about a 4,096-token serving window, not
about how models handle context.

`3d91f85` derives the trim budget from the model's real window and sends a
matching `num_ctx`. Both numbers come from one derivation; raising one alone
trades a visible trim for a silent Ollama truncation.

## Results

Two arms, `none` (no skills, no playbook) and `both`, everything else pinned
including `safe_mode: true`. n=2 per cell except one 4,096 cell.

| model | allocation | arm | n | recall | precision | turns | findings | sec |
|---|---|---|---|---|---|---|---|---|
| 7B | 4,096 | none | 2 | 0.1714 | 0.929 | 25.0 | 6.5 | 360 |
| 7B | 4,096 | both | 2 | 0.1429 | 0.917 | 25.5 | 5.5 | 320 |
| 27B | 4,096 | none | 2 | 0.1286 | 0.817 | 16.5 | 5.5 | 2034 |
| 27B | 4,096 | both | 1 | 0.1143 | 1.000 | 16.0 | 4.0 | 2875 |
| 7B | 20,070 | none | 2 | 0.1143 | 0.900 | 20.5 | 4.5 | 220 |
| 7B | 20,070 | both | 2 | **0.0143** | **0.071** | 18.0 | 3.5 | 315 |
| 27B | 26,048 | none | 2 | 0.0857 | 1.000 | 17.0 | 3.0 | 1684 |
| 27B | 26,048 | both | 2 | **0.0143** | 0.250 | 14.5 | 1.0 | 1554 |

Raw recall values, so n=2 is visible:

```
4,096   7B  none [0.1714, 0.1714]   both [0.1429, 0.1429]
4,096  27B  none [0.1429, 0.1143]   both [0.1143]
aligned 7B  none [0.1143, 0.1143]   both [0.0,    0.0286]
aligned 27B none [0.0857, 0.0857]   both [0.0,    0.0286]
```

## Findings

**1. Injected guidance costs recall on both models, at both allocations, and
the cost grows with the window.**

| | 4,096 | aligned |
|---|---|---|
| 7B `none`→`both` | −0.029 | **−0.100** |
| 27B `none`→`both` | −0.014 | **−0.071** |

**2. A larger context window does not fix it — which was the hypothesis.**
The 27B has 262k of window. Given 26k, its `both` arm lands on exactly the same
recall as the 7B: **0.0143, from identical raw values `[0.0, 0.0286]`**. Two
models 4× apart converge on the same number under the same guidance. The
crowding mechanism is ruled out: at 4,096 the block genuinely could not fit; at
26,048 it fits with room to spare and the damage is five times worse.

**3. More context made every arm worse, including arms with no skills at all.**

```
7B  none   0.1714 → 0.1143
27B none   0.1286 → 0.0857
```

The only change is retaining raw history instead of `_trim_messages`' summarised
recap. The summary appears to be better input than the transcript it replaces.

**4. Precision collapses with recall**, so this is not a breadth/accuracy trade.
7B `both` precision goes 0.900 → 0.071: it produces *more wrong* findings. The
27B `both` arm averaged 1 finding per run.

## Consequences

- **Skills should default off.** As measured, the corpus is a net negative on
  both models tested.
- **Do not raise `ERLIK_CONTEXT_CEILING` expecting improvement.** The 3,600-token
  trim was written for a 4096 window and is close to optimal by accident. The
  model-aware sizing in `3d91f85` exists so the budget can be tuned per model,
  not as an argument for using more.
- **Corpus size still does not equal injected volume.** The router selects under
  a budget, so adding sheets does not change what a run receives — but what a run
  *does* receive is harmful at current settings.

## Limits

n=2 per cell, one target, one guidance corpus, one provider. The `both` arms sit
at 0.0143 in both models, which may be a floor rather than a measured gradient —
a corpus half the size might land in the same place. Wall-clock differs ~7×
between models, so turn counts are not directly comparable. Nothing here
separates *which* part of the injected block does the damage.

## Reproducing

```bash
# 1. restart erlik — a long-running server holds the OLD code and schema
pkill -f "uvicorn orchestrator.main"; ./run.sh &

# 2. one model at a time; they share a GPU
python scripts/context_test.py --model qwen2.5-coder:7b --arms none,both --reps 2 \
  --out data/context_test_v3.jsonl
ERLIK_LLM_CALL_TIMEOUT=900 python scripts/context_test.py --model qwen3.8:27b \
  --arms none,both --reps 2 --out data/context_test_v3.jsonl
```

Each row records the commit, so runs from different code are never pooled.
