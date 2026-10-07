# Warm-start experiment — does the learning loop make erlik better at a target it has seen?

*Status: harness committed, not yet run. It needs a live orchestrator, Ollama and
the Juice Shop target, none of which exist in CI or the dev container — run it on
the lab box. Script: `scripts/warm_start_experiment.py`.*

## The question

Erlik's learning loop (Track A) harvests a run's **verified** findings into
candidate playbooks, a human approves them, and a later run on the same target
injects the approved ones (fenced as untrusted data) at session start. Does that
injected, target-specific, *verified* knowledge actually raise recall on the
repeat run — or does it cost recall the way generic playbooks already did?

This matters because the record already measured a **recall penalty for injected
guidance**: on Juice Shop, `playbook_only` scored 0.1143 vs `none` 0.1429, and
the skills dose ladder fell monotonically on a 7B. The learning loop's bet is
that the *target's own verified exploits* are different in kind from speculative
guidance — class-routed, bounded, and known-true — so they pay for their tokens.

## Design

One target, one model, pinned to the recorded inference path (qwen2.5-coder:7b
on Ollama), so the only thing that moves is the lever under test.

| Phase | Config | What it does |
|---|---|---|
| **Seed** | guided knowledge + `poc_verify` + `learned_playbooks` ON | Produces verified findings, harvested into **pending** candidates. The script then approves every pending candidate for the target via the admin review API. |
| **Measure** | two arms, interleaved reps | `learned_off` (control, `learned_playbooks` False) vs `learned_on` (`learned_playbooks` True → approved candidates injected). |

Both measure arms hold **every other lever identical** (skills, cve_enrich,
primitives, poc_verify, provider, safe_mode); a static test
(`tests/test_warm_start_experiment.py`) enforces that the two arms differ in
exactly `learned_playbooks` and both pin Ollama, so a stray confound cannot
invalidate the result unnoticed.

Runs are **interleaved**, not arm-by-arm: Juice Shop is stateful (runs create
users, store XSS, upload files), so running all of one arm then the other would
turn target drift into an apparent arm effect.

Recall and precision are scored exactly as `scripts/context_test.py` does — the
one-to-one assignment confusion matrix against the seeded ground truth — so the
numbers are directly comparable with the recorded arms.

## Hypothesis

`learned_on` > `learned_off` in recall on the repeat run, **without** the
generic-playbook penalty, because the injected plays are the target's own
verified exploits.

**A null or negative result is itself a finding**, and an important one: it would
say that in-context learned knowledge is no better than authored guidance for
this model — which is the case for Track B (fine-tuning on the same verified
corpus the loop already accumulates) rather than richer prompt injection.

## Running it

```bash
# On the lab box, with the orchestrator + Ollama + Juice Shop up:
ERLIK_API_TOKEN=<admin-token> python scripts/warm_start_experiment.py --reps 5
# Reuse candidates already approved for the target (skip the seed phase):
ERLIK_API_TOKEN=<admin-token> python scripts/warm_start_experiment.py --reps 5 --skip-seed
```

Results append to `data/warm_start_experiment.jsonl` (gitignored) — one `seed`
row recording how many candidates were harvested/approved, then one `measure`
row per rep per arm with `recall`/`precision`/`tp`.

## Reading the result

- **learned_on recall clearly above learned_off, precision not collapsing** →
  the loop works; the tool improves at targets it has seen. Promote
  `learned_playbooks` into a product preset (never the frozen thesis arms).
- **No separation, or learned_on recall below learned_off** → target-specific
  verified context does not help this model in-context; prioritise Track B.
- **Either way**, report the delta against the recorded `none`/`playbook_only`
  penalty, since the whole point is whether *verified* context escapes it.
