# Reproducibility — SHA-256 Checksums and Regeneration Recipe

This file pins the exact outputs reported in the thesis against their
regeneration scripts, and states for each one whether a reader can actually
regenerate it or is taking a committed number on trust.

**The raw evidence is not in this repository.** The campaigns wrote to
`runs/<timestamp>/` and to per-run `pentest.db` files; `runs/` is gitignored,
and the tracked `data/pentest.db` contains only the 54-entry ground-truth
catalogue — `findings`, `sessions`, `steps`, `chains`, `v2_runs` and every
other table are empty. So a clean clone holds the *derived* results, not the
evidence they were derived from.

What a reader can therefore check is narrower than "every claim traces to raw
data", and the table below says exactly how much narrower. One recompute runs
end-to-end from tracked inputs; everything else is **carried forward** — the
committed value is the only copy.

**Reference date:** 2026-04-18
**Git commit (at submission):** fill in with `git rev-parse HEAD` on submission

---

## Pinned output files

Every data file tracked in `docs/`, with what produces it and whether a clean
clone can produce it again. Hashes are of the files as committed.

| File | SHA-256 | Produced by | Regenerable from a clean clone? |
|---|---|---|---|
| `docs/statistical_tests.json` | `c7cba2b7a4a3cab90b6c44eb2c7e5b465a72a599f48f771cb9b85f2ae993267a` | `scripts/recompute_statistical_tests.py` (+ scipy) | **Partly** — 2 of 3 tests; see below |
| `docs/power_analysis.json` | `7482c6145ff49c59642065b67b73163c51114914e875b472aa54c49f19e6a028` | `scripts/power_analysis.py` (+ scipy) | **Yes, but from hard-coded inputs** — see below |
| `docs/recomputed_gt_coverage.json` | `d3146015b6cd54ba6cf328e2985b49a942498ce0d3606c1225f098bc11bc2cef` | `scripts/recompute_gt_coverage.py` | **No** — needs `runs/2026-04-17_19-24-01/ground_truth.json` and a populated `data/pentest.db` |
| `docs/recomputed_all_experiments.json` | `fc3f7e211fb9d9c0c11f4c6d3af4e61668de21756fc676c8b45216c1295c260f` | `scripts/recompute_all_thesis_tables.py` | **No** — needs 27 run directories and their per-run `pentest.db` |
| `docs/recomputed_all_experiments.csv` | `de6330e88c18e42aec58fa209447ee5d4bad5ca1f48a4d75c839a1a212577b02` | `scripts/recompute_all_thesis_tables.py` | **No** — same inputs as the JSON |
| `docs/recomputed_gt_coverage_all.json` | `5dec1d4245e14862f7e196a4ef27b1a95b28a6ea08daa2f94c8a7b36592837ac` | **nothing in this repository** | **No** — no generator exists; see below |
| `docs/seed_variance_results.json` | `1fa554c697514da49fc7658907c8ee5737ae55dcbc0aef4d0c3285a75c344180` | `scripts/overnight_seed_variance.sh` | **No** — re-runs the campaign; needs a GPU, Ollama and a live target |
| `training_data/juicy3_train.jsonl` | `5f2f394469700015dc94c0b5ce9399da02ef61e54fb793ab1d697ac7582a35ed` | `scripts/assemble_juicy3_dataset.py` | **Not in the repo** — 41 MB, gitignored |
| `training_data/juicy3_val.jsonl` | `320099585c0dac63cda470d17c325574108b95efccfef095b51775cadf136081` | `scripts/assemble_juicy3_dataset.py` | **Not in the repo** — 1.7 MB, gitignored |

### What this means for a reader

**All nine hashes above verify** for the seven files that are in the repository —
a `sha256sum -c` confirms the committed bytes are the bytes reported. That is an
integrity check, not a provenance check: it proves the file has not changed since
submission, not that the numbers in it follow from any evidence.

**One pipeline runs end to end from tracked inputs.**
`scripts/recompute_statistical_tests.py --check` reads the ground-truth
catalogue out of `orchestrator/main.py` and the hit sets out of
`docs/recomputed_gt_coverage.json`, recomputes McNemar and Fisher, and asserts
the result is byte-identical to the committed file. This is the one place a
reader can confirm a reported figure was derived rather than typed.

**Note the chain it bottoms out in.** That recompute's input,
`docs/recomputed_gt_coverage.json`, is itself carried forward — it cannot be
regenerated here. So the honest statement is that McNemar and Fisher are
reproducible *from the committed intermediate*, not *from the raw evidence*. The
step from session data to `gt_hit_ids` is taken on trust in a clean clone.

**Everything else in the table is carried forward.** The committed file is the
only surviving copy of those numbers. They were produced by the scripts named,
on a machine that held `runs/`, and re-deriving them requires that data.

### `docs/recomputed_gt_coverage_all.json` has no generator

This file is cited by `docs/THESIS_UNIFIED_RESULTS.md` and holds per-experiment
coverage for ten Juice Shop runs. No script in the repository writes it: it
entered the tree in the initial commit (`79c823c`) and nothing has produced it
since. It is not the output of `scripts/recompute_gt_coverage.py`, which writes
`docs/recomputed_gt_coverage.json` — a different file with different contents.

Treat any figure taken from it as unattributed unless the generating script is
recovered. Where a claim can be sourced instead to
`docs/recomputed_all_experiments.json`, which does name its generator and its
matcher, prefer that.

### `docs/power_analysis.json` does not read the data

`scripts/power_analysis.py` regenerates its output from a clean clone, but its
inputs are literals at the top of the script, not values read from any data
file:

```python
OBSERVED = {"baseline_only": 6, "ftv3_only": 3, "both": 7, "neither": 19}
N_GT = 35
```

Those four counts are the discordance table for the primary comparison,
transcribed by hand. They currently agree exactly with the tracked coverage data
— deriving them from `docs/recomputed_gt_coverage.json` gives
`both=7, baseline_only=6, ftv3_only=3, neither=19` over `gt_total=35` — so the
published power figures are consistent with the rest of the repository as it
stands. But nothing enforces that: if the coverage data were corrected, this
script would keep reporting power for the old effect without failing.

The script is also slow — the Monte-Carlo estimate runs 200,000 simulations per
call and takes well over a minute.

### Caveat on `statistical_tests.json`

This file holds the significance tests for the primary Apr 17 baseline-7B vs
FT-v3-7B comparison. `scripts/recompute_statistical_tests.py` regenerates it and
reproduces the pinned hash byte-for-byte, but only two of its three tests are
recomputed from repository-tracked data:

| Test | Reproducible from a clean clone? | Source |
|---|---|---|
| `mcnemar_per_gt` | yes | `gt_hit_ids` sets in `docs/recomputed_gt_coverage.json` |
| `fisher_per_category_bh` | yes | the same sets, mapped onto `JUICE_SHOP_GROUND_TRUTH` in `orchestrator/main.py` |
| `wilcoxon_per_session` | **no** | needs the per-session findings vector, which exists only in `runs/*/pentest.db` |

`runs/` is gitignored, so a clean clone cannot recompute the Wilcoxon. Run
without arguments, the script carries the committed Wilcoxon values forward and
prints `wilcoxon: CARRIED FORWARD` to say so; supply the paired per-session
counts with `--wilcoxon-pairs` to recompute it.

`--check` recomputes everything and asserts the result is byte-identical to the
committed file, writing nothing. This is the useful verification for a reader:
it confirms the McNemar and Fisher figures follow from the tracked coverage data
rather than having been entered by hand.

## Regeneration commands

### From a clean clone — these work

```bash
# Integrity: every tracked data file against its pinned hash
sha256sum -c <<'EOF'
c7cba2b7a4a3cab90b6c44eb2c7e5b465a72a599f48f771cb9b85f2ae993267a  docs/statistical_tests.json
7482c6145ff49c59642065b67b73163c51114914e875b472aa54c49f19e6a028  docs/power_analysis.json
d3146015b6cd54ba6cf328e2985b49a942498ce0d3606c1225f098bc11bc2cef  docs/recomputed_gt_coverage.json
fc3f7e211fb9d9c0c11f4c6d3af4e61668de21756fc676c8b45216c1295c260f  docs/recomputed_all_experiments.json
de6330e88c18e42aec58fa209447ee5d4bad5ca1f48a4d75c839a1a212577b02  docs/recomputed_all_experiments.csv
5dec1d4245e14862f7e196a4ef27b1a95b28a6ea08daa2f94c8a7b36592837ac  docs/recomputed_gt_coverage_all.json
1fa554c697514da49fc7658907c8ee5737ae55dcbc0aef4d0c3285a75c344180  docs/seed_variance_results.json
EOF

# Provenance: the one recompute that runs from tracked inputs.
# Needs scipy:  pip install -r requirements-analysis.txt
python3 scripts/recompute_statistical_tests.py --check   # verify, write nothing
```

`--check` prints `OK: regenerated output is byte-identical to the committed
file`, and prints `wilcoxon: CARRIED FORWARD` above it to flag the one test it
did not recompute. Both lines are the point of the exercise — read them.

### These need data that a clone does not have

```bash
# Both fail on a clean clone with
#   FileNotFoundError: runs/2026-04-17_19-24-01/ground_truth.json
# They require the campaign output in runs/ plus a populated per-run pentest.db.
python3 scripts/recompute_gt_coverage.py
python3 scripts/recompute_all_thesis_tables.py

# Re-runs the campaign itself: GPU, Ollama and a live target required.
bash scripts/overnight_seed_variance.sh

# Rebuilds the 41 MB training corpus before its hashes mean anything.
python3 scripts/assemble_juicy3_dataset.py
sha256sum -c <<'EOF'
5f2f394469700015dc94c0b5ce9399da02ef61e54fb793ab1d697ac7582a35ed  training_data/juicy3_train.jsonl
320099585c0dac63cda470d17c325574108b95efccfef095b51775cadf136081  training_data/juicy3_val.jsonl
EOF
```

To run the first two, restore `runs/` from the campaign machine to the
repository root. Section 3.13 of `docs/METHODOLOGY.md` gives the procedure for regenerating
`runs/` from scratch, which takes a full matrix execution.

Expected output from each `sha256sum -c` verification is `<file>: OK` on every
line. A mismatch means the committed file has changed since submission.

On macOS use `shasum -a 256 -c` in place of `sha256sum -c`.

**Verification status at time of writing:** all seven `docs/*` data files
present in the repository were re-hashed and every one matches the pinned value
above, and `scripts/recompute_statistical_tests.py --check` reported
`OK: regenerated output is byte-identical to the committed file`.

## Seeds used

All dataset-side operations use **`seed=42`** across Python and PyTorch/TRL.
`scripts/assemble_juicy3_dataset.py:36` sets:

```python
random.seed(42)
```

LoRA training inherits the same seed through `scripts/finetune_lora_cipher.py`,
which exposes `--seed` (default `42`, defined at line 251) and passes it into
the trainer configuration:

```python
training_args = SFTConfig(
    ...
    seed=args.seed,      # line 181
)
trainer = SFTTrainer(...)  # line 184, consumes training_args
```

Reproducing the published dataset hashes therefore requires running with the
default seed; passing `--seed` anything other than `42` will produce a
different corpus and different adapter weights.

## Inference seeding and run-to-run variance

LLM inference during evaluation uses Ollama with `temperature=0.3` and
`top_p=0.9`. The reported campaigns ran at Ollama's default seed, but the
orchestrator **does** support pinning one: `orchestrator/llm_client.py:36`
reads `ERLIK_OLLAMA_SEED` and, when set, injects it as
`body["options"] = {"seed": seed}` at `:50-52`.

**Aggregate metrics are not stable across seeds, and this is the single most
important reproducibility caveat in this project.** The dedicated seed-variance
control (`scripts/overnight_seed_variance.sh`, raw data in
`docs/seed_variance_results.json`, analysis in `docs/SEED_VARIANCE_FINAL.md`)
ran the same baseline `qwen2.5-coder:7b` configuration in one fixed environment,
varying only the inference seed:

| Run | Seed | Canonical GT coverage |
|---|---|---|
| Apr 17 baseline (thesis reference) | Ollama default | 13/35 (37.1%) |
| Baseline re-run | 100 | 10/35 (28.6%) |
| Baseline re-run | 200 | 11/35 (31.4%) |
| Baseline re-run | 300 | ≤8/35 |

That is a spread of roughly **5 ground-truth entries — about 14 percentage
points of coverage — from seed alone**, with every other variable held constant.
Any single-run difference smaller than this is within noise and must not be
attributed to a model, toolset, or fine-tuning effect. `SEED_VARIANCE_FINAL.md`
exists precisely because a reviewer challenged whether the H3 ensemble gain was
stochastic rather than a fine-tuning contribution.

Reproducing a specific published number therefore requires the same environment
*and* an accepting of seed-level variance; set `ERLIK_OLLAMA_SEED` to make an
individual run repeatable.
