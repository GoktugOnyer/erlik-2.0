# Reproducibility — SHA-256 Checksums and Regeneration Recipe

This file pins the exact outputs reported in the thesis against their
regeneration scripts. A viva examiner (or future reader) can verify
that any claim in the thesis originates from the raw data in the
repository by re-running the recompute scripts and comparing hashes.

**Reference date:** 2026-04-18
**Git commit (at submission):** fill in with `git rev-parse HEAD` on submission

---

## Pinned output files

| File | SHA-256 | Size | Produced by | In repo? |
|---|---|---|---|---|
| `docs/recomputed_all_experiments.csv` | `de6330e88c18e42aec58fa209447ee5d4bad5ca1f48a4d75c839a1a212577b02` | ~3 KB | `scripts/recompute_all_thesis_tables.py` | yes |
| `docs/recomputed_all_experiments.json` | `fc3f7e211fb9d9c0c11f4c6d3af4e61668de21756fc676c8b45216c1295c260f` | ~15 KB | `scripts/recompute_all_thesis_tables.py` | yes |
| `docs/statistical_tests.json` | `c7cba2b7a4a3cab90b6c44eb2c7e5b465a72a599f48f771cb9b85f2ae993267a` | ~3 KB | `scripts/recompute_statistical_tests.py` (+ scipy) — partially reproducible, see below | yes |
| `training_data/juicy3_train.jsonl` | `5f2f394469700015dc94c0b5ce9399da02ef61e54fb793ab1d697ac7582a35ed` | 41 MB | `scripts/assemble_juicy3_dataset.py` | **no — see below** |
| `training_data/juicy3_val.jsonl` | `320099585c0dac63cda470d17c325574108b95efccfef095b51775cadf136081` | 1.7 MB | `scripts/assemble_juicy3_dataset.py` | **no — see below** |

### Which hashes a reader can actually check

`training_data/` is excluded by `.gitignore` (alongside `merged_models/`,
`checkpoints/`, and `runs/`) because the corpora are far too large for the
repository. The two dataset hashes are therefore **not verifiable from a clean
clone**. They are published so that a reader who regenerates the corpus with
`scripts/assemble_juicy3_dataset.py` can confirm they reconstructed the same
dataset bit-for-bit.

The three `docs/*` hashes **are** verifiable from a clean clone, and are the
ones backing every number in the results chapter.

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

```bash
# GT coverage for all thesis experiments (results table)
python3 scripts/recompute_all_thesis_tables.py

# GT coverage for the primary baseline-vs-fine-tuned comparison
python3 scripts/recompute_gt_coverage.py

# Significance tests for that comparison (requires scipy)
python3 scripts/recompute_statistical_tests.py --check   # verify, write nothing
python3 scripts/recompute_statistical_tests.py           # regenerate

# Verify against pinned hashes (the three repo-tracked outputs)
sha256sum -c <<'EOF'
de6330e88c18e42aec58fa209447ee5d4bad5ca1f48a4d75c839a1a212577b02  docs/recomputed_all_experiments.csv
fc3f7e211fb9d9c0c11f4c6d3af4e61668de21756fc676c8b45216c1295c260f  docs/recomputed_all_experiments.json
c7cba2b7a4a3cab90b6c44eb2c7e5b465a72a599f48f771cb9b85f2ae993267a  docs/statistical_tests.json
EOF

# Dataset hashes — only after regenerating the corpus locally
python3 scripts/assemble_juicy3_dataset.py
sha256sum -c <<'EOF'
5f2f394469700015dc94c0b5ce9399da02ef61e54fb793ab1d697ac7582a35ed  training_data/juicy3_train.jsonl
320099585c0dac63cda470d17c325574108b95efccfef095b51775cadf136081  training_data/juicy3_val.jsonl
EOF
```

Expected output from each `sha256sum -c` verification is `<file>: OK` on every
line. Any mismatch indicates the source data (in `runs/*/pentest.db`) or the
matcher script has changed since submission.

On macOS use `shasum -a 256 -c` in place of `sha256sum -c`.

**Verification status at time of writing:** the three `docs/*` files present in
the repository were re-hashed and all three match the pinned values above.

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
