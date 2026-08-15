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
| `docs/statistical_tests.json` | `c7cba2b7a4a3cab90b6c44eb2c7e5b465a72a599f48f771cb9b85f2ae993267a` | ~3 KB | `scripts/recompute_gt_coverage.py` (+ scipy) | yes |
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

## Regeneration commands

```bash
# GT coverage for all thesis experiments (results table)
python3 scripts/recompute_all_thesis_tables.py

# Statistical tests for the primary baseline-vs-fine-tuned comparison
python3 scripts/recompute_gt_coverage.py

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

All dataset-side operations use **`seed=42`** across Python, NumPy, and
PyTorch/TRL. `scripts/assemble_juicy3_dataset.py:36` sets:

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

LLM inference during evaluation uses Ollama with `temperature=0.3`,
`top_p=0.9`, and no explicit seed. Ollama does not expose a
reproducibility seed at these hyperparameters, so per-session token
sequences are not bit-identical across runs — but aggregate metrics
(GT coverage, TP counts) are stable within ±1 GT between independent
runs, as verified in the Apr 15 and Apr 17 baseline-7B runs which
produced 11/35 and 13/35 respectively under different tool
configurations (the delta is attributable to 25-vs-27 tools available,
not seed variation).

See `docs/SEED_VARIANCE_FINAL.md` for the dedicated seed-variance control.
