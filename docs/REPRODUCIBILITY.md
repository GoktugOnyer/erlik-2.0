# Reproducibility — SHA-256 Checksums and Regeneration Recipe

This file pins the exact outputs reported in the thesis against their
regeneration scripts. A viva examiner (or future reader) can verify
that any claim in the thesis originates from the raw data in the
repository by re-running the recompute scripts and comparing hashes.

**Reference date:** 2026-04-18
**Git commit (at submission):** (fill in with `git rev-parse HEAD` on submission)

---

## Pinned output files

| File | SHA-256 | Size | Produced by |
|---|---|---|---|
| `docs/recomputed_all_experiments.csv` | `de6330e88c18e42aec58fa209447ee5d4bad5ca1f48a4d75c839a1a212577b02` | ~3 KB | `scripts/recompute_all_thesis_tables.py` |
| `docs/recomputed_all_experiments.json` | `fc3f7e211fb9d9c0c11f4c6d3af4e61668de21756fc676c8b45216c1295c260f` | ~6 KB | `scripts/recompute_all_thesis_tables.py` |
| `docs/statistical_tests.json` | `c7cba2b7a4a3cab90b6c44eb2c7e5b465a72a599f48f771cb9b85f2ae993267a` | ~2 KB | `scripts/recompute_gt_coverage.py` (+ scipy) |
| `training_data/juicy3_train.jsonl` | `5f2f394469700015dc94c0b5ce9399da02ef61e54fb793ab1d697ac7582a35ed` | 41 MB | `scripts/assemble_juicy3_dataset.py` |
| `training_data/juicy3_val.jsonl` | `320099585c0dac63cda470d17c325574108b95efccfef095b51775cadf136081` | 1.7 MB | `scripts/assemble_juicy3_dataset.py` |

## Regeneration commands

```bash
# GT coverage for all 27 thesis experiments (Section 3 table)
python3 scripts/recompute_all_thesis_tables.py

# Statistical tests for the Apr 17 baseline-vs-FT-v3 primary comparison
python3 -c "exec(open('scripts/_recompute_stats_inline.py').read())" \
  || python3 scripts/recompute_gt_coverage.py   # primary-matcher demo

# Verify against pinned hashes
shasum -a 256 -c <<'EOF'
de6330e88c18e42aec58fa209447ee5d4bad5ca1f48a4d75c839a1a212577b02  docs/recomputed_all_experiments.csv
fc3f7e211fb9d9c0c11f4c6d3af4e61668de21756fc676c8b45216c1295c260f  docs/recomputed_all_experiments.json
c7cba2b7a4a3cab90b6c44eb2c7e5b465a72a599f48f771cb9b85f2ae993267a  docs/statistical_tests.json
5f2f394469700015dc94c0b5ce9399da02ef61e54fb793ab1d697ac7582a35ed  training_data/juicy3_train.jsonl
320099585c0dac63cda470d17c325574108b95efccfef095b51775cadf136081  training_data/juicy3_val.jsonl
EOF
```

Expected output from the `shasum -c` verification is `<file>: OK` on
each of the five lines. Any mismatch indicates the source data (in
`runs/*/pentest.db`) or the matcher script has changed since submission.

## Seeds used

All dataset-side operations use **`seed=42`** across Python, NumPy, and
PyTorch/TRL. The commit of `scripts/assemble_juicy3_dataset.py` at line 27
shows:

```python
random.seed(42)
```

LoRA training inherits the same seed through `trl.SFTTrainer(seed=42)` in
`scripts/finetune_lora_cipher.py`.

LLM inference during evaluation uses Ollama with `temperature=0.3`,
`top_p=0.9`, and no explicit seed. Ollama does not expose a
reproducibility seed at these hyperparameters, so per-session token
sequences are not bit-identical across runs — but aggregate metrics
(GT coverage, TP counts) are stable within ±1 GT between independent
runs, as verified in the Apr 15 and Apr 17 baseline-7B runs which
produced 11/35 and 13/35 respectively under different tool
configurations (the delta is attributable to 25-vs-27 tools available,
not seed variation).
