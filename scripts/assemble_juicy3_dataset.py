#!/usr/bin/env python3
"""Merge, dedup, balance, and split all juicy3 data sources into train/val JSONL.

Reads:
  thesis_benchmark/sources/juiceshop_yml.jsonl
  thesis_benchmark/sources/pwning_book.jsonl
  thesis_benchmark/sources/ctfd_export.jsonl
  thesis_benchmark/sources/scthornton.jsonl
  thesis_benchmark/sources/synthetic.jsonl     (from local gen)
  training_data/cipher_train.jsonl + cipher_val.jsonl   (CIPHER chains)
  thesis_benchmark/juicy2_train.jsonl + juicy2_val.jsonl (MediTrack)
  training_data/hf_offensive_redteam.jsonl     (subsample)
  training_data/hf_pentest_agent.jsonl         (subsample)
  training_data/hf_canstralian.jsonl           (subsample)
  training_data/hf_trendyol_offensive.jsonl    (subsample)

Outputs:
  training_data/juicy3_train.jsonl   (~3150)
  training_data/juicy3_val.jsonl     (~350)

Target balance (approximate):
  ~15% CIPHER + MediTrack reasoning (preserve prior investment)
  ~25% Juice Shop specific (challenges.yml + Pwning + CTFd)
  ~15% synthetic
  ~25% scthornton secure-code
  ~20% general pentest HF
"""
import hashlib
import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path


random.seed(42)


def read_jsonl(path: Path, tag: str, max_rows: int | None = None) -> list[dict]:
    if not path.exists():
        print(f"  [skip] {path} not found")
        return []
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if "messages" not in obj or not obj["messages"]:
                    continue
                # Tag with source if not already tagged
                obj.setdefault("_meta", {})
                obj["_meta"].setdefault("source_file", tag)
                rows.append(obj)
            except json.JSONDecodeError:
                continue
    if max_rows and len(rows) > max_rows:
        random.shuffle(rows)
        rows = rows[:max_rows]
    print(f"  loaded {len(rows):>5} from {tag}")
    return rows


def dedup_by_content(rows: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for r in rows:
        msgs = r["messages"]
        # Hash on first user + first assistant content
        user_c = next((m.get("content", "") for m in msgs if m.get("role") == "user"), "")
        asst_c = next((m.get("content", "") for m in msgs if m.get("role") == "assistant"), "")
        h = hashlib.sha256((user_c[:500] + "||" + asst_c[:500]).encode()).hexdigest()
        if h in seen:
            continue
        seen.add(h)
        out.append(r)
    return out


def main():
    print("━" * 60)
    print("Assembling juicy3 dataset")
    print("━" * 60)

    bucket_js_specific = []   # Juice Shop specific: challenges.yml + Pwning + CTFd
    bucket_synthetic = []
    bucket_scthornton = []
    bucket_reasoning = []      # CIPHER + MediTrack
    bucket_generic = []        # general pentest HF

    # Juice Shop specific
    bucket_js_specific += read_jsonl(Path("thesis_benchmark/sources/juiceshop_yml.jsonl"), "challenges.yml")
    bucket_js_specific += read_jsonl(Path("thesis_benchmark/sources/pwning_book.jsonl"), "pwning-book")
    bucket_js_specific += read_jsonl(Path("thesis_benchmark/sources/ctfd_export.jsonl"), "ctfd-api")

    # Synthetic
    bucket_synthetic += read_jsonl(Path("thesis_benchmark/sources/synthetic.jsonl"), "synthetic")

    # scthornton
    bucket_scthornton += read_jsonl(Path("thesis_benchmark/sources/scthornton.jsonl"), "scthornton")

    # Reasoning (CIPHER + MediTrack)
    bucket_reasoning += read_jsonl(Path("training_data/cipher_train.jsonl"), "cipher-train")
    bucket_reasoning += read_jsonl(Path("training_data/cipher_val.jsonl"), "cipher-val")
    bucket_reasoning += read_jsonl(Path("thesis_benchmark/juicy2_train.jsonl"), "meditrack-train")
    bucket_reasoning += read_jsonl(Path("thesis_benchmark/juicy2_val.jsonl"), "meditrack-val")

    # Generic pentest HF — subsample
    bucket_generic += read_jsonl(Path("training_data/hf_offensive_redteam.jsonl"), "hf-offensive-redteam", max_rows=600)
    bucket_generic += read_jsonl(Path("training_data/hf_pentest_agent.jsonl"), "hf-pentest-agent", max_rows=400)
    bucket_generic += read_jsonl(Path("training_data/hf_canstralian.jsonl"), "hf-canstralian", max_rows=400)
    bucket_generic += read_jsonl(Path("training_data/hf_trendyol_offensive.jsonl"), "hf-trendyol", max_rows=200)

    # Dedup each bucket
    for name, bkt in [("js_specific", bucket_js_specific),
                      ("synthetic", bucket_synthetic),
                      ("scthornton", bucket_scthornton),
                      ("reasoning", bucket_reasoning),
                      ("generic", bucket_generic)]:
        before = len(bkt)
        bkt[:] = dedup_by_content(bkt)
        print(f"  dedup {name}: {before} -> {len(bkt)}")

    # Target counts (adjust to available)
    TARGETS = {
        "reasoning": 500,   # preserve CIPHER + MediTrack
        "js_specific": 700, # Juice Shop heavy (challenges + Pwning + CTFd)
        "synthetic": 500,   # synthetic payloads
        "scthornton": 800,  # secure-code
        "generic": 700,     # general pentest HF
    }

    all_rows = []
    for bucket_name, target in TARGETS.items():
        bkt = {"reasoning": bucket_reasoning, "js_specific": bucket_js_specific,
               "synthetic": bucket_synthetic, "scthornton": bucket_scthornton,
               "generic": bucket_generic}[bucket_name]
        if len(bkt) > target:
            random.shuffle(bkt)
            bkt = bkt[:target]
        for r in bkt:
            r["_meta"]["bucket"] = bucket_name
        all_rows.extend(bkt)
        print(f"  bucket {bucket_name:12}: target {target} -> took {len(bkt)}")

    # Final shuffle + split 90/10
    random.shuffle(all_rows)
    split = int(len(all_rows) * 0.9)
    train_rows = all_rows[:split]
    val_rows = all_rows[split:]

    # License histogram
    print("\nLicense histogram:")
    licenses = Counter(r["_meta"].get("license", "unknown") for r in all_rows)
    for lic, n in licenses.most_common():
        print(f"  {lic:40} {n}")

    # Source histogram
    print("\nSource-file histogram:")
    sources = Counter(r["_meta"].get("source_file", "unknown") for r in all_rows)
    for src, n in sources.most_common():
        print(f"  {src:30} {n}")

    # Write
    Path("training_data").mkdir(exist_ok=True)
    with open("training_data/juicy3_train.jsonl", "w") as f:
        for r in train_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with open("training_data/juicy3_val.jsonl", "w") as f:
        for r in val_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"\nTotal: {len(all_rows)}   train: {len(train_rows)}   val: {len(val_rows)}")
    print(f"→ training_data/juicy3_train.jsonl")
    print(f"→ training_data/juicy3_val.jsonl")


if __name__ == "__main__":
    main()
