#!/usr/bin/env python3
"""merge_and_export.py — Merge LoRA adapter with base model and export to GGUF.

After fine-tuning with finetune_lora.py, this script:
1. Loads the base model + LoRA adapter
2. Merges adapter weights into the base model
3. Saves the merged model in HF format
4. Converts to GGUF Q4_K_M for Ollama deployment
5. Generates an Ollama Modelfile

Usage:
  python3 scripts/merge_and_export.py --adapter checkpoints/qwen2.5-coder-7b-pentest-lora --model 7b
  python3 scripts/merge_and_export.py --adapter checkpoints/qwen2.5-coder-14b-pentest-lora --model 14b
  python3 scripts/merge_and_export.py --adapter checkpoints/qwen2.5-coder-32b-pentest-lora --model 32b

Requirements:
  pip install torch transformers peft
  # For GGUF conversion: clone llama.cpp and build convert_hf_to_gguf.py
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


MODEL_MAP = {
    "7b":  "Qwen/Qwen2.5-Coder-7B-Instruct",
    "14b": "Qwen/Qwen2.5-Coder-14B-Instruct",
    "32b": "Qwen/Qwen2.5-Coder-32B-Instruct",
}


def main():
    parser = argparse.ArgumentParser(description="Merge LoRA adapter and export to GGUF")
    parser.add_argument("--adapter", required=True, help="Path to LoRA adapter checkpoint")
    parser.add_argument("--model", required=True, choices=["7b", "14b", "32b"])
    parser.add_argument("--output", default="merged_models", help="Output directory")
    parser.add_argument("--quantize", default="Q4_K_M", help="GGUF quantisation type")
    parser.add_argument("--llama-cpp", default="llama.cpp",
                        help="Path to llama.cpp repo (for GGUF conversion)")
    args = parser.parse_args()

    base_model = MODEL_MAP[args.model]
    adapter_path = Path(args.adapter)
    merged_dir = Path(args.output) / f"qwen2.5-coder-{args.model}-pentest-merged"
    gguf_path = Path(args.output) / f"qwen2.5-coder-{args.model}-pentest-{args.quantize}.gguf"

    print(f"{'='*60}")
    print(f"Merge & Export: {args.model}")
    print(f"  Base:    {base_model}")
    print(f"  Adapter: {adapter_path}")
    print(f"  Merged:  {merged_dir}")
    print(f"  GGUF:    {gguf_path}")
    print(f"{'='*60}")

    # ── Step 1: Merge ─────────────────────────────────────────────────
    print("\n[1/3] Merging adapter into base model...")

    import torch
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(base_model, trust_remote_code=True)

    model = AutoModelForCausalLM.from_pretrained(
        base_model,
        torch_dtype=torch.float16,
        device_map="auto",
        trust_remote_code=True,
    )

    model = PeftModel.from_pretrained(model, str(adapter_path))
    model = model.merge_and_unload()

    merged_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(str(merged_dir))
    tokenizer.save_pretrained(str(merged_dir))
    print(f"  Merged model saved to {merged_dir}")

    # ── Step 2: Convert to GGUF ───────────────────────────────────────
    print("\n[2/3] Converting to GGUF...")

    convert_script = Path(args.llama_cpp) / "convert_hf_to_gguf.py"
    if not convert_script.exists():
        print(f"  WARNING: {convert_script} not found. Skipping GGUF conversion.")
        print(f"  Clone llama.cpp and retry, or convert manually:")
        print(f"    python3 llama.cpp/convert_hf_to_gguf.py {merged_dir} --outtype {args.quantize.lower()} --outfile {gguf_path}")
    else:
        cmd = [
            sys.executable, str(convert_script),
            str(merged_dir),
            "--outtype", args.quantize.lower().replace("_", "-"),
            "--outfile", str(gguf_path),
        ]
        print(f"  Running: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)
        print(f"  GGUF saved to {gguf_path}")

    # ── Step 3: Generate Ollama Modelfile ──────────────────────────────
    print("\n[3/3] Generating Ollama Modelfile...")

    modelfile_path = Path(args.output) / f"Modelfile-{args.model}-pentest"
    model_tag = f"qwen2.5-coder:{args.model}-pentest"

    modelfile_content = f"""FROM {gguf_path}

PARAMETER temperature 0.7
PARAMETER top_p 0.9
PARAMETER repeat_penalty 1.1
PARAMETER num_ctx 8192

SYSTEM \"\"\"You are an autonomous penetration testing agent. You have access to security tools running inside a Kali Linux container. Respond with ONLY JSON objects for tool invocations, findings, or completion.\"\"\"
"""

    modelfile_path.write_text(modelfile_content)
    print(f"  Modelfile saved to {modelfile_path}")
    print(f"\n  To import into Ollama:")
    print(f"    ollama create {model_tag} -f {modelfile_path}")
    print(f"\n  To run evaluation:")
    print(f"    ERLIK_MATRIX_MODEL={model_tag} python3 scripts/sprint_matrix.py --repeats 3")

    print(f"\n{'='*60}")
    print(f"Done! Pipeline complete for {args.model}.")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
