#!/usr/bin/env python3
"""finetune_lora_cipher.py — QLoRA fine-tuning on CIPHER-style reasoning dataset.

Configured specifically for the cipher_train.jsonl / cipher_val.jsonl dataset:
- Defaults to 2-layer LoRA (q_proj, v_proj) — proven best config from R1/R2 experiments
- Default max_seq_length=4096 (dataset max is ~1051 tokens)
- Outputs adapter named "-cipher-r<rank>-L<layers>" for easy identification

Usage:
  # Default: 7B, r=16, 2 layers (recommended)
  python3 scripts/finetune_lora_cipher.py --model 7b

  # Larger rank
  python3 scripts/finetune_lora_cipher.py --model 7b --lora-rank 32

  # 14B variant
  python3 scripts/finetune_lora_cipher.py --model 14b

  # Aggressive (more layers — may cause catastrophic forgetting)
  python3 scripts/finetune_lora_cipher.py --model 7b --target-layers all
"""
import argparse
import json
import os
import sys
from pathlib import Path


# Target module presets
TARGET_MODULE_PRESETS = {
    "minimal": ["q_proj", "v_proj"],                                   # 2 layers — BEST for Erlik
    "attention": ["q_proj", "k_proj", "v_proj", "o_proj"],             # 4 attention layers
    "all": ["q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj"],                       # 7 layers (caused CF in R3)
}


def do_finetune(args):
    import torch
    from datasets import load_dataset
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        BitsAndBytesConfig,
    )
    from trl import SFTTrainer, SFTConfig

    MODEL_MAP = {
        "7b":  "Qwen/Qwen2.5-Coder-7B-Instruct",
        "14b": "Qwen/Qwen2.5-Coder-14B-Instruct",
        "32b": "Qwen/Qwen2.5-Coder-32B-Instruct",
    }

    model_name = MODEL_MAP.get(args.model)
    if not model_name:
        print(f"ABORT: unknown model size '{args.model}'. Use 7b, 14b, or 32b.")
        sys.exit(1)

    target_modules = TARGET_MODULE_PRESETS.get(args.target_layers)
    if not target_modules:
        print(f"ABORT: unknown target-layers '{args.target_layers}'. Use minimal/attention/all.")
        sys.exit(1)

    tag = f"cipher-r{args.lora_rank}-{args.target_layers[0].upper()}{len(target_modules)}"
    output_dir = Path(args.output) / f"qwen2.5-coder-{args.model}-{tag}"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"{'='*60}")
    print(f"Erlik 2.0 — CIPHER LoRA Fine-Tuning")
    print(f"{'='*60}")
    print(f"Base model:    {model_name}")
    print(f"Train data:    {args.train}")
    print(f"Val data:      {args.val}")
    print(f"Output:        {output_dir}")
    print(f"LoRA rank:     {args.lora_rank}")
    print(f"LoRA alpha:    {args.lora_alpha}")
    print(f"Target layers: {args.target_layers} ({len(target_modules)} modules: {target_modules})")
    print(f"Epochs:        {args.epochs}")
    print(f"Batch size:    {args.batch_size} (grad accum {args.grad_accum} → eff {args.batch_size*args.grad_accum})")
    print(f"Learning rate: {args.lr}")
    print(f"Max seq len:   {args.max_seq_length}")
    print(f"{'='*60}")

    # ── Load dataset ──────────────────────────────────────────────────
    print("\n[1/5] Loading dataset...")
    if not os.path.exists(args.train):
        print(f"ABORT: {args.train} not found.")
        sys.exit(1)

    val_path = args.val if os.path.exists(args.val) else args.train
    dataset = load_dataset("json", data_files={
        "train": args.train,
        "validation": val_path,
    })
    print(f"  Train: {len(dataset['train'])} examples")
    print(f"  Val:   {len(dataset['validation'])} examples")

    # Quick length check
    def token_len(ex, tok):
        text = tok.apply_chat_template(ex["messages"], tokenize=False, add_generation_prompt=False)
        return len(tok(text)["input_ids"])

    # ── Tokenizer ─────────────────────────────────────────────────────
    print("\n[2/5] Loading tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
        tokenizer.pad_token_id = tokenizer.eos_token_id

    # Sanity: check token distribution
    sample_lens = [token_len(dataset["train"][i], tokenizer) for i in range(min(50, len(dataset["train"])))]
    p95 = sorted(sample_lens)[int(len(sample_lens) * 0.95)]
    print(f"  Sample token lengths: min={min(sample_lens)}, max={max(sample_lens)}, p95={p95}")
    if p95 > args.max_seq_length:
        print(f"  WARNING: p95 ({p95}) > max_seq_length ({args.max_seq_length}). Consider increasing.")

    # ── Model (4-bit QLoRA) ───────────────────────────────────────────
    print("\n[3/5] Loading model with 4-bit QLoRA...")
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        quantization_config=bnb_config,
        device_map="auto",
        trust_remote_code=True,
        torch_dtype=torch.bfloat16,
    )
    model = prepare_model_for_kbit_training(model)

    # ── LoRA config ───────────────────────────────────────────────────
    print("\n[4/5] Attaching LoRA adapters...")
    lora_config = LoraConfig(
        r=args.lora_rank,
        lora_alpha=args.lora_alpha,
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=target_modules,
    )
    model = get_peft_model(model, lora_config)

    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    total = sum(p.numel() for p in model.parameters())
    print(f"  Trainable: {trainable:,} / {total:,} ({100*trainable/total:.3f}%)")

    # ── Chat template ─────────────────────────────────────────────────
    def format_messages(ex):
        text = tokenizer.apply_chat_template(ex["messages"], tokenize=False, add_generation_prompt=False)
        return {"text": text}

    dataset = dataset.map(format_messages, remove_columns=["messages"])

    # ── Train ─────────────────────────────────────────────────────────
    print("\n[5/5] Training...")
    training_args = SFTConfig(
        output_dir=str(output_dir),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        lr_scheduler_type="cosine",
        warmup_ratio=0.1,
        weight_decay=0.01,
        logging_steps=5,
        eval_strategy="epoch",
        save_strategy="epoch",
        save_total_limit=2,
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        greater_is_better=False,
        bf16=True,
        max_length=args.max_seq_length,
        dataset_text_field="text",
        report_to="none",
        seed=args.seed,
    )

    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=dataset["train"],
        eval_dataset=dataset["validation"],
        processing_class=tokenizer,
    )

    train_result = trainer.train()

    print(f"\nSaving adapter → {output_dir}")
    trainer.save_model(str(output_dir))
    tokenizer.save_pretrained(str(output_dir))

    metrics = {
        "experiment": tag,
        "base_model": model_name,
        "model_size": args.model,
        "lora_rank": args.lora_rank,
        "lora_alpha": args.lora_alpha,
        "target_modules": target_modules,
        "num_target_layers": len(target_modules),
        "epochs": args.epochs,
        "lr": args.lr,
        "batch_size": args.batch_size,
        "grad_accum": args.grad_accum,
        "max_seq_length": args.max_seq_length,
        "train_samples": len(dataset["train"]),
        "val_samples": len(dataset["validation"]),
        "trainable_params": trainable,
        "total_params": total,
        "trainable_pct": 100 * trainable / total,
        "train_loss": train_result.training_loss,
        "train_runtime_s": train_result.metrics.get("train_runtime", 0),
    }

    with open(output_dir / "training_metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"\n{'='*60}")
    print(f"CIPHER training complete!")
    print(f"  Train loss:  {train_result.training_loss:.4f}")
    print(f"  Runtime:     {train_result.metrics.get('train_runtime', 0):.0f}s ({train_result.metrics.get('train_runtime',0)/60:.1f} min)")
    print(f"  Adapter:     {output_dir}")
    print(f"{'='*60}")
    print(f"\nNext steps:")
    print(f"  1. Merge:    python3 scripts/merge_and_export.py --adapter {output_dir} --model {args.model}")
    print(f"  2. Ollama:   ollama create qwen2.5-coder:{args.model}-{tag} -f Modelfile")
    print(f"  3. Eval:     ERLIK_MATRIX_MODEL=qwen2.5-coder:{args.model}-{tag} python3 scripts/sprint_matrix.py --repeats 3")


def main():
    parser = argparse.ArgumentParser(description="CIPHER LoRA fine-tuning")
    parser.add_argument("--model", required=True, choices=["7b", "14b", "32b"])
    parser.add_argument("--train", default="training_data/cipher_train.jsonl")
    parser.add_argument("--val", default="training_data/cipher_val.jsonl")
    parser.add_argument("--output", default="checkpoints")
    parser.add_argument("--lora-rank", type=int, default=16)
    parser.add_argument("--lora-alpha", type=int, default=32)
    parser.add_argument("--target-layers", default="minimal",
                        choices=["minimal", "attention", "all"],
                        help="minimal=2 (q,v) [RECOMMENDED], attention=4, all=7 (caused CF in R3)")
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--grad-accum", type=int, default=8)
    parser.add_argument("--lr", type=float, default=2e-4)
    parser.add_argument("--max-seq-length", type=int, default=4096)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    do_finetune(args)


if __name__ == "__main__":
    main()
