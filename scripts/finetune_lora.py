#!/usr/bin/env python3
"""finetune_lora.py — QLoRA fine-tuning for Erlik pentest agent.

Fine-tunes Qwen2.5-Coder models (7B, 14B, 32B) on pentesting interaction
data using QLoRA (4-bit NF4 quantisation + LoRA adapters).

Produces a LoRA adapter checkpoint that can be merged with the base model
and converted to GGUF for Ollama deployment.

Usage:
  # Fine-tune 7B (fits on RTX 4090)
  python3 scripts/finetune_lora.py --model 7b --data training_data/

  # Fine-tune 14B (tight on RTX 4090)
  python3 scripts/finetune_lora.py --model 14b --data training_data/

  # Fine-tune 32B (needs A100 80GB)
  python3 scripts/finetune_lora.py --model 32b --data training_data/

  # Custom LoRA rank
  python3 scripts/finetune_lora.py --model 7b --data training_data/ --lora-rank 32

Requirements:
  pip install torch transformers peft bitsandbytes accelerate trl datasets
"""
import argparse
import json
import os
import sys
from pathlib import Path

# These imports are deferred so --help works without GPU
def do_finetune(args):
    import torch
    from datasets import load_dataset
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        BitsAndBytesConfig,
        TrainingArguments,
    )
    from trl import SFTTrainer, SFTConfig

    # ── Model mapping ─────────────────────────────────────────────────
    MODEL_MAP = {
        "7b":  "Qwen/Qwen2.5-Coder-7B-Instruct",
        "14b": "Qwen/Qwen2.5-Coder-14B-Instruct",
        "32b": "Qwen/Qwen2.5-Coder-32B-Instruct",
    }

    model_name = MODEL_MAP.get(args.model)
    if not model_name:
        print(f"ABORT: unknown model size '{args.model}'. Use 7b, 14b, or 32b.")
        sys.exit(1)

    data_dir = Path(args.data)
    output_dir = Path(args.output) / f"qwen2.5-coder-{args.model}-pentest-lora"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"{'='*60}")
    print(f"Erlik 2.0 — LoRA Fine-Tuning")
    print(f"{'='*60}")
    print(f"Base model:    {model_name}")
    print(f"Training data: {data_dir}")
    print(f"Output:        {output_dir}")
    print(f"LoRA rank:     {args.lora_rank}")
    print(f"LoRA alpha:    {args.lora_alpha}")
    print(f"Epochs:        {args.epochs}")
    print(f"Batch size:    {args.batch_size} (grad accum {args.grad_accum})")
    print(f"Learning rate: {args.lr}")
    print(f"{'='*60}")

    # ── Load dataset ──────────────────────────────────────────────────
    print("\n[1/5] Loading dataset...")
    train_path = str(data_dir / "train.jsonl")
    val_path = str(data_dir / "val.jsonl")

    if not os.path.exists(train_path):
        print(f"ABORT: {train_path} not found. Run extract_training_data.py first.")
        sys.exit(1)

    dataset = load_dataset("json", data_files={
        "train": train_path,
        "validation": val_path if os.path.exists(val_path) else train_path,
    })
    print(f"  Train: {len(dataset['train'])} examples")
    print(f"  Val:   {len(dataset['validation'])} examples")

    # ── Load tokenizer ────────────────────────────────────────────────
    print("\n[2/5] Loading tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)

    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
        tokenizer.pad_token_id = tokenizer.eos_token_id

    # ── Load model with 4-bit quantisation ────────────────────────────
    print("\n[3/5] Loading model with QLoRA quantisation...")
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

    # ── Configure LoRA ────────────────────────────────────────────────
    print("\n[4/5] Configuring LoRA adapters...")
    lora_config = LoraConfig(
        r=args.lora_rank,
        lora_alpha=args.lora_alpha,
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    )

    model = get_peft_model(model, lora_config)

    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    total_params = sum(p.numel() for p in model.parameters())
    print(f"  Trainable: {trainable_params:,} / {total_params:,} "
          f"({100 * trainable_params / total_params:.3f}%)")

    # ── Format messages for training ──────────────────────────────────
    def format_messages(example):
        """Apply Qwen chat template to messages."""
        messages = example["messages"]
        text = tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=False,
        )
        return {"text": text}

    dataset = dataset.map(format_messages, remove_columns=["messages"])

    # ── Training ──────────────────────────────────────────────────────
    print("\n[5/5] Starting training...")

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

    # Train
    train_result = trainer.train()

    # Save
    print(f"\nSaving adapter to {output_dir}...")
    trainer.save_model(str(output_dir))
    tokenizer.save_pretrained(str(output_dir))

    # Save training metrics
    metrics = {
        "model": model_name,
        "model_size": args.model,
        "lora_rank": args.lora_rank,
        "lora_alpha": args.lora_alpha,
        "epochs": args.epochs,
        "lr": args.lr,
        "train_samples": len(dataset["train"]),
        "val_samples": len(dataset["validation"]),
        "trainable_params": trainable_params,
        "total_params": total_params,
        "trainable_pct": 100 * trainable_params / total_params,
        "train_loss": train_result.training_loss,
        "train_runtime_s": train_result.metrics.get("train_runtime", 0),
    }

    with open(output_dir / "training_metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"\n{'='*60}")
    print(f"Training complete!")
    print(f"  Loss:     {train_result.training_loss:.4f}")
    print(f"  Runtime:  {train_result.metrics.get('train_runtime', 0):.0f}s")
    print(f"  Adapter:  {output_dir}")
    print(f"{'='*60}")
    print(f"\nNext steps:")
    print(f"  1. Merge adapter: python3 scripts/merge_and_export.py --adapter {output_dir} --model {args.model}")
    print(f"  2. Import to Ollama: ollama create qwen2.5-coder:{args.model}-pentest -f Modelfile")
    print(f"  3. Run evaluation: ERLIK_MATRIX_MODEL=qwen2.5-coder:{args.model}-pentest python3 scripts/sprint_matrix.py --repeats 3")


def main():
    parser = argparse.ArgumentParser(description="QLoRA fine-tuning for Erlik pentest agent")
    parser.add_argument("--model", required=True, choices=["7b", "14b", "32b"],
                        help="Model size to fine-tune")
    parser.add_argument("--data", default="training_data",
                        help="Directory with train.jsonl and val.jsonl")
    parser.add_argument("--output", default="checkpoints",
                        help="Output directory for adapter checkpoints")
    parser.add_argument("--lora-rank", type=int, default=16,
                        help="LoRA rank (default: 16)")
    parser.add_argument("--lora-alpha", type=int, default=32,
                        help="LoRA alpha (default: 32)")
    parser.add_argument("--epochs", type=int, default=3,
                        help="Training epochs (default: 3)")
    parser.add_argument("--batch-size", type=int, default=1,
                        help="Per-device batch size (default: 1)")
    parser.add_argument("--grad-accum", type=int, default=4,
                        help="Gradient accumulation steps (default: 4)")
    parser.add_argument("--lr", type=float, default=2e-4,
                        help="Learning rate (default: 2e-4)")
    parser.add_argument("--max-seq-length", type=int, default=8192,
                        help="Max sequence length (default: 8192)")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed (default: 42)")
    args = parser.parse_args()

    do_finetune(args)


if __name__ == "__main__":
    main()
