#!/usr/bin/env python3
"""extract_training_data.py — Build a LoRA fine-tuning dataset from baseline sessions.

Reads the orchestrator SQLite database and produces instruction-response pairs
in the Qwen chat format (system / user / assistant turns). Each example is one
step where the agent chose a tool and executed it.

Positive examples: steps that led to true-positive findings (validated against
ground truth). These teach the model which tool to pick and how to construct
the command.

Negative examples: steps where the model made a poor choice — hallucinated
syntax, duplicate commands, or tools that produced no useful output despite
having actionable context. These are paired with corrected responses.

Output: JSONL file where each line is a conversation in the format expected by
the Hugging Face SFTTrainer / TRL library:
  {"messages": [
    {"role": "system", "content": "..."},
    {"role": "user",   "content": "..."},
    {"role": "assistant", "content": "..."}
  ]}

Usage:
  python3 scripts/extract_training_data.py --db data/pentest.db --out training_data.jsonl
  python3 scripts/extract_training_data.py --db data/pentest.db --out training_data.jsonl --negative-ratio 0.25
"""
import argparse
import json
import os
import random
import sqlite3
import sys
from pathlib import Path


# ── Ground truth matching (simplified from orchestrator) ──────────────────

TYPE_ALIASES = {
    "sql injection": ["sqli", "sql", "injection"],
    "xss": ["cross-site", "xss", "script", "dom", "reflected"],
    "cors misconfiguration": ["cors", "cross-domain", "origin"],
    "information disclosure": ["info", "disclosure", "error", "version", "header"],
    "broken access control": ["access", "authorization", "idor", "privilege"],
    "broken authentication": ["auth", "login", "brute", "jwt", "credential", "password"],
    "sensitive data exposure": ["sensitive", "data", "exposure", "ftp", "backup"],
    "security misconfiguration": ["misconfig", "header", "nikto", "swagger", "config"],
    "ssrf": ["ssrf", "server-side", "request forgery"],
    "open redirect": ["redirect", "open redirect"],
    "command injection": ["command", "commix", "os command"],
    "file upload": ["upload", "file", "unrestricted"],
}

NOISE_TYPES = {
    "connection refused", "missing dependency", "browser tool not installed",
    "http request failed", "internal server error (500)",
}


def is_true_positive(finding: dict, ground_truths: list[dict]) -> bool:
    """Simplified TP check: type match + at least one corroborating dimension."""
    f_type = (finding.get("vuln_type") or "").lower()
    f_url = (finding.get("url") or "").lower()

    if f_type in NOISE_TYPES:
        return False

    for gt in ground_truths:
        gt_type = gt["vuln_type"].lower()
        # Type match
        type_match = gt_type in f_type or f_type in gt_type
        if not type_match:
            for alias in TYPE_ALIASES.get(gt_type, []):
                if alias in f_type:
                    type_match = True
                    break
        if not type_match:
            continue
        # URL match
        gt_pattern = (gt.get("url_pattern") or "").lower()
        if gt_pattern and gt_pattern in f_url:
            return True  # type + url = score 2
        # Parameter match
        gt_param = (gt.get("parameter") or "").lower()
        f_param = (finding.get("parameter") or "").lower()
        if gt_param and f_param and gt_param in f_param:
            return True  # type + param = score 2

    return False


# ── Context builder (mirrors orchestrator logic) ──────────────────────────

def build_context_from_prior_steps(steps: list[dict], current_idx: int) -> str:
    """Build the user context that the model saw before making its decision."""
    parts = []

    # Summary of tools run so far
    tools_run = {}
    findings_so_far = []
    for s in steps[:current_idx]:
        tool = s.get("tool_called", "")
        if tool:
            tools_run[tool] = tools_run.get(tool, 0) + 1

    if tools_run:
        tool_summary = ", ".join(f"{t} ({c}x)" for t, c in tools_run.items())
        parts.append(f"Tools run so far: {tool_summary}")

    # Last tool result (what the model is responding to)
    if current_idx > 0:
        prev = steps[current_idx - 1]
        prev_output = (prev.get("tool_output") or "")[:1500]
        parts.append(f"Previous tool: {prev.get('tool_called', '?')}")
        parts.append(f"Previous command: {prev.get('tool_input', '?')}")
        parts.append(f"Output:\n{prev_output}")

    return "\n".join(parts)


def build_system_prompt(session: dict) -> str:
    """Build a condensed system prompt for training examples."""
    tools = session.get("enabled_tools", "")
    if isinstance(tools, str):
        tool_list = tools
    else:
        tool_list = ", ".join(tools)

    return (
        "You are an autonomous penetration testing agent. "
        "You have access to security tools running inside a Kali Linux container "
        f"targeting {session.get('target_url', 'http://juice-shop:3000')}.\n\n"
        "Respond with ONLY a JSON object. Available actions:\n"
        '{"action": "run_tool", "tool": "<name>", "input": "<command>"}\n'
        '{"action": "finding", "vuln_type": "...", "severity": "...", "url": "...", '
        '"parameter": "...", "evidence": "..."}\n'
        '{"action": "done", "summary": "..."}\n\n'
        f"Available tools: {tool_list}\n\n"
        "RULES:\n"
        "1. One tool at a time. Analyse output before next action.\n"
        "2. Report findings immediately when discovered.\n"
        "3. Cover at least 3 of 4 phases: recon, discovery, vuln_scan, exploitation.\n"
        "4. Chain tool outputs: use discoveries from one tool as input for the next."
    )


# ── Main extraction ───────────────────────────────────────────────────────

def extract_examples(db_path: str, negative_ratio: float = 0.25) -> list[dict]:
    """Extract training examples from the database."""
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row

    # Load ground truth
    gt_rows = db.execute(
        "SELECT vuln_type, severity, url_pattern, parameter, description "
        "FROM ground_truth WHERE target_name = 'OWASP Juice Shop'"
    ).fetchall()
    ground_truths = [dict(r) for r in gt_rows]
    print(f"Loaded {len(ground_truths)} ground truth entries")

    # Load all completed sessions from clean runs
    sessions = db.execute("""
        SELECT id, target_url, enabled_tools, toolset_preset, session_type,
               chain_phase, total_findings, status
        FROM sessions
        WHERE status IN ('completed', 'stopped')
          AND total_steps > 0
        ORDER BY created_at
    """).fetchall()
    print(f"Found {len(sessions)} completed sessions")

    positive_examples = []
    negative_candidates = []

    for session in sessions:
        sid = session["id"]
        session_dict = dict(session)

        # Load steps for this session
        steps = db.execute("""
            SELECT step_number, tool_called, tool_input, tool_output,
                   duration_ms, model_response
            FROM steps
            WHERE session_id = ?
            ORDER BY step_number
        """, (sid,)).fetchall()
        steps = [dict(s) for s in steps]

        if not steps:
            continue

        # Load findings for this session
        findings = db.execute("""
            SELECT vuln_type, severity, url, parameter, evidence, created_at
            FROM findings
            WHERE session_id = ?
            ORDER BY created_at
        """, (sid,)).fetchall()
        findings = [dict(f) for f in findings]

        # Build system prompt
        sys_prompt = build_system_prompt(session_dict)

        # For each step, determine if it's a positive or negative example
        # A step is "positive" if the next finding was a TP (the tool call contributed)
        finding_idx = 0
        for i, step in enumerate(steps):
            tool = step.get("tool_called", "")
            cmd = step.get("tool_input", "")
            output = step.get("tool_output", "") or ""
            model_resp = step.get("model_response", "") or ""

            if not tool or not cmd:
                continue

            # Build the context the model saw
            context = build_context_from_prior_steps(steps, i)

            # The assistant response (what the model generated)
            try:
                assistant_json = json.loads(model_resp) if model_resp else {}
            except (json.JSONDecodeError, TypeError):
                assistant_json = {"action": "run_tool", "tool": tool, "input": cmd}

            # Check if this step led to a finding
            step_led_to_finding = False
            if finding_idx < len(findings):
                # Check if a finding was created around this step's timeframe
                f = findings[finding_idx]
                if is_true_positive(f, ground_truths):
                    # Check if output contains evidence of the finding
                    f_type = (f.get("vuln_type") or "").lower()
                    if any(kw in output.lower() for kw in
                           TYPE_ALIASES.get(f_type, [f_type])):
                        step_led_to_finding = True
                        finding_idx += 1

            example = {
                "messages": [
                    {"role": "system", "content": sys_prompt},
                    {"role": "user", "content": context},
                    {"role": "assistant", "content": json.dumps(assistant_json)},
                ],
                "session_id": sid,
                "step": i,
                "tool": tool,
                "is_positive": step_led_to_finding,
                "toolset": session_dict.get("toolset_preset", ""),
                "session_type": session_dict.get("session_type", ""),
            }

            if step_led_to_finding:
                positive_examples.append(example)
            else:
                negative_candidates.append(example)

    db.close()

    # Sample negatives to match desired ratio
    n_negatives = int(len(positive_examples) * negative_ratio / (1 - negative_ratio))
    n_negatives = min(n_negatives, len(negative_candidates))

    # Prefer diverse negatives: different tools, different sessions
    random.shuffle(negative_candidates)
    negative_examples = negative_candidates[:n_negatives]

    all_examples = positive_examples + negative_examples
    random.shuffle(all_examples)

    print(f"\nDataset summary:")
    print(f"  Positive examples (led to TP): {len(positive_examples)}")
    print(f"  Negative examples (sampled):   {len(negative_examples)}")
    print(f"  Total:                         {len(all_examples)}")
    print(f"  Negative ratio:                {len(negative_examples) / max(len(all_examples), 1):.1%}")

    # Tool distribution
    tool_dist = {}
    for ex in positive_examples:
        t = ex["tool"]
        tool_dist[t] = tool_dist.get(t, 0) + 1
    print(f"\n  Positive examples by tool:")
    for t, c in sorted(tool_dist.items(), key=lambda x: -x[1]):
        print(f"    {t}: {c}")

    return all_examples


def split_dataset(examples: list[dict], train_ratio=0.8, val_ratio=0.1, test_ratio=0.1):
    """Split into train/val/test with stratification by toolset."""
    random.shuffle(examples)
    n = len(examples)
    n_train = int(n * train_ratio)
    n_val = int(n * val_ratio)

    train = examples[:n_train]
    val = examples[n_train:n_train + n_val]
    test = examples[n_train + n_val:]

    return train, val, test


def save_jsonl(examples: list[dict], path: str):
    """Save examples as JSONL (messages only, no metadata)."""
    with open(path, "w") as f:
        for ex in examples:
            # Only save the messages field for training
            line = {"messages": ex["messages"]}
            f.write(json.dumps(line) + "\n")
    print(f"  Saved {len(examples)} examples to {path}")


def main():
    parser = argparse.ArgumentParser(description="Extract LoRA training data from pentest sessions")
    parser.add_argument("--db", default="data/pentest.db", help="Path to SQLite database")
    parser.add_argument("--out", default="training_data", help="Output directory")
    parser.add_argument("--negative-ratio", type=float, default=0.25,
                        help="Fraction of negative examples (default 0.25)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    random.seed(args.seed)

    if not os.path.exists(args.db):
        print(f"ABORT: database not found: {args.db}")
        sys.exit(1)

    # Extract examples
    examples = extract_examples(args.db, args.negative_ratio)

    if not examples:
        print("ABORT: no examples extracted")
        sys.exit(1)

    # Split
    train, val, test = split_dataset(examples)

    # Save
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    save_jsonl(train, str(out_dir / "train.jsonl"))
    save_jsonl(val, str(out_dir / "val.jsonl"))
    save_jsonl(test, str(out_dir / "test.jsonl"))

    # Save full dataset with metadata for analysis
    with open(out_dir / "full_dataset.json", "w") as f:
        json.dump({
            "total": len(examples),
            "positive": sum(1 for e in examples if e["is_positive"]),
            "negative": sum(1 for e in examples if not e["is_positive"]),
            "train_size": len(train),
            "val_size": len(val),
            "test_size": len(test),
            "examples": examples,
        }, f, indent=2)

    print(f"\n  Split: train={len(train)}, val={len(val)}, test={len(test)}")
    print(f"  Output directory: {out_dir}/")
    print("  Done.")


if __name__ == "__main__":
    main()
