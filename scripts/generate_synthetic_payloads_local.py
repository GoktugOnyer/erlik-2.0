#!/usr/bin/env python3
"""Locally (via tunnel to cloud Ollama) generate synthetic CIPHER reasoning chains
for Juice Shop attack patterns.

Output file lives on the local Mac, then will be SFTPd to cloud.
Generation model: qwen2.5-coder:14b-juicy (already loaded on cloud via tunnel).
"""
import argparse
import json
import random
import re
import time
import urllib.request
from pathlib import Path


OLLAMA = "http://localhost:11434"
MODEL = "qwen2.5-coder:14b-juicy"  # best available for CIPHER format

SYS_PROMPT = (
    "You are Erlik, an autonomous penetration testing agent. "
    "You REASON through security problems step-by-step before acting. "
    "For each tool observation: state OBSERVATION (what you see), "
    "HYPOTHESIS (what attack might work and why), "
    "TEST PLAN (specific next action), then output the JSON action. "
    "After a result: state RESULT (what happened), VERIFICATION (did hypothesis hold). "
    "If a test fails, explain WHY, then pivot to an alternative. "
    "Emit valid JSON for actions: "
    '{"action":"run_tool","command":"...","reason":"..."} or '
    '{"action":"finding","vuln_type":"...","severity":"...","url":"...","parameter":"...","evidence":"..."}'
)

# Seed CATEGORIES: (label, description_template, target_endpoint, example_payload_hint)
CATEGORIES = [
    ("SQLi", "SQL injection via product search", "/rest/products/search?q=", "')) UNION SELECT ..."),
    ("SQLi", "Auth-bypass SQLi", "/rest/user/login", "' or 1=1--"),
    ("XSS", "Persisted XSS in feedback comment", "/api/Feedbacks", "<iframe src=javascript:...>"),
    ("XSS", "Reflected XSS via track-result id", "/#/track-result?id=", "<iframe src=javascript:...>"),
    ("IDOR", "IDOR on basket ID", "/rest/basket/{id}", "sequential IDs"),
    ("IDOR", "IDOR on user data export", "/rest/user/data-export", "email collision"),
    ("JWT", "alg:none bypass", "/rest/user/change-password", "Authorization: Bearer <alg:none>"),
    ("JWT", "kid header injection", "/api/*", "kid with SQLi / path"),
    ("SSRF", "URL fetcher SSRF", "/redirect?to=", "internal URL"),
    ("SSRF", "Profile import SSRF", "/api/import", "IMDS metadata"),
    ("Open Redirect", "Redirect allowlist bypass", "/redirect?to=", "https://evil.com?x=..."),
    ("XXE", "XML upload XXE", "/file-upload", "SYSTEM entity"),
    ("Prototype Pollution", "__proto__ in JSON body", "/api/settings", "__proto__ with isAdmin"),
    ("Sensitive Data", "FTP dir traversal", "/ftp/{file}", "%2500.md null byte"),
    ("Mass Assignment", "Register admin via extra field", "/api/Users", 'role: "admin"'),
    ("CSRF", "State-change without token", "/profile", "no CSRF token"),
    ("Path Traversal", "File read via ../", "/api/download?file=", "../../../etc/passwd"),
]

# Few-shot exemplars — keep tight so model's output is the star
FEW_SHOT = """\
Example (SQL injection on /rest/products/search):
OBSERVATION: A product search endpoint at /rest/products/search accepts a `q` parameter. Error responses have leaked a LIKE-wrapped SQL query.

HYPOTHESIS: Since user input is concatenated into a LIKE clause, a UNION SELECT payload should exfiltrate other tables.

TEST PLAN: Close the LIKE with `')) ` and UNION SELECT from `sqlite_master`.

{"action":"run_tool","command":"curl -s \\"http://juice-shop:3000/rest/products/search?q=')) UNION SELECT sql,2,3,4,5,6,7,8,9 FROM sqlite_master--\\"","reason":"UNION extraction of DB schema"}
"""


def make_prompt(cat_label: str, desc: str, endpoint: str, hint: str) -> str:
    return (
        f"Write ONE concise CIPHER-format reasoning chain (<200 words) for the following scenario:\n"
        f"Category: {cat_label}\n"
        f"Scenario: {desc}\n"
        f"Target endpoint: http://juice-shop:3000{endpoint}\n"
        f"Attack hint: {hint}\n\n"
        f"Structure:\nOBSERVATION: ...\nHYPOTHESIS: ...\nTEST PLAN: ...\n\nThen the JSON action on a NEW line.\n\n"
        f"{FEW_SHOT}\n\nNow generate a NEW example for the scenario above. Do NOT repeat the example."
    )


def call_ollama(prompt: str, timeout: int = 120) -> str | None:
    body = json.dumps({
        "model": MODEL,
        "stream": False,
        "messages": [{"role": "user", "content": prompt}],
        "options": {"temperature": 0.8, "top_p": 0.95, "num_predict": 280},
    }).encode()
    req = urllib.request.Request(f"{OLLAMA}/api/chat", data=body,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read())
        return data.get("message", {}).get("content", "").strip()
    except Exception as e:
        print(f"  ollama err: {e}")
        return None


def find_balanced_json(text: str) -> list[str]:
    """Return all top-level {..} blocks (string-aware brace matching)."""
    out = []
    i = 0
    n = len(text)
    while i < n:
        if text[i] == "{":
            start = i
            depth = 0
            in_str = False
            esc = False
            while i < n:
                ch = text[i]
                if in_str:
                    if esc: esc = False
                    elif ch == "\\": esc = True
                    elif ch == '"': in_str = False
                else:
                    if ch == '"': in_str = True
                    elif ch == "{": depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            out.append(text[start:i+1])
                            i += 1
                            break
                i += 1
        else:
            i += 1
    return out


def validate_and_extract(raw: str, cat_label: str) -> dict | None:
    """Ensure the output has OBSERVATION/HYPOTHESIS and one parseable action JSON."""
    if not raw or "OBSERVATION" not in raw.upper() or "HYPOTHESIS" not in raw.upper():
        return None
    candidates = find_balanced_json(raw)
    action = None
    for c in candidates:
        try:
            obj = json.loads(c)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and obj.get("action") in ("run_tool", "finding", "done"):
            action = obj
    if action is None:
        return None
    return {"assistant_content": raw, "action_json": action}


def build_example(prompt: str, assistant_msg: str, cat_label: str, scenario: str) -> dict:
    # The user message in the training data should look like a real tool-output observation,
    # NOT the meta-prompt we used for generation. So we synthesize a clean user msg from the scenario.
    user_msg = f"Target: http://juice-shop:3000\nPlaybook phase: VULN_SCAN\nScenario: {scenario}"
    return {
        "messages": [
            {"role": "system", "content": SYS_PROMPT},
            {"role": "user", "content": user_msg},
            {"role": "assistant", "content": assistant_msg},
        ],
        "_meta": {
            "source": "synthetic (qwen2.5-coder:14b-juicy via local Mac)",
            "license": "generated",
            "category": cat_label,
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=500)
    ap.add_argument("--out", default="thesis_benchmark/sources/synthetic.jsonl")
    args = ap.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    kept = 0
    attempts = 0
    invalid = 0
    random.seed(42)
    with open(out, "w") as f:
        while kept < args.count:
            attempts += 1
            cat_label, desc, endpoint, hint = random.choice(CATEGORIES)
            prompt = make_prompt(cat_label, desc, endpoint, hint)
            raw = call_ollama(prompt)
            if not raw:
                invalid += 1
                continue
            parsed = validate_and_extract(raw, cat_label)
            if not parsed:
                invalid += 1
                if invalid % 10 == 0:
                    print(f"  [warn] {invalid} invalids so far")
                continue
            ex = build_example(prompt, parsed["assistant_content"], cat_label, desc)
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")
            f.flush()
            kept += 1
            if kept % 10 == 0:
                print(f"  kept={kept}/{args.count}  attempts={attempts}  invalid={invalid}", flush=True)

    print(f"Done: kept {kept} / {attempts} attempts ({invalid} invalid)")
    print(f"→ {out}")


if __name__ == "__main__":
    main()
