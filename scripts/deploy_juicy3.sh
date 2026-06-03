#!/bin/bash
# Stage 4: Merge adapter → f16 GGUF → Q4_K_M → Ollama import.
# Run on CLOUD: ssh -p REDACTED_PORT root@REDACTED_HOST "bash -s" < scripts/deploy_juicy3.sh
set -euo pipefail

cd /root

echo "=== Stage 4.1: Merge LoRA adapter ==="
python3 -c "
import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer
from pathlib import Path

ADAPTER = 'checkpoints/qwen2.5-coder-14b-juicy3/qwen2.5-coder-14b-cipher-r32-A4'
BASE = 'Qwen/Qwen2.5-Coder-14B-Instruct'
OUT = Path('merged_models/qwen2.5-coder-14b-juicy3-merged')

OUT.mkdir(parents=True, exist_ok=True)
tok = AutoTokenizer.from_pretrained(BASE, trust_remote_code=True)
m = AutoModelForCausalLM.from_pretrained(BASE, torch_dtype=torch.float16, device_map='auto', trust_remote_code=True)
m = PeftModel.from_pretrained(m, ADAPTER)
m = m.merge_and_unload()
m.save_pretrained(str(OUT))
tok.save_pretrained(str(OUT))
print(f'Merged → {OUT}')
"

echo "=== Stage 4.2: Convert to f16 GGUF ==="
python3 llama.cpp/convert_hf_to_gguf.py \
    merged_models/qwen2.5-coder-14b-juicy3-merged \
    --outtype f16 \
    --outfile merged_models/qwen2.5-coder-14b-juicy3-f16.gguf

echo "=== Stage 4.3: Build llama-quantize if missing ==="
if [ ! -x /root/llama.cpp/build/bin/llama-quantize ]; then
    apt-get install -y cmake build-essential 2>&1 | tail -3
    cd /root/llama.cpp
    cmake -B build -DLLAMA_CURL=OFF -DGGML_CUDA=OFF 2>&1 | tail -5
    cmake --build build --target llama-quantize -j 4 2>&1 | tail -10
    cd /root
fi

echo "=== Stage 4.4: Quantize to Q4_K_M ==="
/root/llama.cpp/build/bin/llama-quantize \
    merged_models/qwen2.5-coder-14b-juicy3-f16.gguf \
    merged_models/qwen2.5-coder-14b-juicy3-Q4_K_M.gguf \
    Q4_K_M

ls -lh merged_models/qwen2.5-coder-14b-juicy3-*.gguf

echo "=== Stage 4.5: Start Ollama ==="
# Kill any zombie
killall ollama 2>/dev/null || true
sleep 2
nohup env OLLAMA_HOST=0.0.0.0:11434 ollama serve > /root/ollama.log 2>&1 &
sleep 5

echo "=== Stage 4.6: Write Modelfile and import ==="
cat > /root/Modelfile-juicy3 <<'MODELFILE'
FROM /root/merged_models/qwen2.5-coder-14b-juicy3-Q4_K_M.gguf

TEMPLATE """{{ if .System }}<|im_start|>system
{{ .System }}<|im_end|>
{{ end }}{{ range .Messages }}{{ if eq .Role "user" }}<|im_start|>user
{{ .Content }}<|im_end|>
{{ else if eq .Role "assistant" }}<|im_start|>assistant
{{ .Content }}<|im_end|>
{{ end }}{{ end }}<|im_start|>assistant
"""

PARAMETER temperature 0.3
PARAMETER top_p 0.9
PARAMETER num_ctx 8192
PARAMETER stop "<|im_start|>"
PARAMETER stop "<|im_end|>"

SYSTEM """You are Erlik, an autonomous penetration testing agent. You REASON through security problems step-by-step before acting. For each tool observation: state OBSERVATION (what you see), HYPOTHESIS (what attack might work and why), TEST PLAN (specific next action), then output the JSON action. After a result: state RESULT (what happened), VERIFICATION (did hypothesis hold). If a test fails, explain WHY, then pivot to an alternative. Emit valid JSON for actions: {\"action\":\"run_tool\",\"command\":\"...\",\"reason\":\"...\"} or {\"action\":\"finding\",\"vuln_type\":\"...\",\"severity\":\"...\",\"url\":\"...\",\"parameter\":\"...\",\"evidence\":\"...\"}"""
MODELFILE

ollama create qwen2.5-coder:14b-juicy3 -f /root/Modelfile-juicy3
ollama list

echo "=== Stage 4.7: Smoke test ==="
curl -s http://localhost:11434/api/chat -d '{
  "model": "qwen2.5-coder:14b-juicy3",
  "stream": false,
  "messages": [{"role":"user","content":"Tool: ffuf | Found: /api/patient/1\n[Phase: VULN_SCAN]"}],
  "options": {"temperature": 0.3, "num_predict": 200}
}' | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('message',{}).get('content','')[:600])"

echo ""
echo "=== DEPLOY COMPLETE ==="
