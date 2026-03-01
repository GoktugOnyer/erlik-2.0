#!/bin/bash
set -e

echo "=== Pentest Agent Setup ==="

# Create venv
if [ ! -d ".venv" ]; then
    echo "[+] Creating Python virtual environment..."
    python -m venv .venv
fi

echo "[+] Activating venv and installing requirements..."
source .venv/Scripts/activate 2>/dev/null || source .venv/bin/activate
pip install -r requirements.txt

echo "[+] Starting Docker containers..."
docker-compose up -d

echo "[+] Waiting for Juice Shop to start..."
for i in $(seq 1 30); do
    if curl -s http://localhost:3000 > /dev/null 2>&1; then
        echo "[+] Juice Shop is ready at http://localhost:3000"
        break
    fi
    sleep 2
done

# Check Ollama
if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "[+] Ollama is running"
    if ! ollama list 2>/dev/null | grep -q "qwen2.5-coder"; then
        echo "[!] Model not found. Run: ollama pull qwen2.5-coder:7b-instruct-q4_K_M"
    fi
else
    echo "[!] Ollama is not running. Start it with: OLLAMA_NUM_GPU=99 ollama serve"
fi

echo "[+] Setup complete!"
