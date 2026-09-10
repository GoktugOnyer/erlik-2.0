#!/bin/bash
set -e

echo "=== Pentest Agent Setup ==="

# Pick the interpreter. macOS ships no bare `python` — only `python3` — so
# calling `python` here aborts the script under `set -e` before anything runs.
if command -v python3 > /dev/null 2>&1; then
    PYTHON=python3
elif command -v python > /dev/null 2>&1; then
    PYTHON=python
else
    echo "[!] No Python found — install Python 3.10+ first." >&2
    exit 1
fi

# Create venv
if [ ! -d ".venv" ]; then
    echo "[+] Creating Python virtual environment with ${PYTHON}..."
    "$PYTHON" -m venv .venv
fi

echo "[+] Activating venv and installing requirements..."
# Test for the file explicitly instead of relying on `source A || source B`:
# under `set -e`, macOS's bash 3.2 treats a failed `source` as a fatal
# special-builtin error and exits before the fallback can run.
if [ -f ".venv/Scripts/activate" ]; then
    source .venv/Scripts/activate      # Windows (Git Bash / MSYS)
elif [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate          # macOS / Linux
else
    echo "[!] Virtualenv creation failed — no activate script under .venv/." >&2
    exit 1
fi

pip install -r requirements.txt

# Compose v2 is a `docker` subcommand; the standalone `docker-compose` binary is
# v1 and is absent from a plugin-only install. This script runs under `set -e`,
# so calling the missing one aborts setup before a single container starts —
# and the README documents `docker compose`, so the two had drifted apart.
if docker compose version > /dev/null 2>&1; then
    COMPOSE="docker compose"
elif command -v docker-compose > /dev/null 2>&1; then
    COMPOSE="docker-compose"
else
    echo "[!] No Docker Compose found — install Docker Desktop or the compose plugin." >&2
    exit 1
fi

echo "[+] Starting Docker containers..."
$COMPOSE up -d

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
        echo "[!] Model not found. Run: ollama pull qwen2.5-coder:7b"
    fi
else
    echo "[!] Ollama is not running. Start it with: OLLAMA_NUM_GPU=99 ollama serve"
fi

echo "[+] Setup complete!"
echo
echo "    Tests:           pip install -r requirements-dev.txt && pytest"
echo "    Assessment lane: $COMPOSE -f docker-compose.integrations.yml \\"
echo "                       --profile integrations build   (see docs/integrations.md)"
echo "    Start:           ./run.sh"
