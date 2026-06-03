#!/bin/bash
set -e

source .venv/Scripts/activate 2>/dev/null || source .venv/bin/activate
find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

# Ensure the docker binary is reachable so tool_executor can run `docker exec`
# against the kali-tools container. OrbStack on macOS installs its CLI here
# but does not always add it to login shell PATHs.
if [ -d "$HOME/.orbstack/bin" ]; then
    export PATH="$HOME/.orbstack/bin:$PATH"
fi

echo "[+] Starting Erlik Pentest Agent on http://localhost:8002"
uvicorn orchestrator.main:app --host 0.0.0.0 --port 8002 --reload
