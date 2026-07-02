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

# Bind to loopback by default so the (attack-launching) API isn't exposed on the
# network. Override with ERLIK_HOST=0.0.0.0 only behind auth / on a trusted net.
# Set ERLIK_API_TOKEN to require a token on state-changing API calls.
ERLIK_HOST="${ERLIK_HOST:-127.0.0.1}"
echo "[+] Starting Erlik Pentest Agent on http://${ERLIK_HOST}:8002"
uvicorn orchestrator.main:app --host "${ERLIK_HOST}" --port 8002 --reload
