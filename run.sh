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
ERLIK_PORT="${ERLIK_PORT:-8002}"

# Stop any previous erlik server still holding the port. A leftover instance
# (common after repeated restarts, and worsened by --reload's parent/child
# processes) keeps serving stale code and breaks the WebSocket live view — the
# browser connects to a dead/old server and logs "WebSocket error".
STALE=$(lsof -ti:"${ERLIK_PORT}" 2>/dev/null || true)
if [ -n "$STALE" ]; then
    echo "[!] Port ${ERLIK_PORT} already in use — stopping the old server (pids: $(echo $STALE))..."
    echo "$STALE" | xargs kill -9 2>/dev/null || true
    sleep 1
fi

echo "[+] Starting Erlik Pentest Agent on http://${ERLIK_HOST}:${ERLIK_PORT}"
# Single clean process by default (reliable Ctrl+C, no zombie children). Set
# ERLIK_RELOAD=1 for dev auto-reload on code changes.
if [ -n "${ERLIK_RELOAD}" ]; then
    exec uvicorn orchestrator.main:app --host "${ERLIK_HOST}" --port "${ERLIK_PORT}" --reload
else
    exec uvicorn orchestrator.main:app --host "${ERLIK_HOST}" --port "${ERLIK_PORT}"
fi
