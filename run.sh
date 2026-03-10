#!/bin/bash
set -e

source .venv/Scripts/activate 2>/dev/null || source .venv/bin/activate
find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
echo "[+] Starting Erlik Pentest Agent on http://localhost:8000"
uvicorn orchestrator.main:app --host 0.0.0.0 --port 8000 --reload
