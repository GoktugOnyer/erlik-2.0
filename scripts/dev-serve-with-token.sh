#!/usr/bin/env bash
# Local verification helper: run the orchestrator with an API token and a
# throwaway database, so the access boundary can be exercised without touching
# data/pentest.db. Not used by run.sh or by CI.
set -euo pipefail
export ERLIK_API_TOKEN="${ERLIK_API_TOKEN:-dev-verification-token}"
export ERLIK_DB_PATH="${ERLIK_DB_PATH:-/tmp/erlik-dev-verify/pentest.db}"
export ERLIK_INTEGRATION_DATA="${ERLIK_INTEGRATION_DATA:-/tmp/erlik-dev-verify/integrations}"
mkdir -p "$(dirname "$ERLIK_DB_PATH")"
exec .venv/bin/uvicorn orchestrator.main:app --host 127.0.0.1 --port "${1:-8010}"
