#!/bin/bash
# Overnight pipeline: 3 sprint matrices + comparison report.
# Robust against: SSH tunnel drops, orchestrator hangs, container issues.

set -u
cd "$(dirname "$0")/.."

SSH_PORT="${CLOUD_SSH_PORT:?Set CLOUD_SSH_PORT to your GPU pod SSH port}"
SSH_HOST="${CLOUD_SSH_HOST:?Set CLOUD_SSH_HOST to your GPU pod IP/host}"
OLLAMA_REMOTE_PORT=11434
OLLAMA_LOCAL_PORT=11434
LOG_DIR="/tmp/overnight_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOG_DIR"

log() { echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOG_DIR/pipeline.log"; }

# ─── Health checks ────────────────────────────────────────────────────────
ensure_tunnel() {
  if ! curl -s --max-time 5 "http://localhost:${OLLAMA_LOCAL_PORT}/api/version" > /dev/null 2>&1; then
    log "Tunnel down, restarting..."
    pkill -f "ssh.*-L.*${OLLAMA_LOCAL_PORT}:localhost:${OLLAMA_REMOTE_PORT}" 2>/dev/null
    sleep 2
    nohup ssh -o StrictHostKeyChecking=no -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
      -N -L ${OLLAMA_LOCAL_PORT}:localhost:${OLLAMA_REMOTE_PORT} \
      -p ${SSH_PORT} root@${SSH_HOST} > "$LOG_DIR/tunnel.log" 2>&1 &
    sleep 5
  fi
}

ensure_orchestrator() {
  if ! curl -s --max-time 5 "http://localhost:8002/api/toolset-presets" > /dev/null 2>&1; then
    log "Orchestrator down, restarting..."
    pkill -f "uvicorn.*orchestrator" 2>/dev/null
    sleep 2
    nohup python3 -m uvicorn orchestrator.main:app --host 0.0.0.0 --port 8002 > "$LOG_DIR/orch.log" 2>&1 &
    sleep 8
  fi
}

ensure_containers() {
  for c in juice-shop kali-tools zap; do
    if ! docker ps --format '{{.Names}}' | grep -q "^${c}$"; then
      log "Container $c down, restarting stack..."
      docker-compose up -d 2>&1 | tail -3 >> "$LOG_DIR/docker.log"
      sleep 10
      return
    fi
  done
}

health_check() {
  ensure_tunnel
  ensure_orchestrator
  ensure_containers
}

# ─── Run one sprint matrix ────────────────────────────────────────────────
run_matrix() {
  local MODEL=$1
  local RUN_LABEL=$2

  log "════════════════════════════════════════════════════"
  log "MATRIX: ${RUN_LABEL}  model=${MODEL}"
  log "════════════════════════════════════════════════════"

  # Pre-warm the model (load into GPU memory on cloud)
  log "  Pre-warming model..."
  curl -s --max-time 180 "http://localhost:11434/api/generate" \
    -d "{\"model\":\"${MODEL}\",\"prompt\":\"hi\",\"stream\":false,\"options\":{\"num_predict\":5}}" \
    > /dev/null 2>&1

  health_check

  # Record timestamp before run to find the runs/<ts>/ dir afterwards
  local BEFORE=$(date +%s)

  ERLIK_MATRIX_MODEL=${MODEL} \
  python3 scripts/sprint_matrix.py > "$LOG_DIR/${RUN_LABEL}_stdout.log" 2>&1 &
  local MATRIX_PID=$!

  # Watchdog: restart tunnel + check health every 2 minutes while matrix runs
  while kill -0 $MATRIX_PID 2>/dev/null; do
    sleep 120
    health_check
  done

  # Find the directory sprint_matrix created (newest runs/<ts>/ after BEFORE)
  local RUN_DIR=$(find runs -maxdepth 1 -type d -newer <(date -r $BEFORE) 2>/dev/null | head -1)
  if [ -z "$RUN_DIR" ]; then
    RUN_DIR=$(ls -1dt runs/2026-* 2>/dev/null | head -1)
  fi
  log "  Matrix complete. Results in ${RUN_DIR}/"

  if [ -f "${RUN_DIR}/summary.csv" ]; then
    python3 -c "
import csv
rows=list(csv.DictReader(open('${RUN_DIR}/summary.csv')))
if not rows: exit()
sessions=len(rows)
findings=sum(int(r.get('total_findings',0) or 0) for r in rows)
tp=sum(int(r.get('true_positives',0) or 0) for r in rows)
fp=sum(int(r.get('false_positives',0) or 0) for r in rows)
print(f'  Sessions: {sessions}/27  |  Findings: {findings}  |  TP: {tp}  |  FP: {fp}  |  Prec: {tp/max(tp+fp,1)*100:.1f}%')
" | tee -a "$LOG_DIR/pipeline.log"
  fi

  echo "$RUN_DIR" > "$LOG_DIR/${RUN_LABEL}_dir.txt"
}

# ─── Main pipeline ────────────────────────────────────────────────────────
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "OVERNIGHT PIPELINE START"
log "  Log dir: $LOG_DIR"
log "  Target: juice-shop (Juice Shop v17.1.1)"
log "  Matrix: 27 sessions/model = 81 total"
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

health_check

# Matrix 1: 7B juicy
run_matrix "qwen2.5-coder:7b-juicy" "7b_juicy"

# Matrix 2: Baseline 7B
run_matrix "qwen2.5-coder:7b" "7b_baseline"

# Matrix 3: 14B juicy
run_matrix "qwen2.5-coder:14b-juicy" "14b_juicy"

# ─── Generate comparison report ────────────────────────────────────────────
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "GENERATING COMPARISON REPORT"

DIR_7BJ=$(cat "$LOG_DIR/7b_juicy_dir.txt" 2>/dev/null)
DIR_7BB=$(cat "$LOG_DIR/7b_baseline_dir.txt" 2>/dev/null)
DIR_14B=$(cat "$LOG_DIR/14b_juicy_dir.txt" 2>/dev/null)

REPORT="docs/OVERNIGHT_RESULTS_$(date +%Y%m%d).md"

python3 scripts/compare_matrices.py \
  --label "7B baseline=${DIR_7BB}" \
  --label "7B juicy=${DIR_7BJ}" \
  --label "14B juicy=${DIR_14B}" \
  --output "${REPORT}" 2>&1 | tee -a "$LOG_DIR/pipeline.log" || true

log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "PIPELINE COMPLETE"
log "  Report: ${REPORT}"
log "  Logs:   ${LOG_DIR}/pipeline.log"
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
