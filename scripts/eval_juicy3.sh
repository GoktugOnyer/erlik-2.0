#!/bin/bash
# Stage 5: Evaluate juicy3 vs baseline across 3 targets.
# Run from erlik-2.0 repo root.
set -u
cd "$(dirname "$0")/.."

MODEL="qwen2.5-coder:14b-juicy3"
RUN_DIR="runs/juicy3_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RUN_DIR"

log() { echo "[$(date '+%H:%M:%S')] $1" | tee -a "$RUN_DIR/pipeline.log"; }

# Tunnel must be up on :11434 → cloud Ollama where juicy3 lives
if ! curl -s --max-time 3 http://localhost:11434/api/tags > /dev/null 2>&1; then
    log "Tunnel down — restarting"
    pkill -f "ssh.*11434:localhost:11434" 2>/dev/null || true
    nohup ssh -N -L 11434:localhost:11434 -p "${CLOUD_SSH_PORT:?Set CLOUD_SSH_PORT}" root@"${CLOUD_SSH_HOST:?Set CLOUD_SSH_HOST}" > /tmp/tunnel_juicy3.log 2>&1 &
    sleep 5
fi

log "═══ Stage 5: Evaluating ${MODEL} ═══"

# 5.1 MediTrack (training target; sanity check)
log "── [1/3] MediTrack (A) sanity ──"
python3 thesis_benchmark/run_eval.py \
    --app A --model "${MODEL}" --turns 45 --toolset full_30 --out "${RUN_DIR}" 2>&1 | tail -30

# 5.2 EduPortal (held-out; generalization)
log "── [2/3] EduPortal (B) generalization ──"
python3 thesis_benchmark/run_eval.py \
    --app B --model "${MODEL}" --turns 45 --toolset full_30 --out "${RUN_DIR}" 2>&1 | tail -30

# 5.3 Juice Shop sprint matrix (27 sessions)
log "── [3/3] Juice Shop 27-session matrix ──"
ERLIK_MATRIX_MODEL="${MODEL}" \
    python3 scripts/sprint_matrix.py 2>&1 | tail -40 > "${RUN_DIR}/juice_shop_stdout.log"

log "═══ All evals complete ═══"
log "Results in ${RUN_DIR}/"
ls -la "${RUN_DIR}/"
