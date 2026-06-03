#!/bin/bash
# sprint_matrix.sh — runs a 13-session eval matrix against Juice Shop.
# Exits on no errors; each session is polled until complete. Partial results
# are written incrementally so the output is useful even if something dies.
#
# Matrix:
#   Phase 1: 9 cold sessions (3 toolsets × 3 turn counts)
#   Phase 2: 3 warm sessions (each using a Phase 1 cold as parent, 30 turns)
#   Phase 3: 1 chain session (auto-progress, standard_20)
#
# Usage: ./scripts/sprint_matrix.sh
set -u
BASE="http://localhost:8002"
TARGET="http://localhost:3000"
MODEL="qwen2.5-coder:7b"
PLAYBOOK="owasp_methodology"
POLL_INTERVAL=5
MAX_WAIT_MIN=20   # hard ceiling per session (minutes)

TS=$(date +%Y-%m-%d_%H-%M-%S)
OUT_DIR="runs/${TS}"
mkdir -p "$OUT_DIR"
CSV="$OUT_DIR/summary.csv"
LOG="$OUT_DIR/run.log"
DETAIL="$OUT_DIR/sessions.jsonl"

echo "session_id,phase,session_type,toolset_preset,max_turns,status,total_steps,total_findings,duration_s,parent_id,label" > "$CSV"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }

# Fetch the playbook prompt once
PROMPT=$(curl -sf "$BASE/api/presets" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['$PLAYBOOK']['prompt'])" 2>/dev/null || echo "")
if [ -z "$PROMPT" ]; then
    log "ERROR: could not fetch playbook '$PLAYBOOK' prompt — aborting"
    exit 1
fi
log "Using playbook '$PLAYBOOK' (${#PROMPT} chars)"

# Create a session via /api/sessions. Echoes the session id.
create_session() {
    local toolset="$1"; local turns="$2"; local stype="$3"; local parent="$4"; local label="$5"
    local parent_json="null"
    if [ -n "$parent" ] && [ "$parent" != "null" ]; then
        parent_json="\"$parent\""
    fi
    local body
    body=$(python3 -c "
import json
print(json.dumps({
    'target_url': '$TARGET',
    'scope_mode': 'full',
    'model': '$MODEL',
    'system_prompt': $(python3 -c "import json,sys; print(json.dumps(sys.argv[1]))" "$PROMPT"),
    'toolset_preset': '$toolset',
    'session_type': '$stype',
    'parent_session_id': $parent_json,
    'no_timeout': False,
    'max_turns': $turns
}))
")
    local resp
    resp=$(curl -sf -X POST -H 'Content-Type: application/json' -d "$body" "$BASE/api/sessions" 2>/dev/null) || { log "  create_session FAILED: $label"; echo ""; return; }
    local sid
    sid=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null)
    echo "$sid"
}

# Start + poll a session until terminal. Emits final row to CSV.
run_session() {
    local sid="$1"; local phase="$2"; local stype="$3"; local toolset="$4"; local turns="$5"; local parent="$6"; local label="$7"
    if [ -z "$sid" ]; then
        log "  SKIP (no sid): $label"
        return
    fi
    log "  started $sid  [$label]"
    curl -sf -X POST "$BASE/api/sessions/$sid/start" -o /dev/null 2>/dev/null || { log "  start FAILED: $sid"; return; }
    local t0=$(date +%s)
    local deadline=$((t0 + MAX_WAIT_MIN*60))
    local status="running"
    local steps=0; local findings=0
    while : ; do
        local now=$(date +%s)
        if [ $now -gt $deadline ]; then
            log "  TIMEOUT $sid after $MAX_WAIT_MIN min"
            curl -sf -X POST "$BASE/api/sessions/$sid/stop" -o /dev/null 2>/dev/null || true
            status="timeout"
            break
        fi
        sleep $POLL_INTERVAL
        local row
        row=$(curl -sf "$BASE/api/sessions/$sid" 2>/dev/null) || continue
        status=$(echo "$row" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null)
        steps=$(echo "$row" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total_steps',0))" 2>/dev/null)
        findings=$(echo "$row" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total_findings',0))" 2>/dev/null)
        if [ "$status" = "completed" ] || [ "$status" = "failed" ] || [ "$status" = "error" ] || [ "$status" = "stopped" ]; then
            break
        fi
    done
    local t1=$(date +%s)
    local dur=$((t1 - t0))
    echo "$sid,$phase,$stype,$toolset,$turns,$status,$steps,$findings,$dur,${parent:-},${label}" >> "$CSV"
    # Save the session row + findings to detail jsonl
    curl -sf "$BASE/api/sessions/$sid" 2>/dev/null >> "$DETAIL" && echo "" >> "$DETAIL" || true
    log "  finished $sid  status=$status  steps=$steps  findings=$findings  dur=${dur}s"
}

# ==========================================================================
# PHASE 1 — 9 cold sessions (3 toolsets × 3 turn counts)
# ==========================================================================
log "=========================================="
log "PHASE 1: 9 cold sessions (toolset × turns)"
log "=========================================="
declare -A COLD_REF  # toolset@turns -> sid (used as Phase 2 parents)

for toolset in core_10 standard_20 full_30; do
    for turns in 15 30 60; do
        label="cold-${toolset}-${turns}t"
        sid=$(create_session "$toolset" "$turns" "cold" "" "$label")
        run_session "$sid" 1 "cold" "$toolset" "$turns" "" "$label"
        if [ "$turns" = "30" ] && [ -n "$sid" ]; then
            COLD_REF[$toolset]="$sid"
        fi
    done
done

# ==========================================================================
# PHASE 2 — 3 warm sessions (30 turns, each parented to the Phase 1 cold 30t)
# ==========================================================================
log "=========================================="
log "PHASE 2: 3 warm sessions (30 turns each)"
log "=========================================="
for toolset in core_10 standard_20 full_30; do
    parent="${COLD_REF[$toolset]:-}"
    if [ -z "$parent" ]; then
        log "  SKIP warm-$toolset: no Phase 1 cold parent available"
        continue
    fi
    label="warm-${toolset}-30t"
    sid=$(create_session "$toolset" "30" "warm" "$parent" "$label")
    run_session "$sid" 2 "warm" "$toolset" "30" "$parent" "$label"
done

# ==========================================================================
# PHASE 3 — 1 chain session (standard_20, auto-progress 4 phases)
# ==========================================================================
log "=========================================="
log "PHASE 3: 1 chain session (standard_20)"
log "=========================================="

chain_body=$(python3 -c "
import json
print(json.dumps({
    'target_url': '$TARGET',
    'scope_mode': 'full',
    'model': '$MODEL',
    'system_prompt': $(python3 -c "import json,sys; print(json.dumps(sys.argv[1]))" "$PROMPT"),
    'toolset_preset': 'standard_20',
    'max_turns_per_session': 30,
    'no_timeout': False,
    'auto_progress': True
}))
")
chain_resp=$(curl -sf -X POST -H 'Content-Type: application/json' -d "$chain_body" "$BASE/api/chains" 2>/dev/null)
if [ -z "$chain_resp" ]; then
    log "  chain creation FAILED"
else
    chain_id=$(echo "$chain_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
    log "  chain created: $chain_id  (auto-progressing — not polled, see dashboard)"
    # Chain auto-starts its first session. We just record the chain id.
    echo "$chain_id,3,chain,standard_20,120,launched,-,-,-,-,chain-standard_20" >> "$CSV"
fi

log "=========================================="
log "MATRIX COMPLETE"
log "CSV:    $CSV"
log "Detail: $DETAIL"
log "Log:    $LOG"
log "=========================================="
