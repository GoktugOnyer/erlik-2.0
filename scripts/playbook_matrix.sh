#!/bin/bash
# playbook_matrix.sh — 9-session ablation to measure the effect of ERLIK_PLAYBOOKS.
#
# Matrix: 3 session kinds (cold, warm, chain) × 3 toolsets (core_10, standard_20,
# full_30), all at 30 turns on Juice Shop. Apples-to-apples with the 30-turn
# slice of docs/OVERNIGHT_RESULTS_20260417.md (baseline 7B, no playbooks).
#
# Orchestrator must be launched with ERLIK_PLAYBOOKS=1 in its environment.
# Verify by grepping its stdout for "[playbooks <sid>] injected ..." lines.
#
# Usage: ./scripts/playbook_matrix.sh

set -u
BASE="http://localhost:8002"
TARGET="http://localhost:3000"
MODEL="qwen2.5-coder:7b"
TURNS=30
POLL_INTERVAL=5
MAX_WAIT_MIN=15
PLAYBOOK_PRESET="owasp_methodology"  # match overnight baseline's system_prompt

# Fetch OWASP methodology system prompt so this matches the overnight baseline;
# the ONLY variable we want to change is ERLIK_PLAYBOOKS.
PROMPT=$(curl -sf "$BASE/api/presets" 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d['$PLAYBOOK_PRESET']['prompt'], end='')
" 2>/dev/null)
if [ -z "$PROMPT" ]; then
    echo "ERROR: could not fetch preset '$PLAYBOOK_PRESET' — aborting" >&2
    exit 1
fi
echo "Using preset '$PLAYBOOK_PRESET' (${#PROMPT} chars)"

TS=$(date +%Y-%m-%d_%H-%M-%S)
OUT_DIR="runs/playbooks_${TS}"
mkdir -p "$OUT_DIR"
CSV="$OUT_DIR/summary.csv"
LOG="$OUT_DIR/run.log"
DETAIL="$OUT_DIR/sessions.jsonl"

echo "session_id,session_kind,toolset,max_turns,status,total_steps,total_findings,duration_s,label" > "$CSV"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }

log "=========================================="
log "PLAYBOOK MATRIX — 9 sessions, 30 turns, 7B"
log "target: $TARGET    out: $OUT_DIR"
log "=========================================="

create_session() {
    local toolset="$1"; local kind="$2"; local parent="$3"; local label="$4"
    # Build the JSON body in Python (handles None/null cleanly)
    local body
    body=$(TARGET="$TARGET" MODEL="$MODEL" TURNS="$TURNS" \
           TS="$toolset" KIND="$kind" PARENT="$parent" PROMPT="$PROMPT" python3 -c '
import json, os
parent = os.environ["PARENT"] or None
print(json.dumps({
    "target_url": os.environ["TARGET"],
    "scope_mode": "full",
    "model": os.environ["MODEL"],
    "system_prompt": os.environ["PROMPT"],
    "toolset_preset": os.environ["TS"],
    "session_type": os.environ["KIND"],
    "parent_session_id": parent,
    "no_timeout": False,
    "max_turns": int(os.environ["TURNS"]),
}))')
    local resp
    resp=$(curl -sf -X POST -H 'Content-Type: application/json' -d "$body" "$BASE/api/sessions" 2>/dev/null) \
        || { log "  create FAIL: $label"; echo ""; return; }
    echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null
}

run_session() {
    local sid="$1"; local kind="$2"; local toolset="$3"; local label="$4"
    if [ -z "$sid" ]; then log "  SKIP (no sid): $label"; return; fi
    log "  started $sid  [$label]"
    curl -sf -X POST "$BASE/api/sessions/$sid/start" -o /dev/null 2>/dev/null \
        || { log "  start FAILED: $sid"; return; }
    local t0
    t0=$(date +%s)
    local deadline=$((t0 + MAX_WAIT_MIN*60))
    local status="running"
    local steps=0; local findings=0
    while : ; do
        local now
        now=$(date +%s)
        if [ $now -gt $deadline ]; then
            log "  TIMEOUT $sid after ${MAX_WAIT_MIN}min"
            curl -sf -X POST "$BASE/api/sessions/$sid/stop" -o /dev/null 2>/dev/null || true
            status="timeout"; break
        fi
        sleep $POLL_INTERVAL
        local row
        row=$(curl -sf "$BASE/api/sessions/$sid" 2>/dev/null) || continue
        status=$(echo "$row" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null)
        steps=$(echo "$row" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total_steps',0))" 2>/dev/null)
        findings=$(echo "$row" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total_findings',0))" 2>/dev/null)
        case "$status" in completed|failed|error|stopped) break ;; esac
    done
    local t1
    t1=$(date +%s)
    local dur=$((t1 - t0))
    echo "$sid,$kind,$toolset,$TURNS,$status,$steps,$findings,$dur,$label" >> "$CSV"
    curl -sf "$BASE/api/sessions/$sid" 2>/dev/null >> "$DETAIL" && echo "" >> "$DETAIL" || true
    log "  done    $sid  status=$status steps=$steps findings=$findings dur=${dur}s"
}

# Parallel-array approach (bash 3.2 compatible — macOS ships bash 3.2)
COLD_SID_core_10=""
COLD_SID_standard_20=""
COLD_SID_full_30=""

# COLD ROUND
log "=== COLD ROUND ==="
for toolset in core_10 standard_20 full_30; do
    sid=$(create_session "$toolset" "cold" "" "cold-$toolset")
    run_session "$sid" "cold" "$toolset" "cold-$toolset"
    if [ -n "$sid" ]; then
        var_name="COLD_SID_${toolset}"
        eval "$var_name=\"$sid\""
    fi
done

# WARM ROUND
log "=== WARM ROUND ==="
for toolset in core_10 standard_20 full_30; do
    var_name="COLD_SID_${toolset}"
    parent=$(eval echo "\$$var_name")
    if [ -z "$parent" ]; then
        log "  SKIP warm-$toolset: no cold parent"; continue
    fi
    sid=$(create_session "$toolset" "warm" "$parent" "warm-$toolset")
    run_session "$sid" "warm" "$toolset" "warm-$toolset"
done

# CHAIN ROUND
log "=== CHAIN ROUND ==="
for toolset in core_10 standard_20 full_30; do
    sid=$(create_session "$toolset" "chain" "" "chain-$toolset")
    run_session "$sid" "chain" "$toolset" "chain-$toolset"
done

log "=========================================="
log "MATRIX COMPLETE  |  CSV=$CSV  |  LOG=$LOG"
log "=========================================="
