#!/usr/bin/env bash
# Overnight seed-variance pipeline (2026-04-21 → 2026-04-22).
# - Waits for the currently-running seed=200 matrix to finish
# - Computes seed=100 ∪ seed=200 canonical ensemble
# - Launches seed=300 baseline matrix (triple-baseline robustness)
# - Computes full 3-seed ensemble
# - Launches FT-v3 seed-varied run (seed=400 on juicy3 7B) if time
# - Produces the thesis-integration paragraph automatically
#
# Watchdog: restarts tunnel/orchestrator/docker if they die.
# All output logged to /tmp/overnight_seed_variance.log

set -u
cd "$(dirname "$0")/.."
LOG=/tmp/overnight_seed_variance.log
: > "$LOG"

CLOUD_IP="${CLOUD_SSH_HOST:?Set CLOUD_SSH_HOST to your GPU pod IP/host}"
CLOUD_PORT="${CLOUD_SSH_PORT:?Set CLOUD_SSH_PORT to your GPU pod SSH port}"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

health_tunnel() {
  if ! curl -s --max-time 5 http://localhost:11434/api/version > /dev/null 2>&1; then
    log "TUNNEL DOWN — reconnecting"
    pkill -f "ssh.*11434:localhost:11434" 2>/dev/null
    sleep 2
    nohup ssh -o StrictHostKeyChecking=no -o ServerAliveInterval=30 \
      -N -L 11434:localhost:11434 -p $CLOUD_PORT root@$CLOUD_IP \
      > /tmp/tunnel_overnight.log 2>&1 &
    sleep 5
  fi
}

health_orch() {
  if ! curl -s --max-time 3 http://localhost:8002/api/tools/test > /dev/null 2>&1; then
    log "ORCH DOWN — need manual restart or env var (seed) may be wrong"
  fi
}

health_docker() {
  if ! docker ps --format '{{.Names}}' | grep -q '^juice-shop$'; then
    log "juice-shop container DOWN — restarting"
    docker-compose up -d juice-shop kali-tools zap 2>&1 | tail -3 >> "$LOG"
    sleep 8
  fi
}

run_matrix() {
  local seed=$1 run_label=$2 model=$3
  log "Starting matrix run_label=$run_label seed=$seed model=$model"

  # Kill orchestrator, restart with seed env
  pkill -f "uvicorn.*orchestrator" 2>/dev/null
  sleep 3
  ERLIK_OLLAMA_SEED=$seed nohup python3 -m uvicorn orchestrator.main:app \
    --host 0.0.0.0 --port 8002 > /tmp/orch_${run_label}.log 2>&1 &
  sleep 8

  # Verify seed env captured
  local orch_pid=$(pgrep -f "uvicorn.*orchestrator" | head -1)
  if [ -n "$orch_pid" ]; then
    ps eww $orch_pid 2>&1 | grep -q "ERLIK_OLLAMA_SEED=${seed}" && \
      log "  orch seed=${seed} confirmed" || log "  !! seed NOT captured in orch env"
  fi

  # Clean stale running sessions
  sqlite3 data/pentest.db "UPDATE sessions SET status='stopped' WHERE status='running'; UPDATE chains SET status='stopped' WHERE status='running';"

  # Launch matrix
  ERLIK_OLLAMA_SEED=$seed ERLIK_MATRIX_MODEL=$model \
    nohup python3 scripts/sprint_matrix.py > /tmp/sprint_${run_label}.log 2>&1 &
  local matrix_pid=$!
  log "  matrix PID=$matrix_pid"

  # Watchdog during matrix run
  while kill -0 $matrix_pid 2>/dev/null; do
    sleep 180  # 3 min
    health_tunnel
    health_orch
    health_docker
  done

  log "Matrix $run_label complete"

  # Discover the output dir
  local latest_dir=$(ls -1dt runs/2026-* 2>/dev/null | head -1)
  log "  output dir: $latest_dir"
  echo "$latest_dir" > /tmp/run_${run_label}_dir.txt
}

compute_canonical() {
  local run_dir=$1 model=$2 label=$3
  python3 - <<PYEOF
import csv, json, sqlite3, sys
from pathlib import Path
sys.path.insert(0, "scripts")
from recompute_gt_coverage import match_finding, compute_gt_coverage

run_dir = Path("$run_dir")
gt = json.load(open("runs/2026-04-17_19-24-01/ground_truth.json"))
db = sqlite3.connect("data/pentest.db"); db.row_factory = sqlite3.Row

sids = set()
for r in csv.DictReader(open(run_dir/"summary.csv")):
    sids.add(r["id"])
    if r["kind"] == "chain":
        c = db.execute("SELECT created_at,updated_at FROM chains WHERE id=?",(r["id"],)).fetchone()
        if c:
            for ch in db.execute("SELECT id FROM sessions WHERE session_type='chain' AND model=? AND created_at>=? AND created_at<=?",("$model",c["created_at"],c["updated_at"])):
                sids.add(ch["id"])

ph = ",".join("?"*len(sids))
findings = [dict(f) for f in db.execute(f"SELECT session_id,vuln_type,url,parameter,evidence FROM findings WHERE session_id IN ({ph})", list(sids))]
cov = compute_gt_coverage(findings, gt)
print(f"$label: {len(sids)} sessions, {cov['findings']} findings, TP={cov['tp_findings']}")
print(f"  Unique GT hit: {cov['unique_gt_hit']}/35 = {cov['unique_gt_hit']/35*100:.1f}%")
print(f"  Hit IDs: {cov['gt_hit_ids']}")

# Save GT hits for ensemble analysis
Path(f"/tmp/gt_hits_$label.json").write_text(json.dumps(cov["gt_hit_ids"], default=str))
PYEOF
}

################################################################################
log "=== OVERNIGHT SEED-VARIANCE PIPELINE START ==="
log "Current time. Plan:"
log "  1. Wait for matrix #2 (seed=200) — already running"
log "  2. Compute canonical GT for seed=200"
log "  3. Launch matrix #3 (seed=300) — ~3 hrs"
log "  4. Compute canonical GT for seed=300"
log "  5. Compute all seed ensembles"
log "  6. Launch FT-v3 seed-varied matrix (seed=400) if time"
log "  7. Write final analysis document"

################################################################################
# STEP 1-2: Wait for matrix #2 then compute canonical
log "--- STEP 1: Wait for seed=200 matrix ---"
while pgrep -f "sprint_matrix" > /dev/null; do
  sleep 120
  health_tunnel
  health_docker
done
log "seed=200 matrix complete"

# Find the seed=200 dir (starts with 2026-04-21_20)
SEED200_DIR=$(ls -1dt runs/2026-04-21_20-* 2>/dev/null | head -1)
log "seed=200 dir: $SEED200_DIR"
echo "$SEED200_DIR" > /tmp/run_seed200_dir.txt

log "--- STEP 2: Canonical GT for seed=200 ---"
compute_canonical "$SEED200_DIR" "qwen2.5-coder:7b" "seed200" 2>&1 | tee -a "$LOG"

################################################################################
# STEP 3-4: Matrix #3 seed=300
log "--- STEP 3: Launch matrix seed=300 ---"
run_matrix 300 seed300 qwen2.5-coder:7b

log "--- STEP 4: Canonical GT for seed=300 ---"
SEED300_DIR=$(cat /tmp/run_seed300_dir.txt 2>/dev/null)
if [ -n "$SEED300_DIR" ]; then
  compute_canonical "$SEED300_DIR" "qwen2.5-coder:7b" "seed300" 2>&1 | tee -a "$LOG"
fi

################################################################################
# STEP 5: Comprehensive ensemble analysis
log "--- STEP 5: Full seed-ensemble analysis ---"
python3 - <<'PYEOF' 2>&1 | tee -a "$LOG"
import json, sys, sqlite3, csv
from pathlib import Path
sys.path.insert(0, "scripts")
from recompute_gt_coverage import match_finding, compute_gt_coverage

gt = json.load(open("runs/2026-04-17_19-24-01/ground_truth.json"))

# Gather all baseline hit sets
runs = {
    "apr17 (default seed)": ("runs/2026-04-17_00-07-23", "qwen2.5-coder:7b"),
    "seed=100":             ("runs/2026-04-21_17-28-12", "qwen2.5-coder:7b"),
}
# seed=200 and seed=300 dirs
for label, path_file in [("seed=200", "/tmp/run_seed200_dir.txt"),
                         ("seed=300", "/tmp/run_seed300_dir.txt")]:
    try:
        p = Path(path_file).read_text().strip()
        if p and Path(p).exists():
            runs[label] = (p, "qwen2.5-coder:7b")
    except FileNotFoundError: pass

# FT-v3
runs["FT-v3 apr17"] = ("runs/2026-04-17_19-24-01", "qwen2.5-coder:7b-juicy3")

all_hits = {}
db = sqlite3.connect("data/pentest.db"); db.row_factory = sqlite3.Row
for label, (run_dir, model) in runs.items():
    rp = Path(run_dir)
    if not rp.exists() or not (rp/"summary.csv").exists():
        continue
    sids = set()
    for r in csv.DictReader(open(rp/"summary.csv")):
        sids.add(r["id"])
        if r["kind"] == "chain":
            c = db.execute("SELECT created_at,updated_at FROM chains WHERE id=?",(r["id"],)).fetchone()
            if c:
                for ch in db.execute("SELECT id FROM sessions WHERE session_type='chain' AND model=? AND created_at>=? AND created_at<=?",(model,c["created_at"],c["updated_at"])):
                    sids.add(ch["id"])
    ph = ",".join("?"*len(sids))
    findings = [dict(f) for f in db.execute(f"SELECT session_id,vuln_type,url,parameter,evidence FROM findings WHERE session_id IN ({ph})", list(sids))]
    cov = compute_gt_coverage(findings, gt)
    all_hits[label] = set(cov["gt_hit_ids"])
    print(f"{label:30} = {cov['unique_gt_hit']:2}/35 ({cov['unique_gt_hit']/35*100:.1f}%)  IDs: {sorted(cov['gt_hit_ids'], key=lambda x:(isinstance(x,str),x))}")

print()
# Pairwise seed unions
baselines = [l for l in all_hits if l != "FT-v3 apr17"]
import itertools
print("=== Pairwise baseline unions ===")
for a, b in itertools.combinations(baselines, 2):
    u = all_hits[a] | all_hits[b]
    print(f"  {a:30} ∪ {b:30} = {len(u):2}/35 ({len(u)/35*100:.1f}%)")

# Triple / all baseline union
if len(baselines) >= 3:
    all_base = set().union(*[all_hits[l] for l in baselines])
    print(f"  all baselines unioned        = {len(all_base):2}/35 ({len(all_base)/35*100:.1f}%)")

# FT ensembles
if "FT-v3 apr17" in all_hits:
    ft = all_hits["FT-v3 apr17"]
    print()
    print("=== FT ensembles ===")
    for l in baselines:
        u = all_hits[l] | ft
        print(f"  {l:30} ∪ FT-v3 = {len(u):2}/35 ({len(u)/35*100:.1f}%)")
    # FT-gain ≥ seed-variance test
    if len(baselines) >= 2:
        max_seed_union = max(len(all_hits[a] | all_hits[b]) for a, b in itertools.combinations(baselines, 2))
        apr17_ft = len(all_hits.get("apr17 (default seed)", set()) | ft)
        print()
        print(f"=== VERDICT ===")
        print(f"  Max seed-only ensemble:  {max_seed_union}/35")
        print(f"  Apr17 ∪ FT-v3 ensemble:  {apr17_ft}/35")
        gap = apr17_ft - max_seed_union
        if gap >= 2:
            print(f"  FT adds +{gap} GT beyond seed-variance → H3 SUPPORTED")
        elif gap == 1:
            print(f"  FT adds +1 GT beyond seed-variance → H3 weakly supported")
        else:
            print(f"  FT adds +{gap} GT (≤0) beyond seed-variance → H3 REJECTED")

Path("docs/seed_variance_results.json").write_text(json.dumps({
    "per_run_hits": {k: sorted(v, key=lambda x: (isinstance(x,str),x)) for k,v in all_hits.items()},
}, indent=2, default=str))
print("\nSaved → docs/seed_variance_results.json")
PYEOF

################################################################################
# STEP 6: FT-v3 seed-varied run (if time + model available)
log "--- STEP 6: FT-v3 seed-varied run ---"
# Check if juicy3 is available on cloud
if ssh -p $CLOUD_PORT -o BatchMode=yes -o ConnectTimeout=10 root@$CLOUD_IP "ollama list | grep -q '7b-juicy3'" 2>/dev/null; then
  log "juicy3 already on cloud"
else
  log "juicy3 NOT on cloud — uploading from local"
  # Try to upload from local if available
  if [ -f "merged_models/qwen2.5-coder-7b-juicy3-Q4_K_M.gguf" ]; then
    scp -P $CLOUD_PORT merged_models/qwen2.5-coder-7b-juicy3-Q4_K_M.gguf root@$CLOUD_IP:/root/ 2>&1 | tail -2 >> "$LOG"
    ssh -p $CLOUD_PORT root@$CLOUD_IP "cat > /root/Modelfile-juicy3 <<'MF'
FROM /root/qwen2.5-coder-7b-juicy3-Q4_K_M.gguf
PARAMETER temperature 0.3
PARAMETER num_ctx 8192
MF
ollama create qwen2.5-coder:7b-juicy3 -f /root/Modelfile-juicy3" 2>&1 | tail -3 >> "$LOG"
  else
    log "juicy3 GGUF not local — skipping FT-v3 seed-varied run"
  fi
fi

# Verify juicy3 available now
if ssh -p $CLOUD_PORT root@$CLOUD_IP "ollama list | grep -q '7b-juicy3'" 2>/dev/null; then
  run_matrix 400 ftv3_seed400 qwen2.5-coder:7b-juicy3
  FTV3_400_DIR=$(cat /tmp/run_ftv3_seed400_dir.txt 2>/dev/null)
  if [ -n "$FTV3_400_DIR" ]; then
    compute_canonical "$FTV3_400_DIR" "qwen2.5-coder:7b-juicy3" "ftv3_seed400" 2>&1 | tee -a "$LOG"
  fi
else
  log "juicy3 not available — skipping step 6"
fi

################################################################################
log "=== PIPELINE COMPLETE ==="
log "Outputs:"
log "  - docs/seed_variance_results.json   (all hit sets)"
log "  - docs/seed_variance_report.md      (see step 7 when written)"
log "  - /tmp/overnight_seed_variance.log  (this log)"
log ""
log "Review docs/seed_variance_results.json in the morning."
