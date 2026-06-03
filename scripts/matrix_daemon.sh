#!/bin/bash
# matrix_daemon.sh — start the sprint matrix as a fully detached background process.
#
# Same trick as orch_daemon.sh: setsid + nohup so the process becomes its own
# session leader and survives termination of the parent shell / task runner.
#
# Usage:
#   ./scripts/matrix_daemon.sh start [--resume runs/<dir>]   # spawn matrix
#   ./scripts/matrix_daemon.sh stop                          # kill running matrix
#   ./scripts/matrix_daemon.sh status                        # show pid + tail log
#   ./scripts/matrix_daemon.sh log                           # follow the live run.log

set -u
cd "$(dirname "$0")/.."  # repo root

PIDFILE="/tmp/erlik-matrix.pid"
SPAWNLOG="/tmp/erlik-matrix-spawn.log"

start() {
    if [ -f "$PIDFILE" ] && kill -0 "$(cat $PIDFILE)" 2>/dev/null; then
        echo "[matrix] already running (pid $(cat $PIDFILE))"
        return 0
    fi

    if ! curl -sf http://localhost:8002/api/health -o /dev/null 2>&1; then
        echo "[matrix] orchestrator NOT running on 8002 — start it first"
        return 1
    fi

    export PATH="$HOME/.orbstack/bin:$PATH"
    source .venv/bin/activate

    shift  # consume "start"
    EXTRA_ARGS="$*"

    # Python double-fork daemonization (same trick as orch_daemon.sh)
    python3 - <<PYEOF >/dev/null 2>&1
import os, sys, shlex
extra = shlex.split("""$EXTRA_ARGS""")
if os.fork() > 0:
    sys.exit(0)
os.setsid()
if os.fork() > 0:
    sys.exit(0)
log_fd = os.open("$SPAWNLOG", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
null_fd = os.open(os.devnull, os.O_RDWR)
os.dup2(null_fd, 0)
os.dup2(log_fd, 1)
os.dup2(log_fd, 2)
os.close(null_fd); os.close(log_fd)
os.execvp("python3", ["python3", "scripts/sprint_matrix.py"] + extra)
PYEOF

    sleep 1
    PID=$(pgrep -f "scripts/sprint_matrix.py" | head -1)
    if [ -n "$PID" ]; then
        echo $PID > "$PIDFILE"
    fi
    echo "[matrix] started (pid ${PID:-unknown}, args: $EXTRA_ARGS)"
    sleep 3
    if [ -d runs ]; then
        LATEST=$(ls -td runs/2026-* 2>/dev/null | head -1)
        if [ -n "$LATEST" ] && [ -f "$LATEST/run.log" ]; then
            echo "[matrix] latest run dir: $LATEST"
            tail -5 "$LATEST/run.log"
        fi
    fi
}

stop() {
    if [ -f "$PIDFILE" ]; then
        PID=$(cat "$PIDFILE")
        if kill -0 "$PID" 2>/dev/null; then
            echo "[matrix] stopping pid $PID"
            kill "$PID"
            sleep 1
            kill -9 "$PID" 2>/dev/null || true
        fi
        rm -f "$PIDFILE"
    fi
    pkill -f "scripts/sprint_matrix.py" 2>/dev/null || true
    echo "[matrix] stopped"
}

status() {
    if [ -f "$PIDFILE" ] && kill -0 "$(cat $PIDFILE)" 2>/dev/null; then
        echo "[matrix] running, pid $(cat $PIDFILE)"
    else
        echo "[matrix] not running"
    fi
    LATEST=$(ls -td runs/2026-* 2>/dev/null | head -1)
    if [ -n "$LATEST" ] && [ -f "$LATEST/run.log" ]; then
        echo "[matrix] latest run dir: $LATEST"
        echo "--- last 8 log lines ---"
        tail -8 "$LATEST/run.log"
    fi
}

logs() {
    LATEST=$(ls -td runs/2026-* 2>/dev/null | head -1)
    [ -z "$LATEST" ] && { echo "[matrix] no runs/ dir found"; exit 1; }
    tail -f "$LATEST/run.log"
}

case "${1:-status}" in
    start)  start "$@" ;;
    stop)   stop ;;
    status) status ;;
    log|logs) logs ;;
    *) echo "usage: $0 {start [args] | stop | status | log}"; exit 1 ;;
esac
