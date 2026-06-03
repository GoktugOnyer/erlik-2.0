#!/bin/bash
# orch_daemon.sh — start/stop/status the orchestrator as a fully detached process.
#
# Why this exists:
# Long-running processes launched from an interactive shell or background-task
# runner can be terminated after a wall-clock limit, even though they aren't
# crashing. By spawning uvicorn through `setsid nohup`, the process becomes its
# own session leader and is reparented to init, fully detaching from the parent
# process tree so it survives the shell that launched it.
#
# Usage:
#   ./scripts/orch_daemon.sh start   # spawn orchestrator (returns instantly)
#   ./scripts/orch_daemon.sh stop    # kill any running orchestrator
#   ./scripts/orch_daemon.sh status  # show pid + health
#   ./scripts/orch_daemon.sh log     # tail the orch log

set -u
cd "$(dirname "$0")/.."  # repo root

PIDFILE="/tmp/erlik-orch.pid"
LOGFILE="/tmp/erlik-orch.log"
PORT=8002

start() {
    if [ -f "$PIDFILE" ] && kill -0 "$(cat $PIDFILE)" 2>/dev/null; then
        echo "[orch] already running (pid $(cat $PIDFILE))"
        return 0
    fi
    if curl -sf "http://localhost:$PORT/api/health" -o /dev/null 2>&1; then
        echo "[orch] something else is already serving on $PORT"
        return 1
    fi

    # Make sure docker (orbstack) is on PATH for tool_executor
    export PATH="$HOME/.orbstack/bin:$PATH"

    # Activate venv
    source .venv/bin/activate 2>/dev/null || {
        echo "[orch] no .venv found — run setup first"
        return 1
    }

    # macOS doesn't ship `setsid`, so we use Python to perform the
    # double-fork-and-setsid daemonization dance. This makes the resulting
    # uvicorn process its own session leader, reparented to launchd, and
    # fully detached from any shell or task tree above us.
    python3 - <<PYEOF >/dev/null 2>&1
import os, sys
# 1st fork
if os.fork() > 0:
    sys.exit(0)
os.setsid()
# 2nd fork
if os.fork() > 0:
    sys.exit(0)
# Redirect stdio to log file
os.chdir(os.getcwd())
sys.stdout.flush(); sys.stderr.flush()
log_fd = os.open("$LOGFILE", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
null_fd = os.open(os.devnull, os.O_RDWR)
os.dup2(null_fd, 0)
os.dup2(log_fd, 1)
os.dup2(log_fd, 2)
os.close(null_fd); os.close(log_fd)
# Exec uvicorn — replaces this Python process entirely
os.execvp("uvicorn", ["uvicorn", "orchestrator.main:app",
                      "--host", "0.0.0.0", "--port", "$PORT"])
PYEOF

    # The Python helper exits immediately after the first fork, so we have
    # to find the actual uvicorn pid by name (the daemon's parent is now 1).
    sleep 1
    PID=$(pgrep -f "uvicorn orchestrator.main:app" | head -1)
    if [ -n "$PID" ]; then
        echo $PID > "$PIDFILE"
    fi

    # Wait briefly for it to come up
    for i in 1 2 3 4 5 6 7 8 9 10; do
        sleep 1
        if curl -sf "http://localhost:$PORT/api/health" -o /dev/null 2>&1; then
            echo "[orch] started (pid $PID, log $LOGFILE) — ready after ${i}s"
            return 0
        fi
    done
    echo "[orch] FAILED to come up after 10s — check $LOGFILE"
    return 1
}

stop() {
    if [ -f "$PIDFILE" ]; then
        PID=$(cat "$PIDFILE")
        if kill -0 "$PID" 2>/dev/null; then
            echo "[orch] stopping pid $PID"
            kill "$PID"
            sleep 1
            kill -9 "$PID" 2>/dev/null || true
        fi
        rm -f "$PIDFILE"
    fi
    # Also catch any orphaned uvicorn processes serving the same port
    pkill -f "uvicorn orchestrator.main:app" 2>/dev/null || true
    echo "[orch] stopped"
}

status() {
    if [ -f "$PIDFILE" ] && kill -0 "$(cat $PIDFILE)" 2>/dev/null; then
        echo "[orch] running, pid $(cat $PIDFILE)"
    else
        echo "[orch] no recorded pid"
    fi
    if curl -sf "http://localhost:$PORT/api/health" 2>&1 | python3 -m json.tool 2>&1; then
        :
    else
        echo "[orch] HTTP not responding on $PORT"
    fi
}

logs() {
    tail -f "$LOGFILE"
}

case "${1:-status}" in
    start)  start ;;
    stop)   stop ;;
    status) status ;;
    log|logs) logs ;;
    restart) stop; sleep 1; start ;;
    *) echo "usage: $0 {start|stop|status|log|restart}"; exit 1 ;;
esac
