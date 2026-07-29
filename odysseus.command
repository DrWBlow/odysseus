#!/bin/bash
# Double-click this in Finder, or run: ./odysseus.command

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
START_SCRIPT="$REPO_DIR/start-macos.sh"
RUNTIME_DIR="$REPO_DIR/logs"
PID_FILE="$RUNTIME_DIR/odysseus.pid"
LOCK_DIR="$RUNTIME_DIR/odysseus.lock"
LOG_FILE="$RUNTIME_DIR/odysseus.log"

umask 077

trim() {
    printf '%s' "$1" | sed 's/^ *//; s/ *$//'
}

is_launcher() {
    pid="$1"
    command="$(LC_ALL=C /bin/ps -ww -p "$pid" -o command= 2>/dev/null)" || return 1
    command="$(trim "$command")"
    [ "$command" = "$START_SCRIPT" ] || [ "$command" = "/bin/bash $START_SCRIPT" ]
}

cleanup() {
    rmdir "$LOCK_DIR" 2>/dev/null || true
}

[ -x "$START_SCRIPT" ] || {
    echo "Missing executable start script: $START_SCRIPT" >&2
    exit 1
}
mkdir -p "$RUNTIME_DIR" || exit 1
chmod 700 "$RUNTIME_DIR" || exit 1
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    echo "Another Odysseus start/stop operation may be running." >&2
    exit 1
fi
trap cleanup EXIT

if [ -f "$PID_FILE" ]; then
    pid="$(cat "$PID_FILE")"
    case "$pid" in ''|*[!0-9]*) echo "Invalid PID file: $PID_FILE" >&2; exit 1 ;; esac
    if is_launcher "$pid"; then
        echo "Odysseus is already starting or running (PID $pid)."
        echo "Logs: $LOG_FILE"
        exit 0
    fi
    if kill -0 "$pid" 2>/dev/null; then
        echo "Refusing to replace an unverified live PID ($pid)." >&2
        exit 1
    fi
    rm -f "$PID_FILE"
fi

echo "Launching Odysseus setup in the background…"
nohup "$START_SCRIPT" >> "$LOG_FILE" 2>&1 &
pid=$!
printf '%s\n' "$pid" > "$PID_FILE"
sleep 1
if ! is_launcher "$pid"; then
    rm -f "$PID_FILE"
    echo "Odysseus exited during startup. Review the log: $LOG_FILE" >&2
    exit 1
fi

echo "Odysseus startup is running (PID $pid)."
echo "Your browser will open when the app is ready."
echo "Logs: $LOG_FILE"
