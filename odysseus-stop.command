#!/bin/bash
# Double-click this in Finder, or run: ./odysseus-stop.command

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
START_SCRIPT="$REPO_DIR/start-macos.sh"
RUNTIME_DIR="$REPO_DIR/logs"
PID_FILE="$RUNTIME_DIR/odysseus.pid"
LOCK_DIR="$RUNTIME_DIR/odysseus.lock"

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

mkdir -p "$RUNTIME_DIR" || exit 1
chmod 700 "$RUNTIME_DIR" || exit 1
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    echo "Another Odysseus start/stop operation may be running." >&2
    exit 1
fi
trap cleanup EXIT

if [ ! -f "$PID_FILE" ]; then
    echo "No verified Odysseus instance is running."
    exit 0
fi
pid="$(cat "$PID_FILE")"
case "$pid" in ''|*[!0-9]*) echo "Invalid PID file: $PID_FILE" >&2; exit 1 ;; esac
if ! is_launcher "$pid"; then
    if kill -0 "$pid" 2>/dev/null; then
        echo "Refusing to signal an unverified live PID ($pid)." >&2
        exit 1
    fi
    rm -f "$PID_FILE"
    echo "Odysseus is not running (stale PID $pid)."
    exit 0
fi

echo "Stopping Odysseus (PID $pid)…"
for child in $(/usr/bin/pgrep -P "$pid" 2>/dev/null); do
    kill -TERM "$child" 2>/dev/null || true
done
kill -TERM "$pid" 2>/dev/null || true

attempt=0
while kill -0 "$pid" 2>/dev/null; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 50 ]; then
        echo "Odysseus did not stop within five seconds; PID file was preserved." >&2
        exit 1
    fi
    sleep 0.1
done
rm -f "$PID_FILE"
echo "Stopped."
