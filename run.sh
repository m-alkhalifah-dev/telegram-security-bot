#!/usr/bin/env bash
# ============================================================
# SecBot v2.0 — start/stop/status/restart script
# Usage: ./run.sh [start|stop|status|restart|dashboard]
# ============================================================

BOT_DIR="$(cd "$(dirname "$0")" && pwd)"
BOT_PID_FILE="$BOT_DIR/.bot.pid"
DASH_PID_FILE="$BOT_DIR/.dash.pid"
VENV="$BOT_DIR/venv"
PYTHON="$VENV/bin/python3"

# Fall back to system python if no venv
if [ ! -f "$PYTHON" ]; then
  PYTHON="$(which python3)"
fi

# ── Helpers ──────────────────────────────────────────────────────────────────

is_running() {
  local pid_file="$1"
  [ -f "$pid_file" ] && kill -0 "$(cat "$pid_file")" 2>/dev/null
}

stop_proc() {
  local pid_file="$1"
  local name="$2"
  if is_running "$pid_file"; then
    kill "$(cat "$pid_file")" 2>/dev/null
    rm -f "$pid_file"
    echo "  Stopped $name"
  else
    echo "  $name is not running"
  fi
}

start_bot() {
  if is_running "$BOT_PID_FILE"; then
    echo "  Bot is already running (PID $(cat "$BOT_PID_FILE"))"
    return
  fi
  cd "$BOT_DIR" || exit 1
  nohup "$PYTHON" bot.py >> "$BOT_DIR/logs/bot.log" 2>&1 &
  echo $! > "$BOT_PID_FILE"
  echo "  Bot started (PID $!)"
}

start_dashboard() {
  if is_running "$DASH_PID_FILE"; then
    echo "  Dashboard is already running (PID $(cat "$DASH_PID_FILE"))"
    return
  fi
  cd "$BOT_DIR" || exit 1
  nohup "$PYTHON" dashboard.py >> "$BOT_DIR/logs/dashboard.log" 2>&1 &
  echo $! > "$DASH_PID_FILE"
  echo "  Dashboard started (PID $!)"
}

# ── Commands ─────────────────────────────────────────────────────────────────

case "${1:-help}" in
  start)
    echo "==> Starting SecBot v2.0"
    mkdir -p "$BOT_DIR/logs"
    start_bot
    start_dashboard
    ;;
  stop)
    echo "==> Stopping SecBot"
    stop_proc "$BOT_PID_FILE" "Bot"
    stop_proc "$DASH_PID_FILE" "Dashboard"
    ;;
  restart)
    "$0" stop
    sleep 1
    "$0" start
    ;;
  status)
    echo "==> SecBot Status"
    if is_running "$BOT_PID_FILE"; then
      echo "  Bot:       RUNNING (PID $(cat "$BOT_PID_FILE"))"
    else
      echo "  Bot:       STOPPED"
    fi
    if is_running "$DASH_PID_FILE"; then
      echo "  Dashboard: RUNNING (PID $(cat "$DASH_PID_FILE"))"
    else
      echo "  Dashboard: STOPPED"
    fi
    ;;
  bot)
    echo "==> Starting Bot only"
    mkdir -p "$BOT_DIR/logs"
    start_bot
    ;;
  dashboard)
    echo "==> Starting Dashboard only"
    mkdir -p "$BOT_DIR/logs"
    start_dashboard
    ;;
  logs)
    echo "==> Tailing logs (Ctrl+C to stop)"
    tail -f "$BOT_DIR/logs/bot.log" "$BOT_DIR/logs/dashboard.log" 2>/dev/null
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|status|bot|dashboard|logs}"
    exit 1
    ;;
esac
