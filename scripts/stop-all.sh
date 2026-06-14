#!/usr/bin/env bash
# Graceful shutdown for everything start-all.sh started.
set -e
LOG_DIR="/tmp"

stop_one() {
  local name=$1 pid_file="$LOG_DIR/$name.pid"
  if [ -f "$pid_file" ]; then
    local pid; pid=$(cat "$pid_file")
    if kill -0 "$pid" 2>/dev/null; then
      echo "Stopping $name (pid=$pid)…"
      kill "$pid" 2>/dev/null || true
      sleep 1
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$pid_file"
  fi
}

stop_one frontend
stop_one backend
stop_one ml-service

# Belt-and-braces fallback by port — handles processes started outside this script.
for port in 5500 8080 8001; do
  pid=$(ss -tlnp 2>/dev/null | awk -v p=":$port" '$4 ~ p {print}' | grep -oP 'pid=\K[0-9]+' | head -1)
  if [ -n "$pid" ]; then
    echo "Killing leftover :$port (pid=$pid)…"
    kill -9 "$pid" 2>/dev/null || true
  fi
done
echo "All services stopped."
