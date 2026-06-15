#!/usr/bin/env bash
# ============================================================
# MADRS — single-command bootstrap.
#
# Starts (or skips if already running):
#   1. ML service        (uvicorn, port 8001)
#   2. Backend           (Spring Boot, port 8080)
#   3. Frontend          (python -m http.server, port 5500)
#
# Uses /tmp/*.log for output and /tmp/*.pid for process tracking.
# Safe to re-run — uses port checks to skip what's already up.
# ============================================================
set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="/tmp"

# Colours
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; RESET='\033[0m'

info()    { echo -e "${BLUE}[INFO]${RESET} $1"; }
ok()      { echo -e "${GREEN}[ OK ]${RESET} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET} $1"; }
err()     { echo -e "${RED}[FAIL]${RESET} $1"; }

is_port_up() {
  ss -tlnp 2>/dev/null | grep -q ":$1 "
}

wait_for_port() {
  local port=$1 name=$2 max=${3:-30}
  for i in $(seq 1 "$max"); do
    if is_port_up "$port"; then
      ok "$name is listening on :$port"
      return 0
    fi
    sleep 1
  done
  err "$name did NOT come up on :$port after ${max}s — check $LOG_DIR/${name}.log"
  return 1
}

# -------------------------------------------------------------
# 1.  ML service  (port 8001)
# -------------------------------------------------------------
start_ml() {
  if is_port_up 8001; then
    ok "ML service already running on :8001"; return 0
  fi

  local ml_dir="$PROJECT_ROOT/ml-service"
  local venv_dir="$PROJECT_ROOT/AI/.venv"

  if [ ! -d "$venv_dir" ]; then
    err "Python venv not found at $venv_dir — create it first"
    return 1
  fi
  if [ ! -d "$ml_dir" ]; then
    err "ML service directory not found at $ml_dir"
    return 1
  fi

  info "Starting ML service…"
  ( cd "$ml_dir" && \
      nohup "$venv_dir/bin/uvicorn" app.main:app \
        --host 127.0.0.1 --port 8001 \
        > "$LOG_DIR/ml-service.log" 2>&1 & \
      echo $! > "$LOG_DIR/ml-service.pid" )
  wait_for_port 8001 "ml-service" 30
}

# -------------------------------------------------------------
# 2.  Backend  (port 8080)
# -------------------------------------------------------------
start_backend() {
  if is_port_up 8080; then
    ok "Backend already running on :8080"; return 0
  fi

  local jar="$PROJECT_ROOT/backend/target/backend-1.0.0.jar"
  if [ ! -f "$jar" ]; then
    info "Backend JAR not found, building…"
    ( cd "$PROJECT_ROOT/backend" && mvn -q -DskipTests package )
  fi

  info "Starting backend…"
  nohup java -jar "$jar" > "$LOG_DIR/backend.log" 2>&1 &
  echo $! > "$LOG_DIR/backend.pid"
  wait_for_port 8080 "backend" 45
}

# -------------------------------------------------------------
# 3.  Frontend  (port 5500)
# -------------------------------------------------------------
start_frontend() {
  if is_port_up 5500; then
    ok "Frontend already running on :5500"; return 0
  fi
  info "Starting frontend (python http.server)…"
  ( cd "$PROJECT_ROOT" && \
      nohup python3 -m http.server 5500 > "$LOG_DIR/frontend.log" 2>&1 & \
      echo $! > "$LOG_DIR/frontend.pid" )
  wait_for_port 5500 "frontend" 5
}

# -------------------------------------------------------------
# main
# -------------------------------------------------------------
echo "============================================================"
echo " MADRS — bootstrap"
echo " Project: $PROJECT_ROOT"
echo "============================================================"

start_ml       || warn "ML service did not start — backend will run in degraded mode"
start_backend
start_frontend

echo
ok "All services up."
echo "  - ML service :  http://127.0.0.1:8001"
echo "  - Backend    :  http://127.0.0.1:8080/api/health"
echo "  - Frontend   :  http://127.0.0.1:5500/login.html"
echo
echo "Logs: $LOG_DIR/{ml-service,backend,frontend}.log"
echo "Stop: scripts/stop-all.sh"
