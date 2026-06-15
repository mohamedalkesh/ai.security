#!/usr/bin/env bash
# Starts the full MADRS stack (ML service + Spring backend + static frontend)
# in the background and tails their logs. Stop with Ctrl+C.

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
LOG_DIR="${LOG_DIR:-$ROOT_DIR/.logs}"
ML_PORT=${ML_PORT:-8001}
API_PORT=${API_PORT:-8080}
FRONTEND_PORT=${FRONTEND_PORT:-5500}

mkdir -p "$LOG_DIR"

ML_LOG="$LOG_DIR/ml-service.log"
API_LOG="$LOG_DIR/backend.log"
FE_LOG="$LOG_DIR/frontend.log"

ml_pid=""
api_pid=""
fe_pid=""

cleanup() {
  echo -e "\nStopping services..."
  [[ -n "$ml_pid" ]] && kill "$ml_pid" >/dev/null 2>&1 || true
  [[ -n "$api_pid" ]] && kill "$api_pid" >/dev/null 2>&1 || true
  [[ -n "$fe_pid" ]] && kill "$fe_pid" >/dev/null 2>&1 || true
  wait >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[1/3] ML service → $ML_LOG"
(
  cd "$ROOT_DIR/ml-service"
  ../AI/.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port "$ML_PORT" --log-level info
) >"$ML_LOG" 2>&1 &
ml_pid=$!

sleep 2

echo "[2/3] Backend API → $API_LOG"
(
  cd "$ROOT_DIR/backend"
  mvn -q spring-boot:run -Dspring-boot.run.jvmArguments="-Dserver.port=$API_PORT"
) >"$API_LOG" 2>&1 &
api_pid=$!

sleep 5

echo "[3/3] Frontend → $FE_LOG"
(
  cd "$ROOT_DIR"
  python3 -m http.server "$FRONTEND_PORT"
) >"$FE_LOG" 2>&1 &
fe_pid=$!

echo
printf "Stack running. Access:\n"
printf "  ML service : http://127.0.0.1:%s/health\n" "$ML_PORT"
printf "  Backend   : http://127.0.0.1:%s/api/health\n" "$API_PORT"
printf "  Frontend  : http://127.0.0.1:%s/index.html\n" "$FRONTEND_PORT"
printf "Logs under : %s\n\n" "$LOG_DIR"

tail -f "$ML_LOG" "$API_LOG" "$FE_LOG"
