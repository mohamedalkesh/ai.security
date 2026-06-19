#!/usr/bin/env bash
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}   COS - Starting All Services          ${NC}"
echo -e "${GREEN}========================================${NC}"

# Check tmux
if ! command -v tmux &>/dev/null; then
  echo "tmux not found. Installing..."
  sudo apt-get install -y tmux
fi

# Kill existing session if running
tmux kill-session -t cos 2>/dev/null && echo -e "${YELLOW}→ Killed existing cos session${NC}" || true

# Start new tmux session
tmux new-session -d -s cos -n backend

# Window 0: Backend
echo -e "${GREEN}→ Starting Backend (port 8080)...${NC}"
tmux send-keys -t cos:backend "cd '$ROOT/backend' && mvn spring-boot:run" Enter

# Window 1: ML Service
echo -e "${GREEN}→ Starting ML Service (port 8001)...${NC}"
tmux new-window -t cos -n ml
tmux send-keys -t cos:ml "cd '$ROOT/ml-service' && ./run.sh" Enter

# Window 2: Frontend
echo -e "${GREEN}→ Starting Frontend (port 5500)...${NC}"
tmux new-window -t cos -n frontend
tmux send-keys -t cos:frontend "cd '$ROOT' && python3 serve.py" Enter

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  All services started!                 ${NC}"
echo -e "${GREEN}  Frontend  → http://127.0.0.1:5500     ${NC}"
echo -e "${GREEN}  Backend   → http://127.0.0.1:8080     ${NC}"
echo -e "${GREEN}  ML Docs   → http://127.0.0.1:8001/docs${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "  Attaching to tmux session (Ctrl+B then 0/1/2 to switch)"
echo "  To detach: Ctrl+B then D"
echo ""

tmux attach-session -t cos
