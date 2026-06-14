#!/usr/bin/env bash
# ============================================================
# grant-capture-perms.sh
#
# One-time setup so the ML service can sniff packets on a real
# network interface (Live Monitor + email traffic detection).
#
# What it does:
#   - Adds cap_net_raw + cap_net_admin to the python3 binary
#     used by the ml-service venv (so libpcap can open the
#     interface in promiscuous mode WITHOUT running as root).
#
# Usage:
#   sudo bash scripts/grant-capture-perms.sh
# ============================================================
set -e

if [ "$EUID" -ne 0 ]; then
  echo "[!] Run as root:  sudo bash $0"
  exit 1
fi

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENV_PY="$PROJECT_ROOT/AI/.venv/bin/python3"

if [ -x "$VENV_PY" ]; then
  PY_BIN="$(readlink -f "$VENV_PY")"
  echo "[+] Using venv python:  $VENV_PY"
  echo "    -> resolved to:     $PY_BIN"
else
  PY_BIN="$(readlink -f "$(which python3)")"
  echo "[!] No venv found at $VENV_PY — falling back to system python3"
  echo "    -> resolved to:     $PY_BIN"
fi

echo "[+] Granting cap_net_raw + cap_net_admin to $PY_BIN"
setcap cap_net_raw,cap_net_admin=eip "$PY_BIN"

echo
echo "[+] Verifying:"
getcap "$PY_BIN"

echo
echo "[ OK ] Capture permissions granted."
echo "      Restart the ML service for the change to take effect:"
echo "        bash scripts/stop-all.sh && bash scripts/start-all.sh"
