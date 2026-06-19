#!/usr/bin/env bash
# Run once with sudo: sudo bash scripts/install-retrain-timer.sh
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
USER_NAME="${SUDO_USER:-$(logname)}"
PYTHON="$ROOT/AI/.venv/bin/python"

echo "→ Installing MADRS retrain timer for user: $USER_NAME"

# ── Service ────────────────────────────────────────────────────────────────────
cat > /etc/systemd/system/madrs-retrain.service << UNIT
[Unit]
Description=MADRS Auto-Retraining Pipeline
After=network.target madrs-ml.service

[Service]
Type=oneshot
User=$USER_NAME
WorkingDirectory=$ROOT
ExecStart=$PYTHON $ROOT/scripts/retrain.py --min-new 50
StandardOutput=journal
StandardError=journal
SyslogIdentifier=madrs-retrain
Environment=DB_USER=aisec
Environment=DB_PASSWORD=aisec_pass
Environment=DB_NAME=ai_ids
UNIT

# ── Timer — runs every Sunday at 02:00 ────────────────────────────────────────
cat > /etc/systemd/system/madrs-retrain.timer << UNIT
[Unit]
Description=MADRS Weekly Retraining Timer
Requires=madrs-retrain.service

[Timer]
OnCalendar=Sun *-*-* 02:00:00
Persistent=true
Unit=madrs-retrain.service

[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload
systemctl enable madrs-retrain.timer
systemctl start  madrs-retrain.timer

echo ""
echo "✓ Retrain timer installed — runs every Sunday at 02:00"
echo ""
echo "  Run manually now:   sudo systemctl start madrs-retrain.service"
echo "  Dry run:            $PYTHON $ROOT/scripts/retrain.py --dry-run"
echo "  Check timer:        systemctl list-timers | grep madrs"
echo "  View logs:          journalctl -u madrs-retrain.service -f"
