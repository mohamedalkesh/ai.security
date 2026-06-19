#!/usr/bin/env bash
# Run once with sudo: sudo bash scripts/install-services.sh
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
USER_NAME="${SUDO_USER:-$(logname)}"

echo "→ Installing MADRS systemd services for user: $USER_NAME"
echo "  Root: $ROOT"

# ── Backend ────────────────────────────────────────────────────────────────────
cat > /etc/systemd/system/madrs-backend.service << UNIT
[Unit]
Description=MADRS Backend (Spring Boot)
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=$USER_NAME
WorkingDirectory=$ROOT/backend
ExecStart=/usr/bin/java -jar $ROOT/backend/target/madrs-backend.jar
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=madrs-backend
Environment=SPRING_DATASOURCE_URL=jdbc:postgresql://127.0.0.1:5432/ai_ids
Environment=DB_USER=aisec
Environment=DB_PASSWORD=aisec_pass

[Install]
WantedBy=multi-user.target
UNIT

# ── ML Service ─────────────────────────────────────────────────────────────────
cat > /etc/systemd/system/madrs-ml.service << UNIT
[Unit]
Description=MADRS ML Service (FastAPI)
After=network.target

[Service]
Type=simple
User=$USER_NAME
WorkingDirectory=$ROOT/ml-service
ExecStart=$ROOT/AI/.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8001
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=madrs-ml

[Install]
WantedBy=multi-user.target
UNIT

# ── Frontend ───────────────────────────────────────────────────────────────────
cat > /etc/systemd/system/madrs-frontend.service << UNIT
[Unit]
Description=MADRS Frontend (static HTTP)
After=network.target

[Service]
Type=simple
User=$USER_NAME
WorkingDirectory=$ROOT
ExecStart=/usr/bin/python3 $ROOT/serve.py
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=madrs-frontend

[Install]
WantedBy=multi-user.target
UNIT

# ── Reload & Enable ────────────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable madrs-backend madrs-ml madrs-frontend
echo ""
echo "✓ Services installed and enabled at boot!"
echo ""
echo "  Start now:    sudo systemctl start madrs-backend madrs-ml madrs-frontend"
echo "  Check status: sudo systemctl status madrs-backend"
echo "  View logs:    sudo journalctl -u madrs-backend -f"
echo ""
echo "  ⚠️  Build the JAR first if not done: bash $ROOT/scripts/build-backend.sh"
