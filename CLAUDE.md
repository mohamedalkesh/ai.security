# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project: MADRS — Network IDS

Three-service architecture:
- **Frontend** — static files served by `python3 serve.py` on port 5500 (dev) or 8080 (prod), in `backend/src/main/resources/static/`
- **Backend** — Spring Boot 3.3.5 (Java 21), port 8080, in `backend/`
- **ML service** — FastAPI (Python), port 8001, in `ml-service/`

## Running

```bash
# All three in tmux (one session, three windows)
bash start.sh

# Individual services
cd backend && mvn spring-boot:run
cd ml-service && ./run.sh
python3 serve.py  # from project root
```

One-time setup to allow packet capture without root:
```bash
sudo bash scripts/grant-capture-perms.sh
```

One-time sudoers entry for nftables blocking:
```bash
sudo tee /etc/sudoers.d/aisec-nft <<'EOF'
mohamed ALL=(root) NOPASSWD: /usr/sbin/nft
EOF
```

## Key Configuration

`backend/src/main/resources/application.yml`:
- `spring.jackson.property-naming-strategy: SNAKE_CASE` — all JSON is snake_case end-to-end
- ML service URL: `http://127.0.0.1:8001`
- nftables: `app.firewall.use-sudo: true`
- `FIREWALL_USE_SUDO`, `ABUSEIPDB_KEY`, `JWT_SECRET` come from env

`ml-service/.env` (auto-created by autostart endpoint):
- `AUTOSTART_INTERFACE` — interface to capture on at boot

## Backend Architecture

Package root: `com.aisec.backend`

- `controller/` — REST endpoints; all under `/api/*`. Controllers are thin; business logic lives in services.
- `service/` — Core logic. Key services: `AlertService`, `BlockedIpService`, `IncidentService`, `MlClient` (HTTP client to ML service), `AuditService`, `GeoIpService`
- `service/firewall/` — `FirewallEnforcer` interface → `NftablesEnforcer` (active) or `NoOpFirewallEnforcer`. Factory auto-detects via `sudo -n nft --version`.
- `service/threatintel/` — AbuseIPDB integration with 24h DB cache
- `entity/` — JPA entities; Hibernate `ddl-auto: update` manages schema
- `dto/` — Request/response POJOs. `BlockIpRequest` fields: `ip`, `reason`, `expiresAt`, `sourceAlertId` — no `severity` field.
- `websocket/` — `AlertBroadcaster` pushes new alerts over WebSocket (`/ws/alerts`)
- `config/AppProperties.java` — Typed config for `app.*` YAML keys (CORS, ML URL, firewall, threat-intel)

## ML Service Architecture

- `app/services/live_monitor.py` — `LiveMonitor` singleton. Runs NFStream in a background thread. Applies ICMP heuristics (flood/sweep detection) before ML inference. Emits detections to `_pending` queue; Java polls via `POST /api/monitor/drain`.
- `app/services/ml_service.py` — `MLService` singleton. Loads v6 artifacts (XGBoost + LightGBM ensemble, per-class thresholds from `runtime_config.json`). Falls back to v5/v4/v3/v2 in order.
- `app/api/monitor.py` — Monitor endpoints: `/api/monitor/interfaces`, `/start`, `/stop`, `/status`, `/drain`, `/autostart`
- Model artifacts: `AI/model_artifacts_v6/` — 7 classes: Benign, DDoS, DoS, Port Scan, Bot, Brute Force, XSS
- NFStream `idle_timeout=2, active_timeout=30` for fast flow export

## Frontend Architecture

All pages share `api.js` (API client) and `env-config.js` (base URL).

`api.js` — `AisecAPI` object with methods for every backend endpoint. Uses `_snakeize()` to convert camelCase request bodies to snake_case (needed because backend expects SNAKE_CASE). Error messages extracted from `data.detail || data.message || data.error`.

`monitoring.js` — Live monitoring page. Polls `/api/monitor/status` + `/api/monitor/drain` every second. Block button logic uses two Sets: `blockedIps` (persistent, loaded from `/api/firewall/blocked`) and `blockingIps` (in-flight, transient). State is re-derived on each render cycle to avoid race conditions with DOM replacement.

IP direction rule: if `src_ip` is private/local → machine is attacker → block `dst_ip` (on OUTPUT chain). Otherwise block `src_ip` (on INPUT chain).

## nftables Blocking

Table `inet aisec` with sets `aisec_block_v4`, `aisec_block_v6`.
- INPUT chain: `ip saddr @aisec_block_v4 drop` — drops inbound FROM blocked IPs
- OUTPUT chain: `ip daddr @aisec_block_v4 drop` — drops outbound TO blocked IPs

Both chains are created by `NftablesEnforcer.ensureInitialised()` on first `applyBlock()` call.

Inspect live state: `sudo nft list table inet aisec`

## ICMP Detection (live_monitor.py)

Heuristic-based, independent of ML model. Thresholds:
- `ICMP_FLOOD_PKTS = 15` packets in `ICMP_WINDOW_SEC = 15` seconds → ICMP Flood
- `ICMP_SWEEP_HOSTS = 3` distinct hosts in window → ICMP Sweep

ICMP heuristic detections bypass the `MIN_REPEAT=2` gate and emit immediately.
