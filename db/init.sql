-- MADRS — PostgreSQL schema initialisation
-- Runs automatically on first docker-compose startup (postgres entrypoint).
-- Hibernate ddl-auto:update will reconcile on every boot; this file ensures
-- the schema is correct even before the first Spring startup.

-- ──────────────────────────────────────────────────────────────────────────
-- EXTENSIONS
-- ──────────────────────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS pg_trgm;   -- for future full-text search

-- ──────────────────────────────────────────────────────────────────────────
-- ENUMS  (defined as CHECK constraints so Hibernate ddl-auto:update is happy)
-- ──────────────────────────────────────────────────────────────────────────

-- ──────────────────────────────────────────────────────────────────────────
-- TABLES  (creation order respects FK dependencies)
-- ──────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS organizations (
    id         BIGSERIAL PRIMARY KEY,
    name       VARCHAR(200) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
    id              BIGSERIAL PRIMARY KEY,
    username        VARCHAR(80)  NOT NULL UNIQUE,
    email           VARCHAR(160) NOT NULL UNIQUE,
    full_name       VARCHAR(100) NOT NULL,
    password_hash   TEXT         NOT NULL,
    role            VARCHAR(16)  NOT NULL DEFAULT 'VIEWER'
                        CHECK (role IN ('ADMIN','ORG_ADMIN','ANALYST','VIEWER')),
    enabled         BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_login_at   TIMESTAMPTZ,
    organization_id BIGINT REFERENCES organizations(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    id               BIGSERIAL PRIMARY KEY,
    correlation_key  VARCHAR(80)  NOT NULL UNIQUE,
    title            VARCHAR(64)  NOT NULL,
    highest_severity VARCHAR(16)  NOT NULL DEFAULT 'INFORMATIONAL'
                         CHECK (highest_severity IN ('INFORMATIONAL','LOW','MEDIUM','HIGH','CRITICAL')),
    status           VARCHAR(20)  NOT NULL DEFAULT 'NEW'
                         CHECK (status IN ('NEW','INVESTIGATING','RESOLVED','FALSE_POSITIVE')),
    alert_count      INT          NOT NULL DEFAULT 0,
    source_ip        VARCHAR(64),
    assigned_to_id   BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_alert_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    resolved_at      TIMESTAMPTZ,
    organization_id  BIGINT REFERENCES organizations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_incidents_key     ON incidents(correlation_key);
CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at);

CREATE TABLE IF NOT EXISTS scan_results (
    id                   BIGSERIAL PRIMARY KEY,
    source_type          VARCHAR(32)  NOT NULL,
    filename             VARCHAR(255),
    total_flows          INT,
    benign_count         INT,
    attack_count         INT,
    avg_confidence       DOUBLE PRECISION,
    summary_json         TEXT,
    metadata_quality_json TEXT,
    sampled              BOOLEAN,
    original_rows        INT,
    sampled_rows         INT,
    status               VARCHAR(32)  NOT NULL DEFAULT 'PROCESSING',
    error_message        TEXT,
    completed_at         TIMESTAMPTZ,
    uploaded_by          BIGINT REFERENCES users(id) ON DELETE SET NULL,
    organization_id      BIGINT REFERENCES organizations(id) ON DELETE CASCADE,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alerts (
    id               BIGSERIAL PRIMARY KEY,
    attack_type      VARCHAR(64)  NOT NULL,
    severity         VARCHAR(16)  NOT NULL DEFAULT 'INFORMATIONAL'
                         CHECK (severity IN ('INFORMATIONAL','LOW','MEDIUM','HIGH','CRITICAL')),
    status           VARCHAR(20)  NOT NULL DEFAULT 'NEW'
                         CHECK (status IN ('NEW','INVESTIGATING','RESOLVED','FALSE_POSITIVE')),
    source_ip        VARCHAR(64),
    dest_ip          VARCHAR(64),
    dest_port        INT,
    protocol         VARCHAR(16),
    confidence       DOUBLE PRECISION,
    mitre_technique  VARCHAR(32),
    mitre_tactic     VARCHAR(64),
    description      VARCHAR(1024),
    explanation      TEXT,
    raw_features_json TEXT,
    src_country      VARCHAR(2),
    dst_country      VARCHAR(2),
    ml_feedback      VARCHAR(16)
                         CHECK (ml_feedback IN ('TRUE_POSITIVE','FALSE_POSITIVE','UNCERTAIN')),
    scan_id          BIGINT REFERENCES scan_results(id) ON DELETE SET NULL,
    assigned_to_id   BIGINT REFERENCES users(id) ON DELETE SET NULL,
    incident_id      BIGINT REFERENCES incidents(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    resolved_at      TIMESTAMPTZ,
    organization_id  BIGINT REFERENCES organizations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_alerts_created  ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_assigned ON alerts(assigned_to_id);
CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts(incident_id);

CREATE TABLE IF NOT EXISTS alert_comments (
    id         BIGSERIAL PRIMARY KEY,
    alert_id   BIGINT      NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    author_id  BIGINT      REFERENCES users(id) ON DELETE SET NULL,
    body       VARCHAR(4000) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alert_comments_alert   ON alert_comments(alert_id);
CREATE INDEX IF NOT EXISTS idx_alert_comments_created ON alert_comments(created_at);

CREATE TABLE IF NOT EXISTS blocked_ips (
    id               BIGSERIAL PRIMARY KEY,
    ip_address       VARCHAR(64) NOT NULL,
    reason           VARCHAR(512),
    source           VARCHAR(24) NOT NULL DEFAULT 'MANUAL'
                         CHECK (source IN ('MANUAL','AUTO_RULE','INCIDENT_RESPONSE')),
    created_by       VARCHAR(64),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at       TIMESTAMPTZ,
    active           BOOLEAN     NOT NULL DEFAULT TRUE,
    organization_id  BIGINT REFERENCES organizations(id) ON DELETE CASCADE,
    source_alert_id  BIGINT REFERENCES alerts(id) ON DELETE SET NULL,
    CONSTRAINT uk_blocked_ip_org UNIQUE (ip_address, organization_id)
);

CREATE INDEX IF NOT EXISTS idx_blocked_ip      ON blocked_ips(ip_address);
CREATE INDEX IF NOT EXISTS idx_blocked_created ON blocked_ips(created_at);

CREATE TABLE IF NOT EXISTS audit_logs (
    id              BIGSERIAL PRIMARY KEY,
    action          VARCHAR(32)  NOT NULL,
    resource_type   VARCHAR(32),
    resource_id     VARCHAR(64),
    actor_username  VARCHAR(80),
    actor_role      VARCHAR(16),
    source_ip       VARCHAR(64),
    details         VARCHAR(1024),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    organization_id BIGINT REFERENCES organizations(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_actor   ON audit_logs(actor_username);
CREATE INDEX IF NOT EXISTS idx_audit_org     ON audit_logs(organization_id);
CREATE INDEX IF NOT EXISTS idx_audit_action  ON audit_logs(action);

CREATE TABLE IF NOT EXISTS app_settings (
    id         BIGINT PRIMARY KEY DEFAULT 1,
    payload    TEXT        NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by VARCHAR(64)
);

CREATE TABLE IF NOT EXISTS ip_reputation (
    id               BIGSERIAL PRIMARY KEY,
    ip_address       VARCHAR(64) NOT NULL UNIQUE,
    provider         VARCHAR(32) NOT NULL,
    abuse_score      INT         NOT NULL DEFAULT 0,
    country_code     VARCHAR(4),
    country          VARCHAR(80),
    isp              VARCHAR(160),
    usage_type       VARCHAR(160),
    total_reports    INT,
    last_reported_at TIMESTAMPTZ,
    fetched_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at       TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_iprep_expires ON ip_reputation(expires_at);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id         BIGSERIAL PRIMARY KEY,
    token      VARCHAR(64) NOT NULL UNIQUE,
    email      TEXT        NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used       BOOLEAN     NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS webhook_configs (
    id                BIGSERIAL PRIMARY KEY,
    name              VARCHAR(80)  NOT NULL,
    url               VARCHAR(500) NOT NULL,
    secret            VARCHAR(128),
    min_severity      VARCHAR(16)  NOT NULL DEFAULT 'HIGH'
                          CHECK (min_severity IN ('INFORMATIONAL','LOW','MEDIUM','HIGH','CRITICAL')),
    enabled           BOOLEAN      NOT NULL DEFAULT TRUE,
    preset            VARCHAR(16)  DEFAULT 'generic',
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_delivered_at TIMESTAMPTZ,
    last_status_code  INT,
    organization_id   BIGINT REFERENCES organizations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_webhook_org ON webhook_configs(organization_id);

CREATE TABLE IF NOT EXISTS ml_training_data (
    id                BIGSERIAL PRIMARY KEY,
    alert_id          BIGINT,
    attack_type       VARCHAR(64) NOT NULL,
    true_label        VARCHAR(16) NOT NULL,
    severity          VARCHAR(16) NOT NULL
                          CHECK (severity IN ('INFORMATIONAL','LOW','MEDIUM','HIGH','CRITICAL')),
    confidence        DOUBLE PRECISION,
    source_ip         VARCHAR(64),
    dest_ip           VARCHAR(64),
    dest_port         INT,
    protocol          VARCHAR(16),
    mitre_technique   VARCHAR(32),
    mitre_tactic      VARCHAR(64),
    resolution_status VARCHAR(20),
    features_json     TEXT,
    raw_features_json TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    alert_created_at  TIMESTAMPTZ,
    resolved_at       TIMESTAMPTZ,
    organization_id   BIGINT REFERENCES organizations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ml_org     ON ml_training_data(organization_id);
CREATE INDEX IF NOT EXISTS idx_ml_created ON ml_training_data(created_at);
CREATE INDEX IF NOT EXISTS idx_ml_label   ON ml_training_data(true_label);
CREATE INDEX IF NOT EXISTS idx_ml_attack  ON ml_training_data(attack_type);
