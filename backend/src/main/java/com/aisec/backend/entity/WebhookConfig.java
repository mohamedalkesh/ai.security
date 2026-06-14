package com.aisec.backend.entity;

import jakarta.persistence.*;
import java.time.Instant;

/**
 * Per-tenant outbound webhook for alert notifications.
 *
 * On a qualifying alert (severity >= minSeverity), the platform POSTs a
 * signed JSON payload to {@link #url}. The receiver verifies authenticity
 * via the {@code X-AISec-Signature} header (HMAC-SHA256 of the body using
 * {@link #secret}).
 */
@Entity
@Table(name = "webhook_configs", indexes = {
        @Index(name = "idx_webhook_org", columnList = "organization_id")
})
public class WebhookConfig {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 80)
    private String name;

    @Column(nullable = false, length = 500)
    private String url;

    /** HMAC secret for request signing — never returned in DTOs after creation. */
    @Column(length = 128)
    private String secret;

    /** Minimum severity that triggers delivery. Default HIGH. */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private Severity minSeverity = Severity.HIGH;

    @Column(nullable = false)
    private boolean enabled = true;

    /** Optional preset: "slack" / "discord" / "generic" — drives payload shape. */
    @Column(length = 16)
    private String preset = "generic";

    @Column(nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    /** Last delivery timestamp (null = never fired). */
    private Instant lastDeliveredAt;

    /** Last delivery status code (0 = pending/never; -1 = transport error). */
    private Integer lastStatusCode;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "organization_id")
    private Organization organization;

    public Long getId() { return id; }
    public String getName() { return name; }
    public void setName(String n) { this.name = n; }
    public String getUrl() { return url; }
    public void setUrl(String u) { this.url = u; }
    public String getSecret() { return secret; }
    public void setSecret(String s) { this.secret = s; }
    public Severity getMinSeverity() { return minSeverity; }
    public void setMinSeverity(Severity s) { this.minSeverity = s; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean e) { this.enabled = e; }
    public String getPreset() { return preset; }
    public void setPreset(String p) { this.preset = p; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getLastDeliveredAt() { return lastDeliveredAt; }
    public void setLastDeliveredAt(Instant t) { this.lastDeliveredAt = t; }
    public Integer getLastStatusCode() { return lastStatusCode; }
    public void setLastStatusCode(Integer c) { this.lastStatusCode = c; }
    public Organization getOrganization() { return organization; }
    public void setOrganization(Organization o) { this.organization = o; }
}
