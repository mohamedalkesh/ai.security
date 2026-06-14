package com.aisec.backend.entity;

import jakarta.persistence.*;
import java.time.Instant;

/**
 * A single firewall blocklist entry. Each row represents one IPv4/IPv6
 * address that should be denied at the perimeter (or inside the SOC's
 * application-layer drop list). Uniqueness is enforced per organisation
 * so two tenants can independently block the same IP.
 */
@Entity
@Table(
    name = "blocked_ips",
    uniqueConstraints = @UniqueConstraint(name = "uk_blocked_ip_org",
            columnNames = {"ip_address", "organization_id"}),
    indexes = {
        @Index(name = "idx_blocked_ip", columnList = "ip_address"),
        @Index(name = "idx_blocked_created", columnList = "createdAt")
    }
)
public class BlockedIp {

    public enum Source { MANUAL, AUTO_RULE, INCIDENT_RESPONSE }

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "ip_address", nullable = false, length = 64)
    private String ipAddress;

    @Column(length = 512)
    private String reason;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 24)
    private Source source = Source.MANUAL;

    /** Username (subject) of the actor who created the entry. */
    @Column(length = 64)
    private String createdBy;

    @Column(nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    /** Optional auto-expiry. Null means "until removed". */
    private Instant expiresAt;

    /** Whether this entry is currently active. Soft-disable lets us audit. */
    @Column(nullable = false)
    private boolean active = true;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "organization_id")
    private Organization organization;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "source_alert_id")
    private Alert sourceAlert;

    // getters / setters
    public Long getId() { return id; }
    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ip) { this.ipAddress = ip; }
    public String getReason() { return reason; }
    public void setReason(String r) { this.reason = r; }
    public Source getSource() { return source; }
    public void setSource(Source s) { this.source = s; }
    public String getCreatedBy() { return createdBy; }
    public void setCreatedBy(String u) { this.createdBy = u; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant e) { this.expiresAt = e; }
    public boolean isActive() { return active; }
    public void setActive(boolean a) { this.active = a; }
    public Organization getOrganization() { return organization; }
    public void setOrganization(Organization o) { this.organization = o; }
    public Alert getSourceAlert() { return sourceAlert; }
    public void setSourceAlert(Alert a) { this.sourceAlert = a; }
}
