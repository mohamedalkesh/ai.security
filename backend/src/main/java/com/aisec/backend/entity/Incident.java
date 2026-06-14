package com.aisec.backend.entity;

import jakarta.persistence.*;

import java.time.Instant;

/**
 * An Incident groups related Alerts (same source IP + same attack family within
 * a sliding window). The grouping key is computed by AlertService when an alert
 * is created. Analysts work on incidents, not individual alerts, which mirrors
 * how mature SOCs handle volume.
 */
@Entity
@Table(name = "incidents", indexes = {
        @Index(name = "idx_incidents_key", columnList = "correlationKey", unique = true),
        @Index(name = "idx_incidents_created", columnList = "createdAt")
})
public class Incident {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Hash of (srcIp, attackFamily, orgId) — used to find existing open incidents. */
    @Column(nullable = false, unique = true, length = 80)
    private String correlationKey;

    @Column(nullable = false, length = 64)
    private String title;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private Severity highestSeverity = Severity.INFORMATIONAL;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private AlertStatus status = AlertStatus.NEW;

    @Column(nullable = false)
    private int alertCount = 0;

    @Column(length = 64) private String sourceIp;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "assigned_to_id")
    private UserAccount assignedTo;

    @Column(nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(nullable = false)
    private Instant lastAlertAt = Instant.now();

    private Instant resolvedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "organization_id")
    private Organization organization;

    public Long getId() { return id; }
    public String getCorrelationKey() { return correlationKey; }
    public void setCorrelationKey(String k) { this.correlationKey = k; }
    public String getTitle() { return title; }
    public void setTitle(String t) { this.title = t; }
    public Severity getHighestSeverity() { return highestSeverity; }
    public void setHighestSeverity(Severity s) { this.highestSeverity = s; }
    public AlertStatus getStatus() { return status; }
    public void setStatus(AlertStatus s) { this.status = s; }
    public int getAlertCount() { return alertCount; }
    public void setAlertCount(int c) { this.alertCount = c; }
    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String s) { this.sourceIp = s; }
    public UserAccount getAssignedTo() { return assignedTo; }
    public void setAssignedTo(UserAccount u) { this.assignedTo = u; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getLastAlertAt() { return lastAlertAt; }
    public void setLastAlertAt(Instant t) { this.lastAlertAt = t; }
    public Instant getResolvedAt() { return resolvedAt; }
    public void setResolvedAt(Instant t) { this.resolvedAt = t; }
    public Organization getOrganization() { return organization; }
    public void setOrganization(Organization o) { this.organization = o; }
}
