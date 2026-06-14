package com.aisec.backend.entity;

import jakarta.persistence.*;

import java.time.Instant;

/**
 * Append-only audit trail. Every sensitive action (auth, user mutation,
 * alert update, settings change) writes one row. Rows must NEVER be edited
 * or deleted via application code — there's no setter for {@code createdAt}
 * and no controller exposing UPDATE/DELETE.
 */
@Entity
@Table(name = "audit_logs", indexes = {
        @Index(name = "idx_audit_created", columnList = "createdAt"),
        @Index(name = "idx_audit_actor",   columnList = "actorUsername"),
        @Index(name = "idx_audit_org",     columnList = "organization_id"),
        @Index(name = "idx_audit_action",  columnList = "action")
})
public class AuditLog {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Coarse action: LOGIN_OK, LOGIN_FAIL, ALERT_UPDATE, USER_CREATE, etc. */
    @Column(nullable = false, length = 32)
    private String action;

    /** Type of resource touched: "Alert", "User", "Settings", null for auth events. */
    @Column(length = 32)
    private String resourceType;

    /** PK / identifier of the resource, free-form. */
    @Column(length = 64)
    private String resourceId;

    /** Username at the time of the event (preserved even if the user is later deleted). */
    @Column(length = 80)
    private String actorUsername;

    /** Role at the time of the event (preserved). */
    @Column(length = 16)
    private String actorRole;

    /** Source IP that initiated the request. */
    @Column(length = 64)
    private String sourceIp;

    /** Free-form details, JSON-ish or plain text. Capped at 1024 to keep table fast. */
    @Column(length = 1024)
    private String details;

    @Column(nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "organization_id")
    private Organization organization;

    public Long getId() { return id; }
    public String getAction() { return action; }
    public void setAction(String a) { this.action = a; }
    public String getResourceType() { return resourceType; }
    public void setResourceType(String t) { this.resourceType = t; }
    public String getResourceId() { return resourceId; }
    public void setResourceId(String r) { this.resourceId = r; }
    public String getActorUsername() { return actorUsername; }
    public void setActorUsername(String a) { this.actorUsername = a; }
    public String getActorRole() { return actorRole; }
    public void setActorRole(String r) { this.actorRole = r; }
    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String s) { this.sourceIp = s; }
    public String getDetails() { return details; }
    public void setDetails(String d) { this.details = d; }
    public Instant getCreatedAt() { return createdAt; }
    public Organization getOrganization() { return organization; }
    public void setOrganization(Organization org) { this.organization = org; }
}
