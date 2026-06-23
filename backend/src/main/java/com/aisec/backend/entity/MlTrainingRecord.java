package com.aisec.backend.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "ml_training_data", indexes = {
        @Index(name = "idx_ml_org",      columnList = "organization_id"),
        @Index(name = "idx_ml_created",  columnList = "createdAt"),
        @Index(name = "idx_ml_label",    columnList = "trueLabel"),
        @Index(name = "idx_ml_attack",   columnList = "attackType")
})
public class MlTrainingRecord {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Original alert this record was derived from. */
    @Column(name = "alert_id")
    private Long alertId;

    /** Model's predicted attack type. */
    @Column(nullable = false, length = 64)
    private String attackType;

    /** Ground-truth label: ATTACK or BENIGN (from analyst mlFeedback). */
    @Column(nullable = false, length = 16)
    private String trueLabel;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Severity severity;

    @Column
    private Double confidence;

    @Column(length = 64) private String sourceIp;
    @Column(length = 64) private String destIp;
    @Column              private Integer destPort;
    @Column(length = 16) private String protocol;
    @Column(length = 2)  private String srcCountry;
    @Column(length = 2)  private String dstCountry;

    @Column(length = 32) private String mitreTechnique;
    @Column(length = 64) private String mitreTactic;

    @Column(length = 1024)
    private String description;

    @Column(length = 16)
    private String mlFeedback;

    @Column(length = 64)
    private String assignedToUsername;

    @Column
    private Long incidentId;

    @Column(length = 64)
    private String responseDecision;

    @Column(length = 1024)
    private String responseAction;

    /** How the alert was closed: RESOLVED or FALSE_POSITIVE. */
    @Column(length = 20)
    private String resolutionStatus;

    /** Rule-based narrative explanation snapshot. */
    @Column(columnDefinition = "TEXT")
    private String featuresJson;

    /** Raw ML feature vector (JSON map) — used for actual model retraining. */
    @Column(columnDefinition = "TEXT")
    private String rawFeaturesJson;

    @Column(nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    private Instant alertCreatedAt;
    private Instant resolvedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "organization_id")
    private Organization organization;

    // ── getters / setters ──────────────────────────────────────────────────
    public Long getId()                       { return id; }
    public Long getAlertId()                  { return alertId; }
    public void setAlertId(Long v)            { this.alertId = v; }
    public String getAttackType()             { return attackType; }
    public void setAttackType(String v)       { this.attackType = v; }
    public String getTrueLabel()              { return trueLabel; }
    public void setTrueLabel(String v)        { this.trueLabel = v; }
    public Severity getSeverity()             { return severity; }
    public void setSeverity(Severity v)       { this.severity = v; }
    public Double getConfidence()             { return confidence; }
    public void setConfidence(Double v)       { this.confidence = v; }
    public String getSourceIp()               { return sourceIp; }
    public void setSourceIp(String v)         { this.sourceIp = v; }
    public String getDestIp()                 { return destIp; }
    public void setDestIp(String v)           { this.destIp = v; }
    public Integer getDestPort()              { return destPort; }
    public void setDestPort(Integer v)        { this.destPort = v; }
    public String getProtocol()               { return protocol; }
    public void setProtocol(String v)         { this.protocol = v; }
    public String getSrcCountry()             { return srcCountry; }
    public void setSrcCountry(String v)       { this.srcCountry = v; }
    public String getDstCountry()             { return dstCountry; }
    public void setDstCountry(String v)       { this.dstCountry = v; }
    public String getMitreTechnique()         { return mitreTechnique; }
    public void setMitreTechnique(String v)   { this.mitreTechnique = v; }
    public String getMitreTactic()            { return mitreTactic; }
    public void setMitreTactic(String v)      { this.mitreTactic = v; }
    public String getDescription()            { return description; }
    public void setDescription(String v)      { this.description = v; }
    public String getMlFeedback()             { return mlFeedback; }
    public void setMlFeedback(String v)       { this.mlFeedback = v; }
    public String getAssignedToUsername()     { return assignedToUsername; }
    public void setAssignedToUsername(String v) { this.assignedToUsername = v; }
    public Long getIncidentId()               { return incidentId; }
    public void setIncidentId(Long v)         { this.incidentId = v; }
    public String getResponseDecision()       { return responseDecision; }
    public void setResponseDecision(String v) { this.responseDecision = v; }
    public String getResponseAction()         { return responseAction; }
    public void setResponseAction(String v)   { this.responseAction = v; }
    public String getResolutionStatus()       { return resolutionStatus; }
    public void setResolutionStatus(String v) { this.resolutionStatus = v; }
    public String getFeaturesJson()           { return featuresJson; }
    public void setFeaturesJson(String v)     { this.featuresJson = v; }
    public String getRawFeaturesJson()        { return rawFeaturesJson; }
    public void setRawFeaturesJson(String v)  { this.rawFeaturesJson = v; }
    public Instant getCreatedAt()             { return createdAt; }
    public Instant getAlertCreatedAt()        { return alertCreatedAt; }
    public void setAlertCreatedAt(Instant v)  { this.alertCreatedAt = v; }
    public Instant getResolvedAt()            { return resolvedAt; }
    public void setResolvedAt(Instant v)      { this.resolvedAt = v; }
    public Organization getOrganization()     { return organization; }
    public void setOrganization(Organization v) { this.organization = v; }
}
