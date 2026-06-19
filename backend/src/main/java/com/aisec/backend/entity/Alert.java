package com.aisec.backend.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "alerts", indexes = {
        @Index(name = "idx_alerts_created", columnList = "createdAt"),
        @Index(name = "idx_alerts_severity", columnList = "severity"),
        @Index(name = "idx_alerts_assigned", columnList = "assigned_to_id"),
        @Index(name = "idx_alerts_incident", columnList = "incident_id")
})
public class Alert {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 64)
    private String attackType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private Severity severity = Severity.INFORMATIONAL;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private AlertStatus status = AlertStatus.NEW;

    @Column(length = 64)  private String sourceIp;
    @Column(length = 64)  private String destIp;
    @Column            private Integer destPort;
    @Column(length = 16)  private String protocol;
    @Column            private Double confidence;
    @Column(length = 32)  private String mitreTechnique;
    @Column(length = 64)  private String mitreTactic;
    @Column(length = 1024) private String description;

    @Column(columnDefinition = "TEXT")
    private String explanation;

    /** Raw ML feature vector (JSON map) used to classify this alert — stored for retraining. */
    @Column(columnDefinition = "TEXT")
    private String rawFeaturesJson;

    /** Free-form ISO country codes — populated lazily by GeoIpService. */
    @Column(length = 2) private String srcCountry;
    @Column(length = 2) private String dstCountry;

    /** Analyst-provided ground truth for the ML feedback loop. */
    @Enumerated(EnumType.STRING)
    @Column(length = 16)
    private MlFeedback mlFeedback;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "scan_id")
    private ScanResult scan;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "assigned_to_id")
    private UserAccount assignedTo;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "incident_id")
    private Incident incident;

    @Column(nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    private Instant resolvedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "organization_id")
    private Organization organization;

    // getters/setters
    public Long getId() { return id; }
    public String getAttackType() { return attackType; }
    public void setAttackType(String t) { this.attackType = t; }
    public Severity getSeverity() { return severity; }
    public void setSeverity(Severity s) { this.severity = s; }
    public AlertStatus getStatus() { return status; }
    public void setStatus(AlertStatus s) { this.status = s; }
    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String s) { this.sourceIp = s; }
    public String getDestIp() { return destIp; }
    public void setDestIp(String d) { this.destIp = d; }
    public Integer getDestPort() { return destPort; }
    public void setDestPort(Integer p) { this.destPort = p; }
    public String getProtocol() { return protocol; }
    public void setProtocol(String p) { this.protocol = p; }
    public Double getConfidence() { return confidence; }
    public void setConfidence(Double c) { this.confidence = c; }
    public String getMitreTechnique() { return mitreTechnique; }
    public void setMitreTechnique(String m) { this.mitreTechnique = m; }
    public String getMitreTactic() { return mitreTactic; }
    public void setMitreTactic(String m) { this.mitreTactic = m; }
    public String getDescription() { return description; }
    public void setDescription(String d) { this.description = d; }
    public String getExplanation() { return explanation; }
    public void setExplanation(String explanation) { this.explanation = explanation; }
    public String getRawFeaturesJson() { return rawFeaturesJson; }
    public void setRawFeaturesJson(String rawFeaturesJson) { this.rawFeaturesJson = rawFeaturesJson; }
    public String getSrcCountry() { return srcCountry; }
    public void setSrcCountry(String c) { this.srcCountry = c; }
    public String getDstCountry() { return dstCountry; }
    public void setDstCountry(String c) { this.dstCountry = c; }
    public MlFeedback getMlFeedback() { return mlFeedback; }
    public void setMlFeedback(MlFeedback f) { this.mlFeedback = f; }
    public ScanResult getScan() { return scan; }
    public void setScan(ScanResult s) { this.scan = s; }
    public UserAccount getAssignedTo() { return assignedTo; }
    public void setAssignedTo(UserAccount u) { this.assignedTo = u; }
    public Incident getIncident() { return incident; }
    public void setIncident(Incident i) { this.incident = i; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getResolvedAt() { return resolvedAt; }
    public void setResolvedAt(Instant r) { this.resolvedAt = r; }
    public Organization getOrganization() { return organization; }
    public void setOrganization(Organization org) { this.organization = org; }
}
