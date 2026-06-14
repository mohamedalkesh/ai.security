package com.aisec.backend.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "scan_results")
public class ScanResult {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 32)
    private String sourceType;            // "PCAP" / "FLOW"

    @Column(length = 255) private String filename;
    @Column private Integer totalFlows;
    @Column private Integer benignCount;
    @Column private Integer attackCount;
    @Column private Double  avgConfidence;
    @Column(columnDefinition = "TEXT") private String summaryJson;
    @Column(columnDefinition = "TEXT") private String metadataQualityJson;
    @Column private Boolean sampled;
    @Column private Integer originalRows;
    @Column private Integer sampledRows;

    @Column(length = 32, nullable = false)
    private String status = "PROCESSING"; // PROCESSING / COMPLETED / FAILED

    @Column(columnDefinition = "TEXT")
    private String errorMessage;

    @Column
    private Instant completedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "uploaded_by")
    private UserAccount uploadedBy;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "organization_id")
    private Organization organization;

    @Column(nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    public Long getId() { return id; }
    public String getSourceType() { return sourceType; }
    public void setSourceType(String s) { this.sourceType = s; }
    public String getFilename() { return filename; }
    public void setFilename(String f) { this.filename = f; }
    public Integer getTotalFlows() { return totalFlows; }
    public void setTotalFlows(Integer t) { this.totalFlows = t; }
    public Integer getBenignCount() { return benignCount; }
    public void setBenignCount(Integer b) { this.benignCount = b; }
    public Integer getAttackCount() { return attackCount; }
    public void setAttackCount(Integer a) { this.attackCount = a; }
    public Double getAvgConfidence() { return avgConfidence; }
    public void setAvgConfidence(Double a) { this.avgConfidence = a; }
    public String getSummaryJson() { return summaryJson; }
    public void setSummaryJson(String s) { this.summaryJson = s; }
    public String getMetadataQualityJson() { return metadataQualityJson; }
    public void setMetadataQualityJson(String metadataQualityJson) { this.metadataQualityJson = metadataQualityJson; }
    public Boolean getSampled() { return sampled; }
    public void setSampled(Boolean sampled) { this.sampled = sampled; }
    public Integer getOriginalRows() { return originalRows; }
    public void setOriginalRows(Integer originalRows) { this.originalRows = originalRows; }
    public Integer getSampledRows() { return sampledRows; }
    public void setSampledRows(Integer sampledRows) { this.sampledRows = sampledRows; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
    public Instant getCompletedAt() { return completedAt; }
    public void setCompletedAt(Instant completedAt) { this.completedAt = completedAt; }
    public UserAccount getUploadedBy() { return uploadedBy; }
    public void setUploadedBy(UserAccount u) { this.uploadedBy = u; }
    public Instant getCreatedAt() { return createdAt; }
    public Organization getOrganization() { return organization; }
    public void setOrganization(Organization org) { this.organization = org; }
}
