package com.aisec.backend.entity;

import jakarta.persistence.*;

import java.time.Instant;

/**
 * Cached threat-intel verdict for a single IP. One row per IP regardless of
 * tenant — the reputation of {@code 1.2.3.4} doesn't change between orgs, so
 * sharing the cache across the whole system both saves API quota and keeps
 * results consistent for analysts.
 */
@Entity
@Table(name = "ip_reputation",
        indexes = { @Index(name = "idx_iprep_expires", columnList = "expiresAt") })
public class IpReputation {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "ip_address", nullable = false, unique = true, length = 64)
    private String ipAddress;

    /** Source of the verdict: {@code abuseipdb}, {@code mock}, etc. */
    @Column(nullable = false, length = 32)
    private String provider;

    /** 0–100 confidence that the IP is malicious. */
    @Column(name = "abuse_score", nullable = false)
    private int abuseScore;

    /** ISO-3166 alpha-2, when known. */
    @Column(length = 4)
    private String countryCode;

    @Column(length = 80)
    private String country;

    @Column(length = 160)
    private String isp;

    @Column(length = 160)
    private String usageType;

    /** Total community reports the upstream provider has on file. */
    @Column(name = "total_reports")
    private Integer totalReports;

    @Column(name = "last_reported_at")
    private Instant lastReportedAt;

    @Column(name = "fetched_at", nullable = false)
    private Instant fetchedAt = Instant.now();

    /** When this row should be re-fetched. Older rows are still served but flagged stale. */
    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    /* getters / setters */

    public Long getId() { return id; }
    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
    public String getProvider() { return provider; }
    public void setProvider(String provider) { this.provider = provider; }
    public int getAbuseScore() { return abuseScore; }
    public void setAbuseScore(int abuseScore) { this.abuseScore = abuseScore; }
    public String getCountryCode() { return countryCode; }
    public void setCountryCode(String countryCode) { this.countryCode = countryCode; }
    public String getCountry() { return country; }
    public void setCountry(String country) { this.country = country; }
    public String getIsp() { return isp; }
    public void setIsp(String isp) { this.isp = isp; }
    public String getUsageType() { return usageType; }
    public void setUsageType(String usageType) { this.usageType = usageType; }
    public Integer getTotalReports() { return totalReports; }
    public void setTotalReports(Integer totalReports) { this.totalReports = totalReports; }
    public Instant getLastReportedAt() { return lastReportedAt; }
    public void setLastReportedAt(Instant lastReportedAt) { this.lastReportedAt = lastReportedAt; }
    public Instant getFetchedAt() { return fetchedAt; }
    public void setFetchedAt(Instant fetchedAt) { this.fetchedAt = fetchedAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }
}
