package com.aisec.backend.dto.threatintel;

import com.aisec.backend.entity.IpReputation;

import java.time.Instant;

/**
 * Compact projection of {@link IpReputation} for the UI and downstream DTOs.
 * The {@code stale} flag tells the frontend whether to show a "refresh"
 * affordance — we always return whatever's cached, even if past its TTL,
 * because partial data beats a spinner.
 */
public record IpReputationDto(
        String ip,
        String provider,
        int abuseScore,
        String countryCode,
        String country,
        String isp,
        String usageType,
        Integer totalReports,
        Instant lastReportedAt,
        Instant fetchedAt,
        boolean stale
) {
    public static IpReputationDto from(IpReputation r) {
        boolean stale = r.getExpiresAt() != null && r.getExpiresAt().isBefore(Instant.now());
        return new IpReputationDto(
                r.getIpAddress(),
                r.getProvider(),
                r.getAbuseScore(),
                r.getCountryCode(),
                r.getCountry(),
                r.getIsp(),
                r.getUsageType(),
                r.getTotalReports(),
                r.getLastReportedAt(),
                r.getFetchedAt(),
                stale
        );
    }
}
