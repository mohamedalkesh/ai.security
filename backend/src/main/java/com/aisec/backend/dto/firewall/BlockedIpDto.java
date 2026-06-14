package com.aisec.backend.dto.firewall;

import com.aisec.backend.dto.threatintel.IpReputationDto;
import com.aisec.backend.entity.BlockedIp;

import java.time.Instant;

public record BlockedIpDto(
        Long id,
        String ip,
        String reason,
        String source,
        String createdBy,
        Instant createdAt,
        Instant expiresAt,
        boolean active,
        Long sourceAlertId,
        Long organizationId,
        /** Side-effect counters returned only on POST — null on list/read. */
        Integer resolvedAlerts,
        Integer resolvedIncidents,
        /** Optional reputation enrichment; null when threat-intel is off or unknown. */
        IpReputationDto reputation
) {
    public static BlockedIpDto from(BlockedIp b) {
        return from(b, null, null, null);
    }

    public static BlockedIpDto from(BlockedIp b, Integer resolvedAlerts, Integer resolvedIncidents) {
        return from(b, resolvedAlerts, resolvedIncidents, null);
    }

    public static BlockedIpDto from(BlockedIp b,
                                    Integer resolvedAlerts,
                                    Integer resolvedIncidents,
                                    IpReputationDto reputation) {
        return new BlockedIpDto(
                b.getId(),
                b.getIpAddress(),
                b.getReason(),
                b.getSource() == null ? null : b.getSource().name(),
                b.getCreatedBy(),
                b.getCreatedAt(),
                b.getExpiresAt(),
                b.isActive(),
                b.getSourceAlert() != null ? b.getSourceAlert().getId() : null,
                b.getOrganization() != null ? b.getOrganization().getId() : null,
                resolvedAlerts,
                resolvedIncidents,
                reputation
        );
    }
}
