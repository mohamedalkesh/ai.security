package com.aisec.backend.dto.incident;

import com.aisec.backend.entity.Incident;

import java.time.Instant;

public record IncidentDto(
        Long id,
        String title,
        String highestSeverity,
        String status,
        int alertCount,
        String sourceIp,
        Long assignedToId,
        String assignedToUsername,
        Instant createdAt,
        Instant lastAlertAt,
        Instant resolvedAt
) {
    public static IncidentDto from(Incident i) {
        return new IncidentDto(
                i.getId(),
                i.getTitle(),
                i.getHighestSeverity().name(),
                i.getStatus().name(),
                i.getAlertCount(),
                i.getSourceIp(),
                i.getAssignedTo() != null ? i.getAssignedTo().getId() : null,
                i.getAssignedTo() != null ? i.getAssignedTo().getUsername() : null,
                i.getCreatedAt(),
                i.getLastAlertAt(),
                i.getResolvedAt()
        );
    }
}
