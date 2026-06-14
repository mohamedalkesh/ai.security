package com.aisec.backend.dto.audit;

import com.aisec.backend.entity.AuditLog;

import java.time.Instant;

public record AuditLogDto(
        Long id,
        String action,
        String resourceType,
        String resourceId,
        String actorUsername,
        String actorRole,
        String sourceIp,
        String details,
        Instant createdAt
) {
    public static AuditLogDto from(AuditLog a) {
        return new AuditLogDto(
                a.getId(),
                a.getAction(),
                a.getResourceType(),
                a.getResourceId(),
                a.getActorUsername(),
                a.getActorRole(),
                a.getSourceIp(),
                a.getDetails(),
                a.getCreatedAt()
        );
    }
}
