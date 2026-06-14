package com.aisec.backend.dto.alert;

import com.aisec.backend.entity.Alert;

import java.time.Instant;

public record AlertDto(
        Long id,
        String attackType,
        String severity,
        String status,
        String sourceIp,
        String destIp,
        Integer destPort,
        String protocol,
        Double confidence,
        String mitreTechnique,
        String mitreTactic,
        String description,
        String explanation,
        String srcCountry,
        String dstCountry,
        String mlFeedback,
        Long assignedToId,
        String assignedToUsername,
        Long incidentId,
        Instant createdAt,
        Instant resolvedAt
) {
    public static AlertDto from(Alert a) {
        return new AlertDto(
                a.getId(), a.getAttackType(),
                a.getSeverity().name(), a.getStatus().name(),
                a.getSourceIp(), a.getDestIp(), a.getDestPort(), a.getProtocol(),
                a.getConfidence(), a.getMitreTechnique(), a.getMitreTactic(),
                a.getDescription(),
                a.getExplanation(),
                a.getSrcCountry(), a.getDstCountry(),
                a.getMlFeedback() != null ? a.getMlFeedback().name() : null,
                a.getAssignedTo() != null ? a.getAssignedTo().getId() : null,
                a.getAssignedTo() != null ? a.getAssignedTo().getUsername() : null,
                a.getIncident() != null ? a.getIncident().getId() : null,
                a.getCreatedAt(), a.getResolvedAt()
        );
    }
}
