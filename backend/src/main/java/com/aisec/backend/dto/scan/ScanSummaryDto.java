package com.aisec.backend.dto.scan;

import com.aisec.backend.entity.ScanResult;

import java.time.Instant;

public record ScanSummaryDto(
        Long id, String sourceType, String filename,
        Integer totalFlows, Integer benignCount, Integer attackCount,
        Double avgConfidence, Instant createdAt, String summaryJson,
        String metadataQualityJson, Boolean sampled,
        Integer originalRows, Integer sampledRows,
        String status, String errorMessage, Instant completedAt
) {
    public static ScanSummaryDto from(ScanResult s) {
        return new ScanSummaryDto(s.getId(), s.getSourceType(), s.getFilename(),
                s.getTotalFlows(), s.getBenignCount(), s.getAttackCount(),
                s.getAvgConfidence(), s.getCreatedAt(), s.getSummaryJson(),
                s.getMetadataQualityJson(), s.getSampled(), s.getOriginalRows(), s.getSampledRows(),
                s.getStatus(), s.getErrorMessage(), s.getCompletedAt());
    }
}
