package com.aisec.backend.dto.alert;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;

/**
 * Request payload for AI-assisted auto-resolve operations.
 */
public record AutoResolveRequest(
        @NotBlank String maxSeverity,
        Double minConfidence,
        @Min(1) @Max(500) Integer limit,
        String reason,
        boolean dryRun
) {
    public AutoResolveRequest {
        maxSeverity = (maxSeverity == null || maxSeverity.isBlank()) ? "MEDIUM" : maxSeverity;
        limit = (limit == null) ? 200 : Math.max(1, Math.min(limit, 500));
        reason = (reason == null || reason.isBlank()) ? "ai_auto_resolve" : reason;
    }
}
