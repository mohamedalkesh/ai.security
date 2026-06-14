package com.aisec.backend.dto.alert;

import jakarta.validation.constraints.NotEmpty;

import java.util.List;

/**
 * PATCH /api/alerts/bulk — apply the same status change to many alerts.
 * Caller-side org isolation still applies; alerts not in the caller's tenant
 * are silently dropped from the result.
 */
public record BulkUpdateRequest(
        @NotEmpty List<Long> ids,
        String status,
        String mlFeedback
) {}
