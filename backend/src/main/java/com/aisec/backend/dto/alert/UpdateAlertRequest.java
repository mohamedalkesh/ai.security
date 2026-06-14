package com.aisec.backend.dto.alert;

/**
 * PATCH /api/alerts/{id} body. All fields optional — set only what you want
 * to change. {@code assignedToId = -1} → unassign.
 */
public record UpdateAlertRequest(
        String status,
        Long assignedToId,
        String mlFeedback
) {}
