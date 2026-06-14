package com.aisec.backend.dto.webhook;

import com.aisec.backend.entity.Severity;
import com.aisec.backend.entity.WebhookConfig;

import java.time.Instant;

/** Read-only projection — never exposes the secret. */
public record WebhookConfigDto(
        Long id,
        String name,
        String url,
        Severity minSeverity,
        boolean enabled,
        String preset,
        Instant createdAt,
        Instant lastDeliveredAt,
        Integer lastStatusCode
) {
    public static WebhookConfigDto from(WebhookConfig w) {
        return new WebhookConfigDto(
                w.getId(), w.getName(), w.getUrl(), w.getMinSeverity(),
                w.isEnabled(), w.getPreset(), w.getCreatedAt(),
                w.getLastDeliveredAt(), w.getLastStatusCode());
    }
}
