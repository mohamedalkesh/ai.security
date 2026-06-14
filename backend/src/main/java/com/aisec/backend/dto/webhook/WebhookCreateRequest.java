package com.aisec.backend.dto.webhook;

import com.aisec.backend.entity.Severity;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record WebhookCreateRequest(
        @NotBlank @Size(max = 80) String name,
        @NotBlank @Size(max = 500) @Pattern(regexp = "^https?://.+") String url,
        Severity minSeverity,
        Boolean enabled,
        @Size(max = 16) String preset
) {}
