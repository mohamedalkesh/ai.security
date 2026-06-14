package com.aisec.backend.dto.firewall;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Payload for {@code POST /api/firewall/blocklist}.
 *
 * <p>The IP regex accepts plain IPv4, IPv4 with /24-style CIDR suffix, and
 * compact IPv6. We deliberately keep validation permissive (length-bound)
 * to avoid blocking corner-case formats analysts paste in from logs;
 * tighter normalisation happens server-side in {@code BlockedIpService}.
 */
public record BlockIpRequest(
        @NotBlank @Size(max = 64)
        @Pattern(regexp = "^[0-9a-fA-F:.\\/]+$", message = "Invalid IP / CIDR format")
        String ip,

        @Size(max = 512)
        String reason,

        /** Optional ISO-8601 expiry. Null = permanent. */
        String expiresAt,

        /** Optional alert that triggered this block (for audit linkage). */
        Long sourceAlertId
) {}
