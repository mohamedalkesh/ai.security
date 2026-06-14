package com.aisec.backend.dto.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Payload for authenticated user creation (POST /api/users).
 *
 * - When called by ORG_ADMIN: organizationId is ignored; the new user
 *   inherits the caller's organisation automatically.
 * - When called by system ADMIN: organizationId selects the target tenant.
 *   Required for non-system roles (ORG_ADMIN/ANALYST/VIEWER); null means
 *   "system tenant" (only valid for role=ADMIN).
 */
public record CreateUserRequest(
        @NotBlank @Size(min = 3, max = 80)  String username,
        @NotBlank @Email                    String email,
        @NotBlank @Size(min = 1, max = 100) String fullName,
        @NotBlank @Size(min = 6, max = 100) String password,
        @NotBlank                           String role,
                                            Long   organizationId
) {}
