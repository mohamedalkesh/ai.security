package com.aisec.backend.dto.user;

import com.aisec.backend.entity.UserAccount;

import java.time.Instant;

public record UserDto(
        Long id, String username, String email, String fullName,
        String role, boolean enabled, Instant createdAt, Instant lastLoginAt,
        Long organizationId, String organizationName
) {
    public static UserDto from(UserAccount u) {
        Long orgId   = u.getOrganization() != null ? u.getOrganization().getId()   : null;
        String orgName = u.getOrganization() != null ? u.getOrganization().getName() : null;
        return new UserDto(u.getId(), u.getUsername(), u.getEmail(), u.getFullName(),
                u.getRole().name(), u.isEnabled(), u.getCreatedAt(), u.getLastLoginAt(),
                orgId, orgName);
    }
}
