package com.aisec.backend.dto.auth;

public record AuthResponse(String token, String username, String role, String fullName, long expiresInMs,
                           Long organizationId, String organizationName) {}
