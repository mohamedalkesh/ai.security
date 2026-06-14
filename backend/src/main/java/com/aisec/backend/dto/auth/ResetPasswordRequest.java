package com.aisec.backend.dto.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ResetPasswordRequest(
    @NotBlank @Email String email,
    @NotBlank String code,
    @NotBlank @Size(min = 8, message = "Password must be at least 8 characters") String newPassword
) {}
