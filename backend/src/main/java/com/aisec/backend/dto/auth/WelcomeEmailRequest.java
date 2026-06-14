package com.aisec.backend.dto.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record WelcomeEmailRequest(
    @NotBlank @Email String email,
    @NotBlank String fullName,
    @NotBlank String username,
    @NotBlank String password
) {}
