package com.aisec.backend.controller;

import com.aisec.backend.dto.auth.AuthResponse;
import com.aisec.backend.dto.auth.ForgotPasswordRequest;
import com.aisec.backend.dto.auth.LoginRequest;
import com.aisec.backend.dto.auth.RegisterRequest;
import com.aisec.backend.dto.auth.ResetPasswordRequest;
import com.aisec.backend.dto.auth.WelcomeEmailRequest;
import com.aisec.backend.dto.user.UserDto;
import com.aisec.backend.repository.UserRepository;
import com.aisec.backend.service.AuthService;
import com.aisec.backend.service.PasswordResetService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService auth;
    private final UserRepository users;
    private final PasswordResetService passwordResetService;

    public AuthController(AuthService auth, UserRepository users,
                          PasswordResetService passwordResetService) {
        this.auth = auth;
        this.users = users;
        this.passwordResetService = passwordResetService;
    }

    @PostMapping("/register")
    public AuthResponse register(@Valid @RequestBody RegisterRequest req) {
        return auth.register(req);
    }

    @PostMapping("/login")
    public AuthResponse login(@Valid @RequestBody LoginRequest req) {
        return auth.login(req);
    }

    @GetMapping("/me")
    public UserDto me(@AuthenticationPrincipal UserDetails principal) {
        var u = users.findByUsername(principal.getUsername()).orElseThrow();
        return UserDto.from(u);
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<Map<String, String>> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest req) {
        try {
            passwordResetService.requestReset(req.email());
            return ResponseEntity.ok(Map.of("message", "Reset code sent to your email."));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest().body(Map.of("error", ex.getMessage()));
        }
    }

    @PostMapping("/verify-reset-code")
    public ResponseEntity<Map<String, String>> verifyResetCode(
            @RequestBody Map<String, String> req) {
        try {
            passwordResetService.verifyCode(req.get("email"), req.get("code"));
            return ResponseEntity.ok(Map.of("message", "Code is valid."));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest().body(Map.of("error", ex.getMessage()));
        }
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Map<String, String>> resetPassword(
            @Valid @RequestBody ResetPasswordRequest req) {
        try {
            passwordResetService.resetPassword(req.email(), req.code(), req.newPassword());
            return ResponseEntity.ok(Map.of("message", "Password updated successfully."));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest().body(Map.of("error", ex.getMessage()));
        }
    }

    @PostMapping("/welcome-email")
    public ResponseEntity<Map<String, String>> sendWelcomeEmail(
            @Valid @RequestBody WelcomeEmailRequest req) {
        passwordResetService.sendWelcomeEmail(req.email(), req.fullName(), req.username(), req.password());
        return ResponseEntity.ok(Map.of("message", "Welcome email sent."));
    }
}
