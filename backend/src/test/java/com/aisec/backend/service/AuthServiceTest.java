package com.aisec.backend.service;

import com.aisec.backend.dto.auth.AuthResponse;
import com.aisec.backend.dto.auth.LoginRequest;
import com.aisec.backend.dto.auth.RegisterRequest;
import com.aisec.backend.entity.Role;
import com.aisec.backend.entity.UserAccount;
import com.aisec.backend.config.AppProperties;
import com.aisec.backend.repository.UserRepository;
import com.aisec.backend.security.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link AuthService} — exercises register() and login() paths
 * with mocked repository, encoder, and auth manager.
 */
@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock UserRepository users;
    @Mock PasswordEncoder encoder;
    @Mock AuthenticationManager authManager;
    @Mock JwtService jwt;
    @Mock AuditService audit;

    AppProperties appProperties;
    AuthService service;

    @BeforeEach
    void setUp() {
        // Use a real AppProperties so register() self-registration gate is open.
        appProperties = new AppProperties();
        appProperties.getSecurity().setAllowSelfRegister(true);
        service = new AuthService(users, encoder, authManager, jwt, audit, appProperties);

        lenient().when(jwt.generate(any(), any())).thenReturn("mock.jwt.token");
        lenient().when(jwt.generate(any(), any(), any())).thenReturn("mock.jwt.token");
        lenient().when(jwt.getExpirationMs()).thenReturn(60_000L);
    }

    @Test
    void register_creates_user_with_VIEWER_role_and_hashed_password() {
        when(users.existsByUsername("alice")).thenReturn(false);
        when(users.existsByEmail("a@x.com")).thenReturn(false);
        when(encoder.encode("secret")).thenReturn("HASHED");
        when(users.save(any(UserAccount.class))).thenAnswer(inv -> inv.getArgument(0));

        RegisterRequest req = new RegisterRequest("alice", "a@x.com", "Alice", "secret");
        AuthResponse resp = service.register(req);

        assertThat(resp.token()).isEqualTo("mock.jwt.token");
        assertThat(resp.role()).isEqualTo("VIEWER");

        verify(users).save(argThat(u ->
                u.getUsername().equals("alice") &&
                u.getEmail().equals("a@x.com") &&
                u.getPasswordHash().equals("HASHED") &&
                u.getRole() == Role.VIEWER
        ));
    }

    @Test
    void register_rejects_duplicate_username() {
        when(users.existsByUsername("alice")).thenReturn(true);

        RegisterRequest req = new RegisterRequest("alice", "a@x.com", "Alice", "secret");
        assertThatThrownBy(() -> service.register(req))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("Username already taken");
        verify(users, never()).save(any());
    }

    @Test
    void register_rejects_duplicate_email() {
        when(users.existsByUsername("alice")).thenReturn(false);
        when(users.existsByEmail("a@x.com")).thenReturn(true);

        assertThatThrownBy(() -> service.register(new RegisterRequest("alice", "a@x.com", "Alice", "secret")))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("Email already taken");
        verify(users, never()).save(any());
    }

    @Test
    void login_issues_token_on_valid_credentials() {
        UserAccount u = new UserAccount();
        u.setUsername("alice");
        u.setEmail("a@x.com");
        u.setFullName("Alice");
        u.setPasswordHash("HASHED");
        u.setRole(Role.ADMIN);

        when(authManager.authenticate(any(UsernamePasswordAuthenticationToken.class))).thenReturn(null);
        when(users.findByUsername("alice")).thenReturn(Optional.of(u));
        when(users.save(any(UserAccount.class))).thenAnswer(inv -> inv.getArgument(0));

        AuthResponse resp = service.login(new LoginRequest("alice", "secret"));

        assertThat(resp.token()).isEqualTo("mock.jwt.token");
        assertThat(resp.role()).isEqualTo("ADMIN");
        assertThat(u.getLastLoginAt()).isNotNull();
        verify(jwt).generate("alice", "ADMIN", null);
    }

    @Test
    void login_rejects_bad_credentials_with_401() {
        when(authManager.authenticate(any())).thenThrow(new BadCredentialsException("bad"));

        assertThatThrownBy(() -> service.login(new LoginRequest("alice", "wrong")))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("Invalid credentials");

        verify(users, never()).save(any());
        verify(jwt,   never()).generate(any(), any());
    }
}
