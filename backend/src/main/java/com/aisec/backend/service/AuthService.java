package com.aisec.backend.service;

import com.aisec.backend.dto.auth.AuthResponse;
import com.aisec.backend.dto.auth.LoginRequest;
import com.aisec.backend.dto.auth.RegisterRequest;
import com.aisec.backend.entity.Role;
import com.aisec.backend.entity.UserAccount;
import com.aisec.backend.repository.UserRepository;
import com.aisec.backend.security.JwtService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

import java.time.Instant;

@Service
public class AuthService {

    private final UserRepository users;
    private final PasswordEncoder encoder;
    private final AuthenticationManager authManager;
    private final JwtService jwt;
    private final AuditService audit;

    public AuthService(UserRepository users, PasswordEncoder encoder,
                       AuthenticationManager authManager, JwtService jwt,
                       AuditService audit) {
        this.users = users;
        this.encoder = encoder;
        this.authManager = authManager;
        this.jwt = jwt;
        this.audit = audit;
    }

    @Transactional
    public AuthResponse register(RegisterRequest req) {
        if (users.existsByUsername(req.username()))
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Username already taken");
        if (users.existsByEmail(req.email()))
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already taken");

        UserAccount u = new UserAccount();
        u.setUsername(req.username());
        u.setEmail(req.email());
        u.setFullName(req.fullName());
        u.setPasswordHash(encoder.encode(req.password()));
        u.setRole(Role.VIEWER);
        users.save(u);

        audit.logAnonymous("REGISTER_OK", u.getUsername(), "role=" + u.getRole());
        return buildToken(u);
    }

    @Transactional
    public AuthResponse login(LoginRequest req) {
        try {
            authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(req.username(), req.password()));
        } catch (BadCredentialsException ex) {
            audit.logAnonymous("LOGIN_FAIL", req.username(), "bad credentials");
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }
        UserAccount u = users.findByUsername(req.username()).orElseThrow();
        u.setLastLoginAt(Instant.now());
        users.save(u);
        audit.logAnonymous("LOGIN_OK", u.getUsername(),
                "role=" + u.getRole() + " org=" + (u.getOrganization() != null ? u.getOrganization().getName() : "system"));
        return buildToken(u);
    }

    private AuthResponse buildToken(UserAccount u) {
        Long orgId   = u.getOrganization() != null ? u.getOrganization().getId()   : null;
        String orgName = u.getOrganization() != null ? u.getOrganization().getName() : null;
        String token = jwt.generate(u.getUsername(), u.getRole().name(), orgId);
        return new AuthResponse(token, u.getUsername(), u.getRole().name(),
                u.getFullName(), jwt.getExpirationMs(), orgId, orgName);
    }
}
