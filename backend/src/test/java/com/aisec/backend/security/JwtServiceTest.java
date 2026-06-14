package com.aisec.backend.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Pure unit tests for {@link JwtService} – exercises token generation, parsing,
 * role claims, and signature verification.
 */
class JwtServiceTest {

    private JwtService jwt;

    @BeforeEach
    void setUp() {
        jwt = new JwtService();
        // 32-byte base64 secret (256-bit) required by HS256
        ReflectionTestUtils.setField(jwt, "secret",
                "dGVzdC1zZWNyZXQtMzItYnl0ZXMtZm9yLWp3dC1zaWduaW5nLWFhYWE=");
        ReflectionTestUtils.setField(jwt, "expirationMs", 3_600_000L);
        jwt.init();
    }

    @Test
    void generate_produces_valid_signed_token() {
        String token = jwt.generate("alice", "ADMIN");

        assertThat(token).isNotBlank().contains(".");
        Claims c = jwt.parse(token);
        assertThat(c.getSubject()).isEqualTo("alice");
        assertThat(c.get("role", String.class)).isEqualTo("ADMIN");
    }

    @Test
    void extractUsername_returns_subject() {
        String token = jwt.generate("bob", "VIEWER");
        assertThat(jwt.extractUsername(token)).isEqualTo("bob");
    }

    @Test
    void parse_rejects_token_signed_with_different_key() {
        // Generate a token with the current key, then swap the key – parse must fail.
        String token = jwt.generate("carol", "ANALYST");

        JwtService other = new JwtService();
        ReflectionTestUtils.setField(other, "secret",
                "YW5vdGhlci1zZWNyZXQtMzItYnl0ZXMtZm9yLWp3dC1zaWduaW5nLXh4eA==");
        ReflectionTestUtils.setField(other, "expirationMs", 3_600_000L);
        other.init();

        assertThatThrownBy(() -> other.parse(token)).isInstanceOf(JwtException.class);
    }

    @Test
    void parse_rejects_expired_token() {
        ReflectionTestUtils.setField(jwt, "expirationMs", -1_000L); // already expired
        String expired = jwt.generate("dave", "VIEWER");
        assertThatThrownBy(() -> jwt.parse(expired)).isInstanceOf(JwtException.class);
    }

    @Test
    void parse_rejects_garbage() {
        assertThatThrownBy(() -> jwt.parse("not-a-jwt")).isInstanceOf(JwtException.class);
    }
}
