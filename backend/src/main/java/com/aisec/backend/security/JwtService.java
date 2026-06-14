package com.aisec.backend.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtService {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(JwtService.class);
    private static final String DEMO_SECRET = "Y2hhbmdlLW1lLXBsZWFzZS10aGlzLWlzLWEtZGVtby1zZWNyZXQtMTIzNA==";

    @Value("${app.jwt.secret}")
    private String secret;

    @Value("${app.jwt.expiration-ms}")
    private long expirationMs;

    private SecretKey key;

    @PostConstruct
    void init() {
        byte[] bytes = Decoders.BASE64.decode(secret);
        if (bytes.length < 32) {
            throw new IllegalStateException(
                "JWT secret too short (" + bytes.length + " bytes). Minimum required: 32 bytes (256 bits). " +
                "Generate a secure key with: openssl rand -base64 32");
        }
        if (secret.equals(DEMO_SECRET)) {
            log.warn("=============================================================");
            log.warn("  SECURITY WARNING: Using the default demo JWT secret!       ");
            log.warn("  Set APP_JWT_SECRET (or JWT_SECRET) env variable in prod.   ");
            log.warn("  Generate: openssl rand -base64 32                          ");
            log.warn("=============================================================");
        }
        this.key = Keys.hmacShaKeyFor(bytes);
    }

    public long getExpirationMs() { return expirationMs; }

    public String generate(String username, String role) {
        return generate(username, role, null);
    }

    public String generate(String username, String role, Long orgId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", role);
        if (orgId != null) claims.put("orgId", orgId);
        Date now = new Date();
        Date exp = new Date(now.getTime() + expirationMs);
        return Jwts.builder()
                .subject(username)
                .claims(claims)
                .issuedAt(now)
                .expiration(exp)
                .signWith(key)
                .compact();
    }

    public Long extractOrgId(String token) {
        Object val = parse(token).get("orgId");
        return val == null ? null : ((Number) val).longValue();
    }

    public Claims parse(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String extractUsername(String token) {
        return parse(token).getSubject();
    }
}
