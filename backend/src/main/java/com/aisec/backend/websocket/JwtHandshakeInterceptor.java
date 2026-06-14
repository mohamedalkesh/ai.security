package com.aisec.backend.websocket;

import com.aisec.backend.security.JwtService;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.server.HandshakeInterceptor;

import java.net.URI;
import java.util.Map;

/**
 * Verifies the JWT passed as `?token=...` on the WebSocket handshake URL.
 * Rejects unauthenticated upgrades with HTTP 401.
 */
@Component
public class JwtHandshakeInterceptor implements HandshakeInterceptor {

    private static final Logger log = LoggerFactory.getLogger(JwtHandshakeInterceptor.class);
    private final JwtService jwt;

    public JwtHandshakeInterceptor(JwtService jwt) { this.jwt = jwt; }

    @Override
    public boolean beforeHandshake(@NonNull ServerHttpRequest request,
                                   @NonNull ServerHttpResponse response,
                                   @NonNull WebSocketHandler wsHandler,
                                   @NonNull Map<String, Object> attributes) {
        String token = extractToken(request);
        if (token == null || token.isBlank()) {
            log.warn("WS handshake rejected: missing token from {}", clientInfo(request));
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return false;
        }
        try {
            Claims c = jwt.parse(token);
            attributes.put("username", c.getSubject());
            attributes.put("role",     c.get("role", String.class));
            // Tenant context — null for system users, Long for org users.
            Object orgClaim = c.get("orgId");
            Long orgId = null;
            if (orgClaim instanceof Number n) orgId = n.longValue();
            else if (orgClaim instanceof String s && !s.isBlank()) {
                try { orgId = Long.parseLong(s); } catch (NumberFormatException ignored) {}
            }
            attributes.put("orgId", orgId);
            return true;
        } catch (Exception e) {
            log.warn("WS handshake rejected: invalid token ({}) from {}", e.getMessage(), clientInfo(request));
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return false;
        }
    }

    @Override
    public void afterHandshake(@NonNull ServerHttpRequest request,
                               @NonNull ServerHttpResponse response,
                               @NonNull WebSocketHandler wsHandler,
                               Exception exception) { /* no-op */ }

    private static String extractToken(ServerHttpRequest request) {
        URI uri = request.getURI();
        String q = uri.getQuery();
        if (q != null) {
            for (String pair : q.split("&")) {
                int eq = pair.indexOf('=');
                if (eq > 0 && "token".equals(pair.substring(0, eq))) {
                    return java.net.URLDecoder.decode(pair.substring(eq + 1), java.nio.charset.StandardCharsets.UTF_8);
                }
            }
        }
        // Also allow ?access_token= for flexibility
        if (request instanceof ServletServerHttpRequest sr) {
            String header = sr.getServletRequest().getHeader("Authorization");
            if (header != null && header.startsWith("Bearer ")) return header.substring(7);
        }
        return null;
    }

    private static String clientInfo(ServerHttpRequest request) {
        if (request instanceof ServletServerHttpRequest sr) return sr.getServletRequest().getRemoteAddr();
        return "unknown";
    }
}
