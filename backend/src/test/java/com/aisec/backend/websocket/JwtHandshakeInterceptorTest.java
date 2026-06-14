package com.aisec.backend.websocket;

import com.aisec.backend.security.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.socket.WebSocketHandler;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Verifies the WebSocket handshake JWT gate:
 *   - no token → 401 + reject
 *   - invalid token → 401 + reject
 *   - valid token → accept + populate session attributes
 */
class JwtHandshakeInterceptorTest {

    private JwtService jwt;
    private JwtHandshakeInterceptor interceptor;

    @BeforeEach
    void setUp() {
        jwt = new JwtService();
        ReflectionTestUtils.setField(jwt, "secret",
                "dGVzdC1zZWNyZXQtMzItYnl0ZXMtZm9yLWp3dC1zaWduaW5nLWFhYWE=");
        ReflectionTestUtils.setField(jwt, "expirationMs", 3_600_000L);
        // init() is package-private; invoke via reflection since we're in a different package.
        ReflectionTestUtils.invokeMethod(jwt, "init");
        interceptor = new JwtHandshakeInterceptor(jwt);
    }

    private boolean doHandshake(String query, Map<String, Object> attrs) {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/ws/alerts");
        if (query != null) req.setQueryString(query);
        MockHttpServletResponse res = new MockHttpServletResponse();
        return interceptor.beforeHandshake(
                new ServletServerHttpRequest(req),
                new ServletServerHttpResponse(res),
                mock(WebSocketHandler.class),
                attrs);
    }

    @Test
    void rejects_when_no_token_is_present() {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/ws/alerts");
        MockHttpServletResponse res = new MockHttpServletResponse();
        boolean ok = interceptor.beforeHandshake(
                new ServletServerHttpRequest(req),
                new ServletServerHttpResponse(res),
                mock(WebSocketHandler.class),
                new HashMap<>());

        assertThat(ok).isFalse();
        assertThat(res.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
    }

    @Test
    void rejects_when_token_is_malformed() {
        Map<String, Object> attrs = new HashMap<>();
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/ws/alerts");
        req.setQueryString("token=not.a.jwt");
        MockHttpServletResponse res = new MockHttpServletResponse();

        boolean ok = interceptor.beforeHandshake(
                new ServletServerHttpRequest(req),
                new ServletServerHttpResponse(res),
                mock(WebSocketHandler.class),
                attrs);

        assertThat(ok).isFalse();
        assertThat(res.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
        assertThat(attrs).isEmpty();
    }

    @Test
    void accepts_valid_token_and_populates_attributes() {
        String token = jwt.generate("alice", "ADMIN");
        Map<String, Object> attrs = new HashMap<>();

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/ws/alerts");
        req.setQueryString("token=" + token);
        MockHttpServletResponse res = new MockHttpServletResponse();

        boolean ok = interceptor.beforeHandshake(
                new ServletServerHttpRequest(req),
                new ServletServerHttpResponse(res),
                mock(WebSocketHandler.class),
                attrs);

        assertThat(ok).isTrue();
        assertThat(attrs).containsEntry("username", "alice");
        assertThat(attrs).containsEntry("role", "ADMIN");
    }

    @Test
    void accepts_token_from_Authorization_header_when_query_is_missing() {
        String token = jwt.generate("bob", "ANALYST");
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/ws/alerts");
        req.addHeader("Authorization", "Bearer " + token);
        MockHttpServletResponse res = new MockHttpServletResponse();

        Map<String, Object> attrs = new HashMap<>();
        boolean ok = interceptor.beforeHandshake(
                new ServletServerHttpRequest(req),
                new ServletServerHttpResponse(res),
                mock(WebSocketHandler.class),
                attrs);

        assertThat(ok).isTrue();
        assertThat(attrs).containsEntry("username", "bob");
    }
}
