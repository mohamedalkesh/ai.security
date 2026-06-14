package com.aisec.backend.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Adds security response headers to every HTTP response.
 * These prevent the most common browser-level attacks:
 * clickjacking, MIME sniffing, XSS, and information leakage.
 */
@Component
@Order(1)
public class SecurityHeadersFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain chain)
            throws ServletException, IOException {

        // Prevent clickjacking — deny framing from any origin.
        response.setHeader("X-Frame-Options", "DENY");

        // Disable MIME type sniffing — browser must honour Content-Type.
        response.setHeader("X-Content-Type-Options", "nosniff");

        // Basic XSS protection for older browsers (modern ones use CSP).
        response.setHeader("X-XSS-Protection", "1; mode=block");

        // Content Security Policy — restrictive default; API is consumed by
        // JS clients so we only need to protect the /actuator HTML pages.
        response.setHeader("Content-Security-Policy",
                "default-src 'none'; frame-ancestors 'none'");

        // Do not send Referer header when navigating away.
        response.setHeader("Referrer-Policy", "no-referrer");

        // Force HTTPS for 1 year once the browser has visited over HTTPS.
        // Safe to include even when behind a reverse-proxy that terminates TLS.
        response.setHeader("Strict-Transport-Security",
                "max-age=31536000; includeSubDomains");

        // Hide the server technology stack.
        response.setHeader("Server", "");

        chain.doFilter(request, response);
    }
}
