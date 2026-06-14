package com.aisec.backend.security;

import com.aisec.backend.service.AuditService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * In-memory token-bucket rate limiter for sensitive auth endpoints.
 *
 * Why not Bucket4j / Redis?
 *   – No new dependency, no extra infra.
 *   – Buckets are per IP; a single Spring instance is fine for a few hundred
 *     concurrent attackers. Behind a load balancer you'd swap in Redis.
 *
 * Limits (intentionally tight):
 *   /api/auth/login           : 10 requests / 60 s per IP
 *   /api/auth/forgot-password : 5  requests / 5 min per IP
 *   /api/auth/reset-password  : 5  requests / 5 min per IP
 *   /api/company-request      : 3  requests / 10 min per IP
 *
 * Returns 429 with a hint header ("Retry-After: <seconds>") when exhausted.
 */
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RateLimitFilter.class);

    private static final class Limit {
        final int max;
        final long windowMs;
        Limit(int max, long windowMs) { this.max = max; this.windowMs = windowMs; }
    }

    private static final java.util.Map<String, Limit> RULES = java.util.Map.of(
            "/api/auth/login",            new Limit(10, 60_000),
            "/api/auth/forgot-password",  new Limit(5,  300_000),
            "/api/auth/verify-reset-code",new Limit(20, 300_000),
            "/api/auth/reset-password",   new Limit(5,  300_000),
            "/api/company-request",       new Limit(3,  600_000)
    );

    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();
    private final AuditService audit;

    public RateLimitFilter(AuditService audit) { this.audit = audit; }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest req, @NonNull HttpServletResponse res, @NonNull FilterChain chain)
            throws ServletException, IOException {

        if (!"POST".equalsIgnoreCase(req.getMethod())) {
            chain.doFilter(req, res);
            return;
        }
        Limit limit = RULES.get(req.getRequestURI());
        if (limit == null) {
            chain.doFilter(req, res);
            return;
        }

        String ip = clientIp(req);
        String key = ip + "|" + req.getRequestURI();
        Bucket b = buckets.computeIfAbsent(key, k -> new Bucket());

        long now = System.currentTimeMillis();
        long retryAfterMs = b.tryAcquire(now, limit);
        if (retryAfterMs > 0) {
            log.warn("Rate limit hit: ip={} path={} retryAfter={}ms", ip, req.getRequestURI(), retryAfterMs);
            audit.logAnonymous("RATE_LIMIT", null, req.getRequestURI() + " from " + ip);
            res.setStatus(429);  // SC_TOO_MANY_REQUESTS — not defined as a constant in Servlet API
            res.setHeader("Retry-After", String.valueOf((retryAfterMs + 999) / 1000));
            res.setContentType("application/json");
            res.getWriter().write(
                "{\"error\":\"Too many requests. Try again in " +
                ((retryAfterMs + 999) / 1000) + "s.\"}"
            );
            return;
        }
        chain.doFilter(req, res);
    }

    private static String clientIp(HttpServletRequest req) {
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) return xff.split(",")[0].trim();
        return req.getRemoteAddr();
    }

    /**
     * Periodically drop buckets whose window has long since expired.
     * Without this, a sustained scan from thousands of IPs would leak memory
     * indefinitely. Runs every 5 minutes; thread-safe via ConcurrentHashMap.
     */
    @Scheduled(fixedDelay = 300_000, initialDelay = 300_000)
    public void cleanupStaleBuckets() {
        long cutoff = System.currentTimeMillis() - 3_600_000L; // 1 hour
        int before = buckets.size();
        buckets.entrySet().removeIf(e -> e.getValue().windowStart.get() < cutoff);
        int after = buckets.size();
        if (before != after) {
            log.debug("Rate-limit bucket cleanup: dropped {} stale entries ({} -> {})",
                    before - after, before, after);
        }
    }

    /**
     * Sliding-window counter — cheaper than a queue of timestamps and accurate
     * enough for human-scale abuse (we don't care about microsecond precision).
     */
    private static final class Bucket {
        private final AtomicLong windowStart = new AtomicLong(0);
        private final AtomicLong count = new AtomicLong(0);

        /** Returns 0 if request is allowed, else the time in ms until the window resets. */
        long tryAcquire(long now, Limit limit) {
            synchronized (this) {
                long start = windowStart.get();
                if (start == 0 || now - start >= limit.windowMs) {
                    windowStart.set(now);
                    count.set(1);
                    return 0;
                }
                if (count.incrementAndGet() <= limit.max) {
                    return 0;
                }
                return limit.windowMs - (now - start);
            }
        }
    }
}
