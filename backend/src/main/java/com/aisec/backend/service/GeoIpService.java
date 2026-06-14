package com.aisec.backend.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Lazy GeoIP lookup via ip-api.com (free, no key, 45 req/min, batch up to 100).
 *
 * Design:
 *   - Synchronous {@link #lookup(String)} uses a strict 1s/2s timeout so a
 *     misbehaving GeoIP provider never wedges the request thread.
 *   - {@link #enrichAsync(Long, String, String, java.util.function.BiConsumer)}
 *     runs on the dedicated {@code geoIpExecutor} pool so alert persistence is
 *     never blocked by an external API call.
 *   - Negative cache TTL: failed lookups expire after 1h, so a transient
 *     ip-api.com outage doesn't poison the cache forever.
 *   - Private IPs (RFC1918, loopback, link-local) return null without a call.
 */
@Service
public class GeoIpService {

    private static final Logger log = LoggerFactory.getLogger(GeoIpService.class);
    private static final String BATCH_URL = "http://ip-api.com/batch?fields=status,query,countryCode";
    private static final Duration NEGATIVE_TTL = Duration.ofHours(1);

    private static final class CacheEntry {
        final String cc;          // null for "lookup failed / not found"
        final Instant expiresAt;  // never expires when cc != null
        CacheEntry(String cc) {
            this.cc = cc;
            this.expiresAt = cc == null ? Instant.now().plus(NEGATIVE_TTL) : null;
        }
        boolean isExpired() { return expiresAt != null && Instant.now().isAfter(expiresAt); }
    }

    private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();
    private final RestClient http;

    @Value("${app.geoip.enabled:true}")
    private boolean enabled;

    public GeoIpService() {
        SimpleClientHttpRequestFactory rf = new SimpleClientHttpRequestFactory();
        rf.setConnectTimeout(1000);   // 1s connect
        rf.setReadTimeout(2000);      // 2s read — past this we give up
        this.http = RestClient.builder().requestFactory(rf).build();
    }

    /** Returns ISO-2 country code, or null for private / unknown / error. */
    public String lookup(String ip) {
        if (!enabled || ip == null || ip.isBlank() || isPrivate(ip)) return null;

        CacheEntry hit = cache.get(ip);
        if (hit != null && !hit.isExpired()) return hit.cc;

        try {
            List<Map<String, String>> body = List.of(Map.of("query", ip));
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> resp = http.post()
                    .uri(BATCH_URL)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(body)
                    .retrieve()
                    .body(List.class);
            if (resp == null || resp.isEmpty()) return cachePut(ip, null);
            Object cc = resp.get(0).get("countryCode");
            return cachePut(ip, cc == null ? null : cc.toString());
        } catch (Exception e) {
            log.debug("GeoIP lookup failed for {}: {}", ip, e.getMessage());
            return cachePut(ip, null);
        }
    }

    /**
     * Async enrichment hook — called AFTER the alert is persisted.
     * Runs on the dedicated geoIpExecutor so request threads never wait on
     * ip-api.com. The {@code persist} callback receives the resolved
     * (srcCountry, dstCountry) pair and is responsible for writing them back.
     */
    @Async("geoIpExecutor")
    public void enrichAsync(String srcIp, String dstIp,
                            java.util.function.BiConsumer<String, String> persist) {
        String src = lookup(srcIp);
        String dst = lookup(dstIp);
        if (src != null || dst != null) {
            try { persist.accept(src, dst); }
            catch (Exception e) { log.debug("GeoIP persist failed: {}", e.getMessage()); }
        }
    }

    private String cachePut(String ip, String cc) {
        cache.put(ip, new CacheEntry(cc));
        return cc;
    }

    /** RFC1918 + loopback + link-local — anything that won't resolve publicly. */
    static boolean isPrivate(String ip) {
        if (ip == null) return true;
        if (ip.startsWith("10.")) return true;
        if (ip.startsWith("127.")) return true;
        if (ip.startsWith("192.168.")) return true;
        if (ip.startsWith("169.254.")) return true;
        if (ip.startsWith("172.")) {
            try {
                int dot = ip.indexOf('.', 4);
                if (dot > 4) {
                    int o2 = Integer.parseInt(ip.substring(4, dot));
                    if (o2 >= 16 && o2 <= 31) return true;
                }
            } catch (Exception ignored) {}
        }
        if (ip.equals("::1") || ip.startsWith("fe80:") || ip.startsWith("fc") || ip.startsWith("fd")) return true;
        return false;
    }

    /** Diagnostic — exposed for /actuator-style cache inspection if needed. */
    public int cacheSize() { return cache.size(); }
}
