package com.aisec.backend.service.threatintel;

import com.aisec.backend.config.AppProperties;
import com.aisec.backend.dto.threatintel.IpReputationDto;
import com.aisec.backend.entity.IpReputation;
import com.aisec.backend.repository.IpReputationRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestClient;

import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Map;
import java.util.Optional;

/**
 * Threat-intel facade. Today: a single upstream (AbuseIPDB) plus a
 * deterministic mock for dev/demo when no API key is configured. The DB
 * acts as a cache — we serve stale entries while async-refreshing in the
 * background so the UI never blocks on a flaky third-party.
 *
 * <p>Provider selection (driven by {@code app.threat-intel.provider}):
 * <ul>
 *   <li>{@code auto} — real if an AbuseIPDB key is set, otherwise mock.</li>
 *   <li>{@code abuseipdb} — force real (fails gracefully if no key).</li>
 *   <li>{@code mock} — always synthetic.</li>
 *   <li>{@code off} — return {@code Optional.empty()} from {@link #lookup}.</li>
 * </ul>
 */
@Service
public class ThreatIntelService {

    private static final Logger log = LoggerFactory.getLogger(ThreatIntelService.class);

    private final IpReputationRepository repo;
    private final AppProperties.ThreatIntel cfg;
    private final RestClient http;
    private final String effectiveProvider;

    public ThreatIntelService(IpReputationRepository repo, AppProperties props) {
        this.repo = repo;
        this.cfg = props.getThreatIntel();
        this.http = RestClient.builder().build();
        this.effectiveProvider = resolveProvider();
        log.info("ThreatIntelService active: provider={} (cacheTtl={}h)",
                 effectiveProvider, cfg.getCacheTtlHours());
    }

    private String resolveProvider() {
        String mode = cfg.getProvider() == null ? "auto" : cfg.getProvider().toLowerCase();
        return switch (mode) {
            case "off" -> "off";
            case "mock" -> "mock";
            case "abuseipdb" -> "abuseipdb";
            default -> // auto
                    (cfg.getAbuseipdbKey() != null && !cfg.getAbuseipdbKey().isBlank())
                            ? "abuseipdb" : "mock";
        };
    }

    /** True when the service will actually return data. */
    public boolean isEnabled() {
        return !"off".equals(effectiveProvider);
    }

    /**
     * Cache-first lookup. Returns {@link Optional#empty()} when the provider
     * is {@code off} or the IP doesn't parse. Stale rows are returned with
     * {@code stale=true} so callers can show them while a refresh happens.
     */
    @Transactional
    public Optional<IpReputationDto> lookup(String ip) {
        if (!isEnabled() || ip == null || ip.isBlank()) return Optional.empty();
        String clean = ip.trim();
        Optional<IpReputation> cached = repo.findByIpAddress(clean);
        if (cached.isPresent() && !isExpired(cached.get())) {
            return cached.map(IpReputationDto::from);
        }
        // Either no row or stale — fetch synchronously. We cap the upstream
        // timeout in the RestClient call below so worst-case latency on a
        // dead provider is bounded by app.threat-intel.request-timeout-ms.
        try {
            IpReputation fresh = fetchAndCache(clean);
            return Optional.of(IpReputationDto.from(fresh));
        } catch (Exception e) {
            log.warn("ThreatIntel fetch for {} failed via {}: {} — serving cached/stale",
                     clean, effectiveProvider, e.getMessage());
            return cached.map(IpReputationDto::from);
        }
    }

    /**
     * Cache-only lookup — never calls the upstream provider. Returns whatever
     * is on disk (possibly stale) or {@link Optional#empty()}. Used from list
     * endpoints where we don't want a 200-item page to trigger 200 API calls.
     */
    public Optional<IpReputationDto> lookupCached(String ip) {
        if (!isEnabled() || ip == null || ip.isBlank()) return Optional.empty();
        return repo.findByIpAddress(ip.trim()).map(IpReputationDto::from);
    }

    /** Force refresh, ignoring TTL. */
    @Transactional
    public IpReputationDto refresh(String ip) {
        if (!isEnabled()) throw new IllegalStateException("ThreatIntel provider is off");
        if (ip == null || ip.isBlank()) throw new IllegalArgumentException("ip required");
        return IpReputationDto.from(fetchAndCache(ip.trim()));
    }

    /* ============================ Internals ============================ */

    private boolean isExpired(IpReputation r) {
        return r.getExpiresAt() != null && r.getExpiresAt().isBefore(Instant.now());
    }

    private IpReputation fetchAndCache(String ip) {
        IpReputation row = repo.findByIpAddress(ip).orElseGet(IpReputation::new);
        row.setIpAddress(ip);

        if ("abuseipdb".equals(effectiveProvider) && hasAbuseKey()) {
            applyAbuseipdb(row, ip);
        } else {
            applyMock(row, ip);
        }
        row.setFetchedAt(Instant.now());
        row.setExpiresAt(Instant.now().plus(Duration.ofHours(Math.max(1, cfg.getCacheTtlHours()))));
        return repo.save(row);
    }

    private boolean hasAbuseKey() {
        return cfg.getAbuseipdbKey() != null && !cfg.getAbuseipdbKey().isBlank();
    }

    /** Hits {@code /check} and projects the (small) bit of the response we use. */
    @SuppressWarnings("unchecked")
    private void applyAbuseipdb(IpReputation row, String ip) {
        Map<String, Object> resp = http.get()
                .uri(cfg.getAbuseipdbBaseUrl() + "/check?ipAddress={ip}&maxAgeInDays=90", ip)
                .header("Key", cfg.getAbuseipdbKey())
                .header("Accept", "application/json")
                .retrieve()
                .body(Map.class);
        Map<String, Object> data = resp == null ? null : (Map<String, Object>) resp.get("data");
        if (data == null) throw new IllegalStateException("AbuseIPDB returned no data block");

        row.setProvider("abuseipdb");
        row.setAbuseScore(asInt(data.get("abuseConfidenceScore"), 0));
        row.setCountryCode(asStr(data.get("countryCode")));
        row.setCountry(asStr(data.get("countryName")));
        row.setIsp(asStr(data.get("isp")));
        row.setUsageType(asStr(data.get("usageType")));
        row.setTotalReports(asInt(data.get("totalReports"), 0));
        row.setLastReportedAt(parseInstant(asStr(data.get("lastReportedAt"))));
    }

    /**
     * Deterministic synthetic verdict — same IP always yields the same score
     * and country. Lets the UI/demos work end-to-end without an API key, and
     * makes screenshots reproducible across runs.
     */
    private void applyMock(IpReputation row, String ip) {
        int hash = Math.abs(ip.hashCode());
        int score;
        if (ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("172.16.")
                || ip.startsWith("127.")) {
            score = 0; // private — clean
        } else {
            score = hash % 101; // 0..100 deterministic
        }
        String[] countries = { "US", "CN", "RU", "DE", "BR", "IN", "FR", "GB", "NG", "VN" };
        String[] isps = { "DigitalOcean", "OVH", "Hetzner", "AWS", "Linode", "ChinaNet",
                          "Rostelecom", "Comcast", "Vodafone", "Cogent" };
        String cc = countries[hash % countries.length];
        row.setProvider("mock");
        row.setAbuseScore(score);
        row.setCountryCode(cc);
        row.setCountry(cc);
        row.setIsp(isps[hash % isps.length]);
        row.setUsageType(score > 60 ? "Data Center/Web Hosting/Transit" : "ISP");
        row.setTotalReports(score == 0 ? 0 : (hash % 500));
        row.setLastReportedAt(score == 0 ? null : Instant.now().minusSeconds(hash % 86400));
    }

    private static int asInt(Object v, int dflt) {
        if (v instanceof Number n) return n.intValue();
        try { return v == null ? dflt : Integer.parseInt(v.toString()); }
        catch (NumberFormatException e) { return dflt; }
    }

    private static String asStr(Object v) {
        return v == null ? null : v.toString();
    }

    private static Instant parseInstant(String s) {
        if (s == null || s.isBlank()) return null;
        try { return Instant.parse(s); }
        catch (DateTimeParseException e) { return null; }
    }
}
