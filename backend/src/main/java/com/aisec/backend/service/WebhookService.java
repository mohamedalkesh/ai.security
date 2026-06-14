package com.aisec.backend.service;

import com.aisec.backend.dto.alert.AlertDto;
import com.aisec.backend.entity.Severity;
import com.aisec.backend.entity.WebhookConfig;
import com.aisec.backend.repository.WebhookConfigRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Outbound webhook delivery for security alerts.
 *
 * Why custom and not Spring Cloud Stream / Kafka:
 *   - Pure HTTP fan-out, no broker required.
 *   - HMAC-SHA256 signing keeps integration server-side simple.
 *   - Slack / Discord / generic presets cover ~95% of SOC integrations.
 *
 * Delivery is fire-and-forget on {@code taskExecutor} — the alert pipeline
 * is never blocked or rolled back by a failing webhook receiver.
 */
@Service
public class WebhookService {

    private static final Logger log = LoggerFactory.getLogger(WebhookService.class);
    private static final SecureRandom RNG = new SecureRandom();

    private final WebhookConfigRepository repo;
    private final AuditService audit;
    private final ObjectMapper json = new ObjectMapper();
    private final RestClient http;

    public WebhookService(WebhookConfigRepository repo, AuditService audit) {
        this.repo = repo;
        this.audit = audit;
        SimpleClientHttpRequestFactory rf = new SimpleClientHttpRequestFactory();
        rf.setConnectTimeout(3000);
        rf.setReadTimeout(5000);
        this.http = RestClient.builder().requestFactory(rf).build();
    }

    /** Generate a 32-byte hex secret for new configs. */
    public String generateSecret() {
        byte[] b = new byte[32];
        RNG.nextBytes(b);
        return HexFormat.of().formatHex(b);
    }

    /**
     * Async fan-out hook — called from AlertService.save() after persistence.
     * Queries enabled hooks for the alert's tenant and dispatches in parallel.
     */
    @Async("taskExecutor")
    public void dispatchAlert(AlertDto alert, Long ownerOrgId) {
        try {
            List<WebhookConfig> hooks = repo.findEnabledByOrg(ownerOrgId);
            if (hooks.isEmpty()) return;

            Severity sev = parseSeverity(alert.severity());
            for (WebhookConfig w : hooks) {
                if (sev == null || sev.ordinal() < w.getMinSeverity().ordinal()) continue;
                deliver(w, alert);
            }
        } catch (Exception e) {
            log.warn("Webhook fan-out failed: {}", e.getMessage());
        }
    }

    /** Backoff schedule for retries — 1 s, 4 s, 16 s (3 attempts total). */
    private static final long[] BACKOFF_MS = { 0L, 1_000L, 4_000L, 16_000L };

    /**
     * Single-receiver delivery with signing, status tracking and bounded retry.
     *
     * Retry policy:
     *   - Transport error (DNS, timeout, refused)  → retry
     *   - HTTP 5xx (server problem on receiver)    → retry
     *   - HTTP 4xx (bad URL, bad signature, etc.)  → permanent, stop now
     *   - HTTP 2xx                                  → success, stop
     *
     * Attempts run inline on the taskExecutor thread because the caller
     * already invoked us via {@code @Async}; sleeping a few seconds is fine.
     */
    private void deliver(WebhookConfig w, AlertDto alert) {
        String body, sig;
        try {
            body = json.writeValueAsString(buildPayload(w, alert));
            sig  = sign(w.getSecret(), body);
        } catch (Exception e) {
            log.warn("Webhook {} payload build failed: {}", w.getName(), e.getMessage());
            recordResult(w, -1);
            return;
        }

        int lastStatus = -1;
        for (int attempt = 1; attempt < BACKOFF_MS.length; attempt++) {
            sleep(BACKOFF_MS[attempt - 1]);
            try {
                lastStatus = http.post()
                        .uri(w.getUrl())
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-AISec-Signature", "sha256=" + sig)
                        .header("X-AISec-Event", "alert.created")
                        .header("X-AISec-Attempt", String.valueOf(attempt))
                        .body(body)
                        .retrieve()
                        .toBodilessEntity()
                        .getStatusCode()
                        .value();
                // 2xx → success
                recordResult(w, lastStatus);
                if (attempt > 1) {
                    log.info("Webhook {} delivered on attempt {}", w.getName(), attempt);
                }
                return;
            } catch (org.springframework.web.client.RestClientResponseException e) {
                lastStatus = e.getStatusCode().value();
                // 4xx is permanent — stop immediately, give up.
                if (lastStatus >= 400 && lastStatus < 500) {
                    recordResult(w, lastStatus);
                    log.warn("Webhook {} -> HTTP {} (permanent), giving up",
                            w.getName(), lastStatus);
                    return;
                }
                log.warn("Webhook {} -> HTTP {} (attempt {}/{}), will retry",
                        w.getName(), lastStatus, attempt, BACKOFF_MS.length - 1);
            } catch (Exception e) {
                lastStatus = -1;
                log.warn("Webhook {} transport error (attempt {}/{}): {}",
                        w.getName(), attempt, BACKOFF_MS.length - 1, e.getMessage());
            }
        }
        // All attempts exhausted.
        recordResult(w, lastStatus);
        log.warn("Webhook {} exhausted all {} attempts (last status {})",
                w.getName(), BACKOFF_MS.length - 1, lastStatus);
    }

    private static void sleep(long ms) {
        if (ms <= 0) return;
        try { Thread.sleep(ms); }
        catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
    }

    private void recordResult(WebhookConfig w, int status) {
        try {
            w.setLastDeliveredAt(Instant.now());
            w.setLastStatusCode(status);
            repo.save(w);
            audit.log("WEBHOOK_DELIVERY", "Webhook", w.getId(),
                    w.getName() + " -> " + status);
        } catch (Exception ignored) { /* never break the dispatcher */ }
    }

    /** Render payload according to the receiver preset. */
    private Map<String, Object> buildPayload(WebhookConfig w, AlertDto a) {
        return switch (w.getPreset() == null ? "generic" : w.getPreset()) {
            case "slack"   -> slackPayload(a);
            case "discord" -> discordPayload(a);
            default        -> genericPayload(a);
        };
    }

    private static Map<String, Object> genericPayload(AlertDto a) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("event", "alert.created");
        m.put("timestamp", Instant.now().toString());
        m.put("alert", a);   // SNAKE_CASE serialized via Jackson global config
        return m;
    }

    private static Severity parseSeverity(String s) {
        if (s == null) return null;
        try { return Severity.valueOf(s); } catch (IllegalArgumentException e) { return null; }
    }

    private static Map<String, Object> slackPayload(AlertDto a) {
        Severity sev = parseSeverity(a.severity());
        String emoji = severityEmoji(sev);
        String text = String.format("%s *%s* — %s\n• Source: `%s`\n• Target: `%s`\n• Confidence: %s",
                emoji, a.severity(), safe(a.attackType()),
                safe(a.sourceIp()), safe(a.destIp()),
                a.confidence() == null ? "n/a" : String.format("%.2f", a.confidence()));
        return Map.of("text", text);
    }

    private static Map<String, Object> discordPayload(AlertDto a) {
        Severity sev = parseSeverity(a.severity());
        Map<String, Object> embed = new LinkedHashMap<>();
        embed.put("title", severityEmoji(sev) + " " + safe(a.attackType()));
        embed.put("description", safe(a.description()));
        embed.put("color", colorForSeverity(sev));
        embed.put("fields", List.of(
                Map.of("name", "Severity", "value", String.valueOf(a.severity()), "inline", true),
                Map.of("name", "Source",   "value", safe(a.sourceIp()), "inline", true),
                Map.of("name", "Target",   "value", safe(a.destIp()),   "inline", true)
        ));
        embed.put("timestamp", Instant.now().toString());
        return Map.of("embeds", List.of(embed));
    }

    private static String severityEmoji(Severity s) {
        if (s == null) return "ℹ️";
        return switch (s) {
            case CRITICAL -> "🚨";
            case HIGH     -> "⚠️";
            case MEDIUM   -> "🔶";
            case LOW      -> "🔵";
            default       -> "ℹ️";
        };
    }

    private static int colorForSeverity(Severity s) {
        if (s == null) return 0x808080;
        return switch (s) {
            case CRITICAL -> 0xDC2626;
            case HIGH     -> 0xEA580C;
            case MEDIUM   -> 0xCA8A04;
            case LOW      -> 0x16A34A;
            default       -> 0x6B7280;
        };
    }

    private static String safe(String s) { return s == null || s.isBlank() ? "—" : s; }

    /** HMAC-SHA256 signing of the raw body bytes. */
    static String sign(String secret, String body) {
        if (secret == null || secret.isBlank()) return "";
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(body.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return "";
        }
    }
}
