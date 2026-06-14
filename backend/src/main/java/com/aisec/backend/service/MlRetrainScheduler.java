package com.aisec.backend.service;

import com.aisec.backend.config.AppProperties;
import com.aisec.backend.repository.AlertRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.time.Instant;
import java.util.Map;

/**
 * Periodically inspects accumulated analyst feedback (TRUE/FALSE-POSITIVE
 * labels on alerts) and asks the ML service to retrain itself.
 *
 * Logic:
 *   1. Every 6 h count feedback rows produced since the last retrain.
 *   2. If ≥ {@code threshold} (default 50), POST to ML's /retrain endpoint.
 *   3. Reset the watermark on success.
 *
 * The ML side is free to ignore the call (returns 404) — we still log the
 * attempt and back off gracefully.
 */
@Service
public class MlRetrainScheduler {

    private static final Logger log = LoggerFactory.getLogger(MlRetrainScheduler.class);

    private final AlertRepository alerts;
    private final AuditService audit;
    private final RestClient http;
    private final AppProperties props;

    @Value("${app.ml.retrain.threshold:50}")
    private int threshold;

    @Value("${app.ml.retrain.enabled:true}")
    private boolean enabled;

    private volatile Instant lastRetrainAt = Instant.now().minusSeconds(86400);

    public MlRetrainScheduler(AlertRepository alerts, AuditService audit,
                              AppProperties props) {
        this.alerts = alerts;
        this.audit = audit;
        this.props = props;
        SimpleClientHttpRequestFactory rf = new SimpleClientHttpRequestFactory();
        rf.setConnectTimeout(3000);
        rf.setReadTimeout(30000);   // ML retrain may be slow — give it 30s
        this.http = RestClient.builder().requestFactory(rf).build();
    }

    /** Every 6 hours. */
    @Scheduled(fixedDelay = 21_600_000L, initialDelay = 600_000L)
    public void considerRetrain() {
        if (!enabled) return;

        // Aggregated across all tenants — the ML model is shared.
        // One pass over the table; runs every 6 h so the cost is negligible.
        long feedbackCount = alerts.findAll().stream()
                .filter(a -> a.getMlFeedback() != null
                          && a.getCreatedAt() != null
                          && a.getCreatedAt().isAfter(lastRetrainAt))
                .count();

        if (feedbackCount < threshold) {
            log.debug("ML retrain skipped — only {} feedback rows since {} (need {})",
                    feedbackCount, lastRetrainAt, threshold);
            return;
        }

        triggerRetrain(feedbackCount);
    }

    private void triggerRetrain(long feedbackCount) {
        String url = props.getMl().getBaseUrl().replaceAll("/+$", "") + "/retrain";
        try {
            Map<?, ?> resp = http.post()
                    .uri(url)
                    .body(Map.of(
                            "trigger", "feedback",
                            "feedback_count", feedbackCount,
                            "since", lastRetrainAt.toString()))
                    .retrieve()
                    .body(Map.class);
            log.info("ML retrain triggered: feedback={} response={}", feedbackCount, resp);
            audit.logAnonymous("ML_RETRAIN", "scheduler",
                    "feedback=" + feedbackCount + " response=" + resp);
            lastRetrainAt = Instant.now();
        } catch (org.springframework.web.client.RestClientResponseException e) {
            // 404 / 405 = ML side hasn't implemented it yet; back off but don't spam.
            if (e.getStatusCode().value() == 404 || e.getStatusCode().value() == 405) {
                log.info("ML /retrain endpoint not yet implemented (HTTP {}). " +
                         "Sleeping until next cycle.", e.getStatusCode().value());
                lastRetrainAt = Instant.now();   // avoid retrying every cycle
            } else {
                log.warn("ML retrain failed: HTTP {} — {}",
                        e.getStatusCode().value(), e.getResponseBodyAsString());
            }
        } catch (Exception e) {
            log.warn("ML retrain transport error: {}", e.getMessage());
        }
    }
}
