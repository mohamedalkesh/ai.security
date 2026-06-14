package com.aisec.backend.service;

import com.aisec.backend.entity.Alert;
import com.aisec.backend.entity.AlertStatus;
import com.aisec.backend.entity.Severity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Polls the ML service's live monitor for new detections every 3 seconds,
 * converts them to Alert entities, and persists + broadcasts them.
 */
@Service
public class LiveMonitorService {

    private static final Logger log = LoggerFactory.getLogger(LiveMonitorService.class);

    private final MlClient mlClient;
    private final AlertService alertService;

    public LiveMonitorService(MlClient mlClient, AlertService alertService) {
        this.mlClient = mlClient;
        this.alertService = alertService;
    }

    /**
     * Scheduled task: drain pending detections from ML service and save as alerts.
     * Runs every 1 second while the monitor is running — combined with the ML
     * service's 150 ms classifier batch interval this means an attack appears
     * in the UI within ~1.2 s of its flow being finalised by NFStream.
     */
    @Scheduled(fixedDelay = 1000, initialDelay = 2000)
    public void pollDetections() {
        try {
            Map<String, Object> status = mlClient.monitorStatus();
            Boolean running = (Boolean) status.get("running");
            if (running == null || !running) {
                return; // monitor not active
            }

            List<Map<String, Object>> detections = mlClient.monitorDrain(200);
            if (detections == null || detections.isEmpty()) {
                return;
            }

            log.info("Draining {} live detections from ML monitor", detections.size());
            for (Map<String, Object> d : detections) {
                try {
                    Alert alert = convertToAlert(d);
                    alertService.save(alert);
                } catch (Exception e) {
                    log.warn("Failed to convert detection to alert: {}", e.getMessage());
                }
            }
        } catch (Exception e) {
            // ML service might be down or monitor not started — log at debug to avoid spam
            log.debug("pollDetections failed: {}", e.getMessage());
        }
    }

    private Alert convertToAlert(Map<String, Object> d) {
        Alert a = new Alert();
        a.setAttackType((String) d.get("predicted"));
        a.setSourceIp((String) d.get("src_ip"));
        a.setDestIp((String) d.get("dst_ip"));
        a.setDestPort(toInt(d.get("dst_port")));
        
        Integer proto = toInt(d.get("protocol"));
        a.setProtocol(proto != null ? String.valueOf(proto) : null);

        Double conf = toDouble(d.get("confidence"));
        a.setConfidence(conf != null ? conf : 0.0);

        String sevStr = (String) d.get("severity");
        a.setSeverity(parseSeverity(sevStr));

        a.setMitreTechnique((String) d.get("mitre_technique"));
        a.setMitreTactic((String) d.get("mitre_tactic"));
        a.setDescription((String) d.get("description"));
        a.setStatus(AlertStatus.NEW);

        // Note: createdAt is auto-set by entity default, but we can't override it
        // since there's no setter. The timestamp will be close enough.

        return a;
    }

    private Integer toInt(Object o) {
        if (o == null) return null;
        if (o instanceof Number) return ((Number) o).intValue();
        try { return Integer.parseInt(o.toString()); }
        catch (NumberFormatException e) { return null; }
    }

    private Double toDouble(Object o) {
        if (o == null) return null;
        if (o instanceof Number) return ((Number) o).doubleValue();
        try { return Double.parseDouble(o.toString()); }
        catch (NumberFormatException e) { return null; }
    }

    private Severity parseSeverity(String s) {
        if (s == null) return Severity.MEDIUM;
        try {
            return Severity.valueOf(s.toUpperCase());
        } catch (IllegalArgumentException e) {
            return Severity.MEDIUM;
        }
    }
}
