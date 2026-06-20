package com.aisec.backend.service;

import com.aisec.backend.dto.alert.AlertCommentDto;
import com.aisec.backend.dto.alert.AlertDto;
import com.aisec.backend.dto.alert.AutoResolveRequest;
import com.aisec.backend.dto.alert.BulkUpdateRequest;
import com.aisec.backend.dto.threatintel.IpReputationDto;
import com.aisec.backend.entity.*;
import com.aisec.backend.repository.AlertCommentRepository;
import com.aisec.backend.repository.AlertRepository;
import com.aisec.backend.repository.BlockedIpRepository;
import com.aisec.backend.repository.UserRepository;
import com.aisec.backend.service.threatintel.ThreatIntelService;
import com.aisec.backend.websocket.AlertBroadcaster;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * All public read/write methods are org-scoped.
 * Pass orgId = null  → operate only on the system tenant (organization IS NULL).
 * Pass orgId = N    → operate only on organisation N.
 * No caller can ever observe data from a different tenant.
 */
@Service
public class AlertService {

    private static final Logger log = LoggerFactory.getLogger(AlertService.class);

    private final AlertRepository repo;
    private final AlertCommentRepository commentRepo;
    private final UserRepository userRepo;
    private final AlertBroadcaster broadcaster;
    private final IncidentService incidents;
    private final GeoIpService geoIp;
    private final AuditService audit;
    private final WebhookService webhooks;
    private final BlockedIpService firewall;
    private final BlockedIpRepository blockedIpRepo;
    private final MlTrainingService mlTraining;
    private final ThreatIntelService threatIntel;

    public AlertService(AlertRepository repo,
                        AlertCommentRepository commentRepo,
                        UserRepository userRepo,
                        AlertBroadcaster broadcaster,
                        IncidentService incidents,
                        GeoIpService geoIp,
                        AuditService audit,
                        WebhookService webhooks,
                        BlockedIpService firewall,
                        BlockedIpRepository blockedIpRepo,
                        MlTrainingService mlTraining,
                        ThreatIntelService threatIntel) {
        this.repo = repo;
        this.commentRepo = commentRepo;
        this.userRepo = userRepo;
        this.broadcaster = broadcaster;
        this.incidents = incidents;
        this.geoIp = geoIp;
        this.audit = audit;
        this.webhooks = webhooks;
        this.firewall = firewall;
        this.blockedIpRepo = blockedIpRepo;
        this.mlTraining = mlTraining;
        this.threatIntel = threatIntel;
    }

    /* ===================================================================
     *                           QUERIES
     * =================================================================== */

    /** Convert Alert → AlertDto and attach cached threat-intel reputation if available. */
    private AlertDto toDto(Alert a) {
        AlertDto base = AlertDto.from(a);
        if (a.getSourceIp() == null || !threatIntel.isEnabled()) return base;
        return threatIntel.lookupCached(a.getSourceIp())
                .map(rep -> base.withReputation(
                        rep.abuseScore(), rep.totalReports(), rep.country(), rep.isp()))
                .orElse(base);
    }

    @Transactional(readOnly = true)
    public Page<AlertDto> list(String severity, String status, Long orgId, Pageable pageable) {
        Page<Alert> page;
        if (severity != null) {
            page = repo.findScopedBySeverity(orgId, Severity.valueOf(severity.toUpperCase()), pageable);
        } else if (status != null) {
            page = repo.findScopedByStatus(orgId, AlertStatus.valueOf(status.toUpperCase()), pageable);
        } else {
            page = repo.findScoped(orgId, pageable);
        }
        return page.map(this::toDto);
    }

    @Transactional(readOnly = true)
    public AlertDto get(Long id, Long orgId) {
        Alert a = repo.findById(id).orElseThrow(() ->
                new ResponseStatusException(HttpStatus.NOT_FOUND, "Alert not found"));
        verifyOrgAccess(a, orgId);
        return AlertDto.from(a);
    }

    @Transactional(readOnly = true)
    public Map<String, Object> stats(Long orgId) {
        Map<String, Object> m = new HashMap<>();
        m.put("total",    repo.countScoped(orgId));
        m.put("active",   repo.countScopedByStatus(orgId, AlertStatus.NEW)
                        + repo.countScopedByStatus(orgId, AlertStatus.INVESTIGATING));
        m.put("resolved", repo.countScopedByStatus(orgId, AlertStatus.RESOLVED));
        m.put("critical", repo.countScopedBySeverity(orgId, Severity.CRITICAL));
        m.put("high",     repo.countScopedBySeverity(orgId, Severity.HIGH));
        m.put("last24h",  repo.countScopedSince(orgId, Instant.now().minusSeconds(86400)));
        return m;
    }

    @Transactional(readOnly = true)
    public List<Map<String, Object>> attackTypeBreakdown(Long orgId) {
        return repo.countByAttackTypeScoped(orgId);
    }

    /* ===================================================================
     *                           MUTATIONS
     * =================================================================== */

    @Transactional
    public AlertDto updateStatus(Long id, String status, Long orgId) {
        Alert a = repo.findById(id).orElseThrow(() ->
                new ResponseStatusException(HttpStatus.NOT_FOUND, "Alert not found"));
        verifyOrgAccess(a, orgId);
        AlertStatus s = AlertStatus.valueOf(status.toUpperCase());
        AlertStatus prev = a.getStatus();
        a.setStatus(s);
        if (s == AlertStatus.RESOLVED || s == AlertStatus.FALSE_POSITIVE) {
            a.setResolvedAt(Instant.now());
        }
        Alert saved = repo.save(a);
        audit.log("ALERT_STATUS", "Alert", a.getId(), prev + " -> " + s);
        if (s == AlertStatus.RESOLVED || s == AlertStatus.FALSE_POSITIVE) {
            try { mlTraining.archiveAlert(saved); } catch (Exception ignored) {}
        }
        AlertDto dto = AlertDto.from(saved);
        deleteIfClosed(saved, "ALERT_AUTO_DELETE");
        return dto;
    }

    /** Multi-field PATCH — status / assignment / ml feedback in one call. */
    @Transactional
    public AlertDto patch(Long id, String status, Long assignedToId, String mlFeedback, Long orgId) {
        Alert a = repo.findById(id).orElseThrow(() ->
                new ResponseStatusException(HttpStatus.NOT_FOUND, "Alert not found"));
        verifyOrgAccess(a, orgId);
        List<String> changes = new ArrayList<>();

        if (status != null) {
            AlertStatus s = AlertStatus.valueOf(status.toUpperCase());
            if (a.getStatus() != s) {
                changes.add("status:" + a.getStatus() + "->" + s);
                a.setStatus(s);
                if (s == AlertStatus.RESOLVED || s == AlertStatus.FALSE_POSITIVE) {
                    a.setResolvedAt(Instant.now());
                }
            }
        }
        if (assignedToId != null) {
            if (assignedToId == -1L) {
                if (a.getAssignedTo() != null) {
                    changes.add("assigned:" + a.getAssignedTo().getUsername() + "->null");
                    a.setAssignedTo(null);
                }
            } else {
                UserAccount u = userRepo.findById(assignedToId).orElseThrow(() ->
                        new ResponseStatusException(HttpStatus.BAD_REQUEST, "Assignee not found"));
                // Cross-tenant assignment forbidden.
                Long uOrg = u.getOrganization() != null ? u.getOrganization().getId() : null;
                if (!Objects.equals(uOrg, orgId)) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Assignee not in your organization");
                }
                String prev = a.getAssignedTo() != null ? a.getAssignedTo().getUsername() : "null";
                changes.add("assigned:" + prev + "->" + u.getUsername());
                a.setAssignedTo(u);
            }
        }
        if (mlFeedback != null) {
            MlFeedback fb = MlFeedback.valueOf(mlFeedback.toUpperCase());
            if (a.getMlFeedback() != fb) {
                changes.add("feedback:" + a.getMlFeedback() + "->" + fb);
                a.setMlFeedback(fb);
            }
        }

        Alert saved = repo.save(a);
        if (!changes.isEmpty()) {
            audit.log("ALERT_UPDATE", "Alert", a.getId(), String.join(", ", changes));
        }
        if (saved.getStatus() == AlertStatus.RESOLVED || saved.getStatus() == AlertStatus.FALSE_POSITIVE) {
            try { mlTraining.archiveAlert(saved); } catch (Exception ignored) {}
        }
        AlertDto dto = AlertDto.from(saved);
        deleteIfClosed(saved, "ALERT_AUTO_DELETE");
        return dto;
    }

    @Transactional
    public List<Long> bulkUpdate(BulkUpdateRequest req, Long orgId) {
        List<Long> applied = new ArrayList<>();
        for (Long id : req.ids()) {
            try {
                patch(id, req.status(), null, req.mlFeedback(), orgId);
                applied.add(id);
            } catch (ResponseStatusException e) {
                // Silently skip cross-tenant or missing alerts.
            }
        }
        audit.log("ALERT_BULK", "Alert", null,
                "ids=" + applied.size() + "/" + req.ids().size() + " status=" + req.status());
        return applied;
    }

    @Transactional
    public Map<String, Object> autoResolve(AutoResolveRequest req, Long orgId, String username) {
        Severity maxSeverity = Severity.valueOf(req.maxSeverity().toUpperCase());
        List<AlertStatus> statuses = List.of(AlertStatus.NEW, AlertStatus.INVESTIGATING);
        PageRequest page = PageRequest.of(0, req.limit());
        Page<Alert> eligible = repo.findEligibleForAutoResolve(orgId, statuses, maxSeverity, req.minConfidence(), page);

        if (req.dryRun()) {
            return Map.of(
                    "matched", eligible.getTotalElements(),
                    "preview", eligible.getContent().stream().map(AlertDto::from).toList()
            );
        }

        int resolved = 0;
        List<Long> ids = new ArrayList<>();
        for (Alert alert : eligible.getContent()) {
            AlertStatus prev = alert.getStatus();
            if (prev == AlertStatus.RESOLVED || prev == AlertStatus.FALSE_POSITIVE) {
                continue;
            }
            alert.setStatus(AlertStatus.RESOLVED);
            alert.setResolvedAt(Instant.now());
            repo.save(alert);
            try { mlTraining.archiveAlert(alert); } catch (Exception ignored) {}

            // Add comment for audit trail within the alert timeline
            AlertComment comment = new AlertComment();
            comment.setAlert(alert);
            comment.setBody("Auto-resolved via AI assist: " + req.reason());
            commentRepo.save(comment);

            audit.log("ALERT_AUTO_RESOLVE", "Alert", alert.getId(),
                    prev + " -> RESOLVED (reason=" + req.reason() + ")");

            ids.add(alert.getId());
            resolved++;

            AlertDto dto = AlertDto.from(alert);
            Long ownerOrgId = alert.getOrganization() != null ? alert.getOrganization().getId() : null;
            broadcaster.broadcast(dto, ownerOrgId);
            deleteIfClosed(alert, "ALERT_AUTO_RESOLVE_DELETE");
        }

        return Map.of(
                "resolved", resolved,
                "ids", ids,
                "requested", eligible.getNumberOfElements()
        );
    }

    @Transactional
    public void delete(Long id, Long orgId) {
        Alert a = repo.findById(id).orElseThrow(() ->
                new ResponseStatusException(HttpStatus.NOT_FOUND, "Alert not found"));
        verifyOrgAccess(a, orgId);
        deleteAlertRow(a);
        audit.log("ALERT_DELETE", "Alert", id, "type=" + a.getAttackType());
    }

    /** Persist + broadcast + enrich + correlate. The one entry point used by
     *  PCAP analyser, scan results, AND the live-monitor poller. */
    @Transactional
    public AlertDto save(Alert a) {
        // Correlation — attach incident BEFORE the first save so the FK is persisted in one round-trip.
        try {
            Incident inc = incidents.correlate(a);
            a.setIncident(inc);
        } catch (Exception ignored) {
            // Correlation failure should never lose the alert.
        }

        Alert saved = repo.save(a);

        // Auto-firewall — only kicks in for HIGH and CRITICAL severities. Lower
        // severities are too noisy to drop traffic over (would generate
        // false-positive blocks on Port Scan probes etc). The service itself
        // also skips RFC1918 / loopback / DNS-style addresses.
        try {
            if (saved.getSeverity() == Severity.HIGH || saved.getSeverity() == Severity.CRITICAL) {
                firewall.autoBlock(saved,
                        "Auto-block: " + saved.getSeverity() + " " + saved.getAttackType()
                        + " (alert #" + saved.getId() + ")");
            }
        } catch (Exception ignored) {
            // Auto-block must never break alert ingestion.
        }

        AlertDto dto = AlertDto.from(saved);
        Long ownerOrgId = saved.getOrganization() != null ? saved.getOrganization().getId() : null;
        broadcaster.broadcast(dto, ownerOrgId);

        // Outbound webhook delivery — fire-and-forget on taskExecutor.
        // Failures never roll back the persistence path.
        try { webhooks.dispatchAlert(dto, ownerOrgId); } catch (Exception ignored) {}

        // GeoIP enrichment runs AFTER the alert is persisted, on a dedicated
        // thread pool. The request returns immediately; the country columns
        // are filled in within a few hundred ms by the geoIpExecutor.
        Long savedId = saved.getId();
        if (savedId != null && (a.getSrcCountry() == null || a.getDstCountry() == null)) {
            try {
                geoIp.enrichAsync(a.getSourceIp(), a.getDestIp(), (src, dst) ->
                        updateGeoColumns(savedId, src, dst));
            } catch (Exception ex) {
                log.debug("GeoIP enrichment skipped for alert {}: {}", savedId, ex.getMessage());
            }
        }

        // Threat-intel cache warm-up — fire-and-forget so the next list() call
        // can serve reputation data from cache without blocking the request.
        if (saved.getSourceIp() != null && threatIntel.isEnabled()) {
            try { threatIntel.lookup(saved.getSourceIp()); }
            catch (Exception ex) {
                log.debug("ThreatIntel warm-up skipped for {}: {}", saved.getSourceIp(), ex.getMessage());
            }
        }

        return dto;
    }

    /**
     * Bulk-persist alerts from a PCAP scan without per-alert side-effects.
     * Uses a single saveAll() batch insert then triggers async GeoIP enrichment.
     *
     * GeoIP tasks are deduplicated by (srcIp, dstIp) pair: a 1000-alert DDoS
     * scan typically has only a handful of distinct IP pairs, so we submit
     * one enrichAsync call per unique pair instead of one per alert. This
     * prevents geoIpExecutor queue overflow on large scans.
     */
    @Transactional
    public int bulkSaveFromScan(List<Alert> batch) {
        if (batch == null || batch.isEmpty()) return 0;
        List<Alert> saved = repo.saveAll(batch);

        // Collect unique (srcIp, dstIp) → list of alert IDs needing enrichment
        java.util.Map<String, java.util.List<Long>> pairToIds = new java.util.LinkedHashMap<>();
        for (Alert a : saved) {
            if (a.getId() == null || (a.getSrcCountry() != null && a.getDstCountry() != null)) continue;
            String key = nullSafe(a.getSourceIp()) + "|" + nullSafe(a.getDestIp());
            pairToIds.computeIfAbsent(key, k -> new java.util.ArrayList<>()).add(a.getId());
        }

        // One enrichAsync task per unique IP pair — safe under any scan size
        for (Alert a : saved) {
            if (a.getId() == null) continue;
            String key = nullSafe(a.getSourceIp()) + "|" + nullSafe(a.getDestIp());
            java.util.List<Long> ids = pairToIds.remove(key); // remove = process once only
            if (ids == null) continue;
            final java.util.List<Long> alertIds = ids;
            try {
                geoIp.enrichAsync(a.getSourceIp(), a.getDestIp(), (src, dst) -> {
                    for (Long id : alertIds) updateGeoColumns(id, src, dst);
                });
            } catch (Exception ex) {
                // GeoIP queue full or unavailable — skip enrichment, never fail the scan
                log.debug("GeoIP enrichment skipped for {} alerts: {}", alertIds.size(), ex.getMessage());
            }
        }
        return saved.size();
    }

    private static String nullSafe(String s) { return s == null ? "" : s; }

    /**
     * Called by the async GeoIP enricher in its own transaction.
     * We don't broadcast on enrichment — clients pull the updated country on next refresh.
     */
    @Transactional
    public void updateGeoColumns(Long alertId, String srcCountry, String dstCountry) {
        repo.findById(alertId).ifPresent(a -> {
            boolean changed = false;
            if (srcCountry != null && a.getSrcCountry() == null) {
                a.setSrcCountry(srcCountry); changed = true;
            }
            if (dstCountry != null && a.getDstCountry() == null) {
                a.setDstCountry(dstCountry); changed = true;
            }
            if (changed) repo.save(a);
        });
    }

    private void deleteIfClosed(Alert alert, String action) {
        if (alert == null || alert.getId() == null) return;
        if (alert.getStatus() != AlertStatus.RESOLVED && alert.getStatus() != AlertStatus.FALSE_POSITIVE) return;
        Long id = alert.getId();
        String type = alert.getAttackType();
        deleteAlertRow(alert);
        audit.log(action, "Alert", id, "closed alert removed from active list: " + type);
    }

    private void deleteAlertRow(Alert alert) {
        Long id = alert.getId();
        blockedIpRepo.detachSourceAlert(id);
        commentRepo.deleteByAlertId(id);
        repo.delete(alert);
    }

    /* ===================================================================
     *                           COMMENTS
     * =================================================================== */

    public List<AlertCommentDto> listComments(Long alertId, Long orgId) {
        Alert a = repo.findById(alertId).orElseThrow(() ->
                new ResponseStatusException(HttpStatus.NOT_FOUND, "Alert not found"));
        verifyOrgAccess(a, orgId);
        return commentRepo.findByAlertIdOrderByCreatedAtAsc(alertId)
                .stream().map(AlertCommentDto::from).toList();
    }

    @Transactional
    public AlertCommentDto addComment(Long alertId, String body, String username, Long orgId) {
        Alert a = repo.findById(alertId).orElseThrow(() ->
                new ResponseStatusException(HttpStatus.NOT_FOUND, "Alert not found"));
        verifyOrgAccess(a, orgId);
        AlertComment c = new AlertComment();
        c.setAlert(a);
        c.setBody(body);
        if (username != null) {
            userRepo.findByUsername(username).ifPresent(c::setAuthor);
        }
        AlertComment saved = commentRepo.save(c);
        audit.log("ALERT_COMMENT", "Alert", alertId, "len=" + body.length());
        return AlertCommentDto.from(saved);
    }

    /* ---------- Tenant-isolation guard ---------- */
    private static void verifyOrgAccess(Alert a, Long callerOrgId) {
        Long ownerOrgId = a.getOrganization() != null ? a.getOrganization().getId() : null;
        if (!Objects.equals(ownerOrgId, callerOrgId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Alert not found");
        }
    }
}
