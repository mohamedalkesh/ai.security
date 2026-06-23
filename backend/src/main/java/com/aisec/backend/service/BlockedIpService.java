package com.aisec.backend.service;

import com.aisec.backend.dto.firewall.BlockIpRequest;
import com.aisec.backend.dto.firewall.BlockedIpDto;
import com.aisec.backend.entity.Alert;
import com.aisec.backend.entity.AlertStatus;
import com.aisec.backend.entity.BlockedIp;
import com.aisec.backend.entity.Incident;
import com.aisec.backend.entity.Organization;
import com.aisec.backend.repository.AlertRepository;
import com.aisec.backend.repository.BlockedIpRepository;
import com.aisec.backend.repository.IncidentRepository;
import com.aisec.backend.repository.OrganizationRepository;
import com.aisec.backend.service.firewall.FirewallEnforcer;
import com.aisec.backend.service.threatintel.ThreatIntelService;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

import java.time.Instant;
import java.time.format.DateTimeParseException;

/**
 * Manages the firewall blocklist.
 *
 * <p>Two callers exist today:
 * <ul>
 *   <li>{@code BlockedIpController} — analyst/admin actions from the UI.</li>
 *   <li>{@code IncidentService}     — auto-block playbooks (future).</li>
 * </ul>
 *
 * <p>The {@code isBlocked} hot-path is intentionally cheap (single indexed
 * lookup) so it can be invoked from the alert pipeline without measurable
 * overhead.
 */
@Service
public class BlockedIpService {

    private static final Logger log = LoggerFactory.getLogger(BlockedIpService.class);

    private static final java.util.List<AlertStatus> OPEN_STATUSES =
            java.util.List.of(AlertStatus.NEW, AlertStatus.INVESTIGATING);

    private final BlockedIpRepository repo;
    private final OrganizationRepository orgs;
    private final AlertRepository alerts;
    private final IncidentRepository incidents;
    private final AuditService audit;
    private final FirewallEnforcer enforcer;
    private final ThreatIntelService threatIntel;
    private final MlTrainingService mlTraining;

    public BlockedIpService(BlockedIpRepository repo,
                            OrganizationRepository orgs,
                            AlertRepository alerts,
                            IncidentRepository incidents,
                            AuditService audit,
                            FirewallEnforcer enforcer,
                            ThreatIntelService threatIntel,
                            MlTrainingService mlTraining) {
        this.repo = repo;
        this.orgs = orgs;
        this.alerts = alerts;
        this.incidents = incidents;
        this.audit = audit;
        this.enforcer = enforcer;
        this.threatIntel = threatIntel;
        this.mlTraining = mlTraining;
    }

    /**
     * Reconcile the kernel-level packet filter with the persistent blocklist
     * once at boot. Anything in the DB gets re-applied; anything stale in
     * nftables (e.g. left over from a previous process that was killed before
     * unblock could fire) is dropped during the flush in {@code syncAll}.
     */
    @PostConstruct
    void syncEnforcerOnStartup() {
        try {
            java.util.List<String> ips = repo.findAllActiveIps();
            enforcer.syncAll(ips);
            log.info("Firewall enforcer={} initialised with {} active block(s)",
                     enforcer.name(), ips.size());
        } catch (Exception e) {
            // Never let a startup-time enforcer hiccup wedge the whole backend.
            log.error("Firewall enforcer startup sync failed: {}", e.getMessage(), e);
        }
    }

    /* ============================ Queries ============================ */

    public Page<BlockedIpDto> list(Long orgId, String q, Pageable page) {
        // Empty string disables the filter (matches everything); see repo Javadoc.
        String needle = (q == null) ? "" : q.trim();
        // Cache-only enrichment: never trigger upstream calls from a list
        // endpoint — a freshly seeded blocklist would otherwise stall behind
        // hundreds of HTTP roundtrips. The UI can hit /api/threat-intel/{ip}
        // on demand for rows that come back without reputation.
        return repo.search(orgId, needle, page).map(b ->
                BlockedIpDto.from(b, null, null,
                        threatIntel.lookupCached(b.getIpAddress()).orElse(null)));
    }

    public boolean isBlocked(String ip, Long orgId) {
        if (ip == null || ip.isBlank()) return false;
        return repo.findActiveForLookup(ip, orgId).isPresent();
    }

    public long countActive(Long orgId) {
        return orgId == null
                ? repo.countByActiveTrue()
                : repo.countByOrganization_IdAndActiveTrue(orgId);
    }

    /* ============================ Mutations ============================ */

    @Transactional
    public BlockedIpDto block(BlockIpRequest req, String actor, Long orgId) {
        String ip = normalise(req.ip());
        if (ip == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid IP address");
        }

        // Idempotency — re-blocking an already-blocked IP just refreshes its
        // metadata instead of creating duplicate rows or 500-ing on the unique
        // constraint.
        BlockedIp row = repo.findByIpAddressAndOrganization_Id(ip, orgId).orElseGet(BlockedIp::new);
        boolean fresh = row.getId() == null;

        row.setIpAddress(ip);
        row.setReason(req.reason());
        row.setActive(true);
        row.setSource(BlockedIp.Source.MANUAL);
        if (fresh) {
            row.setCreatedBy(actor);
        }
        row.setExpiresAt(parseExpiry(req.expiresAt()));

        if (orgId != null) {
            Organization org = orgs.findById(orgId).orElse(null);
            row.setOrganization(org);
        }

        if (req.sourceAlertId() != null) {
            Alert a = alerts.findById(req.sourceAlertId()).orElse(null);
            row.setSourceAlert(a);
            // If reason was empty, derive a useful one from the alert.
            if ((row.getReason() == null || row.getReason().isBlank()) && a != null) {
                row.setReason("Auto from alert #" + a.getId() + " — " + a.getAttackType());
                row.setSource(BlockedIp.Source.INCIDENT_RESPONSE);
            }
        }

        BlockedIp saved = repo.save(row);

        // Side-effect: closing the perimeter against an IP also closes the
        // open alerts & incidents that triggered the block. The analyst no
        // longer has anything actionable, and leaving them in NEW would
        // pollute the SOC dashboard.
        int resolvedAlerts    = autoResolveAlerts(ip, orgId, saved.getId());
        int resolvedIncidents = autoResolveIncidents(ip, orgId, saved.getId());

        // Push the rule down to the kernel. Failures here are logged but
        // never roll back the DB write — the analyst's intent is already
        // captured, and we'll re-sync on next boot.
        try {
            enforcer.applyBlock(ip);
        } catch (Exception e) {
            log.warn("Enforcer applyBlock({}) failed: {}", ip, e.getMessage());
        }

        audit.log(fresh ? "FIREWALL_BLOCK" : "FIREWALL_UPDATE",
                  "BlockedIp", saved.getId(),
                  "ip=" + ip + " reason=" + (req.reason() == null ? "" : req.reason())
                  + " resolvedAlerts=" + resolvedAlerts
                  + " resolvedIncidents=" + resolvedIncidents
                  + " enforcer=" + enforcer.name());
        log.info("Firewall {}: ip={} actor={} org={} resolved={} alerts / {} incidents (enforcer={})",
                 fresh ? "BLOCK" : "UPDATE", ip, actor, orgId,
                 resolvedAlerts, resolvedIncidents, enforcer.name());
        // Eagerly enrich the block response with reputation. The analyst
        // just made an explicit decision about this IP, so the one extra
        // round-trip is acceptable and the UI gets useful context in one go.
        var rep = threatIntel.lookup(ip).orElse(null);
        return BlockedIpDto.from(saved, resolvedAlerts, resolvedIncidents, rep);
    }

    /**
     * Auto-block hook for the alert pipeline. Skips non-actionable/local-only
     * addresses and is a no-op when an active block already exists. Returns true when a
     * brand-new entry was created.
     */
    @Transactional
    public boolean autoBlock(Alert alert, String reason) {
        String ip = normalise(alert == null ? null : alert.getSourceIp());
        if (ip == null || isUnsafeForAutoBlock(ip)) return false;

        Long orgId = alert.getOrganization() != null ? alert.getOrganization().getId() : null;
        if (repo.findActiveForLookup(ip, orgId).isPresent()) return false;

        BlockedIp row = new BlockedIp();
        row.setIpAddress(ip);
        row.setReason(reason);
        row.setActive(true);
        row.setSource(BlockedIp.Source.AUTO_RULE);
        row.setCreatedBy("system");
        row.setSourceAlert(alert);
        if (orgId != null) orgs.findById(orgId).ifPresent(row::setOrganization);

        try {
            BlockedIp saved = repo.save(row);
            try { enforcer.applyBlock(ip); }
            catch (Exception ex) { log.warn("Enforcer applyBlock({}) on autoblock failed: {}", ip, ex.getMessage()); }
            audit.log("FIREWALL_AUTOBLOCK", "BlockedIp", saved.getId(),
                      "ip=" + ip + " alertId=" + alert.getId()
                      + " severity=" + alert.getSeverity()
                      + " reason=" + reason
                      + " enforcer=" + enforcer.name());
            log.info("Firewall AUTOBLOCK: ip={} alert={} severity={} enforcer={}",
                     ip, alert.getId(), alert.getSeverity(), enforcer.name());
            return true;
        } catch (Exception e) {
            // Concurrent insert raced us — that's fine, the IP is blocked.
            log.warn("autoBlock raced for ip={}: {}", ip, e.getMessage());
            return false;
        }
    }

    /**
     * Backfill: apply the auto-block rule to every still-open HIGH/CRITICAL
     * alert in the tenant. Useful right after enabling the feature, when the
     * database holds severe alerts that pre-date the auto-block hook. Returns
     * the number of brand-new blocks created (already-blocked IPs are skipped
     * silently by {@link #autoBlock}).
     */
    @Transactional
    public int backfillAutoBlocks(Long orgId) {
        java.util.List<com.aisec.backend.entity.Severity> sev =
                java.util.List.of(com.aisec.backend.entity.Severity.HIGH,
                                   com.aisec.backend.entity.Severity.CRITICAL);
        java.util.List<Alert> candidates =
                alerts.findOpenBySeverities(orgId, sev, OPEN_STATUSES);
        int created = 0;
        for (Alert a : candidates) {
            if (autoBlock(a, "Backfill auto-block: " + a.getSeverity()
                    + " " + a.getAttackType() + " (alert #" + a.getId() + ")")) {
                created++;
            }
        }
        log.info("backfillAutoBlocks org={}: scanned={} blocked={}",
                 orgId, candidates.size(), created);
        return created;
    }

    @Transactional
    public void unblock(Long id, String actor, Long orgId) {
        BlockedIp row = repo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        // Tenant isolation — non-system callers can't touch other orgs' rows.
        if (orgId != null && row.getOrganization() != null
                && !orgId.equals(row.getOrganization().getId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
        String ip = row.getIpAddress();
        repo.delete(row);
        try { enforcer.removeBlock(ip); }
        catch (Exception e) { log.warn("Enforcer removeBlock({}) failed: {}", ip, e.getMessage()); }
        audit.log("FIREWALL_UNBLOCK", "BlockedIp", id, "ip=" + ip + " enforcer=" + enforcer.name());
        log.info("Firewall UNBLOCK: ip={} actor={} enforcer={}", ip, actor, enforcer.name());
    }

    /* ============================ Helpers ============================ */

    /**
     * Mark every still-open Alert from this source IP as RESOLVED. The
     * resolution timestamp is set so MTTR analytics close cleanly. Returns
     * the number of rows updated.
     */
    private int autoResolveAlerts(String ip, Long orgId, Long blockId) {
        java.util.List<Alert> open = alerts.findOpenBySourceIp(ip, orgId, OPEN_STATUSES);
        if (open.isEmpty()) return 0;
        Instant now = Instant.now();
        for (Alert a : open) {
            a.setStatus(AlertStatus.RESOLVED);
            if (a.getResolvedAt() == null) a.setResolvedAt(now);
            String prev = a.getDescription() == null ? "" : a.getDescription();
            String tag = "[firewall:block#" + blockId + "]";
            if (!prev.contains(tag)) {
                String merged = (prev + " " + tag).trim();
                if (merged.length() > 1024) merged = merged.substring(0, 1024);
                a.setDescription(merged);
            }
        }
        java.util.List<Alert> saved = alerts.saveAll(open);
        for (Alert alert : saved) {
            try { mlTraining.archiveAlert(alert); } catch (Exception ignored) {}
        }
        return saved.size();
    }

    /** Same idea as {@link #autoResolveAlerts} but for Incident rollups. */
    private int autoResolveIncidents(String ip, Long orgId, Long blockId) {
        java.util.List<Incident> open = incidents.findOpenBySourceIp(ip, orgId, OPEN_STATUSES);
        if (open.isEmpty()) return 0;
        Instant now = Instant.now();
        for (Incident inc : open) {
            inc.setStatus(AlertStatus.RESOLVED);
            if (inc.getResolvedAt() == null) inc.setResolvedAt(now);
        }
        incidents.saveAll(open);
        return open.size();
    }

    /**
     * Skip only non-actionable or dangerous addresses. RFC1918 LAN sources are
     * allowed because this IDS is commonly used to contain internal attackers.
     */
    static boolean isUnsafeForAutoBlock(String ip) {
        if (ip == null) return true;
        String s = ip.trim();
        if (s.isEmpty() || s.equalsIgnoreCase("MULTIPLE") || s.equals("0.0.0.0") || s.startsWith("0.")) return true;
        if (s.startsWith("127.") || s.equals("::1")) return true;
        if (s.startsWith("169.254.")) return true;          // link-local
        if (s.startsWith("224.") || s.startsWith("239.")) return true; // multicast
        if (s.startsWith("255.")) return true;              // broadcast
        // IPv6 link-local / multicast
        String low = s.toLowerCase();
        if (low.startsWith("fe80") || low.startsWith("ff")) return true;
        return false;
    }

    /** Trim, lowercase, strip surrounding brackets, reject obvious garbage. */
    private static String normalise(String raw) {
        if (raw == null) return null;
        String s = raw.trim();
        if (s.startsWith("[") && s.endsWith("]")) s = s.substring(1, s.length() - 1);
        if (s.isEmpty() || s.length() > 64) return null;
        // Cheap sanity: must contain at least one ':' (IPv6) or '.' (IPv4).
        if (s.indexOf(':') < 0 && s.indexOf('.') < 0) return null;
        return s;
    }

    private static Instant parseExpiry(String iso) {
        if (iso == null || iso.isBlank()) return null;
        try {
            return Instant.parse(iso.trim());
        } catch (DateTimeParseException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "expiresAt must be ISO-8601 (e.g. 2026-12-31T00:00:00Z)");
        }
    }
}
