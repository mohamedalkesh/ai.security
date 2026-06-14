package com.aisec.backend.service;

import com.aisec.backend.dto.incident.IncidentDto;
import com.aisec.backend.entity.*;
import com.aisec.backend.repository.IncidentRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Groups related alerts into incidents.
 *
 * Correlation rule (intentionally conservative — high precision, low noise):
 *   open incident with same (srcIp, attackFamily, orgId) within 1 hour → merge
 *   otherwise → new incident
 *
 * Attack family is the {@link Alert#getAttackType()} with subtype suffix stripped
 * ("DoS Hulk" → "DoS"), so a hulk + slowloris burst collapses into one record.
 */
@Service
public class IncidentService {

    private static final Duration MERGE_WINDOW = Duration.ofHours(1);
    private static final List<AlertStatus> OPEN_STATUSES =
            List.of(AlertStatus.NEW, AlertStatus.INVESTIGATING);

    private final IncidentRepository repo;

    public IncidentService(IncidentRepository repo) {
        this.repo = repo;
    }

    /**
     * Find an open matching incident or create a new one, attach the alert,
     * and bump the rollup counters. Caller still needs to persist the alert.
     *
     * <p>Two-pass correlation:
     * <ol>
     *   <li>Primary key (srcIp + family + org) — same attacker, repeating.</li>
     *   <li>Distributed key (dst + family + org) prefixed with {@code dist:} —
     *       same target hit by many attackers (typical DDoS / botnet pattern).</li>
     * </ol>
     *
     * <p>If neither matches we fall back to creating a primary-key incident.
     *
     * <p><b>Isolation:</b> runs in {@link Propagation#REQUIRES_NEW} so a unique-key
     * collision (which is *expected* under concurrent PCAP ingest) doesn't
     * poison the caller's session. Without this, a single duplicate-key
     * insert here would mark the outer alert-save transaction as
     * rollback-only and PostgreSQL would refuse every subsequent statement
     * with "current transaction is aborted" — turning one race into a
     * cascade that fails an entire 38MB PCAP scan.
     *
     * The trade-off: each correlate() call commits its own tiny transaction.
     * That's fine here; the unit of work IS "create-or-attach-incident",
     * and the alert insert later runs independently in the outer tx.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public Incident correlate(Alert alert) {
        String family = attackFamily(alert.getAttackType());
        Long orgId = alert.getOrganization() != null ? alert.getOrganization().getId() : null;

        // ----- pass 1: same source IP -----
        String primaryKey = correlationKey(alert.getSourceIp(), family, orgId);
        Optional<Incident> existing = openMatch(primaryKey);

        // ----- pass 2: same target + family (distributed attack) -----
        // Only consult this when there's a real destination AND the family is
        // one prone to distributed sourcing. We keep the list short to avoid
        // false merges of unrelated noise.
        if (existing.isEmpty() && alert.getDestIp() != null && isDistributedFamily(family)) {
            String distKey = "dist:" + correlationKey(alert.getDestIp(), family, orgId);
            existing = openMatch(distKey);
            if (existing.isPresent()) {
                // ensure new alert references this incident even though its srcIp differs
                Incident inc = updateRollup(existing.get(), alert);
                return repo.save(inc);
            }
        }

        Incident inc = existing.orElseGet(() -> {
            Incident n = new Incident();
            n.setCorrelationKey(primaryKey);
            n.setTitle(family + (alert.getSourceIp() != null ? " from " + alert.getSourceIp() : ""));
            n.setSourceIp(alert.getSourceIp());
            n.setOrganization(alert.getOrganization());
            return n;
        });

        // If we found a closed incident with the same primary key, rotate to a fresh one.
        if (existing.isEmpty() && repo.findByCorrelationKey(primaryKey).isPresent()) {
            inc.setCorrelationKey(primaryKey + "-" + Instant.now().getEpochSecond());
        }

        // Use ``saveAndFlush`` so a freshly-created Incident is immediately
        // visible to subsequent ``openMatch`` queries within the same
        // transaction. Without the flush, batched PCAP scans that produce
        // many alerts for the same (srcIp, family, org) tuple created
        // duplicate Incident rows and tripped the unique constraint on
        // ``correlationKey``, aborting the whole pcap upload.
        try {
            return repo.saveAndFlush(updateRollup(inc, alert));
        } catch (org.springframework.dao.DataIntegrityViolationException dup) {
            // Race / concurrent path: another worker already inserted this
            // incident. Re-fetch it and merge our rollup into the canonical
            // row instead of failing the whole batch.
            return repo.findByCorrelationKey(inc.getCorrelationKey())
                    .map(canonical -> repo.saveAndFlush(updateRollup(canonical, alert)))
                    .orElseThrow(() -> dup);
        }
    }

    /** Lookup helper — open + within merge window. */
    private Optional<Incident> openMatch(String key) {
        return repo.findOpenByCorrelationKey(key, OPEN_STATUSES)
                .filter(i -> Duration.between(i.getLastAlertAt(), Instant.now())
                                     .compareTo(MERGE_WINDOW) < 0);
    }

    /** Bump counters + last-seen + escalate severity in-place. */
    private static Incident updateRollup(Incident inc, Alert alert) {
        inc.setAlertCount(inc.getAlertCount() + 1);
        inc.setLastAlertAt(Instant.now());
        if (alert.getSeverity() != null
                && alert.getSeverity().ordinal() > inc.getHighestSeverity().ordinal()) {
            inc.setHighestSeverity(alert.getSeverity());
        }
        return inc;
    }

    /** Families that we expect to come from many sources at once. */
    private static boolean isDistributedFamily(String family) {
        if (family == null) return false;
        String f = family.toLowerCase();
        return f.contains("ddos") || f.contains("dos")
                || f.contains("brute") || f.contains("flood")
                || f.contains("scan");
    }

    public Page<IncidentDto> list(Long orgId, Pageable pageable) {
        return repo.findScoped(orgId, pageable).map(IncidentDto::from);
    }

    public IncidentDto get(Long id, Long orgId) {
        Incident i = repo.findById(id).orElseThrow(() ->
                new ResponseStatusException(HttpStatus.NOT_FOUND, "Incident not found"));
        verifyOrgAccess(i, orgId);
        return IncidentDto.from(i);
    }

    @Transactional
    public IncidentDto updateStatus(Long id, String status, Long orgId) {
        Incident i = repo.findById(id).orElseThrow(() ->
                new ResponseStatusException(HttpStatus.NOT_FOUND, "Incident not found"));
        verifyOrgAccess(i, orgId);
        AlertStatus s = AlertStatus.valueOf(status.toUpperCase());
        i.setStatus(s);
        if (s == AlertStatus.RESOLVED || s == AlertStatus.FALSE_POSITIVE) {
            i.setResolvedAt(Instant.now());
        }
        return IncidentDto.from(repo.save(i));
    }

    /* ------------------------------------------------------------------ */
    private static String correlationKey(String srcIp, String family, Long orgId) {
        String raw = (srcIp == null ? "-" : srcIp) + "|" + family + "|" + (orgId == null ? "sys" : orgId);
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(raw.getBytes());
            // 80-char column, hex of 256 bits = 64 chars — fits comfortably.
            return HexFormat.of().formatHex(h).substring(0, 40);
        } catch (Exception e) {
            return raw.length() > 80 ? raw.substring(0, 80) : raw;
        }
    }

    /** "DoS Hulk", "DoS slowloris" → "DoS";  "PortScan" → "PortScan". */
    static String attackFamily(String attackType) {
        if (attackType == null) return "Unknown";
        int sp = attackType.indexOf(' ');
        return sp > 0 ? attackType.substring(0, sp) : attackType;
    }

    private static void verifyOrgAccess(Incident i, Long callerOrgId) {
        Long ownerOrgId = i.getOrganization() != null ? i.getOrganization().getId() : null;
        if (!Objects.equals(ownerOrgId, callerOrgId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Incident not found");
        }
    }
}
