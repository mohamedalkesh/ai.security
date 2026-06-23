package com.aisec.backend.service;

import com.aisec.backend.entity.Alert;
import com.aisec.backend.entity.AlertStatus;
import com.aisec.backend.entity.MlFeedback;
import com.aisec.backend.entity.MlTrainingRecord;
import com.aisec.backend.repository.MlTrainingRecordRepository;
import com.aisec.backend.security.OrgUserDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@Service
public class MlTrainingService {

    private static final Logger log = LoggerFactory.getLogger(MlTrainingService.class);

    private final MlTrainingRecordRepository repo;

    public MlTrainingService(MlTrainingRecordRepository repo) {
        this.repo = repo;
    }

    /**
     * Called by AlertService whenever an alert transitions to RESOLVED or
     * FALSE_POSITIVE. Idempotent — skips if a record already exists for this alert.
     */
    @Transactional
    public void archiveAlert(Alert alert) {
        if (alert == null || alert.getId() == null) return;
        if (repo.existsByAlertId(alert.getId())) return;

        MlTrainingRecord r = new MlTrainingRecord();
        r.setAlertId(alert.getId());
        r.setAttackType(alert.getAttackType());
        r.setSeverity(alert.getSeverity());
        r.setConfidence(alert.getConfidence());
        r.setSourceIp(alert.getSourceIp());
        r.setDestIp(alert.getDestIp());
        r.setDestPort(alert.getDestPort());
        r.setProtocol(alert.getProtocol());
        r.setSrcCountry(alert.getSrcCountry());
        r.setDstCountry(alert.getDstCountry());
        r.setMitreTechnique(alert.getMitreTechnique());
        r.setMitreTactic(alert.getMitreTactic());
        r.setDescription(alert.getDescription());
        r.setMlFeedback(alert.getMlFeedback() != null ? alert.getMlFeedback().name() : null);
        r.setAssignedToUsername(alert.getAssignedTo() != null ? alert.getAssignedTo().getUsername() : null);
        r.setIncidentId(alert.getIncident() != null ? alert.getIncident().getId() : null);
        r.setFeaturesJson(alert.getExplanation());
        r.setRawFeaturesJson(alert.getRawFeaturesJson());
        r.setAlertCreatedAt(alert.getCreatedAt());
        r.setResolvedAt(alert.getResolvedAt() != null ? alert.getResolvedAt() : Instant.now());
        r.setOrganization(alert.getOrganization());

        // Determine true label:
        // - Analyst marked FALSE_POSITIVE → BENIGN
        // - Alert closed as FALSE_POSITIVE status → BENIGN
        // - Otherwise (RESOLVED, TRUE_POSITIVE, UNCERTAIN) → ATTACK
        MlFeedback fb = alert.getMlFeedback();
        boolean isFp = fb == MlFeedback.FALSE_POSITIVE
                || alert.getStatus() == AlertStatus.FALSE_POSITIVE;
        r.setTrueLabel(isFp ? "BENIGN" : "ATTACK");
        r.setResolutionStatus(alert.getStatus().name());
        applyResponseDecision(r, alert);

        repo.save(r);
        log.info("ML training record saved: alert={} label={} type={}",
                alert.getId(), r.getTrueLabel(), r.getAttackType());
    }

    private void applyResponseDecision(MlTrainingRecord record, Alert alert) {
        String description = alert.getDescription() == null ? "" : alert.getDescription();
        if (description.contains("[firewall:block#")) {
            String blockId = description.replaceAll(".*\\[firewall:block#([0-9]+)\\].*", "$1");
            record.setResponseDecision("BLOCKED");
            record.setResponseAction("Source IP " + alert.getSourceIp() + " was blocked by firewall rule #" + blockId);
            return;
        }
        if (alert.getStatus() == AlertStatus.FALSE_POSITIVE || alert.getMlFeedback() == MlFeedback.FALSE_POSITIVE) {
            record.setResponseDecision("MARKED_FALSE_POSITIVE");
            record.setResponseAction("Alert was closed as benign training feedback");
            return;
        }
        if (alert.getStatus() == AlertStatus.RESOLVED) {
            record.setResponseDecision("RESOLVED");
            record.setResponseAction("Alert was resolved without a recorded firewall block");
            return;
        }
        record.setResponseDecision(alert.getStatus().name());
        record.setResponseAction("Current alert status: " + alert.getStatus().name());
    }

    public Page<MlTrainingRecord> list(Long orgId, String label, String attackType, int page, int size) {
        String pattern = (attackType != null && !attackType.isBlank())
                         ? "%" + attackType.toLowerCase() + "%"
                         : null;
        return repo.search(orgId, label, pattern,
                PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt")));
    }

    public List<MlTrainingRecord> listAll(Long orgId) {
        return repo.findAllForExport(orgId);
    }

    public Map<String, Object> stats(Long orgId) {
        long total  = repo.countByOrganization_Id(orgId);
        long attack = repo.countByOrgAndLabel(orgId, "ATTACK");
        long benign = repo.countByOrgAndLabel(orgId, "BENIGN");
        return Map.of("total", total, "attack", attack, "benign", benign);
    }
}
