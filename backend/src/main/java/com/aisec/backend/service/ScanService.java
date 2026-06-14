package com.aisec.backend.service;

import com.aisec.backend.dto.PcapResult;
import com.aisec.backend.dto.PredictionResult;
import com.aisec.backend.dto.scan.ScanSummaryDto;
import com.aisec.backend.entity.Alert;
import com.aisec.backend.entity.AlertStatus;
import com.aisec.backend.entity.Organization;
import com.aisec.backend.entity.ScanResult;
import com.aisec.backend.entity.Severity;
import com.aisec.backend.repository.OrganizationRepository;
import com.aisec.backend.repository.ScanResultRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.task.TaskExecutor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Service
public class ScanService {

    private static final Logger log = LoggerFactory.getLogger(ScanService.class);
    private static final String STATUS_PROCESSING = "PROCESSING";
    private static final String STATUS_COMPLETED = "COMPLETED";
    private static final String STATUS_FAILED = "FAILED";

    private final MlClient ml;
    private final ScanResultRepository scans;
    private final AlertService alerts;
    private final ObjectMapper mapper;
    private final com.aisec.backend.websocket.AlertBroadcaster broadcaster;
    private final OrganizationRepository orgRepo;
    private final TaskExecutor scanExecutor;
    private final TransactionTemplate txTemplate;

    public ScanService(MlClient ml, ScanResultRepository scans,
                       AlertService alerts, ObjectMapper mapper,
                       com.aisec.backend.websocket.AlertBroadcaster broadcaster,
                       OrganizationRepository orgRepo,
                       @Qualifier("taskExecutor") TaskExecutor scanExecutor,
                       PlatformTransactionManager txManager) {
        this.ml = ml;
        this.scans = scans;
        this.alerts = alerts;
        this.mapper = mapper;
        this.broadcaster = broadcaster;
        this.orgRepo = orgRepo;
        this.scanExecutor = scanExecutor;
        this.txTemplate = new TransactionTemplate(txManager);
    }

    public ScanSummaryDto handlePcap(MultipartFile file, Long orgId) throws IOException {
        Organization org = resolveOrg(orgId);
        ScanResult scan = new ScanResult();
        scan.setSourceType("PCAP");
        scan.setFilename(file.getOriginalFilename());
        scan.setOrganization(org);
        scan.setStatus(STATUS_PROCESSING);
        scan.setErrorMessage(null);
        scan.setCompletedAt(null);
        scan = scans.save(scan);

        Path tmp = Files.createTempFile("aisec-scan-", ".pcap");
        file.transferTo(tmp.toFile());
        final Long scanId = scan.getId();
        final String originalName = file.getOriginalFilename();
        scanExecutor.execute(() -> processScanAsync(scanId, tmp, orgId, originalName));

        return ScanSummaryDto.from(scan);
    }

    @Transactional
    public PredictionResult handleFlow(Map<String, Double> features, Long orgId) {
        Organization org = resolveOrg(orgId);
        PredictionResult r = ml.predictFlow(new com.aisec.backend.dto.FlowRequest(features));
        if (r != null && !"Benign".equalsIgnoreCase(r.predicted())) {
            Alert a = new Alert();
            a.setAttackType(r.predicted());
            a.setConfidence(r.confidence());
            a.setSeverity(toSeverity(r.severity()));
            a.setStatus(AlertStatus.NEW);
            a.setMitreTechnique(r.mitreTechnique());
            a.setMitreTactic(r.mitreTactic());
            a.setDescription(r.description());
            if (r.explanation() != null) {
                try {
                    a.setExplanation(mapper.writeValueAsString(r.explanation()));
                } catch (JsonProcessingException ignored) {}
            }
            a.setOrganization(org);
            alerts.save(a);
        }
        return r;
    }

    public List<ScanSummaryDto> recent(Long orgId) {
        // Always tenant-scoped — system admin (orgId=null) sees only system scans.
        return scans.findRecentByOrg(orgId).stream()
                .limit(20).map(ScanSummaryDto::from).toList();
    }

    public ScanSummaryDto findOne(Long id, Long orgId) {
        ScanResult scan = scans.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Scan not found"));
        Long scanOrgId = scan.getOrganization() != null ? scan.getOrganization().getId() : null;
        if (!Objects.equals(orgId, scanOrgId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Scan not found");
        }
        return ScanSummaryDto.from(scan);
    }

    private Organization resolveOrg(Long orgId) {
        return orgId != null ? orgRepo.findById(orgId).orElse(null) : null;
    }

    private Severity toSeverity(Object o) {
        if (o == null) return Severity.INFORMATIONAL;
        try { return Severity.valueOf(String.valueOf(o).toUpperCase().replace(' ', '_')); }
        catch (Exception e) { return Severity.INFORMATIONAL; }
    }
    private Double toDouble(Object o) {
        if (o == null) return null;
        try { return Double.parseDouble(String.valueOf(o)); } catch (Exception e) { return null; }
    }
    private Integer toInt(Object o) {
        if (o == null) return null;
        try { return (int) Math.round(Double.parseDouble(String.valueOf(o))); }
        catch (Exception e) { return null; }
    }
    private String strOr(Object o, String def) {
        return o == null ? def : String.valueOf(o);
    }

    private void processScanAsync(Long scanId, Path filePath, Long orgId, String originalName) {
        try {
            // 1. Heavy ML work first — no DB transaction is held open during the
            //    network round-trip to the ML service.
            PcapResult res = ml.predictPcap(filePath,
                    originalName != null ? originalName : filePath.getFileName().toString());

            // 2. Persist metrics + COMPLETED in a short, self-contained transaction
            //    and commit immediately so the result becomes visible the instant
            //    analysis finishes — before any (slow) alert fan-out runs.
            ScanSummaryDto summary = txTemplate.execute(tx -> {
                ScanResult scan = scans.findById(scanId).orElse(null);
                if (scan == null) return null;
                populateScanMetrics(scan, res);
                scan.setStatus(STATUS_COMPLETED);
                scan.setCompletedAt(Instant.now());
                scan.setErrorMessage(null);
                return ScanSummaryDto.from(scans.save(scan));
            });
            if (summary == null) return;

            // 3. Instant push to the UI — does not wait for alert persistence.
            broadcaster.broadcastScanComplete(summary, orgId);

            // 4. Alert creation runs AFTER COMPLETED is committed + broadcast, so
            //    the per-alert firewall / webhook / geoip side effects never delay
            //    the visible scan result.
            txTemplate.executeWithoutResult(tx -> {
                ScanResult scan = scans.findById(scanId).orElse(null);
                if (scan != null) createAlertsFromFlows(res.flows(), scan);
            });
        } catch (Exception ex) {
            log.error("Async scan {} failed: {}", scanId, ex.getMessage(), ex);
            markScanFailed(scanId, orgId, ex.getMessage());
        } finally {
            try {
                Files.deleteIfExists(filePath);
            } catch (IOException e) {
                log.warn("Cleanup failed for {}: {}", filePath, e.getMessage());
            }
        }
    }

    private void markScanFailed(Long scanId, Long orgId, String message) {
        try {
            ScanSummaryDto summary = txTemplate.execute(tx -> {
                ScanResult scan = scans.findById(scanId).orElse(null);
                if (scan == null) return null;
                scan.setStatus(STATUS_FAILED);
                scan.setCompletedAt(Instant.now());
                scan.setErrorMessage(message);
                return ScanSummaryDto.from(scans.save(scan));
            });
            if (summary != null) {
                // Push the failure too so the UI reacts instantly instead of
                // waiting for the next poll.
                broadcaster.broadcastScanComplete(summary, orgId);
            }
        } catch (Exception e) {
            log.error("Failed to mark scan {} as FAILED: {}", scanId, e.getMessage());
        }
    }

    private void populateScanMetrics(ScanResult scan, PcapResult res) {
        if (res == null) return;
        scan.setTotalFlows(res.totalFlows());
        scan.setBenignCount(res.benign());
        scan.setAttackCount(res.attacks());
        scan.setAvgConfidence(res.avgConfidence());
        try {
            scan.setSummaryJson(mapper.writeValueAsString(res.summary()));
        } catch (JsonProcessingException ignored) {}

        try {
            if (res.metadataQuality() != null) {
                scan.setMetadataQualityJson(mapper.writeValueAsString(res.metadataQuality()));
            } else {
                scan.setMetadataQualityJson(null);
            }
        } catch (JsonProcessingException ignored) {}
        scan.setSampled(res.sampled());
        scan.setOriginalRows(res.originalRows());
        scan.setSampledRows(res.sampledRows());
    }

    private void createAlertsFromFlows(List<Map<String, Object>> flows, ScanResult scan) {
        if (flows == null) return;
        int created = 0;
        for (Map<String, Object> f : flows) {
            String predicted = String.valueOf(f.getOrDefault("predicted", "Benign"));
            if ("Benign".equalsIgnoreCase(predicted)) continue;
            Alert a = new Alert();
            a.setAttackType(predicted);
            a.setConfidence(toDouble(f.get("confidence")));
            a.setSeverity(toSeverity(f.get("severity")));
            a.setStatus(AlertStatus.NEW);
            a.setSourceIp(strOr(f.get("src_ip"), null));
            a.setDestIp(strOr(f.get("dst_ip"), null));
            a.setDestPort(toInt(f.get("dst_port")));
            a.setProtocol(strOr(f.get("protocol"), null));
            a.setMitreTechnique(strOr(f.get("mitre_technique"), null));
            a.setMitreTactic(strOr(f.get("mitre_tactic"), null));
            a.setDescription(strOr(f.get("description"),
                    predicted + " detected from PCAP scan"));
            Object explanation = f.get("explanation");
            if (explanation != null) {
                try { a.setExplanation(mapper.writeValueAsString(explanation)); }
                catch (JsonProcessingException ignored) {}
            }
            a.setScan(scan);
            a.setOrganization(scan.getOrganization());
            alerts.save(a);
            created++;
            if (created >= 200) break;
        }
        log.info("PCAP scan #{} completed: {} flows, {} alerts created",
                scan.getId(), scan.getTotalFlows(), created);
    }
}
