package com.aisec.backend.controller;

import com.aisec.backend.entity.MlTrainingRecord;
import com.aisec.backend.security.OrgUserDetails;
import com.aisec.backend.service.MlTrainingService;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/training-data")
@PreAuthorize("hasAnyRole('ADMIN','ORG_ADMIN','ANALYST')")
public class MlTrainingController {

    private static final DateTimeFormatter FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneOffset.UTC);

    private final MlTrainingService service;

    public MlTrainingController(MlTrainingService service) {
        this.service = service;
    }

    @GetMapping
    public Page<MlTrainingRecord> list(
            @RequestParam(defaultValue = "0")    int    page,
            @RequestParam(defaultValue = "50")   int    size,
            @RequestParam(required = false)      String label,
            @RequestParam(required = false)      String attackType,
            @AuthenticationPrincipal OrgUserDetails principal) {
        Long orgId = principal != null ? principal.getOrganizationId() : null;
        return service.list(orgId, label, attackType, page, size);
    }

    @GetMapping("/stats")
    public Map<String, Object> stats(@AuthenticationPrincipal OrgUserDetails principal) {
        Long orgId = principal != null ? principal.getOrganizationId() : null;
        return service.stats(orgId);
    }

    @GetMapping("/export.csv")
    public ResponseEntity<byte[]> exportCsv(@AuthenticationPrincipal OrgUserDetails principal) {
        Long orgId = principal != null ? principal.getOrganizationId() : null;
        List<MlTrainingRecord> records = service.listAll(orgId);

        StringBuilder sb = new StringBuilder();
        sb.append("id,alert_id,true_label,attack_type,severity,confidence,source_ip,dest_ip,dest_port,protocol,mitre_technique,mitre_tactic,resolution_status,alert_created_at,resolved_at\n");
        for (MlTrainingRecord r : records) {
            sb.append(csv(r.getId())).append(',')
              .append(csv(r.getAlertId())).append(',')
              .append(csv(r.getTrueLabel())).append(',')
              .append(csv(r.getAttackType())).append(',')
              .append(csv(r.getSeverity())).append(',')
              .append(csv(r.getConfidence())).append(',')
              .append(csv(r.getSourceIp())).append(',')
              .append(csv(r.getDestIp())).append(',')
              .append(csv(r.getDestPort())).append(',')
              .append(csv(r.getProtocol())).append(',')
              .append(csv(r.getMitreTechnique())).append(',')
              .append(csv(r.getMitreTactic())).append(',')
              .append(csv(r.getResolutionStatus())).append(',')
              .append(r.getAlertCreatedAt() != null ? FMT.format(r.getAlertCreatedAt()) : "").append(',')
              .append(r.getResolvedAt() != null ? FMT.format(r.getResolvedAt()) : "")
              .append('\n');
        }

        byte[] bytes = sb.toString().getBytes(StandardCharsets.UTF_8);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"training_data.csv\"")
                .contentType(MediaType.parseMediaType("text/csv"))
                .body(bytes);
    }

    private static String csv(Object v) {
        if (v == null) return "";
        String s = v.toString();
        if (s.contains(",") || s.contains("\"") || s.contains("\n")) {
            s = "\"" + s.replace("\"", "\"\"") + "\"";
        }
        return s;
    }
}
