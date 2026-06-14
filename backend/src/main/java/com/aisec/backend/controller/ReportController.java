package com.aisec.backend.controller;

import com.aisec.backend.repository.AlertRepository;
import com.aisec.backend.repository.ScanResultRepository;
import com.aisec.backend.repository.UserRepository;
import com.aisec.backend.security.OrgUserDetails;
import com.aisec.backend.service.AlertService;
import com.aisec.backend.service.ReportExportService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/reports")
public class ReportController {

    private static final DateTimeFormatter FILE_TS =
            DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").withZone(ZoneId.systemDefault());

    private final AlertRepository alerts;
    private final ScanResultRepository scans;
    private final UserRepository users;
    private final AlertService alertService;
    private final ReportExportService exportService;

    public ReportController(AlertRepository alerts, ScanResultRepository scans,
                            UserRepository users, AlertService alertService,
                            ReportExportService exportService) {
        this.alerts = alerts;
        this.scans = scans;
        this.users = users;
        this.alertService = alertService;
        this.exportService = exportService;
    }

    @GetMapping("/summary")
    public Map<String, Object> summary(@AuthenticationPrincipal OrgUserDetails principal) {
        Long orgId = principal != null ? principal.getOrganizationId() : null;
        Map<String, Object> r = new HashMap<>();
        r.put("alerts", alertService.stats(orgId));
        r.put("scans",  Map.of("total", scans.findRecentByOrg(orgId).size()));
        r.put("users",  Map.of("total", users.findByOrg(orgId).size()));
        r.put("breakdown", alertService.attackTypeBreakdown(orgId));
        return r;
    }

    /** Download tenant-scoped alerts as CSV. */
    @GetMapping("/export.csv")
    public ResponseEntity<StreamingResponseBody> exportCsv(@AuthenticationPrincipal OrgUserDetails principal) {
        Long orgId = principal != null ? principal.getOrganizationId() : null;
        String filename = "alerts-" + FILE_TS.format(Instant.now()) + ".csv";
        StreamingResponseBody body = out -> {
            try {
                exportService.writeCsv(out, orgId);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                .contentType(MediaType.parseMediaType("text/csv; charset=UTF-8"))
                .body(body);
    }

    /** Download the tenant-scoped executive summary as PDF. */
    @GetMapping("/export.pdf")
    public ResponseEntity<byte[]> exportPdf(@AuthenticationPrincipal OrgUserDetails principal) throws Exception {
        Long orgId = principal != null ? principal.getOrganizationId() : null;
        byte[] pdf = exportService.buildPdf(orgId);
        String filename = "security-report-" + FILE_TS.format(Instant.now()) + ".pdf";
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                .contentType(MediaType.APPLICATION_PDF)
                .body(pdf);
    }
}
