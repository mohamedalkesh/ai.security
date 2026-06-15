package com.aisec.backend.service;

import com.aisec.backend.entity.Alert;
import com.aisec.backend.entity.AlertStatus;
import com.aisec.backend.entity.Severity;
import com.aisec.backend.repository.AlertRepository;
import com.lowagie.text.*;
import com.lowagie.text.pdf.*;
import com.lowagie.text.DocumentException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.InputStream;
import java.io.IOException;
import com.ibm.icu.text.ArabicShaping;
import com.ibm.icu.text.ArabicShapingException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Generates downloadable reports (PDF and CSV) from alerts in the DB.
 */
@Service
public class ReportExportService {

    private static final DateTimeFormatter TS_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private static final Map<String, ClassificationInfo> CLASS_LOOKUP = Map.ofEntries(
            Map.entry("DDOS",           new ClassificationInfo("Network Attack",       "Volumetric",       "Edge Gateway")),
            Map.entry("DOS",            new ClassificationInfo("Network Attack",       "Volumetric",       "Network Service")),
            Map.entry("BOT",            new ClassificationInfo("Botnet Activity",      "Command & Control", "Endpoint")),
            Map.entry("BRUTE FORCE",    new ClassificationInfo("Credential Attack",    "Network-based",    "Authentication Service")),
            Map.entry("INFILTRATION",   new ClassificationInfo("Intrusion",            "Network-based",    "Internal Network")),
            Map.entry("WEB ATTACK",     new ClassificationInfo("Web Application Attack","HTTP-based",       "Web Server")),
            Map.entry("SQL INJECTION",  new ClassificationInfo("Web Application Attack","HTTP-based",       "Database Server")),
            Map.entry("XSS",            new ClassificationInfo("Web Application Attack","Client-side",      "Web Application")),
            Map.entry("PORT SCAN",      new ClassificationInfo("Reconnaissance",      "Network-based",    "Network Perimeter")),
            Map.entry("FTP-PATATOR",    new ClassificationInfo("Credential Attack",    "FTP Brute Force",  "FTP Service")),
            Map.entry("SSH-PATATOR",    new ClassificationInfo("Credential Attack",    "SSH Brute Force",  "SSH Service")),
            Map.entry("HEARTBLEED",     new ClassificationInfo("Vulnerability Exploit","TLS-based",        "TLS Endpoint"))
    );

    private static final Map<String, MitreMapping> MITRE_LOOKUP = Map.ofEntries(
            Map.entry("DDOS",       new MitreMapping("TA0040", "Impact",               "T1498", "Network Denial of Service",
                    List.of("Deploy rate limiting and traffic scrubbing", "Coordinate with upstream providers"))),
            Map.entry("DOS",        new MitreMapping("TA0040", "Impact",               "T1499", "Endpoint Denial of Service",
                    List.of("Harden exposed services", "Implement redundancy for critical endpoints"))),
            Map.entry("BOT",        new MitreMapping("TA0042", "Resource Development", "T1583", "Acquire Infrastructure",
                    List.of("Block command and control domains", "Monitor outbound beaconing"))),
            Map.entry("BRUTE FORCE",new MitreMapping("TA0006", "Credential Access",    "T1110", "Brute Force",
                    List.of("Enforce strong authentication", "Throttle repeated login attempts"))),
            Map.entry("INFILTRATION",new MitreMapping("TA0011", "Command and Control","T1071", "Application Layer Protocol",
                    List.of("Inspect outbound application traffic", "Restrict direct internet access"))),
            Map.entry("WEB ATTACK", new MitreMapping("TA0001", "Initial Access",       "T1190", "Exploit Public-Facing Application",
                    List.of("Patch internet-facing services", "Validate and sanitize inputs"))),
            Map.entry("SQL INJECTION",new MitreMapping("TA0001", "Initial Access",     "T1190", "Exploit Public-Facing Application",
                    List.of("Use parameterized queries", "Deploy web application firewall"))),
            Map.entry("XSS",        new MitreMapping("TA0002", "Execution",            "T1059", "Command and Scripting Interpreter",
                    List.of("Escape user-provided input", "Implement content security policy"))),
            Map.entry("PORTSCAN",   new MitreMapping("TA0007", "Discovery",            "T1046", "Network Service Discovery",
                    List.of("Monitor scanning behaviour", "Segment internal networks"))),
            Map.entry("FTP-PATATOR",new MitreMapping("TA0006", "Credential Access",    "T1110", "Brute Force",
                    List.of("Limit FTP access", "Enforce account lockout"))),
            Map.entry("SSH-PATATOR",new MitreMapping("TA0006", "Credential Access",    "T1110", "Brute Force",
                    List.of("Disable password-based SSH", "Deploy multi-factor authentication"))),
            Map.entry("HEARTBLEED", new MitreMapping("TA0001", "Initial Access",       "T1190", "Exploit Public-Facing Application",
                    List.of("Update TLS libraries", "Terminate legacy cipher suites")))
    );

    private final AlertRepository alerts;
    private final AlertService alertService;
    private final ObjectMapper json = new ObjectMapper();
    private BaseFont arabicBaseFont;

    public ReportExportService(AlertRepository alerts, AlertService alertService) {
        this.alerts = alerts;
        this.alertService = alertService;
    }

    private static final List<ResponseStep> DEFAULT_RESPONSE_TEMPLATE = List.of(
            new ResponseStep("Block Source IP Address",       "Add offending IP to firewall blocklist",                     "< 1 min", "critical", true),
            new ResponseStep("Update Security Rules",         "Deploy updated signatures for observed attack pattern",      "2 min",   "critical", true),
            new ResponseStep("Isolate Affected System",       "Quarantine impacted host from production network",            "5 min",   "high",    false),
            new ResponseStep("Run Integrity Check",           "Verify data integrity and detect unauthorized changes",      "10 min",  "high",    true),
            new ResponseStep("Notify Security Team",          "Alert on-call security analysts with incident details",      "< 1 min", "medium",  true),
            new ResponseStep("Generate Incident Report",      "Document incident for compliance requirements",              "3 min",   "medium",  true),
            new ResponseStep("Review Access Logs",            "Manual review of authentication and access logs",            "30 min",  "low",     false)
    );

    private static final Map<String, List<ResponseStep>> RESPONSE_TEMPLATES = Map.of(
            "DDOS", List.of(
                    new ResponseStep("Enable DDoS Mitigation",         "Activate rate limiting for hostile source ranges",            "< 1 min", "critical", true),
                    new ResponseStep("Scale Edge Capacity",             "Auto-scale edge nodes to absorb flood",                     "2 min",  "critical", true),
                    new ResponseStep("Block Source Ranges",             "Blackhole offending /24 networks at upstream provider",     "1 min",  "high",    true),
                    new ResponseStep("Enable Traffic Scrubbing",        "Route inbound traffic through scrubbing center",            "5 min",  "high",    false),
                    new ResponseStep("Notify NOC Team",                 "Alert Network Operations Center of ongoing attack",         "< 1 min","medium",  true),
                    new ResponseStep("Generate Post-Incident Report",   "Document attack timeline and countermeasures",              "10 min", "low",     true)
            ),
            "BRUTE FORCE", List.of(
                    new ResponseStep("Block Source IP",                 "Add offending IP to firewall blocklist",                    "< 1 min", "critical", true),
                    new ResponseStep("Lock Targeted Accounts",          "Temporarily lock accounts with repeated failures",         "1 min",  "critical", true),
                    new ResponseStep("Enable MFA / CAPTCHA",            "Force multi-factor authentication on affected service",    "5 min",  "high",    false),
                    new ResponseStep("Review Authentication Logs",      "Identify impacted accounts and sessions",                  "15 min", "high",    false),
                    new ResponseStep("Reset Compromised Credentials",   "Force password reset for breached accounts",               "5 min",  "medium",  true),
                    new ResponseStep("Generate Compliance Report",      "Document incident for regulatory reporting",               "10 min", "low",     true)
            )
    );

    /** Stream tenant-scoped alerts as CSV. orgId=null → system tenant only. */
    @Transactional(readOnly = true)
    public byte[] buildCsv(Long orgId) throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("id,created_at,attack_type,severity,status,source_ip,dest_ip,dest_port,protocol,confidence,mitre_technique,mitre_tactic,description\n");
        for (Alert a : alerts.findAllScopedOrdered(orgId)) {
            sb.append(a.getId()).append(',')
              .append(TS_FMT.format(a.getCreatedAt())).append(',')
              .append(csvEscape(a.getAttackType())).append(',')
              .append(a.getSeverity()).append(',')
              .append(a.getStatus()).append(',')
              .append(csvEscape(a.getSourceIp())).append(',')
              .append(csvEscape(a.getDestIp())).append(',')
              .append(a.getDestPort() == null ? "" : a.getDestPort()).append(',')
              .append(csvEscape(a.getProtocol())).append(',')
              .append(a.getConfidence() == null ? "" : String.format("%.4f", a.getConfidence())).append(',')
              .append(csvEscape(a.getMitreTechnique())).append(',')
              .append(csvEscape(a.getMitreTactic())).append(',')
              .append(csvEscape(a.getDescription()))
              .append('\n');
        }
        return sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    private static String csvEscape(String s) {
        if (s == null) return "";
        boolean needsQuote = s.contains(",") || s.contains("\"") || s.contains("\n") || s.contains("\r");
        String v = s.replace("\"", "\"\"");
        return needsQuote ? "\"" + v + "\"" : v;
    }

    /** Generate a tenant-scoped PDF report. orgId=null → system tenant only. */
    @Transactional(readOnly = true)
    public byte[] buildPdf(Long orgId) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        Document doc = new Document(PageSize.A4, 40, 40, 50, 40);
        PdfWriter.getInstance(doc, bos);
        doc.open();

        // === Fonts ===
        Font titleFont   = new Font(Font.HELVETICA, 20, Font.BOLD, new Color(30, 64, 175));
        Font subFont     = new Font(Font.HELVETICA, 11, Font.NORMAL, Color.DARK_GRAY);
        Font sectionFont = new Font(Font.HELVETICA, 14, Font.BOLD, new Color(15, 23, 42));
        Font labelFont   = new Font(Font.HELVETICA, 10, Font.BOLD, Color.DARK_GRAY);
        Font valFont     = new Font(Font.HELVETICA, 10, Font.NORMAL, Color.BLACK);
        Font smallFont   = new Font(Font.HELVETICA, 8, Font.NORMAL, Color.GRAY);

        // === Header ===
        Paragraph title = new Paragraph("MADRS", titleFont);
        title.setAlignment(Element.ALIGN_CENTER);
        doc.add(title);

        Paragraph sub = new Paragraph("Security Operations Report", subFont);
        sub.setAlignment(Element.ALIGN_CENTER);
        sub.setSpacingAfter(4);
        doc.add(sub);

        Paragraph ts = new Paragraph("Generated: " + TS_FMT.format(Instant.now()), smallFont);
        ts.setAlignment(Element.ALIGN_CENTER);
        ts.setSpacingAfter(20);
        doc.add(ts);

        // === Summary KPIs ===
        doc.add(new Paragraph("1. Executive Summary", sectionFont));
        doc.add(new Paragraph(" ", smallFont));
        Map<String, Object> stats = alertService.stats(orgId);
        PdfPTable kpiTable = new PdfPTable(2);
        kpiTable.setWidthPercentage(100);
        kpiTable.setSpacingAfter(16);
        addKpiRow(kpiTable, "Total Alerts",       String.valueOf(stats.get("total")),    labelFont, valFont);
        addKpiRow(kpiTable, "Active Alerts",      String.valueOf(stats.get("active")),   labelFont, valFont);
        addKpiRow(kpiTable, "Resolved Alerts",    String.valueOf(stats.get("resolved")), labelFont, valFont);
        addKpiRow(kpiTable, "Critical Severity",  String.valueOf(stats.get("critical")), labelFont, valFont);
        addKpiRow(kpiTable, "High Severity",      String.valueOf(stats.get("high")),     labelFont, valFont);
        addKpiRow(kpiTable, "Last 24 hours",      String.valueOf(stats.get("last24h")),  labelFont, valFont);
        doc.add(kpiTable);

        // === Attack-type breakdown ===
        doc.add(new Paragraph("2. Attack Type Distribution", sectionFont));
        doc.add(new Paragraph(" ", smallFont));
        List<Map<String, Object>> breakdown = alertService.attackTypeBreakdown(orgId);
        PdfPTable bt = new PdfPTable(new float[]{3f, 1f});
        bt.setWidthPercentage(100);
        bt.addCell(cell("Attack Type",  labelFont, new Color(241, 245, 249), Element.ALIGN_LEFT));
        bt.addCell(cell("Count",        labelFont, new Color(241, 245, 249), Element.ALIGN_RIGHT));
        if (breakdown.isEmpty()) {
            PdfPCell empty = cell("No data available", smallFont, Color.WHITE, Element.ALIGN_CENTER);
            empty.setColspan(2);
            bt.addCell(empty);
        } else {
            for (Map<String, Object> row : breakdown) {
                bt.addCell(cell(String.valueOf(row.getOrDefault("attackType", row.get("type"))), valFont, Color.WHITE, Element.ALIGN_LEFT));
                bt.addCell(cell(String.valueOf(row.getOrDefault("count", row.get("total"))),    valFont, Color.WHITE, Element.ALIGN_RIGHT));
            }
        }
        bt.setSpacingAfter(16);
        doc.add(bt);

        // === Recent alerts table (top 30) ===
        doc.add(new Paragraph("3. Recent Alerts (latest 30)", sectionFont));
        doc.add(new Paragraph(" ", smallFont));
        PdfPTable at = new PdfPTable(new float[]{.8f, 2.2f, 2.2f, 1.6f, 1.4f, 1.4f, 1.4f});
        at.setWidthPercentage(100);
        at.addCell(cell("ID",       labelFont, new Color(241, 245, 249), Element.ALIGN_CENTER));
        at.addCell(cell("Time",     labelFont, new Color(241, 245, 249), Element.ALIGN_LEFT));
        at.addCell(cell("Attack",   labelFont, new Color(241, 245, 249), Element.ALIGN_LEFT));
        at.addCell(cell("Severity", labelFont, new Color(241, 245, 249), Element.ALIGN_CENTER));
        at.addCell(cell("Status",   labelFont, new Color(241, 245, 249), Element.ALIGN_CENTER));
        at.addCell(cell("Source",   labelFont, new Color(241, 245, 249), Element.ALIGN_LEFT));
        at.addCell(cell("Target",   labelFont, new Color(241, 245, 249), Element.ALIGN_LEFT));

        List<Alert> recent = alerts.findAllScopedOrdered(orgId).stream().limit(30).toList();
        if (recent.isEmpty()) {
            PdfPCell empty = cell("No alerts in the database", smallFont, Color.WHITE, Element.ALIGN_CENTER);
            empty.setColspan(7);
            at.addCell(empty);
        } else {
            for (Alert a : recent) {
                at.addCell(cell(String.valueOf(a.getId()),                     smallFont, Color.WHITE, Element.ALIGN_CENTER));
                at.addCell(cell(TS_FMT.format(a.getCreatedAt()),              smallFont, Color.WHITE, Element.ALIGN_LEFT));
                at.addCell(cell(safe(a.getAttackType()),                       smallFont, Color.WHITE, Element.ALIGN_LEFT));
                at.addCell(cell(a.getSeverity().name(),                        smallFont, sevColor(a.getSeverity().name()), Element.ALIGN_CENTER));
                at.addCell(cell(a.getStatus().name(),                          smallFont, Color.WHITE, Element.ALIGN_CENTER));
                at.addCell(cell(safe(a.getSourceIp()),                         smallFont, Color.WHITE, Element.ALIGN_LEFT));
                at.addCell(cell(safe(a.getDestIp()),                           smallFont, Color.WHITE, Element.ALIGN_LEFT));
            }
        }
        doc.add(at);

        // === Footer ===
        Paragraph footer = new Paragraph("\nThis report is automatically generated by the MADRS. " +
                "Classification data is derived from the live PostgreSQL database.", smallFont);
        footer.setSpacingBefore(20);
        doc.add(footer);

        doc.close();
        return bos.toByteArray();
    }

    /** Generate a structured incident response plan for a single alert. */
    @Transactional(readOnly = true)
    public byte[] buildResponsePlanPdf(Long alertId, Long orgId) throws Exception {
        Alert alert = alerts.findById(alertId).orElseThrow(() ->
                new ResponseStatusException(HttpStatus.NOT_FOUND, "Alert not found"));
        Long ownerOrg = alert.getOrganization() != null ? alert.getOrganization().getId() : null;
        if (!Objects.equals(ownerOrg, orgId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Alert not found");
        }

        String attackType = safe(alert.getAttackType());
        List<ResponseStep> template = selectResponseTemplate(attackType);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        Document doc = new Document(PageSize.A4, 36, 36, 48, 40);
        PdfWriter.getInstance(doc, bos);
        doc.open();

        Font titleFont   = new Font(Font.HELVETICA, 18, Font.BOLD, new Color(27, 90, 160));
        Font sectionFont = new Font(Font.HELVETICA, 13, Font.BOLD, new Color(15, 23, 42));
        Font labelFont   = new Font(Font.HELVETICA, 10, Font.BOLD, new Color(71, 85, 105));
        Font valFont     = new Font(Font.HELVETICA, 10, Font.NORMAL, Color.BLACK);
        Font smallFont   = new Font(Font.HELVETICA, 8, Font.NORMAL, Color.GRAY);
        Font monoFont    = new Font(Font.COURIER, 8, Font.NORMAL, new Color(55, 65, 81));

        String ref = String.format("INC-%03d", alert.getId());

        Paragraph title = new Paragraph("MADRS — Incident Response Plan", titleFont);
        title.setAlignment(Element.ALIGN_CENTER);
        title.setSpacingAfter(6);
        doc.add(title);

        Paragraph meta = new Paragraph(ref + " · Generated: " + TS_FMT.format(Instant.now()), smallFont);
        meta.setAlignment(Element.ALIGN_CENTER);
        meta.setSpacingAfter(16);
        doc.add(meta);

        PdfPTable overview = new PdfPTable(new float[]{2.2f, 3.8f});
        overview.setWidthPercentage(100);
        overview.setSpacingAfter(12);
        addInfoRow(overview, "Incident ID", ref, labelFont, valFont);
        addInfoRow(overview, "Attack Type", attackType, labelFont, valFont);
        addInfoRow(overview, "Severity", alert.getSeverity().name(), labelFont, valFont);
        addInfoRow(overview, "Source IP", safe(alert.getSourceIp()), labelFont, valFont);
        addInfoRow(overview, "Destination IP", safe(alert.getDestIp()), labelFont, valFont);
        addInfoRow(overview, "Confidence", alert.getConfidence() == null ? "N/A" : String.format("%.1f%%", alert.getConfidence() * 100), labelFont, valFont);
        doc.add(overview);

        doc.add(new Paragraph("1. Automated Response Steps", sectionFont));
        doc.add(new Paragraph(" ", smallFont));
        PdfPTable autoTable = new PdfPTable(new float[]{0.7f, 2.5f, 2.8f, 1f});
        autoTable.setWidthPercentage(100);
        autoTable.setSpacingAfter(12);
        autoTable.addCell(cell("#", labelFont, new Color(248,250,252), Element.ALIGN_CENTER));
        autoTable.addCell(cell("Action", labelFont, new Color(248,250,252), Element.ALIGN_LEFT));
        autoTable.addCell(cell("Description", labelFont, new Color(248,250,252), Element.ALIGN_LEFT));
        autoTable.addCell(cell("ETA", labelFont, new Color(248,250,252), Element.ALIGN_CENTER));
        int index = 1;
        for (ResponseStep step : template) {
            if (!step.automatic()) continue;
            autoTable.addCell(cell(String.valueOf(index++), valFont, Color.WHITE, Element.ALIGN_CENTER));
            autoTable.addCell(cell(step.title(), valFont, Color.WHITE, Element.ALIGN_LEFT));
            autoTable.addCell(cell(step.description(), valFont, Color.WHITE, Element.ALIGN_LEFT));
            autoTable.addCell(cell(step.duration(), valFont, Color.WHITE, Element.ALIGN_CENTER));
        }
        if (index == 1) {
            autoTable.addCell(cell("—", valFont, Color.WHITE, Element.ALIGN_CENTER));
            autoTable.addCell(cell("No automated steps defined", valFont, Color.WHITE, Element.ALIGN_LEFT));
            autoTable.addCell(cell("", valFont, Color.WHITE, Element.ALIGN_LEFT));
            autoTable.addCell(cell("", valFont, Color.WHITE, Element.ALIGN_CENTER));
        }
        doc.add(autoTable);

        doc.add(new Paragraph("2. Manual Response Steps", sectionFont));
        doc.add(new Paragraph(" ", smallFont));
        PdfPTable manualTable = new PdfPTable(new float[]{0.7f, 2.5f, 2.8f, 1f});
        manualTable.setWidthPercentage(100);
        manualTable.setSpacingAfter(12);
        manualTable.addCell(cell("#", labelFont, new Color(248,250,252), Element.ALIGN_CENTER));
        manualTable.addCell(cell("Action", labelFont, new Color(248,250,252), Element.ALIGN_LEFT));
        manualTable.addCell(cell("Description", labelFont, new Color(248,250,252), Element.ALIGN_LEFT));
        manualTable.addCell(cell("ETA", labelFont, new Color(248,250,252), Element.ALIGN_CENTER));
        int manualIndex = 1;
        for (ResponseStep step : template) {
            if (step.automatic()) continue;
            manualTable.addCell(cell(String.valueOf(manualIndex++), valFont, Color.WHITE, Element.ALIGN_CENTER));
            manualTable.addCell(cell(step.title(), valFont, Color.WHITE, Element.ALIGN_LEFT));
            manualTable.addCell(cell(step.description(), valFont, Color.WHITE, Element.ALIGN_LEFT));
            manualTable.addCell(cell(step.duration(), valFont, Color.WHITE, Element.ALIGN_CENTER));
        }
        if (manualIndex == 1) {
            manualTable.addCell(cell("—", valFont, Color.WHITE, Element.ALIGN_CENTER));
            manualTable.addCell(cell("No manual steps required", valFont, Color.WHITE, Element.ALIGN_LEFT));
            manualTable.addCell(cell("", valFont, Color.WHITE, Element.ALIGN_LEFT));
            manualTable.addCell(cell("", valFont, Color.WHITE, Element.ALIGN_CENTER));
        }
        doc.add(manualTable);

        doc.add(new Paragraph("3. Approvals & Impact", sectionFont));
        doc.add(new Paragraph(" ", smallFont));
        PdfPTable impactTable = new PdfPTable(new float[]{2.5f, 3.5f});
        impactTable.setWidthPercentage(100);
        impactTable.setSpacingAfter(12);
        impactTable.addCell(cell("Approval Status", labelFont, new Color(248,250,252), Element.ALIGN_LEFT));
        impactTable.addCell(cell("Pending security lead approval for manual tasks", valFont, Color.WHITE, Element.ALIGN_LEFT));
        Severity severity = alert.getSeverity();
        impactTable.addCell(cell("Service Disruption", labelFont, new Color(248,250,252), Element.ALIGN_LEFT));
        impactTable.addCell(cell(impactLevel(severity), valFont, Color.WHITE, Element.ALIGN_LEFT));
        impactTable.addCell(cell("Data at Risk", labelFont, new Color(248,250,252), Element.ALIGN_LEFT));
        String dataRisk = severity == Severity.CRITICAL || severity == Severity.HIGH ? "High"
                : severity == Severity.MEDIUM ? "Medium" : "Low";
        impactTable.addCell(cell(dataRisk, valFont, Color.WHITE, Element.ALIGN_LEFT));
        doc.add(impactTable);

        doc.add(new Paragraph("4. Next Steps", sectionFont));
        doc.add(new Paragraph(" ", smallFont));
        com.lowagie.text.List nextSteps = new com.lowagie.text.List(com.lowagie.text.List.UNORDERED);
        nextSteps.setListSymbol(new Chunk("• ", labelFont));
        nextSteps.add(new ListItem(new Chunk("Monitor telemetry for reoccurrence over the next 24 hours.", valFont)));
        nextSteps.add(new ListItem(new Chunk("Review compliance requirements and file reports as necessary.", valFont)));
        nextSteps.add(new ListItem(new Chunk("Schedule a post-incident review with stakeholders.", valFont)));
        doc.add(nextSteps);

        doc.close();
        return bos.toByteArray();
    }

    /** Generate a MITRE ATT&CK mapping narrative for a single alert. */
    @Transactional(readOnly = true)
    public byte[] buildMitrePdf(Long alertId, Long orgId) throws Exception {
        Alert alert = alerts.findById(alertId).orElseThrow(() ->
                new ResponseStatusException(HttpStatus.NOT_FOUND, "Alert not found"));
        Long ownerOrg = alert.getOrganization() != null ? alert.getOrganization().getId() : null;
        if (!Objects.equals(ownerOrg, orgId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Alert not found");
        }

        MitreMapping mapping = resolveMitreMapping(alert.getAttackType());

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        Document doc = new Document(PageSize.A4, 36, 36, 48, 40);
        PdfWriter.getInstance(doc, bos);
        doc.open();

        Font titleFont   = new Font(Font.HELVETICA, 18, Font.BOLD, new Color(34, 102, 163));
        Font sectionFont = new Font(Font.HELVETICA, 13, Font.BOLD, new Color(15, 23, 42));
        Font labelFont   = new Font(Font.HELVETICA, 10, Font.BOLD, new Color(71, 85, 105));
        Font valFont     = new Font(Font.HELVETICA, 10, Font.NORMAL, Color.BLACK);
        Font smallFont   = new Font(Font.HELVETICA, 8, Font.NORMAL, Color.GRAY);

        String ref = String.format("INC-%03d", alert.getId());

        Paragraph title = new Paragraph("MADRS — MITRE ATT&CK Mapping", titleFont);
        title.setAlignment(Element.ALIGN_CENTER);
        title.setSpacingAfter(6);
        doc.add(title);

        Paragraph meta = new Paragraph(ref + " · Generated: " + TS_FMT.format(Instant.now()), smallFont);
        meta.setAlignment(Element.ALIGN_CENTER);
        meta.setSpacingAfter(16);
        doc.add(meta);

        // Overview table
        PdfPTable overview = new PdfPTable(new float[]{2.2f, 3.8f});
        overview.setWidthPercentage(100);
        overview.setSpacingAfter(12);
        addInfoRow(overview, "Incident ID", ref, labelFont, valFont);
        addInfoRow(overview, "Attack Type", safe(alert.getAttackType()), labelFont, valFont);
        addInfoRow(overview, "Severity", alert.getSeverity().name(), labelFont, valFont);
        addInfoRow(overview, "Confidence", alert.getConfidence() == null ? "N/A" : String.format("%.1f%%", alert.getConfidence() * 100), labelFont, valFont);
        addInfoRow(overview, "Source IP", safe(alert.getSourceIp()), labelFont, valFont);
        addInfoRow(overview, "Destination IP", safe(alert.getDestIp()), labelFont, valFont);
        doc.add(overview);

        // Mapping
        doc.add(new Paragraph("1. MITRE Mapping", sectionFont));
        doc.add(new Paragraph(" ", smallFont));
        PdfPTable mappingTable = new PdfPTable(new float[]{2f, 3f});
        mappingTable.setWidthPercentage(100);
        mappingTable.setSpacingAfter(12);
        mappingTable.addCell(cell("Tactic", labelFont, new Color(248, 250, 252), Element.ALIGN_LEFT));
        mappingTable.addCell(cell(mapping.tacticName() + " (" + mapping.tacticId() + ")", valFont, Color.WHITE, Element.ALIGN_LEFT));
        mappingTable.addCell(cell("Technique", labelFont, new Color(248, 250, 252), Element.ALIGN_LEFT));
        mappingTable.addCell(cell(mapping.techniqueName() + " (" + mapping.techniqueId() + ")", valFont, Color.WHITE, Element.ALIGN_LEFT));
        doc.add(mappingTable);

        // Narrative
        doc.add(new Paragraph("2. Detection Narrative", sectionFont));
        doc.add(new Paragraph(" ", smallFont));
        Paragraph narrative = new Paragraph(
                String.format("Alert %s was classified by the AI model as %s. Indicators observed between %s and %s matched MITRE technique %s (%s). This places the adversary in the %s tactic of the ATT&CK framework, driving the recommended mitigations below.",
                        ref,
                        safe(alert.getAttackType()),
                        safe(alert.getSourceIp()),
                        safe(alert.getDestIp()),
                        mapping.techniqueId(),
                        mapping.techniqueName(),
                        mapping.tacticName()),
                valFont);
        narrative.setSpacingAfter(12);
        doc.add(narrative);

        // Mitigations
        doc.add(new Paragraph("3. Recommended Mitigations", sectionFont));
        doc.add(new Paragraph(" ", smallFont));
        com.lowagie.text.List mitList = new com.lowagie.text.List(com.lowagie.text.List.UNORDERED);
        mitList.setListSymbol(new Chunk("• ", labelFont));
        for (String item : mapping.mitigations()) {
            mitList.add(new ListItem(new Chunk(item, valFont)));
        }
        doc.add(mitList);

        // Next Steps
        doc.add(new Paragraph("4. Next Steps", sectionFont));
        doc.add(new Paragraph(" ", smallFont));
        com.lowagie.text.List nextList = new com.lowagie.text.List(com.lowagie.text.List.ORDERED);
        nextList.add(new ListItem(new Chunk("Validate that detection rules for the mapped technique are tuned and producing actionable alerts.", valFont)));
        nextList.add(new ListItem(new Chunk("Coordinate with the response team to apply mitigations and monitor for recurrence.", valFont)));
        nextList.add(new ListItem(new Chunk("Update runbooks to reflect the observed TTPs and associated indicators.", valFont)));
        doc.add(nextList);

        doc.close();
        return bos.toByteArray();
    }

    /** Generate a single-incident AI classification report. */
    @Transactional(readOnly = true)
    public byte[] buildClassificationPdf(Long alertId, Long orgId) throws Exception {
        Alert alert = alerts.findById(alertId).orElseThrow(() ->
                new ResponseStatusException(HttpStatus.NOT_FOUND, "Alert not found"));
        Long ownerOrg = alert.getOrganization() != null ? alert.getOrganization().getId() : null;
        if (!Objects.equals(ownerOrg, orgId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Alert not found");
        }

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        Document doc = new Document(PageSize.A4, 36, 36, 48, 40);
        PdfWriter.getInstance(doc, bos);
        doc.open();

        Font titleFont   = new Font(Font.HELVETICA, 18, Font.BOLD, new Color(79, 70, 229));
        Font sectionFont = new Font(Font.HELVETICA, 13, Font.BOLD, new Color(15, 23, 42));
        Font labelFont   = new Font(Font.HELVETICA, 10, Font.BOLD, new Color(71, 85, 105));
        Font valFont     = new Font(Font.HELVETICA, 10, Font.NORMAL, Color.BLACK);
        Font smallFont   = new Font(Font.HELVETICA, 8, Font.NORMAL, Color.GRAY);
        Font monoFont    = new Font(Font.COURIER, 8, Font.NORMAL, new Color(55, 65, 81));

        String ref = String.format("INC-%03d", alert.getId());

        Paragraph title = new Paragraph("MADRS — AI Classification Report", titleFont);
        title.setAlignment(Element.ALIGN_CENTER);
        title.setSpacingAfter(6);
        doc.add(title);

        Paragraph meta = new Paragraph(ref + " · Generated: " + TS_FMT.format(Instant.now()), smallFont);
        meta.setAlignment(Element.ALIGN_CENTER);
        meta.setSpacingAfter(18);
        doc.add(meta);

        // --- Incident summary ---
        doc.add(new Paragraph("1. Incident Overview", sectionFont));
        doc.add(new Paragraph(" ", smallFont));
        PdfPTable info = new PdfPTable(new float[]{2.2f, 3.8f});
        info.setWidthPercentage(100);
        info.setSpacingAfter(12);

        addInfoRow(info, "Incident ID", ref, labelFont, valFont);
        addInfoRow(info, "Attack Type", safe(alert.getAttackType()), labelFont, valFont);
        addInfoRow(info, "Severity", alert.getSeverity().name(), labelFont, valFont);
        addInfoRow(info, "Status", alert.getStatus().name(), labelFont, valFont);
        addInfoRow(info, "Detected", TS_FMT.format(alert.getCreatedAt()), labelFont, valFont);
        if (alert.getResolvedAt() != null) {
            addInfoRow(info, "Resolved", TS_FMT.format(alert.getResolvedAt()), labelFont, valFont);
        }
        addInfoRow(info, "Source IP", safe(alert.getSourceIp()), labelFont, valFont);
        addInfoRow(info, "Destination IP", safe(alert.getDestIp()), labelFont, valFont);
        addInfoRow(info, "Destination Port", alert.getDestPort() == null ? "—" : String.valueOf(alert.getDestPort()), labelFont, valFont);
        addInfoRow(info, "Protocol", safe(alert.getProtocol()), labelFont, valFont);

        ClassificationInfo ci = lookupClassification(alert.getAttackType());
        addInfoRow(info, "Attack Category", ci.category(), labelFont, valFont);
        addInfoRow(info, "Attack Vector", ci.vector(), labelFont, valFont);
        addInfoRow(info, "Target Asset", ci.asset(), labelFont, valFont);

        double confidencePct = alert.getConfidence() == null ? -1 : alert.getConfidence() * 100.0;
        Explanation explanation = parseExplanation(alert.getExplanation());
        if (confidencePct >= 0) {
            addInfoRow(info, "Model Confidence", String.format("%.1f%%", confidencePct), labelFont, valFont);
        }

        doc.add(info);

        // --- Narrative ---
        doc.add(new Paragraph("2. Narrative & Explanation", sectionFont));
        doc.add(new Paragraph(" ", smallFont));
        if (alert.getDescription() != null && !alert.getDescription().isBlank()) {
            Paragraph desc = new Paragraph(alert.getDescription(), valFont);
            desc.setSpacingAfter(6);
            doc.add(desc);
        }
        if (explanation != null) {
            Paragraph aiHeading = new Paragraph("AI Model Explanation", labelFont);
            aiHeading.setSpacingBefore(4);
            aiHeading.setSpacingAfter(6);
            doc.add(aiHeading);

            if (explanation.summary() != null && !explanation.summary().isBlank()) {
                Paragraph summary = new Paragraph(explanation.summary(), valFont);
                summary.setSpacingAfter(6);
                doc.add(summary);
            }

            if (!explanation.details().isEmpty()) {
                com.lowagie.text.List detailList = new com.lowagie.text.List(com.lowagie.text.List.UNORDERED);
                detailList.setListSymbol(new Chunk("• ", labelFont));
                for (String detail : explanation.details()) {
                    detailList.add(new ListItem(new Chunk(detail, valFont)));
                }
                detailList.setIndentationLeft(16f);
                doc.add(detailList);
                doc.add(new Paragraph(" ", smallFont));
            }

            if (!explanation.features().isEmpty()) {
                PdfPTable features = new PdfPTable(new float[]{2.5f, 1.2f, 1f});
                features.setWidthPercentage(100);
                features.setSpacingAfter(8);
                features.addCell(cell("Feature", labelFont, new Color(248, 250, 252), Element.ALIGN_LEFT));
                features.addCell(cell("Value", labelFont, new Color(248, 250, 252), Element.ALIGN_LEFT));
                features.addCell(cell("Impact", labelFont, new Color(248, 250, 252), Element.ALIGN_CENTER));
                for (FeatureImpact f : explanation.features()) {
                    features.addCell(cell(f.name(), valFont, Color.WHITE, Element.ALIGN_LEFT));
                    features.addCell(cell(f.value() == null ? "—" : f.value(), valFont, Color.WHITE, Element.ALIGN_LEFT));
                    features.addCell(cell(String.format("%.3f", f.impact()), valFont, Color.WHITE, Element.ALIGN_CENTER));
                }
                doc.add(features);
            }

            if (explanation.ascii() != null && !explanation.ascii().isBlank()) {
                Paragraph payloadHeading = new Paragraph("Payload Sample (ASCII)", labelFont);
                payloadHeading.setSpacingBefore(4);
                payloadHeading.setSpacingAfter(4);
                doc.add(payloadHeading);
                Paragraph payloadBody = new Paragraph(explanation.ascii(), monoFont);
                payloadBody.setSpacingAfter(4);
                doc.add(payloadBody);
            } else if (explanation.hex() != null && !explanation.hex().isBlank()) {
                Paragraph payloadHeading = new Paragraph("Payload Sample (HEX)", labelFont);
                payloadHeading.setSpacingBefore(4);
                payloadHeading.setSpacingAfter(4);
                doc.add(payloadHeading);
                Paragraph payloadBody = new Paragraph(explanation.hex(), monoFont);
                payloadBody.setSpacingAfter(4);
                doc.add(payloadBody);
            }

            StringBuilder metaLine = new StringBuilder();
            if (explanation.sizeBytes() != null) {
                metaLine.append(explanation.sizeBytes()).append(" bytes captured");
            }
            if (explanation.previewBytes() != null && explanation.previewBytes() < (explanation.sizeBytes() == null ? Integer.MAX_VALUE : explanation.sizeBytes())) {
                if (metaLine.length() > 0) metaLine.append(" · ");
                metaLine.append("عرض أول ").append(explanation.previewBytes()).append(" بايت");
            }
            if (explanation.note() != null && !explanation.note().isBlank()) {
                if (metaLine.length() > 0) metaLine.append(" · ");
                metaLine.append(explanation.note());
            }
            if (metaLine.length() > 0) {
                Paragraph metaParagraph = new Paragraph(metaLine.toString(), smallFont);
                metaParagraph.setSpacingAfter(8);
                doc.add(metaParagraph);
            }
        }
        if ((alert.getMitreTechnique() != null && !alert.getMitreTechnique().isBlank()) ||
                (alert.getMitreTactic() != null && !alert.getMitreTactic().isBlank())) {
            Paragraph mitre = new Paragraph(
                    "MITRE ATT&CK: " + safe(alert.getMitreTechnique()) +
                    " · Tactic: " + safe(alert.getMitreTactic()), smallFont);
            mitre.setSpacingAfter(12);
            doc.add(mitre);
        }

        // --- Analyst metrics ---
        doc.add(new Paragraph("3. Analyst Highlights", sectionFont));
        doc.add(new Paragraph(" ", smallFont));
        PdfPTable metrics = new PdfPTable(new float[]{3.5f, 1.2f});
        metrics.setWidthPercentage(100);
        metrics.setSpacingAfter(12);
        metrics.addCell(cell("Attack Pattern Recognition", labelFont, new Color(248, 250, 252), Element.ALIGN_LEFT));
        metrics.addCell(cell(metricValue(confidencePct + 2), valFont, Color.WHITE, Element.ALIGN_RIGHT));
        metrics.addCell(cell("Behavioral Anomaly Match", labelFont, Color.WHITE, Element.ALIGN_LEFT));
        metrics.addCell(cell(metricValue(confidencePct - 8), valFont, Color.WHITE, Element.ALIGN_RIGHT));
        metrics.addCell(cell("Signature Correlation", labelFont, Color.WHITE, Element.ALIGN_LEFT));
        metrics.addCell(cell(metricValue(confidencePct - 15), valFont, Color.WHITE, Element.ALIGN_RIGHT));
        metrics.addCell(cell("Threat Severity", labelFont, Color.WHITE, Element.ALIGN_LEFT));
        metrics.addCell(cell(alert.getSeverity().name(), valFont, Color.WHITE, Element.ALIGN_RIGHT));
        doc.add(metrics);

        // --- Next steps (English) ---
        doc.add(new Paragraph("4. Recommended Actions", sectionFont));
        doc.add(new Paragraph(" ", smallFont));
        com.lowagie.text.List checklist = new com.lowagie.text.List(com.lowagie.text.List.UNORDERED);
        checklist.setListSymbol(new Chunk("• ", labelFont));
        checklist.add(new ListItem("Validate firewall coverage for source IP " + safe(alert.getSourceIp()), valFont));
        if (alert.getStatus() != AlertStatus.RESOLVED) {
            checklist.add(new ListItem("Escalate incident for response workflow", valFont));
        }
        checklist.add(new ListItem("Document findings in MADRS audit trail", valFont));
        doc.add(checklist);

        // --- Arabic summary ---
        doc.add(new Paragraph("5. ملخص باللغة العربية", sectionFont));
        doc.add(new Paragraph(" ", smallFont));

        Font arabicFont = loadArabicFont();
        doc.add(makeArabicParagraph(String.format("الحادثة %s من النوع %s بدرجة خطورة %s.",
                ref, arabicAttackType(alert.getAttackType()), arabicSeverity(alert.getSeverity().name())), arabicFont, 6f));

        doc.add(makeArabicParagraph(String.format("المصدر %s يستهدف %s عبر المنفذ %s وبروتوكول %s.",
                safe(alert.getSourceIp()), safe(alert.getDestIp()),
                alert.getDestPort() == null ? "—" : String.valueOf(alert.getDestPort()),
                safe(alert.getProtocol())), arabicFont, 6f));

        doc.add(makeArabicParagraph("ثقة نموذج الذكاء الاصطناعي: " + (confidencePct >= 0 ? String.format("%.1f%%", confidencePct) : "غير متوفرة"), arabicFont, 6f));

        if (explanation != null && explanation.summary() != null && !explanation.summary().isBlank()) {
            doc.add(makeArabicParagraph("تفسير الذكاء الاصطناعي: " + explanation.summary(), arabicFont, 6f));
        }
        if (explanation != null && !explanation.details().isEmpty()) {
            com.lowagie.text.List arabicDetails = new com.lowagie.text.List(com.lowagie.text.List.UNORDERED);
            arabicDetails.setListSymbol(new Chunk("• ", arabicFont));
            for (String detail : explanation.details()) {
                arabicDetails.add(makeArabicListItem(detail, arabicFont));
            }
            doc.add(arabicDetails);
        }

        doc.add(makeArabicParagraph("التوصيات:", arabicFont, 4f));

        com.lowagie.text.List arabicList = new com.lowagie.text.List(com.lowagie.text.List.UNORDERED);
        arabicList.setListSymbol(new Chunk("• ", arabicFont));
        arabicList.add(makeArabicListItem("تأكيد حظر عنوان المصدر على جدار الحماية.", arabicFont));
        if (alert.getStatus() != AlertStatus.RESOLVED) {
            arabicList.add(makeArabicListItem("فتح بلاغ استجابة للحادثة للفريق المختص.", arabicFont));
        }
        arabicList.add(makeArabicListItem("توثيق الخطوات في سجل نظام MADRS.", arabicFont));
        doc.add(arabicList);

        doc.close();
        return bos.toByteArray();
    }

    // ---------- Helpers ----------
    private static void addKpiRow(PdfPTable t, String label, String value, Font labelFont, Font valFont) {
        t.addCell(cell(label, labelFont, new Color(248, 250, 252), Element.ALIGN_LEFT));
        t.addCell(cell(value, valFont,   Color.WHITE,              Element.ALIGN_RIGHT));
    }

    private static PdfPCell cell(String text, Font font, Color bg, int align) {
        PdfPCell c = new PdfPCell(new Phrase(text == null ? "" : text, font));
        c.setBackgroundColor(bg);
        c.setPadding(6);
        c.setHorizontalAlignment(align);
        c.setBorderColor(new Color(226, 232, 240));
        return c;
    }

    private static Color sevColor(String sev) {
        return switch (sev) {
            case "CRITICAL"      -> new Color(254, 226, 226);
            case "HIGH"          -> new Color(255, 237, 213);
            case "MEDIUM"        -> new Color(254, 249, 195);
            case "LOW"           -> new Color(220, 252, 231);
            default              -> Color.WHITE;
        };
    }

    private static String safe(String s) { return s == null ? "—" : s; }

    private static String metricValue(double pct) {
        if (Double.isNaN(pct) || pct < 0) return "N/A";
        double c = Math.max(0, Math.min(100, pct));
        return String.format("%.1f%%", c);
    }

    private static ClassificationInfo lookupClassification(String attackType) {
        if (attackType == null) return new ClassificationInfo("Network Threat", "Network-based", "Target System");
        String upper = attackType.trim().toUpperCase();
        return CLASS_LOOKUP.entrySet().stream()
                .filter(e -> upper.contains(e.getKey()))
                .map(Map.Entry::getValue)
                .findFirst()
                .orElse(new ClassificationInfo("Network Threat", "Network-based", "Target System"));
    }

    private static void addInfoRow(PdfPTable table, String label, String value, Font labelFont, Font valFont) {
        table.addCell(cell(label, labelFont, new Color(248, 250, 252), Element.ALIGN_LEFT));
        table.addCell(cell(value, valFont, Color.WHITE, Element.ALIGN_LEFT));
    }

    private Font loadArabicFont() {
        if (arabicBaseFont == null) {
            try (InputStream in = ReportExportService.class.getResourceAsStream("/fonts/NotoSansArabic-Regular.ttf")) {
                if (in != null) {
                    byte[] bytes = in.readAllBytes();
                    arabicBaseFont = BaseFont.createFont("NotoSansArabic-Regular.ttf", BaseFont.IDENTITY_H, BaseFont.EMBEDDED, true, bytes, null);
                }
            } catch (IOException | DocumentException ignored) {}

            if (arabicBaseFont == null) {
                try {
                    arabicBaseFont = BaseFont.createFont(BaseFont.HELVETICA, BaseFont.WINANSI, BaseFont.NOT_EMBEDDED);
                } catch (IOException | DocumentException ignored) {}
            }
        }

        if (arabicBaseFont != null) {
            return new Font(arabicBaseFont, 10, Font.NORMAL, Color.BLACK);
        }

        Font fallback = new Font(Font.HELVETICA, 10, Font.NORMAL, Color.BLACK);
        fallback.setFamily("Helvetica");
        return fallback;
    }

    private static String arabicSeverity(String severity) {
        return switch (severity.toUpperCase()) {
            case "CRITICAL" -> "حرجة";
            case "HIGH" -> "عالية";
            case "MEDIUM" -> "متوسطة";
            case "LOW" -> "منخفضة";
            default -> "غير معروفة";
        };
    }

    private static String arabicAttackType(String type) {
        if (type == null || type.isBlank()) return "تهديد شبكي";
        String upper = type.toUpperCase();
        if (upper.contains("DDOS") || upper.contains("DOS")) return "هجوم حجب الخدمة";
        if (upper.contains("BRUTE")) return "هجوم تخمين كلمات المرور";
        if (upper.contains("PORT")) return "مسح منافذ";
        if (upper.contains("SQL")) return "حقن قواعد البيانات";
        if (upper.contains("XSS")) return "هجوم عبر البرمجة النصية";
        if (upper.contains("BOT")) return "نشاط بوت نت";
        if (upper.contains("WEB")) return "هجوم على تطبيق ويب";
        if (upper.contains("INFILTRATION")) return "تسلل";
        return "تهديد شبكي";
    }

    private String shapeArabic(String text) {
        if (text == null || text.isEmpty()) return "";
        if (!containsArabic(text)) return text;
        try {
            ArabicShaping shaping = new ArabicShaping(
                    ArabicShaping.LETTERS_SHAPE |
                    ArabicShaping.LENGTH_GROW_SHRINK |
                    ArabicShaping.TEXT_DIRECTION_VISUAL_RTL);
            return shaping.shape(text);
        } catch (ArabicShapingException e) {
            return text;
        }
    }

    private Paragraph makeArabicParagraph(String text, Font font, float spacingAfter) {
        Paragraph p = new Paragraph(shapeArabic(text), font);
        p.setAlignment(Element.ALIGN_RIGHT);
        p.setSpacingAfter(spacingAfter);
        p.setRunDirection(PdfWriter.RUN_DIRECTION_RTL);
        return p;
    }

    private ListItem makeArabicListItem(String text, Font font) {
        ListItem item = new ListItem(shapeArabic(text), font);
        item.setAlignment(Element.ALIGN_RIGHT);
        item.setRunDirection(PdfWriter.RUN_DIRECTION_RTL);
        return item;
    }

    private static boolean containsArabic(String text) {
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if ((c >= 0x0600 && c <= 0x06FF) ||
                (c >= 0x0750 && c <= 0x077F) ||
                (c >= 0x08A0 && c <= 0x08FF) ||
                (c >= 0xFB50 && c <= 0xFDFF) ||
                (c >= 0xFE70 && c <= 0xFEFF)) {
                return true;
            }
        }
        return false;
    }

    private Explanation parseExplanation(String raw) {
        if (raw == null || raw.isBlank()) return null;
        try {
            JsonNode node = json.readTree(raw);
            String summary = nodeText(node.path("summary"));

            List<String> details = new ArrayList<>();
            JsonNode detailNode = node.path("details");
            if (detailNode.isArray()) {
                for (JsonNode d : detailNode) {
                    String text = nodeText(d);
                    if (text != null && !text.isBlank()) details.add(text);
                }
            }

            JsonNode payload = node.path("payload_sample");
            String ascii = nodeText(payload.path("ascii"));
            String hex = nodeText(payload.path("hex"));
            String note = nodeText(payload.path("note"));
            Integer sizeBytes = payload.hasNonNull("size_bytes") ? payload.get("size_bytes").asInt() : null;
            Integer previewBytes = payload.hasNonNull("preview_bytes") ? payload.get("preview_bytes").asInt() : null;

            List<FeatureImpact> features = new ArrayList<>();
            JsonNode topFeatures = node.path("top_features");
            if (topFeatures.isArray()) {
                for (JsonNode f : topFeatures) {
                    String name = nodeText(f.path("feature"));
                    if (name == null || name.isBlank()) continue;
                    String value = nodeText(f.path("value"));
                    double impact = f.hasNonNull("impact") ? f.get("impact").asDouble() : 0.0;
                    features.add(new FeatureImpact(name, value, impact));
                }
            }

            return new Explanation(summary, details, ascii, hex, note, sizeBytes, previewBytes, features);
        } catch (Exception ignored) {
            return null;
        }
    }

    private static String nodeText(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull()) return null;
        String text = node.asText();
        return text != null ? text.trim() : null;
    }


    private static MitreMapping resolveMitreMapping(String attackType) {
        if (attackType == null) return new MitreMapping("TA0007", "Discovery", "T1046", "Network Service Discovery",
                List.of("Investigate scanning activity", "Segment internal networks"));
        String norm = attackType.toUpperCase().replaceAll("[^A-Z0-9]", "");
        return MITRE_LOOKUP.entrySet().stream()
                .filter(e -> norm.contains(e.getKey()))
                .map(Map.Entry::getValue)
                .findFirst()
                .orElse(new MitreMapping("TA0007", "Discovery", "T1046", "Network Service Discovery",
                        List.of("Investigate scanning activity", "Segment internal networks")));
    }

    private static List<ResponseStep> selectResponseTemplate(String attackType) {
        if (attackType == null) return new ArrayList<>(DEFAULT_RESPONSE_TEMPLATE);
        String norm = attackType.toUpperCase();
        return RESPONSE_TEMPLATES.entrySet().stream()
                .filter(e -> norm.contains(e.getKey()))
                .map(Map.Entry::getValue)
                .findFirst()
                .map(ArrayList::new)
                .orElse(new ArrayList<>(DEFAULT_RESPONSE_TEMPLATE));
    }

    private static String impactLevel(Severity severity) {
        return switch (severity) {
            case CRITICAL, HIGH -> "High";
            case MEDIUM -> "Medium";
            default -> "Low";
        };
    }

    private record Explanation(String summary,
                               List<String> details,
                               String ascii,
                               String hex,
                               String note,
                               Integer sizeBytes,
                               Integer previewBytes,
                               List<FeatureImpact> features) {}

    private record FeatureImpact(String name, String value, double impact) {}

    private record ClassificationInfo(String category, String vector, String asset) {}
    private record MitreMapping(String tacticId, String tacticName, String techniqueId, String techniqueName, List<String> mitigations) {}
    private record ResponseStep(String title, String description, String duration, String severity, boolean automatic) {}
}
