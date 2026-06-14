package com.aisec.backend.service;

import com.aisec.backend.entity.Alert;
import com.aisec.backend.repository.AlertRepository;
import com.lowagie.text.*;
import com.lowagie.text.pdf.*;
import org.springframework.stereotype.Service;

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

/**
 * Generates downloadable reports (PDF and CSV) from alerts in the DB.
 */
@Service
public class ReportExportService {

    private static final DateTimeFormatter TS_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private final AlertRepository alerts;
    private final AlertService alertService;

    public ReportExportService(AlertRepository alerts, AlertService alertService) {
        this.alerts = alerts;
        this.alertService = alertService;
    }

    /** Stream tenant-scoped alerts as CSV. orgId=null → system tenant only. */
    public void writeCsv(OutputStream out, Long orgId) throws Exception {
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
        out.write(sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        out.flush();
    }

    private static String csvEscape(String s) {
        if (s == null) return "";
        boolean needsQuote = s.contains(",") || s.contains("\"") || s.contains("\n") || s.contains("\r");
        String v = s.replace("\"", "\"\"");
        return needsQuote ? "\"" + v + "\"" : v;
    }

    /** Generate a tenant-scoped PDF report. orgId=null → system tenant only. */
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
        Paragraph title = new Paragraph("AI Security Platform", titleFont);
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
        Paragraph footer = new Paragraph("\nThis report is automatically generated by the AI Security Platform. " +
                "Classification data is derived from the live PostgreSQL database.", smallFont);
        footer.setSpacingBefore(20);
        doc.add(footer);

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
}
