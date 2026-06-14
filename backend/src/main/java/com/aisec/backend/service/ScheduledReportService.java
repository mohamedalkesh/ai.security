package com.aisec.backend.service;

import com.aisec.backend.entity.Organization;
import com.aisec.backend.entity.Role;
import com.aisec.backend.entity.UserAccount;
import com.aisec.backend.repository.OrganizationRepository;
import com.aisec.backend.repository.UserRepository;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.util.ByteArrayDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Generates weekly executive PDFs and emails them to every ORG_ADMIN of every
 * tenant (and to system ADMINs for the system tenant).
 *
 * Scheduled for Mondays 06:00 server time. Disable globally via
 * {@code app.reports.scheduled-enabled=false}.
 */
@Service
public class ScheduledReportService {

    private static final Logger log = LoggerFactory.getLogger(ScheduledReportService.class);
    private static final DateTimeFormatter DATE_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneId.systemDefault());

    private final OrganizationRepository orgs;
    private final UserRepository users;
    private final ReportExportService exportService;
    private final JavaMailSender mailSender;
    private final AuditService audit;

    @Value("${spring.mail.username:noreply@aisec.local}")
    private String fromEmail;

    @Value("${app.reports.scheduled-enabled:true}")
    private boolean enabled;

    public ScheduledReportService(OrganizationRepository orgs, UserRepository users,
                                  ReportExportService exportService,
                                  JavaMailSender mailSender,
                                  AuditService audit) {
        this.orgs = orgs;
        this.users = users;
        this.exportService = exportService;
        this.mailSender = mailSender;
        this.audit = audit;
    }

    /** Mondays 06:00 server time. */
    @Scheduled(cron = "0 0 6 * * MON")
    public void deliverWeeklyReports() {
        if (!enabled) { log.info("Scheduled reports disabled, skipping"); return; }
        log.info("Starting weekly report delivery cycle");

        // System tenant (orgId=null) — system admins only.
        deliverForTenant(null, "System", systemAdmins());

        // Every customer organisation.
        for (Organization org : orgs.findAll()) {
            deliverForTenant(org.getId(), org.getName(), orgAdmins(org.getId()));
        }
        audit.logAnonymous("REPORT_WEEKLY_RUN", "scheduler",
                "weekly digest cycle complete");
    }

    private void deliverForTenant(Long orgId, String tenantName, List<UserAccount> recipients) {
        if (recipients.isEmpty()) {
            log.debug("No admin recipients for tenant {}, skipping", tenantName);
            return;
        }
        try {
            byte[] pdf = exportService.buildPdf(orgId);
            String subject = "AI Security — Weekly Report (" + tenantName + ") "
                    + DATE_FMT.format(Instant.now());
            String filename = "security-report-" + DATE_FMT.format(Instant.now()) + ".pdf";

            for (UserAccount u : recipients) {
                if (u.getEmail() == null || u.getEmail().isBlank()) continue;
                sendOne(u.getEmail(), u.getFullName(), subject, filename, pdf, tenantName);
            }
            log.info("Weekly report sent to {} recipients in tenant {}",
                    recipients.size(), tenantName);
        } catch (Exception e) {
            log.warn("Weekly report failed for tenant {}: {}", tenantName, e.getMessage());
        }
    }

    private void sendOne(String to, String fullName, String subject, String filename,
                         byte[] pdf, String tenantName) {
        try {
            MimeMessage msg = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(msg, true, "UTF-8");
            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(htmlBody(fullName, tenantName), true);
            helper.addAttachment(filename, new ByteArrayDataSource(pdf, "application/pdf"));
            mailSender.send(msg);
        } catch (MailException | MessagingException ex) {
            log.warn("Failed to email weekly report to {}: {}", to, ex.getMessage());
        }
    }

    private List<UserAccount> systemAdmins() {
        return users.findByOrg(null).stream()
                .filter(u -> u.getRole() == Role.ADMIN)
                .toList();
    }

    private List<UserAccount> orgAdmins(Long orgId) {
        return users.findByOrg(orgId).stream()
                .filter(u -> u.getRole() == Role.ORG_ADMIN)
                .toList();
    }

    private static String htmlBody(String fullName, String tenantName) {
        String name = fullName == null || fullName.isBlank() ? "Administrator" : fullName;
        return "<!DOCTYPE html><html><body style='font-family:Inter,Arial,sans-serif;background:#0b1628;color:#cbd5e1;padding:24px'>"
             + "<div style='max-width:560px;margin:0 auto;background:#16243d;border:1px solid #1e3557;border-radius:12px;padding:32px'>"
             + "<h2 style='color:#22b8cf;margin:0 0 12px'>🛡️ Weekly Security Digest</h2>"
             + "<p style='margin:0 0 8px'>Hello <strong>" + name + "</strong>,</p>"
             + "<p style='margin:0 0 16px;line-height:1.6'>Attached is the weekly security report for "
             + "<strong>" + tenantName + "</strong>. It summarises new alerts, "
             + "severity distribution, and the top recent incidents.</p>"
             + "<p style='font-size:12px;color:#8ea0b8;margin:24px 0 0'>Generated automatically by AI Security Platform — "
             + "do not reply.</p></div></body></html>";
    }
}
