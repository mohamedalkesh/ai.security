package com.aisec.backend.service;

import com.aisec.backend.config.AppProperties;
import com.aisec.backend.dto.CompanyRequestDto;
import com.aisec.backend.entity.Organization;
import com.aisec.backend.entity.Role;
import com.aisec.backend.entity.UserAccount;
import com.aisec.backend.repository.OrganizationRepository;
import com.aisec.backend.repository.UserRepository;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;

@Service
public class CompanyRequestService {

    private static final Logger log = LoggerFactory.getLogger(CompanyRequestService.class);
    private static final String CHARS = "ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";

    private final JavaMailSender mailSender;
    private final AppProperties appProperties;
    private final OrganizationRepository orgRepo;
    private final UserRepository userRepo;
    private final PasswordEncoder passwordEncoder;

    public CompanyRequestService(JavaMailSender mailSender, AppProperties appProperties,
                                  OrganizationRepository orgRepo, UserRepository userRepo,
                                  PasswordEncoder passwordEncoder) {
        this.mailSender = mailSender;
        this.appProperties = appProperties;
        this.orgRepo = orgRepo;
        this.userRepo = userRepo;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public void submitRequest(CompanyRequestDto dto) {
        String supportEmail = appProperties.getSupportEmail();
        if (supportEmail == null || supportEmail.isBlank()) {
            supportEmail = "MADRS.support@gmail.com";
        }

        Organization org = createOrganization(dto.companyName());
        String username = generateUsername(dto.companyName());
        String password = generatePassword();
        createAdminUser(org, dto.contactName(), dto.contactEmail(), username, password);

        sendInternalNotification(dto, supportEmail, username);
        sendWelcomeEmail(dto.contactName(), dto.contactEmail(), dto.companyName(),
                         username, password, supportEmail);
    }

    private Organization createOrganization(String companyName) {
        if (orgRepo.existsByName(companyName)) {
            return orgRepo.findByName(companyName).orElseThrow();
        }
        Organization org = new Organization();
        org.setName(companyName);
        return orgRepo.save(org);
    }

    private void createAdminUser(Organization org, String fullName, String email,
                                  String username, String password) {
        // Fail loudly on collision so the @Transactional rolls back the org too,
        // instead of silently sending a welcome email with credentials we never stored.
        if (userRepo.existsByUsername(username))
            throw new IllegalStateException("Username already exists: " + username);
        if (userRepo.existsByEmail(email))
            throw new IllegalStateException(
                    "An account already exists for this email. Please use a different contact email.");
        UserAccount u = new UserAccount();
        u.setUsername(username);
        u.setEmail(email);
        u.setFullName(fullName);
        u.setPasswordHash(passwordEncoder.encode(password));
        u.setRole(Role.ORG_ADMIN);
        u.setOrganization(org);
        userRepo.save(u);
        log.info("Created org admin: {} for org: {}", username, org.getName());
    }

    private String generateUsername(String companyName) {
        String base = companyName.toLowerCase()
                .replaceAll("[^a-z0-9]+", "_")
                .replaceAll("^_+|_+$", "");
        if (base.length() > 20) base = base.substring(0, 20);
        String candidate = base + "_admin";
        if (!userRepo.existsByUsername(candidate)) return candidate;
        for (int i = 2; i <= 99; i++) {
            String next = base + "_admin" + i;
            if (!userRepo.existsByUsername(next)) return next;
        }
        return base + "_" + System.currentTimeMillis();
    }

    private String generatePassword() {
        SecureRandom rnd = new SecureRandom();
        StringBuilder sb = new StringBuilder(12);
        for (int i = 0; i < 12; i++) sb.append(CHARS.charAt(rnd.nextInt(CHARS.length())));
        return sb.toString();
    }

    private void sendInternalNotification(CompanyRequestDto dto, String supportEmail, String username) {
        String subject = "New org account created — " + dto.companyName();
        StringBuilder body = new StringBuilder();
        body.append("Company/Institution: ").append(dto.companyName()).append("\n");
        body.append("Contact person: ").append(dto.contactName()).append("\n");
        body.append("Contact email: ").append(dto.contactEmail()).append("\n");
        body.append("Admin username: ").append(username).append("\n");
        if (dto.notes() != null && !dto.notes().isBlank()) {
            body.append("Notes: ").append(dto.notes()).append("\n");
        }

        try {
            MimeMessage msg = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(msg, false, "UTF-8");
            helper.setFrom(supportEmail);
            helper.setTo(supportEmail);
            helper.setSubject(subject);
            helper.setText(body.toString(), false);
            mailSender.send(msg);
            log.info("Internal notification sent to {}", supportEmail);
        } catch (MailException | MessagingException ex) {
            log.warn("Internal notification failed: {}", ex.getMessage());
        }
    }

    private void sendWelcomeEmail(String contactName, String toEmail, String companyName,
                                    String username, String password, String supportEmail) {
        String safeContactName = escapeHtml(contactName);
        String safeCompanyName = escapeHtml(companyName);
        String safeUsername = escapeHtml(username);
        String safePassword = escapeHtml(password);
        String safeSupportEmail = escapeHtml(supportEmail);
        String platformUrl = appProperties.getFrontendUrl() + "/login.html";
        String safePlatformUrl = escapeHtml(platformUrl);

        String logo =
            "<table cellpadding='0' cellspacing='0' style='margin:0 auto 18px'><tr><td align='center'>" +
            "<svg width='96' height='96' viewBox='0 0 160 160' fill='none' xmlns='http://www.w3.org/2000/svg' style='display:block;margin:0 auto;filter:drop-shadow(0 0 18px rgba(34,184,207,.35))'>" +
            "<defs>" +
            "<linearGradient id='outer-ring-mail' x1='24' y1='18' x2='136' y2='142' gradientUnits='userSpaceOnUse'><stop offset='0' stop-color='#24E0FF'/><stop offset='1' stop-color='#127CFF'/></linearGradient>" +
            "<linearGradient id='inner-ring-mail' x1='48' y1='40' x2='112' y2='120' gradientUnits='userSpaceOnUse'><stop offset='0' stop-color='#24BAFF' stop-opacity='0.95'/><stop offset='1' stop-color='#1060D4' stop-opacity='0.85'/></linearGradient>" +
            "<radialGradient id='radar-mail' cx='0' cy='0' r='1' gradientUnits='userSpaceOnUse' gradientTransform='translate(80 80) rotate(90) scale(58)'><stop offset='0' stop-color='#031629' stop-opacity='0'/><stop offset='0.55' stop-color='#051C34' stop-opacity='0.7'/><stop offset='1' stop-color='#041427'/></radialGradient>" +
            "</defs>" +
            "<polygon points='80,14 136,47 136,113 80,146 24,113 24,47' fill='#010A16' stroke='url(#outer-ring-mail)' stroke-width='3' stroke-linejoin='round'/>" +
            "<polygon points='80,30 122,55 122,105 80,130 38,105 38,55' fill='url(#radar-mail)' stroke='url(#inner-ring-mail)' stroke-width='2' stroke-linejoin='round'/>" +
            "<circle cx='80' cy='80' r='43' stroke='#1ED6FF' stroke-opacity='0.5' stroke-width='2' stroke-dasharray='10 7'/>" +
            "<circle cx='80' cy='80' r='30' stroke='#25E5FF' stroke-opacity='0.7' stroke-width='2'/>" +
            "<path d='M80 52C71.5 52 60 67.2 60 80C60 92.8 71.5 108 80 108C88.5 108 100 92.8 100 80C100 67.2 88.5 52 80 52Z' fill='#072139' stroke='#24E0FF' stroke-width='2'/>" +
            "<circle cx='80' cy='80' r='12' fill='#0AB6FF' stroke='#7DF2FF' stroke-width='2'/>" +
            "<circle cx='80' cy='80' r='5' fill='#001220'/>" +
            "<path d='M82 64L108 80L82 96' stroke='#24E0FF' stroke-width='2.4' stroke-linecap='round' stroke-linejoin='round'/>" +
            "<path d='M78 64L52 80L78 96' stroke='#24E0FF' stroke-width='2.4' stroke-linecap='round' stroke-linejoin='round'/>" +
            "<circle cx='108' cy='73' r='4' fill='#FFB347'/>" +
            "<circle cx='60' cy='94' r='4.2' fill='#FF4D6D'/>" +
            "<path d='M80 36V28M80 132V124M46 80H38M122 80H130M58 58L52 50M108 110L114 118M108 58L114 50M58 110L52 118' stroke='#22D8FF' stroke-opacity='0.7' stroke-width='2' stroke-linecap='round'/>" +
            "</svg>" +
            "</td></tr></table>";

        String html =
            "<!DOCTYPE html><html><head><meta charset='UTF-8'/>" +
            "<meta name='viewport' content='width=device-width,initial-scale=1'/></head>" +
            "<body style='margin:0;padding:0;background:#030712;font-family:Arial,Helvetica,sans-serif;color:#e5edf7'>" +
            "<table width='100%' cellpadding='0' cellspacing='0' style='background:linear-gradient(180deg,#030712 0%,#06111f 100%);padding:34px 12px'>" +
            "<tr><td align='center'>" +
            "<table width='560' cellpadding='0' cellspacing='0' style='max-width:560px;width:100%;background:#071426;border-radius:26px;border:1px solid #18324d;overflow:hidden;box-shadow:0 28px 80px rgba(0,0,0,.65)'>" +

            // ── Header ──
            "<tr><td style='background:radial-gradient(circle at 50% 0%,rgba(34,184,207,.28),transparent 42%),linear-gradient(145deg,#06172e 0%,#0b1f37 52%,#06111f 100%);padding:42px 38px 34px;text-align:center;border-bottom:1px solid #173049'>" +
            logo +
            "<div style='color:#f8fafc;font-size:30px;font-weight:900;letter-spacing:.5px;line-height:1;margin:0'>MADRS</div>" +
            "<div style='color:#22b8cf;font-size:11px;font-weight:800;letter-spacing:4px;text-transform:uppercase;margin-top:10px'>Security Platform</div>" +
            "<div style='height:3px;width:84px;background:linear-gradient(90deg,transparent,#22b8cf,transparent);margin:22px auto 0;border-radius:999px'></div>" +
            "</td></tr>" +

            // ── Title bar ──
            "<tr><td style='background:#0a1728;padding:18px 34px;border-bottom:1px solid #173049'>" +
            "<table width='100%' cellpadding='0' cellspacing='0'><tr>" +
            "<td style='color:#dbeafe;font-size:13px;font-weight:800;letter-spacing:1.6px;text-transform:uppercase'>Organisation Account Ready</td>" +
            "<td align='right' style='color:#22b8cf;font-size:12px;font-weight:800'>2026</td>" +
            "</tr></table>" +
            "</td></tr>" +

            // ── Body ──
            "<tr><td style='padding:38px 34px 34px'>" +
            "<p style='color:#f8fafc;font-size:18px;line-height:1.6;margin:0 0 12px'>Hello, <strong>" + safeContactName + "</strong></p>" +
            "<p style='color:#9fb0c5;font-size:14px;line-height:1.8;margin:0 0 26px'>" +
            "Your organisation <strong style='color:#22d3ee'>" + safeCompanyName + "</strong> has been successfully registered on the MADRS Security Platform. Your secure administrator access is ready below." +
            "</p>" +

            // ── Credentials box ──
            "<table width='100%' cellpadding='0' cellspacing='0' style='background:#09182b;border:1px solid #1f3b58;border-radius:18px;margin:0 0 22px'>" +
            "<tr><td style='padding:22px 24px'>" +
            "<p style='color:#22b8cf;font-size:11px;font-weight:900;letter-spacing:2.6px;text-transform:uppercase;margin:0 0 18px'>Admin Credentials</p>" +
            "<table width='100%' cellpadding='0' cellspacing='0'>" +
            "<tr><td style='padding:13px 0;border-bottom:1px solid #18324d;color:#6f86a3;font-size:12px;width:34%;text-transform:uppercase;letter-spacing:.7px'>Platform URL</td>" +
            "<td style='padding:13px 0;border-bottom:1px solid #18324d;color:#22d3ee;font-size:13px;font-weight:800;word-break:break-all'><a href='" + safePlatformUrl + "' style='color:#22d3ee;text-decoration:none'>" + safePlatformUrl + "</a></td></tr>" +
            "<tr><td style='padding:13px 0;border-bottom:1px solid #18324d;color:#6f86a3;font-size:12px;text-transform:uppercase;letter-spacing:.7px'>Organisation</td>" +
            "<td style='padding:13px 0;border-bottom:1px solid #18324d;color:#f1f5f9;font-size:14px;font-weight:800'>" + safeCompanyName + "</td></tr>" +
            "<tr><td style='padding:13px 0;border-bottom:1px solid #18324d;color:#6f86a3;font-size:12px;text-transform:uppercase;letter-spacing:.7px'>Username</td>" +
            "<td style='padding:13px 0;border-bottom:1px solid #18324d;color:#f8fafc;font-size:14px;font-weight:900;font-family:Courier New,monospace'>" + safeUsername + "</td></tr>" +
            "<tr><td style='padding:13px 0;color:#6f86a3;font-size:12px;text-transform:uppercase;letter-spacing:.7px'>Password</td>" +
            "<td style='padding:13px 0;color:#f8fafc;font-size:14px;font-weight:900;font-family:Courier New,monospace'>" + safePassword + "</td></tr>" +
            "</table></td></tr></table>" +

            // ── Warning box ──
            "<table width='100%' cellpadding='0' cellspacing='0' style='margin:0 0 24px'><tr>" +
            "<td style='background:#1c1607;border:1px solid rgba(251,191,36,.34);border-radius:16px;padding:16px 18px'>" +
            "<p style='color:#fbbf24;font-size:13px;font-weight:900;margin:0 0 6px'>Security Notice</p>" +
            "<p style='color:#d6b45d;font-size:13px;line-height:1.7;margin:0'>Change your password immediately after your first login. Keep these credentials private and share them only through approved secure channels.</p>" +
            "</td></tr></table>" +

            "<p style='color:#7f93ad;font-size:13px;line-height:1.75;margin:0'>" +
            "Need help getting started? Contact MADRS support at <a href='mailto:" + safeSupportEmail + "' style='color:#22d3ee;text-decoration:none;font-weight:700'>" + safeSupportEmail + "</a>." +
            "</p>" +
            "</td></tr>" +

            // ── Footer ──
            "<tr><td style='background:#050d19;padding:24px 34px;border-top:1px solid #173049;text-align:center'>" +
            "<p style='color:#5f7897;font-size:12px;margin:0 0 8px;font-weight:700'>MADRS &mdash; Malicious Activity Detection &amp; Response System</p>" +
            "<p style='color:#405873;font-size:11px;margin:0'>&#169; 2026 MADRS &mdash; Professional Security Operations Platform</p>" +
            "</td></tr>" +

            "</table></td></tr></table></body></html>";

        try {
            MimeMessage msg = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(msg, true, "UTF-8");
            helper.setFrom(supportEmail);
            helper.setTo(toEmail);
            helper.setSubject("Welcome to MADRS — Your Organisation Account");
            helper.setText(html, true);
            mailSender.send(msg);
            log.info("Welcome email sent to org admin: {}", toEmail);
        } catch (MailException | MessagingException ex) {
            log.warn("Could not send welcome email to {}: {}", toEmail, ex.getMessage());
        }
    }

    private static String escapeHtml(String value) {
        if (value == null) return "";
        return value.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}
