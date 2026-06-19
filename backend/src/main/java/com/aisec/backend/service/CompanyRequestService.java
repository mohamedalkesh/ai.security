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
        String logo =
            "<table cellpadding='0' cellspacing='0' style='margin:0 auto 18px'><tr><td align='center'>" +
            "<svg width='64' height='64' viewBox='0 0 64 64' xmlns='http://www.w3.org/2000/svg'>" +
            "<defs><linearGradient id='sg' x1='0' y1='0' x2='1' y2='1'>" +
            "<stop offset='0%' stop-color='#22b8cf'/><stop offset='100%' stop-color='#0f7490'/>" +
            "</linearGradient></defs>" +
            "<path d='M32 4 L56 14 L56 32 C56 46 45 57 32 60 C19 57 8 46 8 32 L8 14 Z' fill='url(#sg)' opacity='.18'/>" +
            "<path d='M32 8 L52 17 L52 32 C52 44 43 54 32 57 C21 54 12 44 12 32 L12 17 Z' fill='none' stroke='#22b8cf' stroke-width='1.5' opacity='.6'/>" +
            "<path d='M32 14 L46 21 L46 32 C46 40 40 47 32 50 C24 47 18 40 18 32 L18 21 Z' fill='url(#sg)' opacity='.35'/>" +
            "<text x='32' y='37' text-anchor='middle' font-family='Arial,sans-serif' font-weight='800' font-size='16' fill='#ffffff'>M</text>" +
            "</svg>" +
            "</td></tr></table>";

        String html =
            "<!DOCTYPE html><html><head><meta charset='UTF-8'/>" +
            "<meta name='viewport' content='width=device-width,initial-scale=1'/></head>" +
            "<body style='margin:0;padding:0;background:#060e1e;font-family:Arial,Helvetica,sans-serif'>" +
            "<table width='100%' cellpadding='0' cellspacing='0' style='background:#060e1e;padding:48px 0'>" +
            "<tr><td align='center'>" +
            "<table width='540' cellpadding='0' cellspacing='0' style='max-width:540px;width:100%;background:#0d1b2e;" +
            "border-radius:20px;border:1px solid #162840;overflow:hidden;box-shadow:0 24px 64px rgba(0,0,0,.6)'>" +

            // ── Header ──
            "<tr><td style='background:linear-gradient(160deg,#0a2444 0%,#0d1b2e 100%);" +
            "padding:40px 48px 32px;text-align:center;border-bottom:1px solid #162840'>" +
            logo +
            "<h1 style='color:#e8f0fc;font-size:26px;font-weight:800;margin:0 0 6px;letter-spacing:-.5px'>MADRS</h1>" +
            "<p style='color:#22b8cf;font-size:12px;font-weight:600;letter-spacing:3px;text-transform:uppercase;margin:0'>" +
            "Security Platform</p>" +
            "</td></tr>" +

            // ── Title bar ──
            "<tr><td style='background:#0b1525;padding:20px 48px;border-bottom:1px solid #162840'>" +
            "<p style='color:#94a3b8;font-size:13px;font-weight:600;letter-spacing:1.5px;" +
            "text-transform:uppercase;margin:0;text-align:center'>&#x1F3E2; Organisation Account Ready</p>" +
            "</td></tr>" +

            // ── Body ──
            "<tr><td style='padding:40px 48px'>" +
            "<p style='color:#e2e8f0;font-size:16px;margin:0 0 10px'>Hello, <strong style='color:#ffffff'>" + contactName + "</strong></p>" +
            "<p style='color:#64748b;font-size:14px;line-height:1.8;margin:0 0 28px'>" +
            "Your organisation <strong style='color:#22b8cf'>" + companyName + "</strong> has been successfully " +
            "registered on the MADRS Security Platform. Below are your admin credentials to get started." +
            "</p>" +

            // ── Credentials box ──
            "<div style='background:#060e1e;border:1px solid #162840;border-radius:16px;padding:24px 28px;margin:0 0 24px'>" +
            "<p style='color:#475569;font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;margin:0 0 16px'>Admin Credentials</p>" +
            "<table width='100%' cellpadding='0' cellspacing='0'>" +
            "<tr><td style='padding:10px 0;border-bottom:1px solid #0f2035;color:#475569;font-size:13px;width:38%'>&#x1F310; Platform URL</td>" +
            "<td style='padding:10px 0;border-bottom:1px solid #0f2035;color:#22b8cf;font-size:13px;font-weight:600'>http://127.0.0.1:5500/login.html</td></tr>" +
            "<tr><td style='padding:10px 0;border-bottom:1px solid #0f2035;color:#475569;font-size:13px'>&#x1F3E2; Organisation</td>" +
            "<td style='padding:10px 0;border-bottom:1px solid #0f2035;color:#e2e8f0;font-size:13px;font-weight:600'>" + companyName + "</td></tr>" +
            "<tr><td style='padding:10px 0;border-bottom:1px solid #0f2035;color:#475569;font-size:13px'>&#x1F464; Username</td>" +
            "<td style='padding:10px 0;border-bottom:1px solid #0f2035;color:#e2e8f0;font-size:13px;font-weight:700;font-family:Courier New,monospace'>" + username + "</td></tr>" +
            "<tr><td style='padding:10px 0;color:#475569;font-size:13px'>&#x1F511; Password</td>" +
            "<td style='padding:10px 0;color:#e2e8f0;font-size:13px;font-weight:700;font-family:Courier New,monospace'>" + password + "</td></tr>" +
            "</table></div>" +

            // ── Warning box ──
            "<table width='100%' cellpadding='0' cellspacing='0' style='margin:0 0 24px'><tr>" +
            "<td style='background:rgba(251,191,36,.06);border:1px solid rgba(251,191,36,.2);" +
            "border-radius:12px;padding:16px 20px'>" +
            "<p style='color:#fbbf24;font-size:13px;font-weight:700;margin:0 0 4px'>&#x26A0;&#xFE0F; Security Notice</p>" +
            "<p style='color:#92400e;font-size:13px;line-height:1.6;margin:0'>" +
            "Change your password immediately after your first login. Never share your credentials with anyone.</p>" +
            "</td></tr></table>" +

            "<p style='color:#475569;font-size:13px;line-height:1.7;margin:0'>" +
            "Need help getting started? Our support team is available 24/7.<br>" +
            "Contact us at <a href='mailto:" + supportEmail + "' style='color:#22b8cf;text-decoration:none'>" + supportEmail + "</a>." +
            "</p>" +
            "</td></tr>" +

            // ── Footer ──
            "<tr><td style='background:#08111f;padding:24px 48px;border-top:1px solid #162840;text-align:center'>" +
            "<p style='color:#1e3a5f;font-size:12px;margin:0 0 6px'>" +
            "MADRS &mdash; Malicious Activity Detection &amp; Response System</p>" +
            "<p style='color:#1e3a5f;font-size:11px;margin:0'>" +
            "&#169; 2025 MADRS &mdash; Do not share your credentials &mdash; " +
            "<a href='mailto:" + supportEmail + "' style='color:#22b8cf;text-decoration:none'>" + supportEmail + "</a>" +
            "</p></td></tr>" +

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
}
