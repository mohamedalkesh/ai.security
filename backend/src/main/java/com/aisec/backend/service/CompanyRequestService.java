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
            supportEmail = "ai.security.support@gmail.com";
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
        String html = "<!DOCTYPE html><html><head><meta charset='UTF-8'/></head><body " +
            "style='margin:0;padding:0;background:#0b1628;font-family:Inter,Arial,sans-serif'>" +
            "<table width='100%' cellpadding='0' cellspacing='0' style='background:#0b1628;padding:40px 0'>" +
            "<tr><td align='center'>" +
            "<table width='520' cellpadding='0' cellspacing='0' style='background:#16243d;" +
            "border-radius:16px;border:1px solid #1e3557;overflow:hidden'>" +
            "<tr><td style='background:linear-gradient(135deg,#0f3460,#16243d);padding:32px 40px;text-align:center'>" +
            "<div style='display:inline-block;width:56px;height:56px;background:rgba(34,184,207,.15);" +
            "border-radius:14px;line-height:56px;font-size:28px;margin-bottom:14px'>🛡️</div>" +
            "<h1 style='color:#e6edf7;font-size:22px;font-weight:700;margin:0'>MADRS</h1>" +
            "<p style='color:#8ea0b8;font-size:13px;margin:6px 0 0'>Your Organisation Account is Ready</p>" +
            "</td></tr>" +
            "<tr><td style='padding:36px 40px'>" +
            "<p style='color:#cbd5e1;font-size:15px;margin:0 0 8px'>Hello <strong style='color:#e6edf7'>" + contactName + "</strong> 👋</p>" +
            "<p style='color:#8ea0b8;font-size:14px;line-height:1.7;margin:0 0 24px'>" +
            "Your organisation <strong style='color:#e6edf7'>" + companyName + "</strong> has been registered on the " +
            "<strong style='color:#22b8cf'>MADRS</strong>. Here are your admin credentials:</p>" +
            "<div style='background:#0b1628;border:1px solid #1e3557;border-radius:12px;padding:20px 24px;margin:0 0 24px'>" +
            "<table width='100%' cellpadding='0' cellspacing='0'>" +
            "<tr><td style='padding:7px 0;color:#8ea0b8;font-size:13px;width:40%'>🌐 Platform URL</td>" +
            "<td style='padding:7px 0;color:#22b8cf;font-size:13px;font-weight:600'>http://127.0.0.1:5500/login.html</td></tr>" +
            "<tr><td style='padding:7px 0;color:#8ea0b8;font-size:13px'>🏢 Organisation</td>" +
            "<td style='padding:7px 0;color:#e6edf7;font-size:13px;font-weight:600'>" + companyName + "</td></tr>" +
            "<tr><td style='padding:7px 0;color:#8ea0b8;font-size:13px'>👤 Username</td>" +
            "<td style='padding:7px 0;color:#e6edf7;font-size:13px;font-weight:700;font-family:monospace'>" + username + "</td></tr>" +
            "<tr><td style='padding:7px 0;color:#8ea0b8;font-size:13px'>� Password</td>" +
            "<td style='padding:7px 0;color:#e6edf7;font-size:13px;font-weight:700;font-family:monospace'>" + password + "</td></tr>" +
            "</table></div>" +
            "<p style='color:#fbbf24;font-size:12px;background:rgba(251,191,36,.08);border:1px solid rgba(251,191,36,.2);" +
            "border-radius:8px;padding:10px 14px;line-height:1.6;margin:0 0 16px'>" +
            "⚠️ For security, please change your password immediately after your first login.</p>" +
            "<p style='color:#8ea0b8;font-size:13px;line-height:1.6;margin:0'>" +
            "Need help? Contact us at <a href='mailto:" + supportEmail + "' style='color:#22b8cf;text-decoration:none'>" + supportEmail + "</a>.</p>" +
            "</td></tr>" +
            "<tr><td style='background:#0f1d35;padding:20px 40px;text-align:center;border-top:1px solid #1e3557'>" +
            "<p style='color:#4a6080;font-size:12px;margin:0'>© 2025 MADRS — Do not share your credentials.</p>" +
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
}
