package com.aisec.backend.service;

import com.aisec.backend.entity.PasswordResetToken;
import com.aisec.backend.entity.UserAccount;
import com.aisec.backend.repository.PasswordResetTokenRepository;
import com.aisec.backend.repository.UserRepository;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Optional;

@Service
public class PasswordResetService {

    private static final Logger log = LoggerFactory.getLogger(PasswordResetService.class);
    private static final long EXPIRY_MINUTES = 3;

    private final PasswordResetTokenRepository tokenRepo;
    private final UserRepository userRepo;
    private final PasswordEncoder passwordEncoder;
    private final JavaMailSender mailSender;
    private final AuditService audit;

    @Value("${spring.mail.username:noreply@aisec.local}")
    private String fromEmail;

    @Value("${app.frontend-url:http://127.0.0.1:5500}")
    private String frontendUrl;

    public PasswordResetService(PasswordResetTokenRepository tokenRepo,
                                UserRepository userRepo,
                                PasswordEncoder passwordEncoder,
                                JavaMailSender mailSender,
                                AuditService audit) {
        this.tokenRepo = tokenRepo;
        this.userRepo = userRepo;
        this.passwordEncoder = passwordEncoder;
        this.mailSender = mailSender;
        this.audit = audit;
    }

    @Transactional
    public void requestReset(String email) {
        Optional<UserAccount> userOpt = userRepo.findByEmail(email);
        if (userOpt.isEmpty()) {
            log.info("Password reset requested for unknown email: {}", email);
            throw new IllegalArgumentException("No account is registered with this email address.");
        }

        tokenRepo.deleteAllByEmail(email);
        audit.logAnonymous("PASSWORD_RESET_REQUEST", userOpt.get().getUsername(), "email=" + email);

        String code = String.format("%06d", new SecureRandom().nextInt(1_000_000));

        PasswordResetToken prt = new PasswordResetToken(
                code, email, Instant.now().plusSeconds(EXPIRY_MINUTES * 60));
        tokenRepo.save(prt);

        sendCodeEmail(email, userOpt.get().getFullName(), code);
    }

    public void verifyCode(String email, String code) {
        PasswordResetToken prt = tokenRepo.findByEmailAndToken(email, code)
                .orElseThrow(() -> new IllegalArgumentException("Invalid verification code."));
        if (prt.isUsed())    throw new IllegalArgumentException("This code has already been used.");
        if (prt.isExpired()) throw new IllegalArgumentException("Code has expired. Please request a new one.");
    }

    @Transactional
    public void resetPassword(String email, String code, String newPassword) {
        PasswordResetToken prt = tokenRepo.findByEmailAndToken(email, code)
                .orElseThrow(() -> new IllegalArgumentException("Invalid verification code"));

        if (prt.isUsed()) {
            throw new IllegalArgumentException("This code has already been used");
        }
        if (prt.isExpired()) {
            throw new IllegalArgumentException("Code has expired. Please request a new one.");
        }

        UserAccount user = userRepo.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (passwordEncoder.matches(newPassword, user.getPasswordHash())) {
            throw new IllegalArgumentException("New password must be different from your current password.");
        }

        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepo.save(user);

        prt.setUsed(true);
        tokenRepo.save(prt);
        audit.logAnonymous("PASSWORD_RESET", user.getUsername(), "password changed via reset flow");

        log.info("Password successfully reset for: {}", email);
    }

    public void sendWelcomeEmail(String toEmail, String fullName, String username, String password) {
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
            "<p style='color:#8ea0b8;font-size:13px;margin:6px 0 0'>Welcome to the Team!</p>" +
            "</td></tr>" +
            "<tr><td style='padding:36px 40px'>" +
            "<p style='color:#cbd5e1;font-size:15px;margin:0 0 8px'>Hello <strong style='color:#e6edf7'>" + fullName + "</strong> 👋</p>" +
            "<p style='color:#8ea0b8;font-size:14px;line-height:1.7;margin:0 0 28px'>" +
            "Your account has been created on the MADRS. " +
            "Here are your login credentials:</p>" +
            "<div style='background:#0b1628;border:1px solid #1e3557;border-radius:12px;padding:20px 24px;margin:0 0 24px'>" +
            "<table width='100%' cellpadding='0' cellspacing='0'>" +
            "<tr><td style='padding:7px 0;color:#8ea0b8;font-size:13px;width:40%'>🌐 Platform URL</td>" +
            "<td style='padding:7px 0;color:#22b8cf;font-size:13px;font-weight:600'>" + frontendUrl + "/login.html</td></tr>" +
            "<tr><td style='padding:7px 0;color:#8ea0b8;font-size:13px'>👤 Username</td>" +
            "<td style='padding:7px 0;color:#e6edf7;font-size:13px;font-weight:700;font-family:monospace'>" + username + "</td></tr>" +
            "<tr><td style='padding:7px 0;color:#8ea0b8;font-size:13px'>🔑 Password</td>" +
            "<td style='padding:7px 0;color:#e6edf7;font-size:13px;font-weight:700;font-family:monospace'>" + password + "</td></tr>" +
            "</table></div>" +
            "<p style='color:#fbbf24;font-size:12px;background:rgba(251,191,36,.08);border:1px solid rgba(251,191,36,.2);" +
            "border-radius:8px;padding:10px 14px;line-height:1.6;margin:0'>" +
            "⚠️ For security, please change your password immediately after your first login.</p>" +
            "</td></tr>" +
            "<tr><td style='background:#0f1d35;padding:20px 40px;text-align:center;border-top:1px solid #1e3557'>" +
            "<p style='color:#4a6080;font-size:12px;margin:0'>© 2025 MADRS — Do not share your credentials.</p>" +
            "</td></tr>" +
            "</table></td></tr></table></body></html>";
        try {
            MimeMessage msg = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(msg, true, "UTF-8");
            helper.setFrom(fromEmail);
            helper.setTo(toEmail);
            helper.setSubject("Welcome to MADRS — Your Account Details");
            helper.setText(html, true);
            mailSender.send(msg);
            log.info("Welcome email sent to: {}", toEmail);
        } catch (MailException | MessagingException ex) {
            log.error("Failed to send welcome email to {}: {}", toEmail, ex.getMessage());
            log.warn(">>> DEV FALLBACK — Welcome email for {} | username: {} | password: {}", toEmail, username, password);
        }
    }

    private void sendCodeEmail(String toEmail, String fullName, String code) {
        String name = (fullName != null && !fullName.isBlank()) ? fullName : toEmail;
        String displayCode = code.substring(0, 3) + " " + code.substring(3);

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
            "text-transform:uppercase;margin:0;text-align:center'>&#x1F510; Password Reset Request</p>" +
            "</td></tr>" +

            // ── Body ──
            "<tr><td style='padding:40px 48px'>" +
            "<p style='color:#e2e8f0;font-size:16px;margin:0 0 10px'>Hello, <strong style='color:#ffffff'>" + name + "</strong></p>" +
            "<p style='color:#64748b;font-size:14px;line-height:1.8;margin:0 0 32px'>" +
            "We received a request to reset the password for your MADRS account.<br>" +
            "Enter the verification code below to proceed." +
            "</p>" +

            // ── Code box ──
            "<table width='100%' cellpadding='0' cellspacing='0' style='margin:0 0 28px'><tr><td align='center'>" +
            "<div style='background:#060e1e;border:2px solid #22b8cf;border-radius:16px;padding:28px 32px;" +
            "display:inline-block;min-width:280px'>" +
            "<p style='color:#475569;font-size:11px;font-weight:700;letter-spacing:3px;" +
            "text-transform:uppercase;margin:0 0 14px'>YOUR VERIFICATION CODE</p>" +
            "<p style='color:#22b8cf;font-size:48px;font-weight:800;letter-spacing:14px;" +
            "font-family:Courier New,monospace;margin:0 0 14px'>" + displayCode + "</p>" +
            "<table cellpadding='0' cellspacing='0' style='margin:0 auto'><tr>" +
            "<td style='background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);" +
            "border-radius:20px;padding:5px 16px'>" +
            "<p style='color:#f87171;font-size:12px;font-weight:600;margin:0'>&#x23F1; Expires in " + EXPIRY_MINUTES + " minutes</p>" +
            "</td></tr></table>" +
            "</div>" +
            "</td></tr></table>" +

            // ── Warning box ──
            "<table width='100%' cellpadding='0' cellspacing='0' style='margin:0 0 24px'><tr>" +
            "<td style='background:rgba(251,191,36,.06);border:1px solid rgba(251,191,36,.2);" +
            "border-radius:12px;padding:16px 20px'>" +
            "<p style='color:#fbbf24;font-size:13px;font-weight:700;margin:0 0 4px'>&#x26A0;&#xFE0F; Security Notice</p>" +
            "<p style='color:#92400e;font-size:13px;line-height:1.6;margin:0'>" +
            "Never share this code with anyone. MADRS staff will never ask for your verification code.</p>" +
            "</td></tr></table>" +

            "<p style='color:#475569;font-size:13px;line-height:1.7;margin:0'>" +
            "If you did not request a password reset, you can safely ignore this email. " +
            "Your account remains secure and no changes will be made." +
            "</p>" +
            "</td></tr>" +

            // ── Footer ──
            "<tr><td style='background:#08111f;padding:24px 48px;border-top:1px solid #162840'>" +
            "<table width='100%' cellpadding='0' cellspacing='0'><tr>" +
            "<td style='text-align:center'>" +
            "<p style='color:#1e3a5f;font-size:12px;margin:0 0 6px'>" +
            "MADRS &mdash; Malicious Activity Detection &amp; Response System</p>" +
            "<p style='color:#1e3a5f;font-size:11px;margin:0'>" +
            "&#169; 2025 MADRS &mdash; Automated message, do not reply &mdash; " +
            "<a href='mailto:MADRS.support@gmail.com' style='color:#22b8cf;text-decoration:none'>MADRS.support@gmail.com</a>" +
            "</p></td></tr></table>" +
            "</td></tr>" +

            "</table></td></tr></table></body></html>";

        try {
            MimeMessage msg = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(msg, true, "UTF-8");
            helper.setFrom(fromEmail);
            helper.setTo(toEmail);
            helper.setSubject("MADRS — Your Reset Code: " + displayCode);
            helper.setText(html, true);
            mailSender.send(msg);
            log.info("Reset code email sent to: {}", toEmail);
        } catch (MailException | MessagingException ex) {
            log.error("Failed to send reset code email to {}: {}", toEmail, ex.getMessage());
            log.warn(">>> DEV FALLBACK — Reset code for {}: {}", toEmail, code);
        }
    }
}
