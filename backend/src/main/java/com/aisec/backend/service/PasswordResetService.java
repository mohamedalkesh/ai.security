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
    private static final long EXPIRY_MINUTES = 10;

    private final PasswordResetTokenRepository tokenRepo;
    private final UserRepository userRepo;
    private final PasswordEncoder passwordEncoder;
    private final JavaMailSender mailSender;
    private final AuditService audit;

    @Value("${spring.mail.username:noreply@aisec.local}")
    private String fromEmail;

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
            "<h1 style='color:#e6edf7;font-size:22px;font-weight:700;margin:0'>AI Security Platform</h1>" +
            "<p style='color:#8ea0b8;font-size:13px;margin:6px 0 0'>Welcome to the Team!</p>" +
            "</td></tr>" +
            "<tr><td style='padding:36px 40px'>" +
            "<p style='color:#cbd5e1;font-size:15px;margin:0 0 8px'>Hello <strong style='color:#e6edf7'>" + fullName + "</strong> 👋</p>" +
            "<p style='color:#8ea0b8;font-size:14px;line-height:1.7;margin:0 0 28px'>" +
            "Your account has been created on the AI Security Platform. " +
            "Here are your login credentials:</p>" +
            "<div style='background:#0b1628;border:1px solid #1e3557;border-radius:12px;padding:20px 24px;margin:0 0 24px'>" +
            "<table width='100%' cellpadding='0' cellspacing='0'>" +
            "<tr><td style='padding:7px 0;color:#8ea0b8;font-size:13px;width:40%'>🌐 Platform URL</td>" +
            "<td style='padding:7px 0;color:#22b8cf;font-size:13px;font-weight:600'>http://127.0.0.1:5500/login.html</td></tr>" +
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
            "<p style='color:#4a6080;font-size:12px;margin:0'>© 2025 AI Security Platform — Do not share your credentials.</p>" +
            "</td></tr>" +
            "</table></td></tr></table></body></html>";
        try {
            MimeMessage msg = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(msg, true, "UTF-8");
            helper.setFrom(fromEmail);
            helper.setTo(toEmail);
            helper.setSubject("Welcome to AI Security Platform — Your Account Details");
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
        // Format code as "123 456" for readability
        String displayCode = code.substring(0, 3) + " " + code.substring(3);

        String html = "<!DOCTYPE html><html><head><meta charset='UTF-8'/></head><body " +
            "style='margin:0;padding:0;background:#0b1628;font-family:Inter,Arial,sans-serif'>" +
            "<table width='100%' cellpadding='0' cellspacing='0' style='background:#0b1628;padding:40px 0'>" +
            "<tr><td align='center'>" +
            "<table width='520' cellpadding='0' cellspacing='0' style='background:#16243d;" +
            "border-radius:16px;border:1px solid #1e3557;overflow:hidden'>" +
            // Header
            "<tr><td style='background:linear-gradient(135deg,#0f3460,#16243d);" +
            "padding:32px 40px;text-align:center'>" +
            "<div style='display:inline-block;width:56px;height:56px;background:rgba(34,184,207,.15);" +
            "border-radius:14px;line-height:56px;font-size:26px;margin-bottom:14px'>🔐</div>" +
            "<h1 style='color:#e6edf7;font-size:22px;font-weight:700;margin:0'>AI Security Platform</h1>" +
            "<p style='color:#8ea0b8;font-size:13px;margin:6px 0 0'>Password Reset Request</p>" +
            "</td></tr>" +
            // Body
            "<tr><td style='padding:36px 40px'>" +
            "<p style='color:#cbd5e1;font-size:15px;margin:0 0 8px'>Hello <strong>" + name + "</strong>,</p>" +
            "<p style='color:#8ea0b8;font-size:14px;line-height:1.7;margin:0 0 28px'>" +
            "Use the verification code below to reset your password.<br>" +
            "This code expires in <strong style='color:#22b8cf'>" + EXPIRY_MINUTES + " minutes</strong>.</p>" +
            // Code box
            "<div style='background:#0b1628;border:2px solid #22b8cf;border-radius:14px;" +
            "padding:24px;text-align:center;margin:0 0 28px'>" +
            "<p style='color:#8ea0b8;font-size:12px;letter-spacing:2px;text-transform:uppercase;" +
            "margin:0 0 10px'>YOUR VERIFICATION CODE</p>" +
            "<span style='color:#22b8cf;font-size:42px;font-weight:800;letter-spacing:10px;" +
            "font-family:monospace'>" + displayCode + "</span>" +
            "</div>" +
            "<p style='color:#8ea0b8;font-size:13px;line-height:1.6;margin:0'>" +
            "If you did not request this, please ignore this email. Your password will not change.</p>" +
            "</td></tr>" +
            // Footer
            "<tr><td style='background:#0f1d35;padding:20px 40px;text-align:center;" +
            "border-top:1px solid #1e3557'>" +
            "<p style='color:#4a6080;font-size:12px;margin:0'>© 2025 AI Security Platform — " +
            "This is an automated message, please do not reply.</p>" +
            "</td></tr>" +
            "</table></td></tr></table></body></html>";

        try {
            MimeMessage msg = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(msg, true, "UTF-8");
            helper.setFrom(fromEmail);
            helper.setTo(toEmail);
            helper.setSubject("AI Security Platform — Your Reset Code: " + displayCode);
            helper.setText(html, true);
            mailSender.send(msg);
            log.info("Reset code email sent to: {}", toEmail);
        } catch (MailException | MessagingException ex) {
            log.error("Failed to send reset code email to {}: {}", toEmail, ex.getMessage());
            log.warn(">>> DEV FALLBACK — Reset code for {}: {}", toEmail, code);
        }
    }
}
