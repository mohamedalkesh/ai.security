package com.aisec.backend.config;

import com.aisec.backend.entity.Alert;
import com.aisec.backend.entity.AlertStatus;
import com.aisec.backend.entity.Role;
import com.aisec.backend.entity.Severity;
import com.aisec.backend.entity.UserAccount;
import com.aisec.backend.repository.AlertRepository;
import com.aisec.backend.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DataSeeder implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DataSeeder.class);

    private final UserRepository users;
    private final AlertRepository alerts;
    private final PasswordEncoder encoder;

    @Value("${app.seed.enabled:false}")
    private boolean enabled;

    public DataSeeder(UserRepository users, AlertRepository alerts, PasswordEncoder encoder) {
        this.users = users;
        this.alerts = alerts;
        this.encoder = encoder;
    }

    @Override
    public void run(String... args) {
        if (!enabled) return;
        seedUsers();
        // Alerts are NOT seeded — they will arrive only from real PCAP/flow scans.
    }

    private void seedUsers() {
        if (users.count() > 0) return;
        users.save(make("admin",   "admin@aisec.local",   "Platform Admin",   "admin123", Role.ADMIN));
        users.save(make("analyst", "analyst@aisec.local", "Senior Analyst",   "analyst123", Role.ANALYST));
        users.save(make("viewer",  "viewer@aisec.local",  "Viewer Account",   "viewer123", Role.VIEWER));
        log.info("Seeded 3 default users (admin/analyst/viewer)");
    }

    private UserAccount make(String u, String e, String n, String pw, Role r) {
        UserAccount a = new UserAccount();
        a.setUsername(u); a.setEmail(e); a.setFullName(n);
        a.setPasswordHash(encoder.encode(pw)); a.setRole(r);
        return a;
    }

    private void seedAlerts() {
        if (alerts.count() > 0) return;
        alerts.save(buildAlert("DDoS",        Severity.CRITICAL, "203.0.113.10",   "10.0.0.5",  443, "TCP", 0.98, "T1498", "Impact"));
        alerts.save(buildAlert("Port Scan",   Severity.MEDIUM,   "198.51.100.42",  "10.0.0.5",   22, "TCP", 0.91, "T1046", "Discovery"));
        alerts.save(buildAlert("Brute Force", Severity.HIGH,     "185.22.4.10",    "10.0.0.20",  22, "TCP", 0.89, "T1110", "Credential Access"));
        alerts.save(buildAlert("Port Scan",   Severity.LOW,      "172.16.3.22",    "10.0.0.5",   80, "TCP", 0.78, "T1046", "Discovery"));
        log.info("Seeded sample alerts");
    }

    private Alert buildAlert(String type, Severity sev, String src, String dst, int port,
                             String proto, double conf, String tech, String tactic) {
        Alert a = new Alert();
        a.setAttackType(type); a.setSeverity(sev); a.setStatus(AlertStatus.NEW);
        a.setSourceIp(src); a.setDestIp(dst); a.setDestPort(port); a.setProtocol(proto);
        a.setConfidence(conf); a.setMitreTechnique(tech); a.setMitreTactic(tactic);
        a.setDescription(type + " detected from " + src);
        return a;
    }
}
