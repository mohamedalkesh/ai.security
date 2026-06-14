package com.aisec.backend.service;

import com.aisec.backend.entity.AuditLog;
import com.aisec.backend.entity.Organization;
import com.aisec.backend.entity.UserAccount;
import com.aisec.backend.repository.AuditLogRepository;
import com.aisec.backend.repository.UserRepository;
import com.aisec.backend.security.OrgUserDetails;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    private final AuditLogRepository repo;
    private final UserRepository users;

    public AuditService(AuditLogRepository repo, UserRepository users) {
        this.repo = repo;
        this.users = users;
    }

    /**
     * Record an audit event. NEVER throws — auditing must not break the request.
     * Runs in its own transaction so a rollback in the calling code keeps the
     * audit row (e.g. ALERT_DELETE_ATTEMPT vs ALERT_DELETE_OK).
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void log(String action, String resourceType, Object resourceId, String details) {
        try {
            AuditLog row = new AuditLog();
            row.setAction(action);
            row.setResourceType(resourceType);
            row.setResourceId(resourceId == null ? null : String.valueOf(resourceId));
            row.setDetails(truncate(details, 1024));
            populateActorAndIp(row);
            repo.save(row);
        } catch (Exception e) {
            log.warn("Audit write failed for action={} resource={}/{} : {}",
                    action, resourceType, resourceId, e.getMessage());
        }
    }

    /** Variant for events without an authenticated principal (failed logins, anonymous endpoints). */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logAnonymous(String action, String username, String details) {
        try {
            AuditLog row = new AuditLog();
            row.setAction(action);
            row.setActorUsername(username);
            row.setDetails(truncate(details, 1024));
            row.setSourceIp(currentIp());
            repo.save(row);
        } catch (Exception e) {
            log.warn("Anonymous audit write failed: {}", e.getMessage());
        }
    }

    private void populateActorAndIp(AuditLog row) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && auth.getPrincipal() instanceof OrgUserDetails p) {
            row.setActorUsername(p.getUsername());
            // Resolve role + org via the DB to keep it cheap and tolerant of schema drift.
            users.findByUsername(p.getUsername()).ifPresent((UserAccount u) -> {
                row.setActorRole(u.getRole() != null ? u.getRole().name() : null);
                Organization org = u.getOrganization();
                row.setOrganization(org);
            });
        }
        row.setSourceIp(currentIp());
    }

    private static String currentIp() {
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs == null) return null;
            HttpServletRequest req = attrs.getRequest();
            String xff = req.getHeader("X-Forwarded-For");
            if (xff != null && !xff.isBlank()) return xff.split(",")[0].trim();
            return req.getRemoteAddr();
        } catch (Exception e) {
            return null;
        }
    }

    private static String truncate(String s, int max) {
        if (s == null) return null;
        return s.length() <= max ? s : s.substring(0, max - 1) + "…";
    }
}
