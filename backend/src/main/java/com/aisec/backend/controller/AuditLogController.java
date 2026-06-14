package com.aisec.backend.controller;

import com.aisec.backend.dto.audit.AuditLogDto;
import com.aisec.backend.repository.AuditLogRepository;
import com.aisec.backend.security.OrgUserDetails;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

/**
 * Read-only audit log endpoint. ADMIN sees system events (org IS NULL);
 * ORG_ADMIN sees their tenant's events only. No write endpoints — audit
 * trail is intentionally immutable from the application side.
 */
@RestController
@RequestMapping("/api/audit-logs")
@PreAuthorize("hasAnyRole('ADMIN','ORG_ADMIN')")
public class AuditLogController {

    private final AuditLogRepository repo;

    public AuditLogController(AuditLogRepository repo) {
        this.repo = repo;
    }

    @GetMapping
    public Page<AuditLogDto> list(
            @RequestParam(required = false) String action,
            @RequestParam(required = false) String actor,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size,
            @AuthenticationPrincipal OrgUserDetails principal) {
        Long orgId = principal != null ? principal.getOrganizationId() : null;
        var pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        Page<com.aisec.backend.entity.AuditLog> p;
        if (action != null && !action.isBlank()) {
            p = repo.findScopedByAction(orgId, action, pageable);
        } else if (actor != null && !actor.isBlank()) {
            p = repo.findScopedByActor(orgId, actor, pageable);
        } else {
            p = repo.findScoped(orgId, pageable);
        }
        return p.map(AuditLogDto::from);
    }
}
