package com.aisec.backend.controller;

import com.aisec.backend.dto.alert.*;
import com.aisec.backend.security.OrgUserDetails;
import com.aisec.backend.service.AlertService;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/alerts")
public class AlertController {

    private final AlertService service;
    public AlertController(AlertService service) { this.service = service; }

    @GetMapping
    public Page<AlertDto> list(
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String status,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @AuthenticationPrincipal OrgUserDetails principal) {
        Long orgId = principal != null ? principal.getOrganizationId() : null;
        return service.list(severity, status, orgId,
                PageRequest.of(page, Math.min(Math.max(size, 1), 1000)));
    }

    @GetMapping("/{id}")
    public AlertDto get(@PathVariable Long id,
                       @AuthenticationPrincipal OrgUserDetails principal) {
        Long orgId = principal != null ? principal.getOrganizationId() : null;
        return service.get(id, orgId);
    }

    @GetMapping("/stats")
    public Map<String, Object> stats(@AuthenticationPrincipal OrgUserDetails principal) {
        Long orgId = principal != null ? principal.getOrganizationId() : null;
        return service.stats(orgId);
    }

    @GetMapping("/breakdown")
    public List<Map<String, Object>> breakdown(@AuthenticationPrincipal OrgUserDetails principal) {
        Long orgId = principal != null ? principal.getOrganizationId() : null;
        return service.attackTypeBreakdown(orgId);
    }

    @PreAuthorize("hasAnyRole('ADMIN','ORG_ADMIN','ANALYST')")
    @PatchMapping("/{id}")
    public AlertDto update(@PathVariable Long id, @RequestBody UpdateAlertRequest req,
                           @AuthenticationPrincipal OrgUserDetails principal) {
        Long orgId = principal != null ? principal.getOrganizationId() : null;
        return service.patch(id, req.status(), req.assignedToId(), req.mlFeedback(), orgId);
    }

    @PreAuthorize("hasAnyRole('ADMIN','ORG_ADMIN','ANALYST')")
    @PatchMapping("/bulk")
    public Map<String, Object> bulk(@Valid @RequestBody BulkUpdateRequest req,
                                    @AuthenticationPrincipal OrgUserDetails principal) {
        Long orgId = principal != null ? principal.getOrganizationId() : null;
        List<Long> applied = service.bulkUpdate(req, orgId);
        return Map.of("requested", req.ids().size(), "applied", applied.size(), "ids", applied);
    }

    @PreAuthorize("hasAnyRole('ADMIN','ORG_ADMIN','ANALYST')")
    @PostMapping("/auto-resolve")
    public Map<String, Object> autoResolve(@Valid @RequestBody AutoResolveRequest req,
                                           @AuthenticationPrincipal OrgUserDetails principal) {
        Long orgId = principal != null ? principal.getOrganizationId() : null;
        String username = principal != null ? principal.getUsername() : "system";
        return service.autoResolve(req, orgId, username);
    }

    @PreAuthorize("hasAnyRole('ADMIN','ORG_ADMIN','ANALYST')")
    @PatchMapping("/auto-resolve")
    public Map<String, Object> autoResolvePatch(@Valid @RequestBody AutoResolveRequest req,
                                                @AuthenticationPrincipal OrgUserDetails principal) {
        return autoResolve(req, principal);
    }

    @PreAuthorize("hasAnyRole('ADMIN','ORG_ADMIN')")
    @DeleteMapping("/{id}")
    public void delete(@PathVariable Long id,
                       @AuthenticationPrincipal OrgUserDetails principal) {
        Long orgId = principal != null ? principal.getOrganizationId() : null;
        service.delete(id, orgId);
    }

    /* ============== Comments ============== */

    @GetMapping("/{id}/comments")
    public List<AlertCommentDto> comments(@PathVariable Long id,
                                          @AuthenticationPrincipal OrgUserDetails principal) {
        Long orgId = principal != null ? principal.getOrganizationId() : null;
        return service.listComments(id, orgId);
    }

    @PreAuthorize("hasAnyRole('ADMIN','ORG_ADMIN','ANALYST')")
    @PostMapping("/{id}/comments")
    public AlertCommentDto addComment(@PathVariable Long id,
                                      @Valid @RequestBody CreateCommentRequest req,
                                      @AuthenticationPrincipal OrgUserDetails principal) {
        Long orgId = principal != null ? principal.getOrganizationId() : null;
        String username = principal != null ? principal.getUsername() : null;
        return service.addComment(id, req.body(), username, orgId);
    }
}
