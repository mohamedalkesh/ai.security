package com.aisec.backend.controller;

import com.aisec.backend.dto.firewall.BlockIpRequest;
import com.aisec.backend.dto.firewall.BlockedIpDto;
import com.aisec.backend.security.OrgUserDetails;
import com.aisec.backend.service.BlockedIpService;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Firewall blocklist API. All write endpoints are gated to admin/analyst
 * roles — viewers can read but not modify.
 */
@RestController
@RequestMapping("/api/firewall")
public class FirewallController {

    private final BlockedIpService service;

    public FirewallController(BlockedIpService service) { this.service = service; }

    @GetMapping("/blocklist")
    public Page<BlockedIpDto> list(
            @RequestParam(required = false) String q,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size,
            @AuthenticationPrincipal OrgUserDetails principal) {
        Long orgId = principal != null ? principal.getOrganizationId() : null;
        return service.list(orgId, q,
                PageRequest.of(page, Math.min(size, 200), Sort.by("createdAt").descending()));
    }

    @GetMapping("/blocklist/check")
    public Map<String, Object> check(
            @RequestParam String ip,
            @AuthenticationPrincipal OrgUserDetails principal) {
        Long orgId = principal != null ? principal.getOrganizationId() : null;
        return Map.of("ip", ip, "blocked", service.isBlocked(ip, orgId));
    }

    @GetMapping("/stats")
    public Map<String, Object> stats(@AuthenticationPrincipal OrgUserDetails principal) {
        Long orgId = principal != null ? principal.getOrganizationId() : null;
        return Map.of("active", service.countActive(orgId));
    }

    @PreAuthorize("hasAnyRole('ADMIN','ORG_ADMIN','ANALYST')")
    @PostMapping("/blocklist")
    public BlockedIpDto block(@Valid @RequestBody BlockIpRequest req,
                              @AuthenticationPrincipal OrgUserDetails principal) {
        String actor = principal != null ? principal.getUsername() : "system";
        Long orgId  = principal != null ? principal.getOrganizationId() : null;
        return service.block(req, actor, orgId);
    }

    /**
     * Retroactively apply the auto-block rule to every still-open HIGH/CRITICAL
     * alert. Useful right after enabling the feature or after dismissing
     * false-positive blocks. Returns the count of newly-created entries.
     */
    @PreAuthorize("hasAnyRole('ADMIN','ORG_ADMIN','ANALYST')")
    @PostMapping("/blocklist/backfill")
    public Map<String, Object> backfill(@AuthenticationPrincipal OrgUserDetails principal) {
        Long orgId = principal != null ? principal.getOrganizationId() : null;
        int created = service.backfillAutoBlocks(orgId);
        return Map.of("created", created);
    }

    @PreAuthorize("hasAnyRole('ADMIN','ORG_ADMIN','ANALYST')")
    @DeleteMapping("/blocklist/{id}")
    public Map<String, Object> unblock(@PathVariable Long id,
                                       @AuthenticationPrincipal OrgUserDetails principal) {
        String actor = principal != null ? principal.getUsername() : "system";
        Long orgId  = principal != null ? principal.getOrganizationId() : null;
        service.unblock(id, actor, orgId);
        return Map.of("id", id, "removed", true);
    }
}
