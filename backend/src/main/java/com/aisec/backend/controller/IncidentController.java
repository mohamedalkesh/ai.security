package com.aisec.backend.controller;

import com.aisec.backend.dto.alert.UpdateAlertRequest;
import com.aisec.backend.dto.incident.IncidentDto;
import com.aisec.backend.security.OrgUserDetails;
import com.aisec.backend.service.IncidentService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/incidents")
public class IncidentController {

    private final IncidentService service;

    public IncidentController(IncidentService service) {
        this.service = service;
    }

    @GetMapping
    public Page<IncidentDto> list(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @AuthenticationPrincipal OrgUserDetails principal) {
        Long orgId = principal != null ? principal.getOrganizationId() : null;
        return service.list(orgId, PageRequest.of(page, size, Sort.by("lastAlertAt").descending()));
    }

    @GetMapping("/{id}")
    public IncidentDto get(@PathVariable Long id,
                           @AuthenticationPrincipal OrgUserDetails principal) {
        Long orgId = principal != null ? principal.getOrganizationId() : null;
        return service.get(id, orgId);
    }

    @PreAuthorize("hasAnyRole('ADMIN','ORG_ADMIN','ANALYST')")
    @PatchMapping("/{id}")
    public IncidentDto update(@PathVariable Long id,
                              @RequestBody UpdateAlertRequest req,
                              @AuthenticationPrincipal OrgUserDetails principal) {
        Long orgId = principal != null ? principal.getOrganizationId() : null;
        return service.updateStatus(id, req.status(), orgId);
    }
}
