package com.aisec.backend.controller;

import com.aisec.backend.entity.Organization;
import com.aisec.backend.repository.OrganizationRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Organization listing — system ADMIN only.
 * Used by the user-management UI to pick which org a new user belongs to.
 */
@RestController
@RequestMapping("/api/organizations")
@PreAuthorize("hasRole('ADMIN')")
public class OrganizationController {

    private final OrganizationRepository orgs;

    public OrganizationController(OrganizationRepository orgs) { this.orgs = orgs; }

    @GetMapping
    public List<Map<String, Object>> list() {
        return orgs.findAll().stream()
                .sorted((a, b) -> a.getName().compareToIgnoreCase(b.getName()))
                .<Map<String, Object>>map(o -> Map.of(
                        "id",   (Object) o.getId(),
                        "name", (Object) o.getName()))
                .toList();
    }

    public record OrgDto(Long id, String name) {
        public static OrgDto from(Organization o) { return new OrgDto(o.getId(), o.getName()); }
    }
}
