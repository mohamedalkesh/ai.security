package com.aisec.backend.controller;

import com.aisec.backend.dto.threatintel.IpReputationDto;
import com.aisec.backend.service.threatintel.ThreatIntelService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

/**
 * Thin HTTP surface for the reputation cache. Reads are open to any
 * authenticated user (analysts inspecting alerts); the refresh side-effect
 * stays gated to roles that can actually act on the verdict.
 */
@RestController
@RequestMapping("/api/threat-intel")
public class ThreatIntelController {

    private final ThreatIntelService service;

    public ThreatIntelController(ThreatIntelService service) {
        this.service = service;
    }

    @GetMapping("/{ip}")
    public ResponseEntity<IpReputationDto> lookup(@PathVariable String ip) {
        Optional<IpReputationDto> dto = service.lookup(ip);
        return dto.map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.noContent().build());
    }

    @PreAuthorize("hasAnyRole('ADMIN','ORG_ADMIN','ANALYST')")
    @PostMapping("/{ip}/refresh")
    public IpReputationDto refresh(@PathVariable String ip) {
        return service.refresh(ip);
    }
}
