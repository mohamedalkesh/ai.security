package com.aisec.backend.controller;

import com.aisec.backend.dto.webhook.WebhookConfigDto;
import com.aisec.backend.dto.webhook.WebhookCreateRequest;
import com.aisec.backend.entity.Organization;
import com.aisec.backend.entity.Severity;
import com.aisec.backend.entity.WebhookConfig;
import com.aisec.backend.repository.OrganizationRepository;
import com.aisec.backend.repository.WebhookConfigRepository;
import com.aisec.backend.security.OrgUserDetails;
import com.aisec.backend.service.AuditService;
import com.aisec.backend.service.WebhookService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Per-tenant webhook CRUD. Only ADMIN / ORG_ADMIN can manage webhooks.
 *
 * Secret handling:
 *  - Auto-generated server-side on creation.
 *  - Returned ONCE in the create response — clients must store it themselves.
 *  - Subsequent reads never expose the secret.
 *  - Rotation via POST /api/webhooks/{id}/rotate-secret.
 */
@RestController
@RequestMapping("/api/webhooks")
@PreAuthorize("hasAnyRole('ADMIN','ORG_ADMIN')")
public class WebhookController {

    private final WebhookConfigRepository repo;
    private final OrganizationRepository orgs;
    private final WebhookService service;
    private final AuditService audit;

    public WebhookController(WebhookConfigRepository repo,
                             OrganizationRepository orgs,
                             WebhookService service,
                             AuditService audit) {
        this.repo = repo;
        this.orgs = orgs;
        this.service = service;
        this.audit = audit;
    }

    @GetMapping
    public List<WebhookConfigDto> list(@AuthenticationPrincipal OrgUserDetails p) {
        Long orgId = p != null ? p.getOrganizationId() : null;
        return repo.findByOrg(orgId).stream().map(WebhookConfigDto::from).toList();
    }

    @PostMapping
    public Map<String, Object> create(@RequestBody @Valid WebhookCreateRequest req,
                                       @AuthenticationPrincipal OrgUserDetails p) {
        Long orgId = p != null ? p.getOrganizationId() : null;
        WebhookConfig w = new WebhookConfig();
        w.setName(req.name());
        w.setUrl(req.url());
        w.setMinSeverity(req.minSeverity() != null ? req.minSeverity() : Severity.HIGH);
        w.setEnabled(req.enabled() == null || req.enabled());
        w.setPreset(req.preset() != null ? req.preset() : "generic");
        w.setSecret(service.generateSecret());
        if (orgId != null) {
            Organization org = orgs.findById(orgId).orElseThrow(() ->
                    new ResponseStatusException(HttpStatus.BAD_REQUEST, "Organisation not found"));
            w.setOrganization(org);
        }
        WebhookConfig saved = repo.save(w);
        audit.log("WEBHOOK_CREATE", "Webhook", saved.getId(),
                "name=" + saved.getName() + " url=" + saved.getUrl());
        // Secret is returned ONCE.
        return Map.of(
                "config", WebhookConfigDto.from(saved),
                "secret", saved.getSecret()
        );
    }

    @PutMapping("/{id}")
    public WebhookConfigDto update(@PathVariable Long id,
                                   @RequestBody @Valid WebhookCreateRequest req,
                                   @AuthenticationPrincipal OrgUserDetails p) {
        WebhookConfig w = load(id, p);
        w.setName(req.name());
        w.setUrl(req.url());
        if (req.minSeverity() != null) w.setMinSeverity(req.minSeverity());
        if (req.enabled() != null) w.setEnabled(req.enabled());
        if (req.preset() != null) w.setPreset(req.preset());
        WebhookConfig saved = repo.save(w);
        audit.log("WEBHOOK_UPDATE", "Webhook", saved.getId(), saved.getName());
        return WebhookConfigDto.from(saved);
    }

    @PostMapping("/{id}/rotate-secret")
    public Map<String, String> rotate(@PathVariable Long id,
                                      @AuthenticationPrincipal OrgUserDetails p) {
        WebhookConfig w = load(id, p);
        String fresh = service.generateSecret();
        w.setSecret(fresh);
        repo.save(w);
        audit.log("WEBHOOK_ROTATE", "Webhook", w.getId(), w.getName());
        return Map.of("secret", fresh);
    }

    @DeleteMapping("/{id}")
    public void delete(@PathVariable Long id,
                       @AuthenticationPrincipal OrgUserDetails p) {
        WebhookConfig w = load(id, p);
        repo.delete(w);
        audit.log("WEBHOOK_DELETE", "Webhook", id, w.getName());
    }

    private WebhookConfig load(Long id, OrgUserDetails p) {
        WebhookConfig w = repo.findById(id).orElseThrow(() ->
                new ResponseStatusException(HttpStatus.NOT_FOUND));
        Long callerOrg = p != null ? p.getOrganizationId() : null;
        Long ownerOrg  = w.getOrganization() != null ? w.getOrganization().getId() : null;
        if (!Objects.equals(callerOrg, ownerOrg)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        return w;
    }
}
