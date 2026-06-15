package com.aisec.backend.controller;

import com.aisec.backend.entity.AppSetting;
import com.aisec.backend.repository.AppSettingRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Map;

@RestController
@RequestMapping("/api/settings")
public class SettingsController {

    private final AppSettingRepository repo;
    private final ObjectMapper mapper;

    public SettingsController(AppSettingRepository repo, ObjectMapper mapper) {
        this.repo = repo;
        this.mapper = mapper;
    }

    /** Any authenticated user may read settings. */
    @GetMapping
    public Map<String, Object> get() throws Exception {
        AppSetting s = repo.findById(1L).orElseGet(this::defaults);
        ObjectNode payload = (ObjectNode) mapper.readTree(s.getPayload());
        ObjectNode resp = mapper.createObjectNode();
        resp.set("settings", payload);
        resp.put("updatedAt", s.getUpdatedAt().toString());
        resp.put("updatedBy", s.getUpdatedBy() == null ? "" : s.getUpdatedBy());
        return mapper.convertValue(resp, Map.class);
    }

    /** Only ADMIN can change platform settings. */
    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping
    public ResponseEntity<Map<String, Object>> update(@RequestBody JsonNode body,
                                                       @AuthenticationPrincipal UserDetails principal) throws Exception {
        AppSetting s = repo.findById(1L).orElseGet(this::defaults);
        s.setPayload(mapper.writeValueAsString(body));
        s.setUpdatedAt(Instant.now());
        s.setUpdatedBy(principal != null ? principal.getUsername() : "system");
        repo.save(s);
        return ResponseEntity.ok(get());
    }

    /** Only ADMIN can reset to defaults. */
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/reset")
    public Map<String, Object> reset(@AuthenticationPrincipal UserDetails principal) throws Exception {
        AppSetting s = defaults();
        s.setUpdatedBy(principal != null ? principal.getUsername() : "system");
        repo.save(s);
        return get();
    }

    private AppSetting defaults() {
        AppSetting s = new AppSetting();
        s.setId(1L);
        ObjectNode d = mapper.createObjectNode();

        ObjectNode general = d.putObject("general");
        general.put("systemName",   "MADRS");
        general.put("organization", "AISec Libya");
        general.put("timezone",     "UTC+02:00 - Libya");

        ObjectNode security = d.putObject("security");
        security.put("twoFactor",       true);
        security.put("ipWhitelist",     false);
        security.put("autoLockout",     true);

        ObjectNode ai = d.putObject("ai");
        ai.put("sensitivity",     75);
        ai.put("model",           "SecurityNet-AI v3.2 (Latest)");
        ai.put("autoClassify",    true);

        ObjectNode notif = d.putObject("notifications");
        notif.put("email", true);
        notif.put("sms",   true);
        notif.put("slack", false);

        try { s.setPayload(mapper.writeValueAsString(d)); } catch (Exception ignored) {}
        s.setUpdatedAt(Instant.now());
        return s;
    }
}
