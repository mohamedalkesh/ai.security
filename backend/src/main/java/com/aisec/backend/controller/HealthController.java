package com.aisec.backend.controller;

import com.aisec.backend.service.MlClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class HealthController {

    private final MlClient ml;

    public HealthController(MlClient ml) { this.ml = ml; }

    @GetMapping("/health")
    public Map<String, Object> health() {
        Map<String, Object> r = new HashMap<>();
        r.put("status", "ok");
        r.put("service", "ai-security-backend");
        r.put("timestamp", Instant.now().toString());
        try { r.put("ml", ml.health()); }
        catch (Exception e) { r.put("ml", Map.of("status", "down", "error", e.getMessage())); }
        return r;
    }
}
