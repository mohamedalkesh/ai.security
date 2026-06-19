package com.aisec.backend.controller;

import com.aisec.backend.service.MlClient;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Proxies read-only ML service endpoints to the frontend.
 * The ML service runs on 127.0.0.1:8001 and is not exposed publicly,
 * so all frontend calls go through this controller (which enforces auth).
 */
@RestController
@RequestMapping("/api/ml")
@PreAuthorize("hasAnyRole('ADMIN','ORG_ADMIN','ANALYST','VIEWER')")
public class MlProxyController {

    private final MlClient ml;

    public MlProxyController(MlClient ml) {
        this.ml = ml;
    }

    @GetMapping("/drift")
    public Map<String, Object> driftReport() {
        return ml.driftReport();
    }

    @GetMapping("/drift/summary")
    public Map<String, Object> driftSummary() {
        return ml.driftSummary();
    }
}
