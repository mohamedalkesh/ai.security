package com.aisec.backend.controller;

import com.aisec.backend.service.MlClient;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;

/**
 * Proxies live network monitoring and host-isolation requests to the ML service.
 */
@RestController
@RequestMapping("/api/monitor")
public class MonitorController {

    private final MlClient mlClient;

    public MonitorController(MlClient mlClient) {
        this.mlClient = mlClient;
    }

    @GetMapping("/interfaces")
    public List<Map<String, Object>> listInterfaces() {
        return mlClient.monitorInterfaces();
    }

    /**
     * Start capture.  Accepts {@code {"interface": "eth0"}} (single) or
     * {@code {"interfaces": ["eth0","wlan0"]}} (multi-interface).
     */
    @PostMapping("/start")
    @SuppressWarnings("unchecked")
    public Map<String, Object> start(@RequestBody Map<String, Object> req) {
        Object multi = req.get("interfaces");
        if (multi instanceof List) {
            return mlClient.monitorStart(multi);
        }
        Object single = req.get("interface");
        return mlClient.monitorStart(single != null ? single.toString() : "");
    }

    @PostMapping("/stop")
    public Map<String, Object> stop() {
        return mlClient.monitorStop();
    }

    @GetMapping("/status")
    public Map<String, Object> status() {
        return mlClient.monitorStatus();
    }

    // ── Network-wide isolation (ARP-based) ─────────────────────────────────

    @PostMapping("/isolate")
    public Map<String, Object> isolate(@RequestBody Map<String, String> req) {
        String ip     = req.get("ip");
        String reason = req.getOrDefault("reason", "");
        if (ip == null || ip.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "ip is required");
        }
        return mlClient.monitorIsolate(ip, reason);
    }

    @DeleteMapping("/isolate/{ip}")
    public Map<String, Object> release(@PathVariable String ip) {
        return mlClient.monitorRelease(ip);
    }

    @GetMapping("/isolated")
    public List<Map<String, Object>> listIsolated() {
        return mlClient.monitorListIsolated();
    }
}
