package com.aisec.backend.controller;

import com.aisec.backend.service.MlClient;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Proxies live network monitoring requests to the ML service.
 */
@RestController
@RequestMapping("/api/monitor")
public class MonitorController {

    private final MlClient mlClient;

    public MonitorController(MlClient mlClient) {
        this.mlClient = mlClient;
    }

    @GetMapping("/interfaces")
    public java.util.List<Map<String, Object>> listInterfaces() {
        return mlClient.monitorInterfaces();
    }

    @PostMapping("/start")
    public Map<String, Object> start(@RequestBody Map<String, String> req) {
        String iface = req.get("interface");
        return mlClient.monitorStart(iface);
    }

    @PostMapping("/stop")
    public Map<String, Object> stop() {
        return mlClient.monitorStop();
    }

    @GetMapping("/status")
    public Map<String, Object> status() {
        return mlClient.monitorStatus();
    }
}
