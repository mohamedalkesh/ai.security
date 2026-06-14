package com.aisec.backend.controller;

import com.aisec.backend.repository.AlertRepository;
import com.aisec.backend.security.OrgUserDetails;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Read-only analytics endpoints — every query is org-scoped.
 *
 * Exposes:
 *   GET /api/analytics/mttr               — mean time-to-resolve (seconds)
 *   GET /api/analytics/trend?days=N       — daily alert counts
 *   GET /api/analytics/severity-trend?days=N
 *   GET /api/analytics/top-attackers?limit=10&days=7
 *   GET /api/analytics/summary            — everything in one payload
 */
@RestController
@RequestMapping("/api/analytics")
@PreAuthorize("hasAnyRole('ADMIN','ORG_ADMIN','ANALYST','VIEWER')")
public class AnalyticsController {

    private final AlertRepository alerts;

    public AnalyticsController(AlertRepository alerts) {
        this.alerts = alerts;
    }

    @GetMapping("/mttr")
    public Map<String, Object> mttr(@AuthenticationPrincipal OrgUserDetails p) {
        Long orgId = p != null ? p.getOrganizationId() : null;
        Double sec = alerts.mttrSecondsScoped(orgId);
        Map<String, Object> r = new HashMap<>();
        r.put("seconds", sec);
        r.put("humanReadable", humanizeSeconds(sec));
        return r;
    }

    @GetMapping("/trend")
    public List<Map<String, Object>> trend(@RequestParam(defaultValue = "14") int days,
                                           @AuthenticationPrincipal OrgUserDetails p) {
        Long orgId = p != null ? p.getOrganizationId() : null;
        return alerts.dailyCountsScoped(orgId, daysAgo(days));
    }

    @GetMapping("/severity-trend")
    public List<Map<String, Object>> severityTrend(@RequestParam(defaultValue = "14") int days,
                                                    @AuthenticationPrincipal OrgUserDetails p) {
        Long orgId = p != null ? p.getOrganizationId() : null;
        return alerts.severityTrendScoped(orgId, daysAgo(days));
    }

    @GetMapping("/top-attackers")
    public List<Map<String, Object>> topAttackers(@RequestParam(defaultValue = "10") int limit,
                                                   @RequestParam(defaultValue = "7") int days,
                                                   @AuthenticationPrincipal OrgUserDetails p) {
        Long orgId = p != null ? p.getOrganizationId() : null;
        int safeLimit = Math.min(Math.max(limit, 1), 100);
        return alerts.topAttackersScoped(orgId, daysAgo(days), safeLimit);
    }

    /** One-stop endpoint for the dashboard page. */
    @GetMapping("/summary")
    public Map<String, Object> summary(@RequestParam(defaultValue = "14") int days,
                                       @AuthenticationPrincipal OrgUserDetails p) {
        Long orgId = p != null ? p.getOrganizationId() : null;
        Instant since = daysAgo(days);
        Map<String, Object> r = new HashMap<>();
        Double sec = alerts.mttrSecondsScoped(orgId);
        r.put("mttr", Map.of(
                "seconds", sec == null ? 0.0 : sec,
                "humanReadable", humanizeSeconds(sec)));
        r.put("trend",         alerts.dailyCountsScoped(orgId, since));
        r.put("severityTrend", alerts.severityTrendScoped(orgId, since));
        r.put("topAttackers",  alerts.topAttackersScoped(orgId, since, 10));
        r.put("days", days);
        return r;
    }

    /* ---------- helpers ---------- */
    private static Instant daysAgo(int days) {
        int safe = Math.min(Math.max(days, 1), 90);
        return Instant.now().minusSeconds(safe * 86400L);
    }

    private static String humanizeSeconds(Double s) {
        if (s == null || s <= 0) return "n/a";
        long sec = s.longValue();
        if (sec < 60)        return sec + "s";
        if (sec < 3600)      return (sec / 60) + "m " + (sec % 60) + "s";
        if (sec < 86400)     return (sec / 3600) + "h " + ((sec % 3600) / 60) + "m";
        return (sec / 86400) + "d " + ((sec % 86400) / 3600) + "h";
    }
}
