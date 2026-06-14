package com.aisec.backend.controller;

import com.sun.management.OperatingSystemMXBean;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Exposes real OS-level system metrics for the Monitoring page.
 *
 *   GET /api/metrics    →  point-in-time CPU/memory/disk/network usage
 *
 * On Linux we read /proc directly for accurate, OS-wide numbers.
 * On other platforms we fall back to JVM-level metrics which still produce
 * sensible (if narrower) values.
 */
@RestController
@RequestMapping("/api")
public class MetricsController {

    private final OperatingSystemMXBean os =
            (OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();

    /** Cached previous /proc/stat snapshot for OS-wide CPU% calculation */
    private long[] prevCpuTotals = null;
    private long[] prevNetBytes = null;     // [rx, tx, timestamp ms]

    @GetMapping("/metrics")
    public Map<String, Object> metrics() {
        Map<String, Object> out = new LinkedHashMap<>();

        // ── CPU ───────────────────────────────────────────────────────
        double cpuPct = readLinuxCpuPercent();
        if (cpuPct < 0) {
            // JVM fallback (system load average / available processors)
            double load = os.getCpuLoad() * 100.0;
            cpuPct = load >= 0 ? load : 0;
        }
        Map<String, Object> cpu = new LinkedHashMap<>();
        cpu.put("percent", round1(cpuPct));
        cpu.put("cores",   Runtime.getRuntime().availableProcessors());
        out.put("cpu", cpu);

        // ── Memory ────────────────────────────────────────────────────
        long total = os.getTotalMemorySize();
        long free  = os.getFreeMemorySize();
        long used  = total - free;
        Map<String, Object> mem = new LinkedHashMap<>();
        mem.put("percent",   total > 0 ? round1(used * 100.0 / total) : 0);
        mem.put("used_mb",   used  / (1024 * 1024));
        mem.put("total_mb",  total / (1024 * 1024));
        out.put("memory", mem);

        // ── Disk (root partition) ────────────────────────────────────
        File root = new File("/");
        long dTot  = root.getTotalSpace();
        long dFree = root.getUsableSpace();
        long dUsed = dTot - dFree;
        Map<String, Object> disk = new LinkedHashMap<>();
        disk.put("percent",   dTot > 0 ? round1(dUsed * 100.0 / dTot) : 0);
        disk.put("used_gb",   dUsed / (1024L * 1024 * 1024));
        disk.put("total_gb",  dTot  / (1024L * 1024 * 1024));
        out.put("disk", disk);

        // ── Network throughput (Linux: /proc/net/dev) ───────────────
        Map<String, Object> net = readLinuxNetThroughput();
        if (net == null) {
            net = new LinkedHashMap<>();
            net.put("rx_mbps", 0);
            net.put("tx_mbps", 0);
            net.put("total_mbps", 0);
        }
        out.put("network", net);

        // ── Uptime / load ────────────────────────────────────────────
        Map<String, Object> sys = new LinkedHashMap<>();
        sys.put("uptime_ms",  ManagementFactory.getRuntimeMXBean().getUptime());
        sys.put("load_avg",   os.getSystemLoadAverage());
        sys.put("processors", os.getAvailableProcessors());
        out.put("system", sys);

        return out;
    }

    // ─────────── Linux helpers ───────────

    /**
     * Reads /proc/stat twice (once cached) and returns the % of CPU time spent
     * outside idle/iowait. Returns -1 on non-Linux or read failure.
     */
    private double readLinuxCpuPercent() {
        try {
            List<String> lines = Files.readAllLines(Path.of("/proc/stat"));
            String first = lines.isEmpty() ? "" : lines.get(0);
            if (!first.startsWith("cpu ")) return -1;
            String[] tok = first.trim().split("\\s+");
            // tok[0] = "cpu", then user nice system idle iowait irq softirq steal …
            long user = pl(tok, 1), nice = pl(tok, 2), sys = pl(tok, 3),
                 idle = pl(tok, 4), iowait = pl(tok, 5),
                 irq  = pl(tok, 6), soft = pl(tok, 7), steal = pl(tok, 8);
            long idleAll = idle + iowait;
            long busy    = user + nice + sys + irq + soft + steal;
            long total   = idleAll + busy;

            double pct = 0;
            if (prevCpuTotals != null) {
                long dTotal = total   - prevCpuTotals[0];
                long dIdle  = idleAll - prevCpuTotals[1];
                if (dTotal > 0) pct = (dTotal - dIdle) * 100.0 / dTotal;
            }
            prevCpuTotals = new long[]{ total, idleAll };
            return pct;
        } catch (IOException e) {
            return -1;
        }
    }

    /**
     * Reads /proc/net/dev twice (once cached) and returns rx/tx Mbps across all
     * non-loopback interfaces. Returns null on non-Linux or read failure.
     */
    private Map<String, Object> readLinuxNetThroughput() {
        try {
            List<String> lines = Files.readAllLines(Path.of("/proc/net/dev"));
            long rx = 0, tx = 0;
            for (String line : lines) {
                int colon = line.indexOf(':');
                if (colon < 0) continue;
                String iface = line.substring(0, colon).trim();
                if (iface.equals("lo") || iface.startsWith("docker") || iface.startsWith("veth")) continue;
                String[] f = line.substring(colon + 1).trim().split("\\s+");
                if (f.length < 9) continue;
                rx += Long.parseLong(f[0]);   // bytes received
                tx += Long.parseLong(f[8]);   // bytes transmitted
            }
            long now = System.currentTimeMillis();
            Map<String, Object> r = new LinkedHashMap<>();
            if (prevNetBytes != null) {
                long dt = now - prevNetBytes[2];
                if (dt > 0) {
                    double rxMbps = (rx - prevNetBytes[0]) * 8.0 / 1_000_000.0 / (dt / 1000.0);
                    double txMbps = (tx - prevNetBytes[1]) * 8.0 / 1_000_000.0 / (dt / 1000.0);
                    r.put("rx_mbps",    round1(Math.max(0, rxMbps)));
                    r.put("tx_mbps",    round1(Math.max(0, txMbps)));
                    r.put("total_mbps", round1(Math.max(0, rxMbps + txMbps)));
                }
            }
            if (r.isEmpty()) {
                r.put("rx_mbps", 0); r.put("tx_mbps", 0); r.put("total_mbps", 0);
            }
            prevNetBytes = new long[]{ rx, tx, now };
            return r;
        } catch (IOException e) {
            return null;
        }
    }

    private static long pl(String[] a, int i) {
        return i < a.length ? Long.parseLong(a[i]) : 0;
    }
    private static double round1(double v) {
        return Math.round(v * 10.0) / 10.0;
    }
}
