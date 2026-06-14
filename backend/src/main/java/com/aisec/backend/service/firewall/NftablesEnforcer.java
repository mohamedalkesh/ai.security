package com.aisec.backend.service.firewall;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * nftables-backed enforcer. Maintains two named sets — {@code aisec_block_v4}
 * and {@code aisec_block_v6} — inside the {@code inet aisec} table, and a
 * single drop rule that matches either set on the input chain. The table is
 * created lazily on first use; everything else is idempotent so we can
 * re-apply on restart without checking state first.
 *
 * <p>All nft invocations go through {@code sudo -n} (non-interactive). The
 * operator is expected to grant a single sudoers line of the form:
 *
 * <pre>{@code
 *   aisec ALL=(root) NOPASSWD: /usr/sbin/nft
 * }</pre>
 *
 * If sudo prompts, exits non-zero, or {@code nft} isn't on PATH, the auto-detect
 * in {@link FirewallEnforcerFactory} falls back to {@link NoOpFirewallEnforcer}
 * — we never want to crash the backend over a missing capability.
 */
public class NftablesEnforcer implements FirewallEnforcer {

    private static final Logger log = LoggerFactory.getLogger(NftablesEnforcer.class);

    private static final String TABLE = "aisec";
    private static final String SET_V4 = "aisec_block_v4";
    private static final String SET_V6 = "aisec_block_v6";
    private static final int CMD_TIMEOUT_SEC = 5;

    private final String nftPath;
    private final boolean useSudo;
    private volatile boolean initialised = false;

    public NftablesEnforcer(String nftPath, boolean useSudo) {
        this.nftPath = nftPath;
        this.useSudo = useSudo;
    }

    @Override public String name() { return "nftables"; }
    @Override public boolean isActive() { return true; }

    @Override
    public synchronized void applyBlock(String ip) {
        ensureInitialised();
        String set = isIpv6(ip) ? SET_V6 : SET_V4;
        // "{ @set, element }" with the {} braces is the literal nft syntax.
        runNft("add", "element", "inet", TABLE, set, "{ " + ip + " }");
    }

    @Override
    public synchronized void removeBlock(String ip) {
        // No init required — if the set doesn't exist there's nothing to remove.
        if (!initialised) return;
        String set = isIpv6(ip) ? SET_V6 : SET_V4;
        // nft errors with "Error: Could not process rule: No such file" when
        // the element isn't present. We swallow that — the caller's contract
        // already guarantees idempotency.
        runNftIgnoreFailure("delete", "element", "inet", TABLE, set, "{ " + ip + " }");
    }

    @Override
    public synchronized void syncAll(Collection<String> ips) {
        ensureInitialised();
        // Flush both sets, then re-add. Flush is cheap and avoids drift if
        // someone touched the rules manually between restarts.
        runNftIgnoreFailure("flush", "set", "inet", TABLE, SET_V4);
        runNftIgnoreFailure("flush", "set", "inet", TABLE, SET_V6);
        List<String> v4 = new ArrayList<>();
        List<String> v6 = new ArrayList<>();
        for (String ip : ips) {
            if (ip == null || ip.isBlank()) continue;
            (isIpv6(ip) ? v6 : v4).add(ip.trim());
        }
        if (!v4.isEmpty()) {
            runNft("add", "element", "inet", TABLE, SET_V4, "{ " + String.join(", ", v4) + " }");
        }
        if (!v6.isEmpty()) {
            runNft("add", "element", "inet", TABLE, SET_V6, "{ " + String.join(", ", v6) + " }");
        }
        log.info("nftables sync complete: {} v4 + {} v6 entries", v4.size(), v6.size());
    }

    /* ============================ Internals ============================ */

    /**
     * Lazily create the table, sets, and drop rule. Each step is wrapped in
     * its own nft invocation because nft refuses partial transactions if any
     * piece already exists — splitting lets us tolerate restarts cleanly.
     */
    private void ensureInitialised() {
        if (initialised) return;
        // Create-if-absent ladder. "create" errors when present, which is
        // why we use runNftIgnoreFailure for the structural pieces.
        runNftIgnoreFailure("add", "table", "inet", TABLE);
        runNftIgnoreFailure("add", "set", "inet", TABLE, SET_V4,
                "{ type ipv4_addr; flags interval; }");
        runNftIgnoreFailure("add", "set", "inet", TABLE, SET_V6,
                "{ type ipv6_addr; flags interval; }");
        runNftIgnoreFailure("add", "chain", "inet", TABLE, "input",
                "{ type filter hook input priority -10; policy accept; }");
        // The drop rule itself is added twice (once per family). Both forms
        // are idempotent-friendly: if a matching rule already exists, nft
        // happily appends a duplicate — harmless, but we use a handle-free
        // string-compare against `nft list` to avoid stacking copies.
        if (!ruleExists("ip saddr @" + SET_V4)) {
            runNftIgnoreFailure("add", "rule", "inet", TABLE, "input",
                    "ip saddr @" + SET_V4 + " drop");
        }
        if (!ruleExists("ip6 saddr @" + SET_V6)) {
            runNftIgnoreFailure("add", "rule", "inet", TABLE, "input",
                    "ip6 saddr @" + SET_V6 + " drop");
        }
        initialised = true;
        log.info("nftables enforcer initialised (table=inet/{}, sets={},{})",
                 TABLE, SET_V4, SET_V6);
    }

    private boolean ruleExists(String needle) {
        String out = runNftCapture("list", "table", "inet", TABLE);
        return out != null && out.contains(needle);
    }

    private void runNft(String... args) {
        Result r = exec(args);
        if (r.exitCode != 0) {
            log.warn("nft {} failed (exit={}): {}", String.join(" ", args), r.exitCode, r.stderr);
            throw new RuntimeException("nft command failed: " + r.stderr);
        }
    }

    private void runNftIgnoreFailure(String... args) {
        Result r = exec(args);
        if (r.exitCode != 0) {
            log.debug("nft {} (ignored, exit={}): {}",
                      String.join(" ", args), r.exitCode, r.stderr);
        }
    }

    private String runNftCapture(String... args) {
        Result r = exec(args);
        return r.exitCode == 0 ? r.stdout : null;
    }

    private Result exec(String... nftArgs) {
        List<String> cmd = new ArrayList<>();
        if (useSudo) { cmd.add("sudo"); cmd.add("-n"); }
        cmd.add(nftPath);
        for (String a : nftArgs) cmd.add(a);
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(false);
            Process p = pb.start();
            String out = drain(p.getInputStream());
            String err = drain(p.getErrorStream());
            if (!p.waitFor(CMD_TIMEOUT_SEC, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return new Result(-1, out, "timeout after " + CMD_TIMEOUT_SEC + "s");
            }
            return new Result(p.exitValue(), out, err);
        } catch (Exception e) {
            return new Result(-1, "", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private static String drain(java.io.InputStream in) {
        try (BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) sb.append(line).append('\n');
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private static boolean isIpv6(String ip) {
        return ip != null && ip.indexOf(':') >= 0;
    }

    private record Result(int exitCode, String stdout, String stderr) {}
}
