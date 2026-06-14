package com.aisec.backend.service.firewall;

import com.aisec.backend.config.AppProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.File;
import java.util.concurrent.TimeUnit;

/**
 * Picks the right {@link FirewallEnforcer} implementation at startup. The
 * choice is driven by configuration first ({@code app.firewall.enforcer=auto
 * |nftables|noop}) and then by a runtime capability probe — we'd rather
 * silently degrade than start the backend in an unbootable state because the
 * operator forgot a sudoers line.
 */
@Configuration
public class FirewallEnforcerFactory {

    private static final Logger log = LoggerFactory.getLogger(FirewallEnforcerFactory.class);

    @Bean
    public FirewallEnforcer firewallEnforcer(AppProperties props) {
        AppProperties.Firewall cfg = props.getFirewall();
        String mode = cfg.getEnforcer() == null ? "auto" : cfg.getEnforcer().toLowerCase();

        if ("noop".equals(mode)) {
            return new NoOpFirewallEnforcer("explicitly disabled");
        }

        String nft = locateNft(cfg.getNftPath());
        if (nft == null) {
            if ("nftables".equals(mode)) {
                log.warn("app.firewall.enforcer=nftables requested but 'nft' binary not found on PATH; falling back to NoOp");
            }
            return new NoOpFirewallEnforcer("nft binary not found");
        }

        boolean sudo = cfg.isUseSudo();
        if (!canExec(nft, sudo)) {
            if ("nftables".equals(mode)) {
                log.warn("nft probe failed (sudo={}). Add a sudoers line: <user> ALL=(root) NOPASSWD: {}",
                         sudo, nft);
            }
            return new NoOpFirewallEnforcer("nft not executable (sudo=" + sudo + ")");
        }

        log.info("Firewall enforcer: nftables (binary={}, sudo={})", nft, sudo);
        return new NftablesEnforcer(nft, sudo);
    }

    /** First-match lookup: explicit config wins, otherwise scan common spots. */
    private static String locateNft(String configured) {
        if (configured != null && !configured.isBlank() && new File(configured).canExecute()) {
            return configured;
        }
        for (String p : new String[]{"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"}) {
            if (new File(p).canExecute()) return p;
        }
        return null;
    }

    /** Quick {@code nft --version} (or {@code sudo -n nft --version}) probe. */
    private static boolean canExec(String nftPath, boolean useSudo) {
        try {
            ProcessBuilder pb = useSudo
                    ? new ProcessBuilder("sudo", "-n", nftPath, "--version")
                    : new ProcessBuilder(nftPath, "--version");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            if (!p.waitFor(3, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return false;
            }
            return p.exitValue() == 0;
        } catch (Exception e) {
            return false;
        }
    }
}
