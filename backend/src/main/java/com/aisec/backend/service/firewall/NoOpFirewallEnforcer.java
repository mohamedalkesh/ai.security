package com.aisec.backend.service.firewall;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;

/**
 * Fallback enforcer used when the host doesn't expose a usable packet-filter
 * (e.g. running inside a container without {@code CAP_NET_ADMIN}, on macOS in
 * dev, or when the operator hasn't granted the sudoers entry yet). Keeps the
 * application functional — the blocklist is still authoritative in the DB and
 * still consulted from the alert pipeline; only the kernel-level enforcement
 * is skipped.
 */
public class NoOpFirewallEnforcer implements FirewallEnforcer {

    private static final Logger log = LoggerFactory.getLogger(NoOpFirewallEnforcer.class);

    private final String reason;

    public NoOpFirewallEnforcer(String reason) {
        this.reason = reason;
        log.warn("FirewallEnforcer: using NO-OP backend ({}). " +
                 "Blocked IPs are tracked in the DB but NOT dropped at the kernel level.",
                 reason);
    }

    @Override public String name() { return "noop(" + reason + ")"; }
    @Override public boolean isActive() { return false; }

    @Override
    public void applyBlock(String ip) {
        log.debug("[noop] applyBlock({}) — not enforced", ip);
    }

    @Override
    public void removeBlock(String ip) {
        log.debug("[noop] removeBlock({}) — not enforced", ip);
    }

    @Override
    public void syncAll(Collection<String> ips) {
        log.info("[noop] syncAll({} entries) — not enforced", ips.size());
    }
}
