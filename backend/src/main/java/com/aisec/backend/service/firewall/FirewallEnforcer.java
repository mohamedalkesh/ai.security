package com.aisec.backend.service.firewall;

import java.util.Collection;

/**
 * Abstraction over the host's packet-filter. Implementations actually push the
 * blocklist down to the kernel (e.g. nftables) so a blocked IP is dropped
 * before it ever reaches the application stack — the database row alone is
 * just metadata.
 *
 * <p>The contract is intentionally idempotent: blocking an already-blocked IP
 * or unblocking an unknown one is a no-op, not an error. This matches how
 * {@code BlockedIpService} re-syncs on startup without having to know the
 * previous state.
 */
public interface FirewallEnforcer {

    /** Best-effort name surfaced in logs / health checks. */
    String name();

    /** True when the underlying backend is actually wired up (not a NoOp). */
    boolean isActive();

    /** Add {@code ip} to the kernel drop set. Safe to call repeatedly. */
    void applyBlock(String ip);

    /** Remove {@code ip} from the kernel drop set. Safe if absent. */
    void removeBlock(String ip);

    /**
     * Replace the kernel set with {@code ips} verbatim. Called once at app
     * startup to reconcile the persistent blocklist with whatever survived
     * across restarts.
     */
    void syncAll(Collection<String> ips);
}
