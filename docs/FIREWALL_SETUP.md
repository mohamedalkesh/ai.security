# Firewall enforcement & Threat Intelligence

This document describes how to enable kernel-level blocking (nftables) and
external reputation lookups (AbuseIPDB) for the AI Security Platform.

## 1. nftables enforcement

The backend can push the blocklist into the host's nftables ruleset so blocked
IPs are dropped *before* they reach any service on the machine. Without this,
the blocklist is still authoritative inside the application but is not
enforced at the network layer.

### Requirements

* Linux host with `nft` available (Debian/Ubuntu: `sudo apt install nftables`).
* The user running the backend (e.g. `mohamed`) must be able to invoke
  `nft` non-interactively via `sudo`.

### Sudoers setup (one-time)

Replace `mohamed` with the user running the Java process:

```bash
sudo tee /etc/sudoers.d/aisec-nft <<'EOF'
mohamed ALL=(root) NOPASSWD: /usr/sbin/nft
EOF
sudo chmod 0440 /etc/sudoers.d/aisec-nft
```

Validate:

```bash
sudo -n /usr/sbin/nft --version   # should print "nftables vX.Y" with no prompt
```

### Verify it activated

Start the backend and look for one of these log lines:

```
Firewall enforcer: nftables (binary=/usr/sbin/nft, sudo=true)
Firewall enforcer=nftables initialised with N active block(s)
```

If you see `NoOpFirewallEnforcer` instead, check the warning line — it
explains why the probe failed (missing binary, sudo prompt, etc.).

### Inspect the live ruleset

```bash
sudo nft list table inet aisec
```

You should see two named sets (`aisec_block_v4`, `aisec_block_v6`) and a
matching drop rule in the `input` chain.

### Configuration knobs

In `application.yml` (or via env vars):

```yaml
app:
  firewall:
    enforcer: auto       # auto | nftables | noop
    nft-path: ""         # override binary location; empty = auto-probe
    use-sudo: true       # set false if running the JVM as root
```

* `enforcer: noop` — disable kernel enforcement entirely (DB-only blocking).
* `enforcer: nftables` — fail loud if probe fails (useful in production).
* `enforcer: auto` (default) — silently fall back to NoOp if the host can't
  support nftables.

## 2. AbuseIPDB integration

Per-IP reputation is shown next to blocked IPs and incident source IPs. With
no API key configured, the service serves a deterministic synthetic verdict
so the UI works for dev/demo.

### Get an API key

1. Create a free account at <https://www.abuseipdb.com>.
2. Generate an API key (free tier: 1,000 lookups/day).

### Configure

Set the env var or `application.yml`:

```bash
export ABUSEIPDB_KEY="your-key-here"
```

Or in YAML:

```yaml
app:
  threat-intel:
    provider: auto              # auto | abuseipdb | mock | off
    abuseipdb-key: "${ABUSEIPDB_KEY:}"
    cache-ttl-hours: 24
```

Provider modes:

| Mode        | Behaviour                                                       |
|-------------|-----------------------------------------------------------------|
| `auto`      | AbuseIPDB if key set; otherwise deterministic mock.             |
| `abuseipdb` | Force AbuseIPDB (will return cached/stale if key is missing).   |
| `mock`      | Always use the synthetic provider (good for screenshots/demos). |
| `off`       | Return no data; UI shows a `Check` placeholder.                 |

### Cache

All verdicts are cached for `cache-ttl-hours` (default 24h) in the
`ip_reputation` table. Stale rows are still served while a refresh is
attempted, so the UI never blocks on a slow upstream.
