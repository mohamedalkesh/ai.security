"""
SOC Response Playbook: maps detected attacks to recommended SOC actions
and generates ready-to-copy firewall commands (iptables / nftables / firewalld).

Use:
    from response_recommender import recommend_for_threat, build_action_plan
"""

from __future__ import annotations

from typing import List, Dict
import pandas as pd


SEVERITY_RANK = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def _block_ip_cmds(ip: str, comment: str = "") -> Dict[str, str]:
    """Return firewall commands for blocking a source IP across common stacks."""
    return {
        "iptables":  f"sudo iptables -I INPUT -s {ip} -j DROP -m comment --comment \"{comment}\"",
        "nftables":  f"sudo nft add rule inet filter input ip saddr {ip} drop",
        "firewalld": f"sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address={ip} drop' && sudo firewall-cmd --reload",
        "ufw":       f"sudo ufw deny from {ip}",
    }


def _block_port_cmds(port: int, proto: str = "tcp") -> Dict[str, str]:
    return {
        "iptables":  f"sudo iptables -I INPUT -p {proto} --dport {port} -j DROP",
        "nftables":  f"sudo nft add rule inet filter input {proto} dport {port} drop",
        "firewalld": f"sudo firewall-cmd --permanent --remove-port={port}/{proto} && sudo firewall-cmd --reload",
        "ufw":       f"sudo ufw deny {port}/{proto}",
    }


def _rate_limit_cmds(ip: str, rate: str = "10/min") -> Dict[str, str]:
    return {
        "iptables": (
            f"sudo iptables -I INPUT -s {ip} -m hashlimit --hashlimit-above {rate} "
            f"--hashlimit-mode srcip --hashlimit-name throttle_{ip.replace('.', '_')} -j DROP"
        ),
    }


# ---------- Per-attack playbooks ----------
PLAYBOOKS: Dict[str, Dict] = {
    "Port Scan": {
        "tactic": "Discovery (T1046)",
        "priority": "Medium",
        "actions": [
            "🛑 Block scanner source IP at perimeter firewall.",
            "📈 Enable connection rate-limiting per source IP.",
            "📝 Log all subsequent attempts from this IP for forensics.",
            "🔍 Verify exposed services on targeted ports; close unnecessary ones.",
        ],
    },
    "DDoS": {
        "tactic": "Impact (T1498)",
        "priority": "High",
        "actions": [
            "🚨 Activate upstream DDoS mitigation (CDN / scrubbing).",
            "🛑 Drop traffic from top source IPs at the edge router.",
            "🌐 Notify ISP to apply BGP blackhole or RTBH for the targeted /32.",
            "📈 Enable SYN cookies and connection rate-limiting on the target host.",
            "🧯 Reduce timeout values to free resources from half-open connections.",
        ],
    },
    "Brute Force": {
        "tactic": "Credential Access (T1110)",
        "priority": "High",
        "actions": [
            "🛑 Immediately block source IP at the firewall.",
            "🔐 Force password reset for any account that received a successful login from that IP.",
            "📵 Enforce MFA on the affected service.",
            "⏱️ Add fail2ban / pam_tally2 lockout for failed-auth bursts.",
            "📝 Audit auth logs for successful logins around the attack window.",
        ],
    },
    "Unknown": {
        "tactic": "Unknown",
        "priority": "Low",
        "actions": [
            "👀 Manual analyst review required.",
            "📝 Capture full PCAP context for the flow.",
            "🧪 Cross-check source IP against threat intelligence feeds.",
        ],
    },
    "Benign": {
        "tactic": "N/A",
        "priority": "Informational",
        "actions": ["✅ No action required."],
    },
}


def recommend_for_threat(attack_type: str, ip: str | None = None,
                         port: int | None = None, proto: str = "tcp") -> Dict:
    """Generate a structured recommendation for a single threat instance."""
    book = PLAYBOOKS.get(attack_type, PLAYBOOKS["Unknown"])
    rec = {
        "attack_type": attack_type,
        "tactic": book["tactic"],
        "priority": book["priority"],
        "actions": list(book["actions"]),
        "commands": {},
    }

    if ip:
        rec["commands"][f"Block IP {ip}"] = _block_ip_cmds(ip, comment=f"AutoBlock: {attack_type}")
        if attack_type in ("Port Scan", "DDoS"):
            rec["commands"][f"Rate-limit {ip}"] = _rate_limit_cmds(ip)
    if port and attack_type == "Port Scan":
        rec["commands"][f"Close port {port}/{proto}"] = _block_port_cmds(port, proto)

    return rec


def build_action_plan(detections: pd.DataFrame, min_severity: str = "Medium",
                      top_n_per_class: int = 5) -> List[Dict]:
    """
    Build a prioritized action plan from a DataFrame of detections.
    Required columns: Predicted, Severity. Optional: src_ip, dst_port, protocol.
    """
    if "Predicted" not in detections.columns:
        return []

    threshold = SEVERITY_RANK.get(min_severity, 2)
    df = detections.copy()
    if "Severity" in df.columns:
        df = df[df["Severity"].map(lambda s: SEVERITY_RANK.get(s, 0) >= threshold)]
    df = df[df["Predicted"] != "Benign"]

    if df.empty:
        return []

    plan: List[Dict] = []
    for attack_type, group in df.groupby("Predicted"):
        # Pick the most-frequent offenders for this class
        if "src_ip" in group.columns:
            top = group["src_ip"].value_counts().head(top_n_per_class)
        else:
            top = pd.Series(dtype=int)

        sample = group.iloc[0]
        port = int(sample.get("dst_port", 0)) if "dst_port" in group.columns else None
        proto_num = sample.get("protocol", 6) if "protocol" in group.columns else 6
        proto = "tcp" if str(proto_num) == "6" else ("udp" if str(proto_num) == "17" else "tcp")

        if not top.empty:
            for ip, hits in top.items():
                rec = recommend_for_threat(attack_type, ip=str(ip), port=port, proto=proto)
                rec["hits"] = int(hits)
                plan.append(rec)
        else:
            plan.append(recommend_for_threat(attack_type, port=port, proto=proto))

    plan.sort(key=lambda r: SEVERITY_RANK.get(r["priority"], 0), reverse=True)
    return plan


def print_plan(plan: List[Dict]) -> None:
    """Pretty-print a plan to stdout (CLI usage)."""
    if not plan:
        print("No high-severity actions required.")
        return

    print(f"\n========== SOC RESPONSE PLAN ({len(plan)} items) ==========\n")
    for i, item in enumerate(plan, 1):
        print(f"[{i}] {item['attack_type']}  |  {item['tactic']}  |  Priority: {item['priority']}")
        if item.get("hits"):
            print(f"    Offender hits: {item['hits']}")
        print("    Recommended actions:")
        for a in item["actions"]:
            print(f"      - {a}")
        if item["commands"]:
            print("    Ready-to-run commands:")
            for label, cmds in item["commands"].items():
                print(f"      ▸ {label}")
                print(f"        {cmds['iptables']}")
        print()


def expand_with_session_detections(df: pd.DataFrame,
                                   port_scan_ports: int = 50,
                                   port_scan_flows: int = 100,
                                   ddos_flows: int = 5000) -> pd.DataFrame:
    """Augment a per-flow predictions DataFrame with session-level attack rows."""
    rows = [df[df["Predicted"] != "Benign"].copy()] if "Predicted" in df.columns else []

    if {"src_ip", "dst_port"}.issubset(df.columns):
        srcs = df.groupby("src_ip").agg(
            total_flows=("dst_port", "size"),
            unique_dst_ports=("dst_port", "nunique"),
        ).reset_index()
        scanners = srcs[(srcs["unique_dst_ports"] >= port_scan_ports) & (srcs["total_flows"] >= port_scan_flows)].copy()
        if not scanners.empty:
            scanners["Predicted"] = "Port Scan"
            scanners["Severity"] = "Medium"
            rows.append(scanners[["src_ip", "Predicted", "Severity"]])

    if {"src_ip", "dst_ip"}.issubset(df.columns):
        tgt_stats = df.groupby("dst_ip").agg(total_flows=("src_ip", "size")).reset_index()
        flooded = tgt_stats[tgt_stats["total_flows"] >= ddos_flows]
        for tgt in flooded["dst_ip"]:
            top_attackers = df[df["dst_ip"] == tgt]["src_ip"].value_counts().head(10).index.tolist()
            rows.append(pd.DataFrame({
                "src_ip": top_attackers,
                "Predicted": "DDoS",
                "Severity": "High",
                "dst_ip": tgt,
            }))

    rows = [r for r in rows if not r.empty]
    return pd.concat(rows, ignore_index=True) if rows else pd.DataFrame()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate SOC response plan from predictions CSV")
    parser.add_argument("results_csv", help="CSV produced by predict_pcap.py --save")
    parser.add_argument("--min-severity", default="Medium", choices=list(SEVERITY_RANK.keys()))
    parser.add_argument("--top", type=int, default=5)
    args = parser.parse_args()

    df = pd.read_csv(args.results_csv)
    unified = expand_with_session_detections(df)
    plan = build_action_plan(unified, min_severity=args.min_severity, top_n_per_class=args.top)
    print_plan(plan)
