"""
Session-level attack detector that complements the per-flow IDS model.

Aggregates flows by source IP to detect:
- Port Scan: one source contacting many destination ports.
- DDoS/Flood: many sources contacting one destination intensively.

Usage:
    .venv/bin/python session_detector.py ./pcap_results.csv
"""

from __future__ import annotations

import argparse
from typing import Dict

import pandas as pd

PORTSCAN_PORT_THRESHOLD = 50    # distinct dst_ports per source -> port scan
PORTSCAN_FLOWS_THRESHOLD = 100  # min flows from a source to consider scanning
DDOS_FLOWS_PER_TARGET = 5000    # flows toward one destination -> DDoS suspect


MITRE = {
    "Port Scan": {"technique": "T1046", "tactic": "Discovery", "severity": "Medium"},
    "DDoS":      {"technique": "T1498", "tactic": "Impact",    "severity": "High"},
    "Benign":    {"technique": "N/A",   "tactic": "N/A",       "severity": "Informational"},
}


def detect_port_scanners(df: pd.DataFrame) -> pd.DataFrame:
    grouped = df.groupby("src_ip").agg(
        total_flows=("dst_port", "size"),
        unique_dst_ports=("dst_port", "nunique"),
        unique_dst_ips=("dst_ip", "nunique"),
    ).reset_index()

    scanners = grouped[
        (grouped["unique_dst_ports"] >= PORTSCAN_PORT_THRESHOLD) &
        (grouped["total_flows"] >= PORTSCAN_FLOWS_THRESHOLD)
    ].copy()

    scanners["Verdict"] = "Port Scan"
    scanners["Technique"] = MITRE["Port Scan"]["technique"]
    scanners["Tactic"] = MITRE["Port Scan"]["tactic"]
    scanners["Severity"] = MITRE["Port Scan"]["severity"]
    return scanners.sort_values("unique_dst_ports", ascending=False)


def detect_ddos_targets(df: pd.DataFrame) -> pd.DataFrame:
    grouped = df.groupby("dst_ip").agg(
        total_flows=("src_ip", "size"),
        unique_src_ips=("src_ip", "nunique"),
    ).reset_index()

    targets = grouped[grouped["total_flows"] >= DDOS_FLOWS_PER_TARGET].copy()
    targets["Verdict"] = "DDoS"
    targets["Technique"] = MITRE["DDoS"]["technique"]
    targets["Tactic"] = MITRE["DDoS"]["tactic"]
    targets["Severity"] = MITRE["DDoS"]["severity"]
    return targets.sort_values("total_flows", ascending=False)


def parse_args():
    p = argparse.ArgumentParser(description="Session-level attack aggregator")
    p.add_argument("results_csv", help="CSV produced by predict_pcap.py --save")
    p.add_argument("--top", type=int, default=20)
    return p.parse_args()


def main():
    args = parse_args()
    df = pd.read_csv(args.results_csv)

    if "src_ip" not in df.columns or "dst_ip" not in df.columns:
        print("ERROR: results CSV is missing src_ip/dst_ip. Re-run predict_pcap.py to regenerate.")
        return

    print(f"Loaded {len(df):,} flows")
    print(f"Unique sources: {df['src_ip'].nunique():,} | Unique destinations: {df['dst_ip'].nunique():,}")

    print("\n========== PORT SCAN DETECTION ==========")
    scanners = detect_port_scanners(df)
    if scanners.empty:
        print("No port scanners detected.")
    else:
        print(f"Detected {len(scanners)} scanner IPs.")
        print(scanners.head(args.top).to_string(index=False))

    print("\n========== DDoS / FLOOD DETECTION ==========")
    targets = detect_ddos_targets(df)
    if targets.empty:
        print("No DDoS targets detected.")
    else:
        print(f"Detected {len(targets)} flooded targets.")
        print(targets.head(args.top).to_string(index=False))

    print("\n========== SUMMARY ==========")
    total_scan_flows = int(df[df["src_ip"].isin(scanners["src_ip"])].shape[0]) if not scanners.empty else 0
    print(f"Flows from scanner IPs: {total_scan_flows:,} ({total_scan_flows/len(df):.1%})")
    print(f"Scanner IPs           : {len(scanners):,}")
    print(f"Flooded targets       : {len(targets):,}")


if __name__ == "__main__":
    main()
