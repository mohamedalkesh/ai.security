"""
Live network IDS monitor.

Captures flows from a network interface in real time using NFStream,
runs them through the trained classifier, applies session-level
correlation, and emits alerts.

Requires CAP_NET_RAW or root:
    sudo .venv/bin/python live_monitor.py --iface wlp0s20f3
"""

from __future__ import annotations

import argparse
import json
import os
import pickle
import signal
import sys
import time
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional

import numpy as np
import pandas as pd

ARTIFACT_DIR = "./model_artifacts"
CONFIDENCE_THRESHOLD = 0.6

# Session detection thresholds (rolling window)
PORTSCAN_PORTS_THRESHOLD = 30
PORTSCAN_FLOWS_THRESHOLD = 50
DDOS_FLOWS_PER_TARGET = 500


def load_artifacts():
    out = {}
    for k in ("model", "label_encoder", "scaler", "feature_names"):
        with open(os.path.join(ARTIFACT_DIR, f"{k}.pkl"), "rb") as f:
            out[k] = pickle.load(f)
    return out["model"], out["label_encoder"], out["scaler"], out["feature_names"]


def nflow_to_cicids_dict(flow) -> Dict:
    """Map a single NFStream flow object to CICIDS-style feature dict."""
    def g(name, default=0):
        return getattr(flow, name, default) or 0

    flow_dur_us = g("bidirectional_duration_ms") * 1000.0
    fwd_dur_us = g("src2dst_duration_ms") * 1000.0
    bwd_dur_us = g("dst2src_duration_ms") * 1000.0

    # Avoid div-by-zero
    safe = lambda n, d: (n / d) if d else 0  # noqa: E731

    return {
        "Flow Duration": flow_dur_us,
        "Total Fwd Packets": g("src2dst_packets"),
        "Total Backward Packets": g("dst2src_packets"),
        "Total Length of Fwd Packets": g("src2dst_bytes"),
        "Total Length of Bwd Packets": g("dst2src_bytes"),
        "Fwd Packet Length Max": g("src2dst_max_ps"),
        "Fwd Packet Length Min": g("src2dst_min_ps"),
        "Fwd Packet Length Mean": g("src2dst_mean_ps"),
        "Fwd Packet Length Std": g("src2dst_stddev_ps"),
        "Bwd Packet Length Max": g("dst2src_max_ps"),
        "Bwd Packet Length Min": g("dst2src_min_ps"),
        "Bwd Packet Length Mean": g("dst2src_mean_ps"),
        "Bwd Packet Length Std": g("dst2src_stddev_ps"),
        "Flow Bytes/s": safe(g("bidirectional_bytes"), g("bidirectional_duration_ms") / 1000.0),
        "Flow Packets/s": safe(g("bidirectional_packets"), g("bidirectional_duration_ms") / 1000.0),
        "Flow IAT Mean": g("bidirectional_mean_piat_ms") * 1000.0,
        "Flow IAT Std": g("bidirectional_stddev_piat_ms") * 1000.0,
        "Flow IAT Max": g("bidirectional_max_piat_ms") * 1000.0,
        "Flow IAT Min": g("bidirectional_min_piat_ms") * 1000.0,
        "Fwd IAT Total": fwd_dur_us,
        "Fwd IAT Mean": g("src2dst_mean_piat_ms") * 1000.0,
        "Fwd IAT Std": g("src2dst_stddev_piat_ms") * 1000.0,
        "Fwd IAT Max": g("src2dst_max_piat_ms") * 1000.0,
        "Fwd IAT Min": g("src2dst_min_piat_ms") * 1000.0,
        "Bwd IAT Total": bwd_dur_us,
        "Bwd IAT Mean": g("dst2src_mean_piat_ms") * 1000.0,
        "Bwd IAT Std": g("dst2src_stddev_piat_ms") * 1000.0,
        "Bwd IAT Max": g("dst2src_max_piat_ms") * 1000.0,
        "Bwd IAT Min": g("dst2src_min_piat_ms") * 1000.0,
        "Fwd PSH Flags": g("src2dst_psh_packets"),
        "Bwd PSH Flags": g("dst2src_psh_packets"),
        "Fwd URG Flags": g("src2dst_urg_packets"),
        "Bwd URG Flags": g("dst2src_urg_packets"),
        "Fwd Header Length": g("src2dst_packets") * 40,
        "Bwd Header Length": g("dst2src_packets") * 40,
        "Fwd Header Length.1": g("src2dst_packets") * 40,
        "Fwd Packets/s": safe(g("src2dst_packets"), g("src2dst_duration_ms") / 1000.0),
        "Bwd Packets/s": safe(g("dst2src_packets"), g("dst2src_duration_ms") / 1000.0),
        "Min Packet Length": g("bidirectional_min_ps"),
        "Max Packet Length": g("bidirectional_max_ps"),
        "Packet Length Mean": g("bidirectional_mean_ps"),
        "Packet Length Std": g("bidirectional_stddev_ps"),
        "Packet Length Variance": g("bidirectional_stddev_ps") ** 2,
        "FIN Flag Count": g("bidirectional_fin_packets"),
        "SYN Flag Count": g("bidirectional_syn_packets"),
        "RST Flag Count": g("bidirectional_rst_packets"),
        "PSH Flag Count": g("bidirectional_psh_packets"),
        "ACK Flag Count": g("bidirectional_ack_packets"),
        "URG Flag Count": g("bidirectional_urg_packets"),
        "CWE Flag Count": g("bidirectional_cwr_packets"),
        "ECE Flag Count": g("bidirectional_ece_packets"),
        "Down/Up Ratio": safe(g("dst2src_packets"), g("src2dst_packets")),
        "Average Packet Size": g("bidirectional_mean_ps"),
        "Avg Fwd Segment Size": g("src2dst_mean_ps"),
        "Avg Bwd Segment Size": g("dst2src_mean_ps"),
        "Fwd Avg Bytes/Bulk": 0,
        "Fwd Avg Packets/Bulk": 0,
        "Fwd Avg Bulk Rate": 0,
        "Bwd Avg Bytes/Bulk": 0,
        "Bwd Avg Packets/Bulk": 0,
        "Bwd Avg Bulk Rate": 0,
        "Subflow Fwd Packets": g("src2dst_packets"),
        "Subflow Fwd Bytes": g("src2dst_bytes"),
        "Subflow Bwd Packets": g("dst2src_packets"),
        "Subflow Bwd Bytes": g("dst2src_bytes"),
        "Init_Win_bytes_forward": 0,
        "Init_Win_bytes_backward": 0,
        "act_data_pkt_fwd": g("src2dst_packets"),
        "min_seg_size_forward": g("src2dst_min_ps"),
        "Active Mean": 0, "Active Std": 0, "Active Max": 0, "Active Min": 0,
        "Idle Mean": 0, "Idle Std": 0, "Idle Max": 0, "Idle Min": 0,
    }


# ANSI colors
class C:
    RESET = "\033[0m"
    DIM = "\033[2m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"


SEVERITY_COLOR = {
    "Benign": C.GREEN,
    "Port Scan": C.YELLOW,
    "DDoS": C.RED,
    "Brute Force": C.RED,
    "Unknown": C.CYAN,
}


class LiveMonitor:
    def __init__(self, iface: str, log_path: Optional[str] = None,
                 quiet: bool = False, alert_only: bool = False):
        self.iface = iface
        self.log_path = log_path
        self.quiet = quiet
        self.alert_only = alert_only
        self.model, self.label_encoder, self.scaler, self.feature_names = load_artifacts()

        # Rolling stats per source/destination IP for session correlation
        self.src_stats: Dict[str, Dict] = defaultdict(lambda: {"flows": 0, "ports": set(), "first": None})
        self.dst_stats: Dict[str, Dict] = defaultdict(lambda: {"flows": 0, "sources": set()})
        self.alerted_sources = set()
        self.alerted_targets = set()

        self.total_flows = 0
        self.total_attacks = 0
        self.start_time = time.time()
        self.log_file = open(log_path, "a") if log_path else None

    # ------------------------------------------------------------------
    def _classify(self, feat_dict: Dict) -> tuple[str, float]:
        row = [feat_dict.get(f, 0) for f in self.feature_names]
        X = np.array([row], dtype=float)
        Xs = self.scaler.transform(X)
        proba = self.model.predict_proba(Xs)[0]
        idx = int(np.argmax(proba))
        conf = float(proba[idx])
        cls = self.label_encoder.inverse_transform([idx])[0]
        if conf < CONFIDENCE_THRESHOLD:
            cls = "Unknown"
        return cls, conf

    # ------------------------------------------------------------------
    def _update_session_state(self, flow, predicted: str) -> List[str]:
        """Return list of new session-level alerts to emit."""
        alerts: List[str] = []
        src = getattr(flow, "src_ip", None)
        dst = getattr(flow, "dst_ip", None)
        port = getattr(flow, "dst_port", 0)
        if not src:
            return alerts

        s = self.src_stats[src]
        s["flows"] += 1
        s["ports"].add(port)
        if s["first"] is None:
            s["first"] = time.time()

        if (
            len(s["ports"]) >= PORTSCAN_PORTS_THRESHOLD
            and s["flows"] >= PORTSCAN_FLOWS_THRESHOLD
            and src not in self.alerted_sources
        ):
            alerts.append(
                f"{C.RED}[SESSION ALERT]{C.RESET} 🎯 Port-Scan from {C.BOLD}{src}{C.RESET} "
                f"-> {len(s['ports'])} distinct ports / {s['flows']} flows"
            )
            self.alerted_sources.add(src)

        if dst:
            t = self.dst_stats[dst]
            t["flows"] += 1
            t["sources"].add(src)
            if (
                t["flows"] >= DDOS_FLOWS_PER_TARGET
                and len(t["sources"]) >= 50
                and dst not in self.alerted_targets
            ):
                alerts.append(
                    f"{C.RED}[SESSION ALERT]{C.RESET} 💥 Possible DDoS toward {C.BOLD}{dst}{C.RESET} "
                    f"-> {t['flows']} flows from {len(t['sources'])} sources"
                )
                self.alerted_targets.add(dst)
        return alerts

    # ------------------------------------------------------------------
    def _print_flow(self, flow, predicted: str, conf: float):
        color = SEVERITY_COLOR.get(predicted, C.RESET)
        ts = datetime.now().strftime("%H:%M:%S")
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(getattr(flow, "protocol", 0), "?")
        line = (
            f"{C.DIM}{ts}{C.RESET}  "
            f"{color}{predicted:10s}{C.RESET} "
            f"{conf:5.2f}  "
            f"{proto_name:4s}  "
            f"{getattr(flow, 'src_ip', '-'):>15s}:{getattr(flow, 'src_port', 0):<5d} "
            f"-> {getattr(flow, 'dst_ip', '-'):>15s}:{getattr(flow, 'dst_port', 0):<5d}  "
            f"{getattr(flow, 'bidirectional_packets', 0)}pkt"
        )
        print(line)

    # ------------------------------------------------------------------
    def _log_json(self, flow, predicted: str, conf: float):
        if not self.log_file:
            return
        entry = {
            "ts": datetime.now().isoformat(timespec="seconds"),
            "src_ip": getattr(flow, "src_ip", None),
            "dst_ip": getattr(flow, "dst_ip", None),
            "src_port": getattr(flow, "src_port", None),
            "dst_port": getattr(flow, "dst_port", None),
            "protocol": getattr(flow, "protocol", None),
            "packets": getattr(flow, "bidirectional_packets", None),
            "bytes": getattr(flow, "bidirectional_bytes", None),
            "predicted": predicted,
            "confidence": round(conf, 4),
        }
        self.log_file.write(json.dumps(entry) + "\n")
        self.log_file.flush()

    # ------------------------------------------------------------------
    def _print_status(self):
        elapsed = time.time() - self.start_time
        rate = self.total_flows / elapsed if elapsed else 0
        print(
            f"{C.DIM}--- {self.total_flows} flows | "
            f"{self.total_attacks} attacks | "
            f"{rate:.1f} flows/s | "
            f"scanners={len(self.alerted_sources)} | "
            f"ddos_targets={len(self.alerted_targets)} ---{C.RESET}"
        )

    # ------------------------------------------------------------------
    def run(self):
        from nfstream import NFStreamer

        print(f"{C.BOLD}{C.CYAN}🛡️  Live IDS Monitor{C.RESET}")
        print(f"Interface : {C.BOLD}{self.iface}{C.RESET}")
        print(f"Model     : {type(self.model).__name__}  ({len(self.label_encoder.classes_)} classes)")
        print(f"Log file  : {self.log_path or 'disabled'}")
        print(f"{C.DIM}Press Ctrl+C to stop{C.RESET}\n")
        header = f"{'time':8s}  {'pred':10s} {'conf':5s}  {'proto':4s}  {'src':>15s}:{'sp':<5s} -> {'dst':>15s}:{'dp':<5s}"
        print(C.BOLD + header + C.RESET)

        signal.signal(signal.SIGINT, self._stop)

        streamer = NFStreamer(
            source=self.iface,
            statistical_analysis=True,
            n_dissections=0,
            accounting_mode=0,
            idle_timeout=15,
            active_timeout=60,
        )

        last_status = time.time()
        try:
            for flow in streamer:
                self.total_flows += 1
                feat = nflow_to_cicids_dict(flow)
                predicted, conf = self._classify(feat)
                if predicted != "Benign":
                    self.total_attacks += 1

                if not self.quiet and (not self.alert_only or predicted != "Benign"):
                    self._print_flow(flow, predicted, conf)

                self._log_json(flow, predicted, conf)

                for alert in self._update_session_state(flow, predicted):
                    print(alert)

                if time.time() - last_status > 10:
                    self._print_status()
                    last_status = time.time()
        except KeyboardInterrupt:
            self._stop()

    # ------------------------------------------------------------------
    def _stop(self, *_):
        print(f"\n{C.BOLD}{C.CYAN}=== Final Report ==={C.RESET}")
        self._print_status()
        if self.log_file:
            self.log_file.close()
        sys.exit(0)


def parse_args():
    p = argparse.ArgumentParser(description="Live IDS network monitor (NFStream + XGBoost)")
    p.add_argument("--iface", required=True, help="Network interface (e.g. wlp0s20f3, eth0)")
    p.add_argument("--log", default=None, help="Path to JSONL alert log file")
    p.add_argument("--alert-only", action="store_true", help="Print only non-Benign flows")
    p.add_argument("--quiet", action="store_true", help="Suppress per-flow output, keep session alerts")
    return p.parse_args()


def main():
    args = parse_args()
    LiveMonitor(args.iface, log_path=args.log, quiet=args.quiet, alert_only=args.alert_only).run()


if __name__ == "__main__":
    main()
