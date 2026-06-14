"""
Convert PCAP -> CICIDS2017-style flow features expected by the model.

Backend: NFStream (libpcap + nDPI in C, much faster than scapy-based parsers).
Output columns are renamed/derived to match CICIDS2017 feature names so
the existing XGBoost model can consume them directly.
"""

from __future__ import annotations

import json
import os
import tempfile
import warnings
from typing import List, Optional

import numpy as np
import pandas as pd


def _safe_div(num, den):
    den = den.replace(0, np.nan)
    return (num / den).fillna(0)


def _resolve_worker_threads(requested: Optional[int] = None) -> int:
    """Pick an NFStream worker-thread count.

    Priority order:
        1. Explicit ``requested`` value passed to ``pcap_to_dataframe``.
        2. Environment variable ``NFSTREAM_THREADS``.
        3. Auto: CPU count (clamped to >=1).
    """

    candidates = [requested]
    env_val = os.environ.get("NFSTREAM_THREADS")
    if env_val:
        try:
            candidates.append(int(env_val))
        except ValueError:
            warnings.warn("NFSTREAM_THREADS env var is not an integer; ignoring.")
    for value in candidates:
        if value is None:
            continue
        if value > 0:
            return value
    cpu = os.cpu_count() or 1
    return max(1, cpu)


def _nfstream_to_cicids(nf: pd.DataFrame) -> pd.DataFrame:
    """Map NFStream bidirectional flow stats to CICIDS2017 feature names."""
    df = pd.DataFrame()

    # CICIDS Flow Duration is in microseconds; NFStream returns milliseconds
    flow_dur_us = nf["bidirectional_duration_ms"] * 1000.0
    fwd_dur_us = nf["src2dst_duration_ms"] * 1000.0
    bwd_dur_us = nf["dst2src_duration_ms"] * 1000.0

    df["Flow Duration"] = flow_dur_us
    df["Total Fwd Packets"] = nf["src2dst_packets"]
    df["Total Backward Packets"] = nf["dst2src_packets"]
    df["Total Length of Fwd Packets"] = nf["src2dst_bytes"]
    df["Total Length of Bwd Packets"] = nf["dst2src_bytes"]

    df["Fwd Packet Length Max"] = nf["src2dst_max_ps"]
    df["Fwd Packet Length Min"] = nf["src2dst_min_ps"]
    df["Fwd Packet Length Mean"] = nf["src2dst_mean_ps"]
    df["Fwd Packet Length Std"] = nf["src2dst_stddev_ps"]
    df["Bwd Packet Length Max"] = nf["dst2src_max_ps"]
    df["Bwd Packet Length Min"] = nf["dst2src_min_ps"]
    df["Bwd Packet Length Mean"] = nf["dst2src_mean_ps"]
    df["Bwd Packet Length Std"] = nf["dst2src_stddev_ps"]

    df["Flow Bytes/s"] = _safe_div(nf["bidirectional_bytes"], nf["bidirectional_duration_ms"] / 1000.0)
    df["Flow Packets/s"] = _safe_div(nf["bidirectional_packets"], nf["bidirectional_duration_ms"] / 1000.0)

    # IAT in microseconds
    df["Flow IAT Mean"] = nf["bidirectional_mean_piat_ms"] * 1000.0
    df["Flow IAT Std"] = nf["bidirectional_stddev_piat_ms"] * 1000.0
    df["Flow IAT Max"] = nf["bidirectional_max_piat_ms"] * 1000.0
    df["Flow IAT Min"] = nf["bidirectional_min_piat_ms"] * 1000.0

    df["Fwd IAT Total"] = fwd_dur_us
    df["Fwd IAT Mean"] = nf["src2dst_mean_piat_ms"] * 1000.0
    df["Fwd IAT Std"] = nf["src2dst_stddev_piat_ms"] * 1000.0
    df["Fwd IAT Max"] = nf["src2dst_max_piat_ms"] * 1000.0
    df["Fwd IAT Min"] = nf["src2dst_min_piat_ms"] * 1000.0

    df["Bwd IAT Total"] = bwd_dur_us
    df["Bwd IAT Mean"] = nf["dst2src_mean_piat_ms"] * 1000.0
    df["Bwd IAT Std"] = nf["dst2src_stddev_piat_ms"] * 1000.0
    df["Bwd IAT Max"] = nf["dst2src_max_piat_ms"] * 1000.0
    df["Bwd IAT Min"] = nf["dst2src_min_piat_ms"] * 1000.0

    df["Fwd PSH Flags"] = nf["src2dst_psh_packets"]
    df["Bwd PSH Flags"] = nf["dst2src_psh_packets"]
    df["Fwd URG Flags"] = nf["src2dst_urg_packets"]
    df["Bwd URG Flags"] = nf["dst2src_urg_packets"]

    # Approximate: typical TCP/IP header is 40 bytes per packet
    df["Fwd Header Length"] = nf["src2dst_packets"] * 40
    df["Bwd Header Length"] = nf["dst2src_packets"] * 40
    df["Fwd Header Length.1"] = df["Fwd Header Length"]

    df["Fwd Packets/s"] = _safe_div(nf["src2dst_packets"], nf["src2dst_duration_ms"] / 1000.0)
    df["Bwd Packets/s"] = _safe_div(nf["dst2src_packets"], nf["dst2src_duration_ms"] / 1000.0)

    df["Min Packet Length"] = nf["bidirectional_min_ps"]
    df["Max Packet Length"] = nf["bidirectional_max_ps"]
    df["Packet Length Mean"] = nf["bidirectional_mean_ps"]
    df["Packet Length Std"] = nf["bidirectional_stddev_ps"]
    df["Packet Length Variance"] = nf["bidirectional_stddev_ps"] ** 2

    df["FIN Flag Count"] = nf["bidirectional_fin_packets"]
    df["SYN Flag Count"] = nf["bidirectional_syn_packets"]
    df["RST Flag Count"] = nf["bidirectional_rst_packets"]
    df["PSH Flag Count"] = nf["bidirectional_psh_packets"]
    df["ACK Flag Count"] = nf["bidirectional_ack_packets"]
    df["URG Flag Count"] = nf["bidirectional_urg_packets"]
    df["CWE Flag Count"] = nf["bidirectional_cwr_packets"]
    df["ECE Flag Count"] = nf["bidirectional_ece_packets"]

    df["Down/Up Ratio"] = _safe_div(nf["dst2src_packets"], nf["src2dst_packets"])
    df["Average Packet Size"] = nf["bidirectional_mean_ps"]
    df["Avg Fwd Segment Size"] = nf["src2dst_mean_ps"]
    df["Avg Bwd Segment Size"] = nf["dst2src_mean_ps"]

    # Bulk transfer features (NFStream doesn't expose these) -> 0
    for col in ["Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
                "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate"]:
        df[col] = 0

    # Subflow approximated to whole flow (single subflow)
    df["Subflow Fwd Packets"] = nf["src2dst_packets"]
    df["Subflow Fwd Bytes"] = nf["src2dst_bytes"]
    df["Subflow Bwd Packets"] = nf["dst2src_packets"]
    df["Subflow Bwd Bytes"] = nf["dst2src_bytes"]

    df["Init_Win_bytes_forward"] = 0
    df["Init_Win_bytes_backward"] = 0
    df["act_data_pkt_fwd"] = nf["src2dst_packets"]
    df["min_seg_size_forward"] = nf["src2dst_min_ps"]

    # Active/Idle stats not directly available
    for col in ["Active Mean", "Active Std", "Active Max", "Active Min",
                "Idle Mean", "Idle Std", "Idle Max", "Idle Min"]:
        df[col] = 0

    # Carry flow metadata for downstream session detection
    for meta in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol"):
        if meta in nf.columns:
            df[meta] = nf[meta].values

    # Preserve heuristic label coming from _aggregate_scan_flows (if any).
    # Clean numeric columns only so string metadata like src_ip survives.
    df = df.replace([np.inf, -np.inf], np.nan)
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    if len(numeric_cols) > 0:
        df[numeric_cols] = df[numeric_cols].fillna(0)
    missing_cols = [c for c in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol") if c in nf.columns and c in df.columns]
    for col in missing_cols:
        df[col] = nf[col].values
    df = df.fillna("")
    if "_synthetic_label" in nf.columns:
        df["_synthetic_label"] = nf["_synthetic_label"].values
    return df


def _aggregate_scan_flows(nf: pd.DataFrame) -> pd.DataFrame:
    """Collapse scan / flood bursts into representative flows.

    CICIDS2017 — the model's training set — contains no per-packet textbook
    floods or port-scan probes. Real-world attack PCAPs, however, almost
    always look like that to NFStream:

      * **TCP SYN flood**, **UDP flood**, **ICMP flood** → thousands of
        one-packet, no-response flows converging on the same destination.
      * **Nmap port scan** → many tiny (1-2 packet) flows from one source
        hitting many destination ports on the same target.

    Neither shape resembles anything in the training distribution, so the
    model defaults to ``Benign`` on every individual probe. To recover the
    correct verdict we group these probes into synthetic flows tagged with
    a heuristic label (``DDoS`` or ``Port Scan``), and the ML service
    short-circuits to that label instead of consulting the classifier.

    Threshold defaults are deliberately small so even modest captures (a
    few seconds of attack traffic) are recognised.
    """
    if nf.empty:
        return nf

    # A "single-packet probe" is any flow with one packet and no response —
    # protocol-agnostic on purpose so UDP / ICMP floods are caught the same
    # way as SYN floods.
    is_flood_probe = (
        (nf["bidirectional_packets"] == 1)
        & (nf["dst2src_packets"] == 0)
    )
    # A "scan probe" is a tiny bidirectional exchange (≤4 packets) that
    # didn't progress past the handshake — matches nmap SS/ST/SF/SX/SU
    # patterns where the target sends a single RST/SYN-ACK back.
    is_scan_probe = (
        (nf["bidirectional_packets"] <= 4)
        & (nf["src2dst_packets"] <= 2)
        & (nf["dst2src_packets"] <= 2)
    ) & ~is_flood_probe

    # ICMP carries no ports, so a ping sweep/flood is invisible to the
    # port-diversity heuristic below. Detect it directly off the L4 protocol
    # number (1 = ICMP, 58 = ICMPv6) which NFStream exposes as ``protocol``.
    if "protocol" in nf.columns:
        proto_num = pd.to_numeric(nf["protocol"], errors="coerce")
        is_icmp = proto_num.isin([1, 58])
    else:
        is_icmp = pd.Series(False, index=nf.index)
    has_icmp = bool(is_icmp.any())

    AGG_THRESHOLD = 5       # min probes per group before we consider it a burst
    ICMP_SWEEP_HOSTS = 5    # distinct hosts one source must ping to be a sweep
    ICMP_FLOOD_PKTS = 50    # packets in a single ICMP flow that mark a flood
    aggregated_rows: list[pd.Series] = []
    consumed_idx: set[int] = set()
    inplace_labels: dict[int, str] = {}  # idx -> label, kept (not aggregated)

    def _agg(group: pd.DataFrame) -> dict:
        """Build a single representative flow row from N single-packet probes."""
        n = len(group)
        first_ms = group["bidirectional_first_seen_ms"].min()
        last_ms = group["bidirectional_first_seen_ms"].max()
        dur_ms = max(last_ms - first_ms, 1)  # avoid /0 — at least 1 ms
        total_bytes = int(group["bidirectional_bytes"].sum())
        sizes = group["bidirectional_bytes"].astype(float)

        row = {col: 0 for col in nf.columns}
        # Identity columns: use the *most common* tuple values from the burst.
        for col in ("src_ip", "src_port", "dst_ip", "dst_port", "protocol",
                    "ip_version", "vlan_id", "tunnel_id"):
            if col in group.columns and not group[col].empty:
                try:
                    row[col] = group[col].mode().iloc[0]
                except Exception:
                    row[col] = group[col].iloc[0]

        row["bidirectional_packets"] = n
        row["src2dst_packets"] = n
        row["dst2src_packets"] = 0
        row["bidirectional_bytes"] = total_bytes
        row["src2dst_bytes"] = total_bytes
        row["dst2src_bytes"] = 0
        row["bidirectional_first_seen_ms"] = first_ms
        row["bidirectional_last_seen_ms"] = last_ms
        row["bidirectional_duration_ms"] = dur_ms
        row["src2dst_first_seen_ms"] = first_ms
        row["src2dst_last_seen_ms"] = last_ms
        row["src2dst_duration_ms"] = dur_ms

        if "src_ip" in group.columns:
            try:
                counts = group["src_ip"].fillna("?").astype(str).value_counts()
                if not counts.empty:
                    top = counts.head(10).to_dict()
                    row["_source_breakdown"] = json.dumps(top)
                    row["_unique_sources"] = int(counts.size)
            except Exception:
                row["_source_breakdown"] = json.dumps({})
        if "dst_ip" in group.columns:
            try:
                dcounts = group["dst_ip"].fillna("?").astype(str).value_counts()
                if not dcounts.empty:
                    row["_dest_breakdown"] = json.dumps(dcounts.head(10).to_dict())
                    row["_unique_dests"] = int(dcounts.size)
            except Exception:
                row["_dest_breakdown"] = json.dumps({})

        # Flag aggregates (sum across all probes — every one had SYN=1)
        for col in ("bidirectional_syn_packets", "src2dst_syn_packets"):
            if col in nf.columns:
                row[col] = int(group[col].sum())

        # Packet-size statistics
        row["bidirectional_min_ps"] = int(sizes.min())
        row["bidirectional_max_ps"] = int(sizes.max())
        row["bidirectional_mean_ps"] = float(sizes.mean())
        row["bidirectional_stddev_ps"] = float(sizes.std(ddof=0)) if n > 1 else 0.0
        row["src2dst_min_ps"] = row["bidirectional_min_ps"]
        row["src2dst_max_ps"] = row["bidirectional_max_ps"]
        row["src2dst_mean_ps"] = row["bidirectional_mean_ps"]
        row["src2dst_stddev_ps"] = row["bidirectional_stddev_ps"]

        # Inter-arrival times (ms) — derived from per-probe timestamps
        if n > 1:
            ts = group["bidirectional_first_seen_ms"].sort_values().values
            iats = ts[1:] - ts[:-1]
            row["bidirectional_mean_piat_ms"] = float(iats.mean())
            row["bidirectional_stddev_piat_ms"] = float(iats.std(ddof=0))
            row["bidirectional_min_piat_ms"] = float(iats.min())
            row["bidirectional_max_piat_ms"] = float(iats.max())
            row["src2dst_mean_piat_ms"] = row["bidirectional_mean_piat_ms"]
            row["src2dst_stddev_piat_ms"] = row["bidirectional_stddev_piat_ms"]
            row["src2dst_min_piat_ms"] = row["bidirectional_min_piat_ms"]
            row["src2dst_max_piat_ms"] = row["bidirectional_max_piat_ms"]
        return row

    # ===== ICMP-specific detection (runs before the TCP/UDP passes) =======
    # CICIDS2017 has no ICMP attacks and the model never sees the L4 protocol
    # number, so ping floods / sweeps would otherwise fall through to
    # "Benign". Surface them with dedicated heuristic labels here so an ICMP
    # burst is never mislabelled as a plain DDoS in the generic passes.
    if has_icmp:
        # Pass A - high-rate single-flow ICMP flood (ping -f, hping3 --flood).
        # NFStream collapses same-(src,dst,proto) ICMP into one fat flow, so a
        # real flood shows up as a single row with a large packet count rather
        # than thousands of probes. Tag it in place to preserve its real
        # bidirectional features (the ML short-circuit forces the label).
        icmp_big = nf[is_icmp & (nf["bidirectional_packets"] >= ICMP_FLOOD_PKTS)]
        for idx in icmp_big.index:
            inplace_labels[idx] = "ICMP Flood"

        # Probe-shaped ICMP (echo request +/- reply) - sweep/flood candidates.
        icmp_probes = nf[is_icmp & (is_flood_probe | is_scan_probe)]
        icmp_probes = icmp_probes.drop(index=list(inplace_labels), errors="ignore")

        # Pass B - ping sweep: one source touching many distinct hosts.
        if not icmp_probes.empty:
            for src_ip, group in icmp_probes.groupby("src_ip"):
                if group["dst_ip"].nunique() >= ICMP_SWEEP_HOSTS:
                    row = _agg(group)
                    row["_synthetic_label"] = "ICMP Sweep"
                    aggregated_rows.append(row)
                    consumed_idx.update(group.index.tolist())

        # Pass C - distributed / smurf-style flood: many single-packet ICMP
        # probes converging on one destination.
        icmp_left = icmp_probes.drop(index=list(consumed_idx), errors="ignore")
        if not icmp_left.empty:
            for dst_ip, group in icmp_left.groupby("dst_ip"):
                if len(group) >= AGG_THRESHOLD:
                    row = _agg(group)
                    row["_synthetic_label"] = "ICMP Flood"
                    aggregated_rows.append(row)
                    consumed_idx.update(group.index.tolist())

    flood_probes = nf[is_flood_probe].drop(index=list(consumed_idx), errors="ignore")
    scan_probes = nf[is_scan_probe].drop(index=list(consumed_idx), errors="ignore")
    all_probes = pd.concat([flood_probes, scan_probes])

    # ----- Pass 1: port scans — one src hitting many dst_ports on one dst.
    # Detect this first so a UDP/SYN scan isn't mistakenly merged into a
    # flood bucket in Pass 2. Threshold uses port diversity, not raw count.
    if not all_probes.empty:
        for (src_ip, dst_ip), group in all_probes.groupby(["src_ip", "dst_ip"]):
            if group["dst_port"].nunique() >= AGG_THRESHOLD * 2:
                row = _agg(group)
                row["_synthetic_label"] = "Port Scan"
                aggregated_rows.append(row)
                consumed_idx.update(group.index.tolist())

    # ----- Pass 2: floods — many single-packet probes to the same dst_ip.
    # Amplification attacks reach the victim on many random source-derived
    # ports, so we *cannot* require dst_port equality here; grouping by
    # dst_ip alone is what surfaces them as DDoS.
    remaining = flood_probes.drop(index=list(consumed_idx), errors="ignore")
    if not remaining.empty:
        for dst_ip, group in remaining.groupby("dst_ip"):
            if len(group) >= AGG_THRESHOLD:
                row = _agg(group)
                src_count = group["src_ip"].nunique() if "src_ip" in group.columns else 0
                if src_count > 1:
                    row["src_ip"] = "MULTIPLE"
                    row["_synthetic_label"] = "DDoS"
                else:
                    row["_synthetic_label"] = "DoS"
                aggregated_rows.append(row)
                consumed_idx.update(group.index.tolist())

    # Anything that wasn't aggregated is dropped — leaving thousands of
    # 1-packet OOD rows in the output would re-introduce the very failure
    # mode this function exists to prevent (all-Benign predictions).
    untouched = nf.drop(index=list(consumed_idx), errors="ignore")
    # Drop straggler probes that didn't meet either threshold.
    untouched = untouched[~(untouched.index.isin(flood_probes.index)
                            | untouched.index.isin(scan_probes.index))
                          | (untouched["bidirectional_packets"] > 1)]

    # Tag in-place ICMP floods (kept as real flows, not aggregated probes).
    untouched = untouched.copy()
    if "_synthetic_label" not in untouched.columns:
        untouched["_synthetic_label"] = ""
    for idx, lbl in inplace_labels.items():
        if idx in untouched.index:
            untouched.loc[idx, "_synthetic_label"] = lbl

    extra_cols = list(nf.columns) + ["_synthetic_label"]
    parts = [untouched]
    if aggregated_rows:
        parts.append(pd.DataFrame(aggregated_rows, columns=extra_cols))
    return pd.concat(parts, ignore_index=True)


def pcap_to_dataframe(
    pcap_path: str,
    expected_features: List[str],
    max_flows: int | None = None,
    worker_threads: int | None = None,
) -> pd.DataFrame:
    """Convert a PCAP into a DataFrame aligned with the model's feature columns.

    If max_flows is set, NFStream stops after producing N flows (quick preview).
    """
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    from nfstream import NFStreamer

    threads = _resolve_worker_threads(worker_threads)
    streamer_kwargs = dict(
        source=pcap_path,
        statistical_analysis=True,
        n_dissections=0,            # disable DPI for speed
        accounting_mode=0,          # link-layer accounting disabled
    )
    if threads > 1:
        streamer_kwargs["number_of_threads"] = threads
    try:
        streamer = NFStreamer(**streamer_kwargs)
    except TypeError as exc:
        # Older NFStream releases may not accept number_of_threads.
        if "number_of_threads" in str(exc):
            warnings.warn(
                "NFStreamer version does not support number_of_threads — falling back to single thread."
            )
            streamer_kwargs.pop("number_of_threads", None)
            streamer = NFStreamer(**streamer_kwargs)
        else:
            raise

    if max_flows is None or max_flows <= 0:
        nf_df = streamer.to_pandas()
    else:
        rows = []
        attr_names = None
        for i, flow in enumerate(streamer):
            if i >= max_flows:
                break
            if attr_names is None:
                attr_names = [
                    k for k in dir(flow)
                    if not k.startswith("_") and not callable(getattr(flow, k, None))
                ]
            row = {}
            for k in attr_names:
                try:
                    row[k] = getattr(flow, k)
                except AttributeError:
                    row[k] = None
            rows.append(row)
        nf_df = pd.DataFrame(rows)

    if nf_df.empty:
        raise RuntimeError("NFStream produced no flows. PCAP may be empty or malformed.")

    # Collapse single-packet SYN bursts (floods / scans) before feature
    # mapping so the model sees them as multi-packet flows comparable to
    # what CICIDS2017 contains.
    nf_df = _aggregate_scan_flows(nf_df)

    df = _nfstream_to_cicids(nf_df)

    # Ensure every expected feature exists
    for col in expected_features:
        if col not in df.columns:
            df[col] = 0

    return df


def main():
    import argparse
    import pickle

    parser = argparse.ArgumentParser(description="Convert PCAP to CICIDS-style features CSV")
    parser.add_argument("pcap", help="Path to .pcap file")
    parser.add_argument("--out", default="./pcap_flows.csv", help="Output CSV path")
    parser.add_argument("--max-flows", type=int, default=None, help="Limit flows for fast preview")
    parser.add_argument("--feature-names", default="./model_artifacts/feature_names.pkl")
    args = parser.parse_args()

    with open(args.feature_names, "rb") as f:
        features = pickle.load(f)

    df = pcap_to_dataframe(args.pcap, features, max_flows=args.max_flows)
    df.to_csv(args.out, index=False)
    print(f"Saved {len(df)} flows -> {args.out}")


if __name__ == "__main__":
    main()
