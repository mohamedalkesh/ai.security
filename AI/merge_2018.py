"""
Merge CSE-CIC-IDS-2018 v2 (~3.15M rows, 16 attack labels) into the
canonical v3 schema (combine_v3.csv) to produce combine_v4.csv.

The 2018 CSV uses CICFlowMeter snake_case column names (e.g. ``ACK_Flag_Cnt``,
``Bwd_Pkt_Len_Max``). The v3 corpus uses the Title-Case names CICFlowMeter V3
emits (``ACK Flag Count``, ``Bwd Packet Length Max``). We hand-map the 78
features to keep semantics exact — there is no field where the two datasets
report subtly different quantities under the same name.

Labels are also normalised here so the training pipeline can treat them
identically regardless of source (e.g. ``DDOS attack-HOIC`` and
``DDOS attack-LOIC-UDP`` both collapse to ``DDoS``).
"""

from __future__ import annotations

import logging
import os
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# 2018 (snake_case) → v3 (Title Case) feature mapping.
COL_MAP: dict[str, str] = {
    "Dst_Port": "Destination Port",
    "Protocol": "Protocol",  # not in v3, will be dropped at align step
    "Flow_Duration": "Flow Duration",
    "Tot_Fwd_Pkts": "Total Fwd Packets",
    "Tot_Bwd_Pkts": "Total Backward Packets",
    "TotLen_Fwd_Pkts": "Total Length of Fwd Packets",
    "TotLen_Bwd_Pkts": "Total Length of Bwd Packets",
    "Fwd_Pkt_Len_Max": "Fwd Packet Length Max",
    "Fwd_Pkt_Len_Min": "Fwd Packet Length Min",
    "Fwd_Pkt_Len_Mean": "Fwd Packet Length Mean",
    "Fwd_Pkt_Len_Std": "Fwd Packet Length Std",
    "Bwd_Pkt_Len_Max": "Bwd Packet Length Max",
    "Bwd_Pkt_Len_Min": "Bwd Packet Length Min",
    "Bwd_Pkt_Len_Mean": "Bwd Packet Length Mean",
    "Bwd_Pkt_Len_Std": "Bwd Packet Length Std",
    "Flow_Byts/s": "Flow Bytes/s",
    "Flow_Pkts/s": "Flow Packets/s",
    "Flow_IAT_Mean": "Flow IAT Mean",
    "Flow_IAT_Std": "Flow IAT Std",
    "Flow_IAT_Max": "Flow IAT Max",
    "Flow_IAT_Min": "Flow IAT Min",
    "Fwd_IAT_Tot": "Fwd IAT Total",
    "Fwd_IAT_Mean": "Fwd IAT Mean",
    "Fwd_IAT_Std": "Fwd IAT Std",
    "Fwd_IAT_Max": "Fwd IAT Max",
    "Fwd_IAT_Min": "Fwd IAT Min",
    "Bwd_IAT_Tot": "Bwd IAT Total",
    "Bwd_IAT_Mean": "Bwd IAT Mean",
    "Bwd_IAT_Std": "Bwd IAT Std",
    "Bwd_IAT_Max": "Bwd IAT Max",
    "Bwd_IAT_Min": "Bwd IAT Min",
    "Fwd_PSH_Flags": "Fwd PSH Flags",
    "Bwd_PSH_Flags": "Bwd PSH Flags",
    "Fwd_URG_Flags": "Fwd URG Flags",
    "Bwd_URG_Flags": "Bwd URG Flags",
    "Fwd_Header_Len": "Fwd Header Length",
    "Bwd_Header_Len": "Bwd Header Length",
    "Fwd_Pkts/s": "Fwd Packets/s",
    "Bwd_Pkts/s": "Bwd Packets/s",
    "Pkt_Len_Min": "Min Packet Length",
    "Pkt_Len_Max": "Max Packet Length",
    "Pkt_Len_Mean": "Packet Length Mean",
    "Pkt_Len_Std": "Packet Length Std",
    "Pkt_Len_Var": "Packet Length Variance",
    "FIN_Flag_Cnt": "FIN Flag Count",
    "SYN_Flag_Cnt": "SYN Flag Count",
    "RST_Flag_Cnt": "RST Flag Count",
    "PSH_Flag_Cnt": "PSH Flag Count",
    "ACK_Flag_Cnt": "ACK Flag Count",
    "URG_Flag_Cnt": "URG Flag Count",
    "CWE_Flag_Count": "CWE Flag Count",
    "ECE_Flag_Cnt": "ECE Flag Count",
    "Down/Up_Ratio": "Down/Up Ratio",
    "Pkt_Size_Avg": "Average Packet Size",
    "Fwd_Seg_Size_Avg": "Avg Fwd Segment Size",
    "Bwd_Seg_Size_Avg": "Avg Bwd Segment Size",
    "Fwd_Byts/b_Avg": "Fwd Avg Bytes/Bulk",
    "Fwd_Pkts/b_Avg": "Fwd Avg Packets/Bulk",
    "Fwd_Blk_Rate_Avg": "Fwd Avg Bulk Rate",
    "Bwd_Byts/b_Avg": "Bwd Avg Bytes/Bulk",
    "Bwd_Pkts/b_Avg": "Bwd Avg Packets/Bulk",
    "Bwd_Blk_Rate_Avg": "Bwd Avg Bulk Rate",
    "Subflow_Fwd_Pkts": "Subflow Fwd Packets",
    "Subflow_Fwd_Byts": "Subflow Fwd Bytes",
    "Subflow_Bwd_Pkts": "Subflow Bwd Packets",
    "Subflow_Bwd_Byts": "Subflow Bwd Bytes",
    "Init_Fwd_Win_Byts": "Init_Win_bytes_forward",
    "Init_Bwd_Win_Byts": "Init_Win_bytes_backward",
    "Fwd_Act_Data_Pkts": "act_data_pkt_fwd",
    "Fwd_Seg_Size_Min": "min_seg_size_forward",
    "Active_Mean": "Active Mean",
    "Active_Std": "Active Std",
    "Active_Max": "Active Max",
    "Active_Min": "Active Min",
    "Idle_Mean": "Idle Mean",
    "Idle_Std": "Idle Std",
    "Idle_Max": "Idle Max",
    "Idle_Min": "Idle Min",
    "label": "Label",
}


def main() -> None:
    base = "/home/mohamed/Desktop/cos/AI/data"
    src_v3 = os.path.join(base, "combine_v3.csv")
    src_2018 = os.path.join(base, "extra", "cse_cic_ids2018_v2.csv")
    out_v4 = os.path.join(base, "combine_v4.csv")

    logger.info("Loading combine_v3 schema…")
    v3_cols = pd.read_csv(src_v3, nrows=1).columns.tolist()
    v3_cols = [c.strip() for c in v3_cols]
    logger.info("v3 schema: %d columns", len(v3_cols))

    logger.info("Loading 2018 dataset (chunked)…")
    chunks = []
    chunk_iter = pd.read_csv(src_2018, low_memory=False, chunksize=500_000)
    for i, chunk in enumerate(chunk_iter):
        chunk = chunk.rename(columns=COL_MAP)
        # Mirror v3 layout: Fwd Header Length.1 duplicates Fwd Header Length.
        if "Fwd Header Length" in chunk.columns:
            chunk["Fwd Header Length.1"] = chunk["Fwd Header Length"]
        # Add any missing v3 columns as 0; drop extras like Protocol.
        for c in v3_cols:
            if c not in chunk.columns:
                chunk[c] = 0
        chunk = chunk[v3_cols]
        chunks.append(chunk)
        logger.info("  chunk %d: %d rows", i + 1, len(chunk))
    df_2018 = pd.concat(chunks, ignore_index=True)
    logger.info("2018 aligned: %d rows", len(df_2018))
    logger.info("2018 labels:\n%s", df_2018["Label"].astype(str).str.strip().value_counts())

    logger.info("Loading combine_v3…")
    df_v3 = pd.read_csv(src_v3, low_memory=False)
    df_v3.columns = df_v3.columns.str.strip()
    logger.info("v3: %d rows", len(df_v3))

    merged = pd.concat([df_v3, df_2018], ignore_index=True)
    logger.info("Merged v4: %d rows", len(merged))
    logger.info("Merged labels:\n%s",
                merged["Label"].astype(str).str.strip().value_counts())

    merged.to_csv(out_v4, index=False)
    logger.info("Wrote %s", out_v4)


if __name__ == "__main__":
    main()
