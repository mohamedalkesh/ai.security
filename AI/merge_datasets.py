"""
Merge CICIDS2017 days (V3 schema in combine.csv + V4 schema in extra/*.csv)
into a single canonical CSV with the same 77 features the v2 model uses.

Background
----------
``data/combine.csv`` was generated with CICFlowMeter V3 (the column names
have leading spaces and use snake_case for a few fields). The Tuesday and
Thursday CSVs we just downloaded from HuggingFace use CICFlowMeter V4
(no leading spaces, camelCase, a couple of renamed fields). The two
exports describe the same features — we just need to translate column
names so they can be concatenated.

Output
------
``data/combine_v3.csv`` containing every original combine.csv row plus
the new Tuesday + Thursday rows aligned to the V3 schema. Labels are
left untouched here; remapping to operational classes happens in the
training pipeline.
"""

from __future__ import annotations

import logging
import os
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# V4 column name → V3 column name (after both sides are stripped of whitespace).
V4_TO_V3: dict[str, str] = {
    "Dst Port": "Destination Port",
    "Total Fwd Packet": "Total Fwd Packets",
    "Total Bwd packets": "Total Backward Packets",
    "Total Length of Fwd Packet": "Total Length of Fwd Packets",
    "Total Length of Bwd Packet": "Total Length of Bwd Packets",
    "Packet Length Min": "Min Packet Length",
    "Packet Length Max": "Max Packet Length",
    "Fwd Bytes/Bulk Avg": "Fwd Avg Bytes/Bulk",
    "Fwd Packet/Bulk Avg": "Fwd Avg Packets/Bulk",
    "Fwd Bulk Rate Avg": "Fwd Avg Bulk Rate",
    "Bwd Bytes/Bulk Avg": "Bwd Avg Bytes/Bulk",
    "Bwd Packet/Bulk Avg": "Bwd Avg Packets/Bulk",
    "Bwd Bulk Rate Avg": "Bwd Avg Bulk Rate",
    "Fwd Segment Size Avg": "Avg Fwd Segment Size",
    "Bwd Segment Size Avg": "Avg Bwd Segment Size",
    "FWD Init Win Bytes": "Init_Win_bytes_forward",
    "Bwd Init Win Bytes": "Init_Win_bytes_backward",
    "Fwd Act Data Pkts": "act_data_pkt_fwd",
    "Fwd Seg Size Min": "min_seg_size_forward",
    # V3 has a typo in the CWR flag column.
    "CWR Flag Count": "CWE Flag Count",
}


def normalize_v4_to_v3(df: pd.DataFrame) -> pd.DataFrame:
    """Rename V4 columns to V3 equivalents, drop V4-only / metadata cols."""
    df = df.copy()
    df.columns = df.columns.str.strip()
    df = df.rename(columns=V4_TO_V3)
    # The duplicate header in V3 (Fwd Header Length.1) is just a copy of
    # Fwd Header Length. Add it so feature alignment passes.
    if "Fwd Header Length" in df.columns and "Fwd Header Length.1" not in df.columns:
        df["Fwd Header Length.1"] = df["Fwd Header Length"]
    return df


def normalize_v3(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = df.columns.str.strip()
    return df


def align_to_schema(df: pd.DataFrame, target_cols: list[str]) -> pd.DataFrame:
    """Project ``df`` onto ``target_cols``; missing columns are added with 0."""
    for c in target_cols:
        if c not in df.columns:
            df[c] = 0
    return df[target_cols]


def main() -> None:
    base = "/home/mohamed/Desktop/cos/AI/data"
    out_path = os.path.join(base, "combine_v3.csv")

    logger.info("Loading combine.csv (V3)…")
    main_df = pd.read_csv(os.path.join(base, "combine.csv"), low_memory=False)
    main_df = normalize_v3(main_df)
    target_cols = list(main_df.columns)
    logger.info("V3 schema: %d columns, %d rows", len(target_cols), len(main_df))

    extras = []
    for fname in ("tuesday.csv", "thursday.csv"):
        path = os.path.join(base, "extra", fname)
        if not os.path.exists(path):
            logger.warning("Missing %s, skipping", path)
            continue
        logger.info("Loading %s…", fname)
        df = pd.read_csv(path, low_memory=False)
        df = normalize_v4_to_v3(df)
        df = align_to_schema(df, target_cols)
        logger.info("  → %d rows after alignment", len(df))
        extras.append(df)

    merged = pd.concat([main_df] + extras, ignore_index=True)
    logger.info("Merged shape: %s", merged.shape)
    logger.info("Label distribution:\n%s", merged["Label"].astype(str).str.strip().value_counts())

    merged.to_csv(out_path, index=False)
    logger.info("Wrote %s", out_path)


if __name__ == "__main__":
    main()
