"""
Run the trained IDS model on a PCAP file (real network traffic).

Pipeline:
    PCAP -> CICFlowMeter (Python) -> 77 CICIDS features -> XGBoost -> MITRE ATT&CK

Usage:
    .venv/bin/python predict_pcap.py path/to/file.pcap
    .venv/bin/python predict_pcap.py file.pcap --top 20
"""

from __future__ import annotations

import argparse
import os
import pickle
from typing import Dict

import numpy as np
import pandas as pd

from pcap_to_features import pcap_to_dataframe

ARTIFACT_DIR = "./model_artifacts"
CONFIDENCE_THRESHOLD = 0.6

MITRE_MAPPING: Dict[str, Dict[str, str]] = {
    "Benign":      {"technique": "N/A",     "tactic": "N/A",                "severity": "Informational",
                    "description": "Normal network traffic."},
    "Brute Force": {"technique": "T1110",   "tactic": "Credential Access",  "severity": "High",
                    "description": "Repeated password/login guessing."},
    "Port Scan":   {"technique": "T1046",   "tactic": "Discovery",          "severity": "Medium",
                    "description": "Scanning network services and open ports."},
    "DDoS":        {"technique": "T1498",   "tactic": "Impact",             "severity": "High",
                    "description": "Service degradation via traffic flooding."},
    "Unknown":     {"technique": "Unknown", "tactic": "Unknown",            "severity": "Low",
                    "description": "Confidence below threshold."},
}


def load_artifacts():
    paths = ["model.pkl", "label_encoder.pkl", "scaler.pkl", "feature_names.pkl"]
    objs = []
    for name in paths:
        with open(os.path.join(ARTIFACT_DIR, name), "rb") as f:
            objs.append(pickle.load(f))
    return objs[0], objs[1], objs[2], objs[3]


def classify_flows(df: pd.DataFrame, model, label_encoder, scaler, feature_names):
    X = df[feature_names].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0)
    Xs = scaler.transform(X.to_numpy(dtype=float))
    proba = model.predict_proba(Xs)
    idx = np.argmax(proba, axis=1)
    conf = np.max(proba, axis=1)
    classes = label_encoder.inverse_transform(idx)
    classes = np.where(conf < CONFIDENCE_THRESHOLD, "Unknown", classes)

    result = pd.DataFrame({
        "Predicted": classes,
        "Confidence": np.round(conf, 4),
    })
    result["Technique"] = result["Predicted"].map(lambda p: MITRE_MAPPING.get(p, MITRE_MAPPING["Unknown"])["technique"])
    result["Tactic"] = result["Predicted"].map(lambda p: MITRE_MAPPING.get(p, MITRE_MAPPING["Unknown"])["tactic"])
    result["Severity"] = result["Predicted"].map(lambda p: MITRE_MAPPING.get(p, MITRE_MAPPING["Unknown"])["severity"])
    result["Description"] = result["Predicted"].map(lambda p: MITRE_MAPPING.get(p, MITRE_MAPPING["Unknown"])["description"])

    for col in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol"):
        if col in df.columns:
            result[col] = df[col].values

    return result


def parse_args():
    p = argparse.ArgumentParser(description="Classify a PCAP file using the IDS model")
    p.add_argument("pcap", help="Path to .pcap or .pcapng file")
    p.add_argument("--top", type=int, default=10, help="How many flows to print")
    p.add_argument("--save", default=None, help="Optional CSV path to save full results")
    return p.parse_args()


def main():
    args = parse_args()
    print(f"Loading model from {ARTIFACT_DIR}...")
    model, label_encoder, scaler, feature_names = load_artifacts()
    print(f"Classes: {list(label_encoder.classes_)}  |  Features: {len(feature_names)}")

    print(f"\nExtracting flows from {args.pcap} ...")
    df = pcap_to_dataframe(args.pcap, feature_names)
    print(f"Extracted {len(df)} flows")

    if df.empty:
        print("No flows extracted. PCAP may be too small.")
        return

    print("Running classification...")
    result = classify_flows(df, model, label_encoder, scaler, feature_names)

    print("\n========== SUMMARY ==========")
    counts = result["Predicted"].value_counts()
    for cls, c in counts.items():
        print(f"  {cls:<12} : {c}")
    attacks = int((result["Predicted"] != "Benign").sum())
    print(f"\nTotal flows  : {len(result)}")
    print(f"Benign       : {len(result) - attacks}")
    print(f"Attacks      : {attacks}")
    print(f"Avg conf.    : {result['Confidence'].mean():.4f}")

    print(f"\n========== TOP {min(args.top, len(result))} FLOWS ==========")
    cols = [c for c in ["src_ip", "dst_ip", "dst_port", "protocol",
                        "Predicted", "Confidence", "Technique", "Tactic", "Severity"] if c in result.columns]
    print(result[cols].head(args.top).to_string(index=False))

    if args.save:
        result.to_csv(args.save, index=False)
        print(f"\nFull results saved to {args.save}")


if __name__ == "__main__":
    main()
