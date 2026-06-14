#!/usr/bin/env python3
"""
Standalone model tester (no API, no frontend).

Loads trained artifacts from ./model_artifacts and runs predictions
against random rows from ./data/combine.csv, printing the classification
result enriched with MITRE ATT&CK mapping.

Usage:
    python3 test_model.py
    python3 test_model.py --samples 10
    python3 test_model.py --dataset ./data/combine.csv --samples 5
"""

from __future__ import annotations

import argparse
import os
import pickle
from typing import Dict, List

import numpy as np
import pandas as pd

ARTIFACT_DIR = "./model_artifacts"
DEFAULT_DATASET = "./data/combine.csv"
CONFIDENCE_THRESHOLD = 0.6

LABEL_MAP: Dict[str, str] = {
    "benign": "Benign", "Benign": "Benign", "BENIGN": "Benign",
    "ftp-patator": "Brute Force", "FTP-Patator": "Brute Force",
    "ssh-patator": "Brute Force", "SSH-Patator": "Brute Force",
    "ddos": "DDoS", "DDoS": "DDoS",
    "dos hulk": "DDoS", "DoS Hulk": "DDoS",
    "dos goldeneye": "DDoS", "DoS GoldenEye": "DDoS",
    "dos slowloris": "DDoS", "DoS slowloris": "DDoS",
    "dos slowhttptest": "DDoS", "DoS Slowhttptest": "DDoS",
    "heartbleed": "DDoS", "Heartbleed": "DDoS",
    "portscan": "Port Scan", "PortScan": "Port Scan",
}


def normalize_label(raw: str) -> str:
    return LABEL_MAP.get(raw.strip(), raw.strip())


MITRE_MAPPING: Dict[str, Dict[str, str]] = {
    "Benign": {
        "technique": "N/A",
        "tactic": "N/A",
        "description": "Normal network traffic with no malicious behavior detected.",
        "severity": "Informational",
    },
    "Brute Force": {
        "technique": "T1110",
        "tactic": "Credential Access",
        "description": "Adversary attempts repeated password/login guessing.",
        "severity": "High",
    },
    "Port Scan": {
        "technique": "T1046",
        "tactic": "Discovery",
        "description": "Adversary scans network services and open ports.",
        "severity": "Medium",
    },
    "DDoS": {
        "technique": "T1498",
        "tactic": "Impact",
        "description": "Adversary degrades service availability using traffic flooding.",
        "severity": "High",
    },
    "Unknown": {
        "technique": "Unknown",
        "tactic": "Unknown",
        "description": "Model confidence below threshold, analyst review required.",
        "severity": "Low",
    },
}


def load_artifacts(artifact_dir: str):
    paths = {
        "model": os.path.join(artifact_dir, "model.pkl"),
        "label_encoder": os.path.join(artifact_dir, "label_encoder.pkl"),
        "scaler": os.path.join(artifact_dir, "scaler.pkl"),
        "feature_names": os.path.join(artifact_dir, "feature_names.pkl"),
    }
    missing = [p for p in paths.values() if not os.path.exists(p)]
    if missing:
        raise FileNotFoundError(
            "Missing artifacts. Train first: python3 ids_pipeline.py --data-path ./data/combine.csv\n"
            "Missing: " + ", ".join(missing)
        )
    loaded = {}
    for key, path in paths.items():
        with open(path, "rb") as f:
            loaded[key] = pickle.load(f)
    return loaded["model"], loaded["label_encoder"], loaded["scaler"], loaded["feature_names"]


def get_label_column(df: pd.DataFrame) -> str | None:
    for candidate in ["Label", "label", "LABEL", "Class", "class"]:
        if candidate in df.columns:
            return candidate
    return None


def predict_row(model, label_encoder, scaler, features: np.ndarray) -> Dict[str, object]:
    sample_scaled = scaler.transform(features.reshape(1, -1))
    probabilities = model.predict_proba(sample_scaled)[0]
    pred_idx = int(np.argmax(probabilities))
    confidence = float(np.max(probabilities))
    attack_type = label_encoder.inverse_transform([pred_idx])[0]

    if confidence < CONFIDENCE_THRESHOLD:
        attack_type = "Unknown"

    mitre = MITRE_MAPPING.get(attack_type, MITRE_MAPPING["Unknown"])
    return {
        "attack_type": attack_type,
        "confidence": round(confidence, 4),
        "mitre_technique": mitre["technique"],
        "mitre_tactic": mitre["tactic"],
        "severity": mitre["severity"],
        "description": mitre["description"],
    }


def print_result(idx: int, true_label: str | None, result: Dict[str, object]) -> None:
    print(f"\n--- Sample #{idx} ---")
    if true_label is not None:
        normalized = normalize_label(true_label)
        match = "MATCH" if normalized == result["attack_type"] else "MISMATCH"
        print(f"True Label      : {true_label} -> {normalized}  [{match}]")
    print(f"Predicted Class : {result['attack_type']}")
    print(f"Confidence      : {result['confidence']}")
    print(f"MITRE Technique : {result['mitre_technique']}")
    print(f"MITRE Tactic    : {result['mitre_tactic']}")
    print(f"Severity        : {result['severity']}")
    print(f"Description     : {result['description']}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Standalone IDS model tester")
    parser.add_argument("--dataset", type=str, default=DEFAULT_DATASET, help="Path to dataset CSV")
    parser.add_argument("--samples", type=int, default=5, help="How many random rows to test")
    parser.add_argument("--seed", type=int, default=None, help="Optional random seed")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    print("Loading model artifacts...")
    model, label_encoder, scaler, feature_names = load_artifacts(ARTIFACT_DIR)
    print(f"Model     : {type(model).__name__}")
    print(f"Classes   : {list(label_encoder.classes_)}")
    print(f"Features  : {len(feature_names)}")

    if not os.path.exists(args.dataset):
        raise FileNotFoundError(f"Dataset not found: {args.dataset}")

    print(f"\nLoading dataset: {args.dataset}")
    df = pd.read_csv(args.dataset)
    df.columns = df.columns.str.strip()

    missing = [feature for feature in feature_names if feature not in df.columns]
    if missing:
        raise ValueError(f"Dataset is missing {len(missing)} required features. Example: {missing[:5]}")

    label_col = get_label_column(df)
    sampled = df.sample(n=args.samples, random_state=args.seed).reset_index(drop=True)

    correct = 0
    evaluated = 0
    for i, row in sampled.iterrows():
        features = pd.to_numeric(row[feature_names], errors="coerce").replace([np.inf, -np.inf], np.nan)
        if features.isna().any():
            print(f"\n--- Sample #{i + 1} skipped (invalid numeric values) ---")
            continue

        true_label = str(row[label_col]) if label_col else None
        result = predict_row(model, label_encoder, scaler, features.to_numpy(dtype=float))
        print_result(i + 1, true_label, result)

        if true_label is not None:
            evaluated += 1
            if normalize_label(true_label) == result["attack_type"]:
                correct += 1

    if evaluated:
        print(f"\nQuick accuracy on {evaluated} samples: {correct}/{evaluated} = {correct / evaluated:.2%}")


if __name__ == "__main__":
    main()
