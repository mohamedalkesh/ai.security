"""
IDS pipeline v5 — 15-class taxonomy with modern attack families.

Operational classes (15)
------------------------
Existing (v4):
  Benign, DDoS, DoS, Port Scan, Bot, Brute Force, Infiltration

Split from "Web Attack" (was 1 class, now 3):
  SQL Injection, XSS, Web Attack (residual)

New attack families:
  Ransomware, Cryptomining, DNS Tunneling, Lateral Movement, ICMP Flood

Compatible with: CICIDS2017, CICIDS2019, UNSW-NB15, NF-UQ-NIDS-2022, TON-IoT

Run
---
    # Single CSV (converted from any supported dataset):
    python3 ids_pipeline_v5.py --data /path/to/combined_v5.csv --out AI/model_artifacts_v5

    # Multiple CSVs merged on-the-fly:
    python3 ids_pipeline_v5.py \\
        --data AI/data/cicids2017.csv AI/data/nf_uq_nids.csv AI/data/toniot.csv \\
        --dataset-names cicids2017 nf-uq-nids toniot \\
        --out AI/model_artifacts_v5
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import pickle
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import yaml
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    f1_score, precision_score, recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from lightgbm import LGBMClassifier
from xgboost import XGBClassifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent

# ── 15-class taxonomy ─────────────────────────────────────────────────────────
ALLOWED_LABELS = {
    "Benign",
    "DDoS", "DoS",
    "Port Scan",
    "Bot",
    "Brute Force",
    "SQL Injection", "XSS", "Web Attack",
    "Infiltration",
    "Ransomware",
    "Cryptomining",
    "DNS Tunneling",
    "Lateral Movement",
    "ICMP Flood",
}

# MITRE ATT&CK mapping — v5 (covers all 15 classes)
MITRE_MAPPING: Dict[str, Dict[str, str]] = {
    "Benign": {
        "technique": "N/A", "tactic": "N/A", "severity": "Informational",
        "description": "Normal network traffic — no malicious behaviour detected.",
    },
    "DDoS": {
        "technique": "T1498", "tactic": "Impact", "severity": "High",
        "description": "Volumetric flood attack degrading service availability.",
    },
    "DoS": {
        "technique": "T1499", "tactic": "Impact", "severity": "High",
        "description": "Application-layer denial of service exhausting target resources.",
    },
    "Port Scan": {
        "technique": "T1046", "tactic": "Discovery", "severity": "Medium",
        "description": "Adversary enumerates network services and open ports.",
    },
    "Bot": {
        "technique": "T1071", "tactic": "Command and Control", "severity": "High",
        "description": "Compromised host communicating with botnet C2 infrastructure.",
    },
    "Brute Force": {
        "technique": "T1110", "tactic": "Credential Access", "severity": "High",
        "description": "Repeated credential guessing against authentication services.",
    },
    "SQL Injection": {
        "technique": "T1190", "tactic": "Initial Access", "severity": "Critical",
        "description": "SQL injection attempt to extract or manipulate database contents.",
    },
    "XSS": {
        "technique": "T1059.007", "tactic": "Execution", "severity": "High",
        "description": "Cross-site scripting payload injected into web application.",
    },
    "Web Attack": {
        "technique": "T1190", "tactic": "Initial Access", "severity": "High",
        "description": "Generic web application exploitation attempt.",
    },
    "Infiltration": {
        "technique": "T1133", "tactic": "Initial Access", "severity": "Critical",
        "description": "Adversary established a foothold — possible backdoor or shell.",
    },
    "Ransomware": {
        "technique": "T1486", "tactic": "Impact", "severity": "Critical",
        "description": "Ransomware activity detected — data encryption in progress.",
    },
    "Cryptomining": {
        "technique": "T1496", "tactic": "Impact", "severity": "Medium",
        "description": "Unauthorised cryptocurrency mining consuming host resources.",
    },
    "DNS Tunneling": {
        "technique": "T1071.004", "tactic": "Command and Control", "severity": "High",
        "description": "Data exfiltration or C2 communication hidden in DNS queries.",
    },
    "Lateral Movement": {
        "technique": "T1021", "tactic": "Lateral Movement", "severity": "Critical",
        "description": "Adversary moving between internal hosts using stolen credentials.",
    },
    "ICMP Flood": {
        "technique": "T1498.001", "tactic": "Impact", "severity": "Medium",
        "description": "ICMP ping flood or sweep targeting network availability.",
    },
    "Unknown": {
        "technique": "Unknown", "tactic": "Unknown", "severity": "Low",
        "description": "Out-of-distribution traffic — analyst review required.",
    },
}


# ── Label loading from label_map.yaml ─────────────────────────────────────────
def build_label_map(dataset_name: Optional[str] = None) -> Dict[str, str]:
    """Return raw-label → canonical-label dict from label_map.yaml."""
    yaml_path = ROOT / "datasets" / "label_map.yaml"
    if not yaml_path.exists():
        logger.warning("label_map.yaml not found; using empty map")
        return {}
    with open(yaml_path) as f:
        cfg = yaml.safe_load(f)

    # Build reverse map: alias → canonical
    result: Dict[str, str] = {}
    for canonical, aliases in cfg.get("canonical", {}).items():
        for alias in aliases:
            result[str(alias)] = canonical

    # Dataset-specific overrides take priority
    if dataset_name and dataset_name in cfg.get("datasets", {}):
        for raw, canon in cfg["datasets"][dataset_name].items():
            result[str(raw)] = canon

    return result


# ── Data loading ──────────────────────────────────────────────────────────────
def load_csv(csv_path: str, dataset_name: Optional[str] = None,
             sample_per_class: Optional[int] = None,
             random_state: int = 42) -> pd.DataFrame:
    logger.info("Loading %s (dataset=%s)", csv_path, dataset_name or "auto")
    df = pd.read_csv(csv_path, low_memory=False)
    df.columns = df.columns.str.strip()

    # Detect label column
    label_col = None
    for c in ("Label", "label", "attack_cat", "class", "Class"):
        if c in df.columns:
            label_col = c
            break
    if label_col is None:
        raise ValueError(f"No label column found. Columns: {list(df.columns)[:8]}")
    if label_col != "Label":
        df = df.rename(columns={label_col: "Label"})

    label_map = build_label_map(dataset_name)
    df["Label"] = df["Label"].astype(str).str.strip()
    df["Label"] = df["Label"].map(label_map).fillna(df["Label"])

    before = len(df)
    df = df[df["Label"].isin(ALLOWED_LABELS)]
    logger.info("Label filter: %d → %d rows | classes: %s",
                before, len(df), sorted(df["Label"].unique()))

    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=numeric_cols)
    df = df[numeric_cols + ["Label"]]

    if sample_per_class:
        parts = [
            (g.sample(n=sample_per_class, random_state=random_state)
             if len(g) > sample_per_class else g)
            for _, g in df.groupby("Label")
        ]
        df = pd.concat(parts, ignore_index=True).sample(frac=1, random_state=random_state)
        logger.info("After per-class cap (%d): %d rows", sample_per_class, len(df))

    return df


def load_and_merge(csv_paths: List[str], dataset_names: Optional[List[str]] = None,
                   sample_per_class: Optional[int] = None,
                   random_state: int = 42) -> pd.DataFrame:
    """Load multiple CSVs with their respective label maps and merge."""
    frames = []
    for i, path in enumerate(csv_paths):
        name = dataset_names[i] if dataset_names and i < len(dataset_names) else None
        df = load_csv(path, dataset_name=name,
                      sample_per_class=sample_per_class, random_state=random_state)
        frames.append(df)
    combined = pd.concat(frames, ignore_index=True, sort=False).fillna(0)
    logger.info("Merged: %d rows | %d features | classes: %s",
                len(combined), len(combined.columns) - 1,
                sorted(combined["Label"].unique()))
    return combined


# ── Training ──────────────────────────────────────────────────────────────────
def train_ensemble(
    X_train: pd.DataFrame, y_train: pd.Series,
    random_state: int = 42,
    checkpoint_dir: Optional[str] = None,
) -> Tuple[Any, Any, LabelEncoder, StandardScaler]:

    le = LabelEncoder()
    y_enc = le.fit_transform(y_train)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_train)

    logger.info("Training XGBoost (n_classes=%d) …", len(le.classes_))
    t0 = time.time()
    xgb = XGBClassifier(
        n_estimators=300, max_depth=10, learning_rate=0.08,
        use_label_encoder=False, eval_metric="mlogloss",
        n_jobs=-1, random_state=random_state,
        subsample=0.9, colsample_bytree=0.9,
    )
    xgb.fit(X_scaled, y_enc)
    logger.info("XGBoost done in %.0fs", time.time() - t0)
    if checkpoint_dir:
        os.makedirs(checkpoint_dir, exist_ok=True)
        with open(os.path.join(checkpoint_dir, "xgb.pkl"), "wb") as f:
            pickle.dump(xgb, f)

    logger.info("Training LightGBM …")
    t0 = time.time()
    lgbm = LGBMClassifier(
        n_estimators=250, max_depth=-1, num_leaves=63, learning_rate=0.07,
        n_jobs=-1, random_state=random_state, verbose=-1,
        subsample=0.9, colsample_bytree=0.9,
    )
    lgbm.fit(X_scaled, y_enc)
    logger.info("LightGBM done in %.0fs", time.time() - t0)
    return xgb, lgbm, le, scaler


def train_anomaly(X_scaled: np.ndarray, contamination: float = 0.05,
                  random_state: int = 42) -> IsolationForest:
    logger.info("Training IsolationForest (contamination=%.2f) …", contamination)
    iso = IsolationForest(n_estimators=100, contamination=contamination,
                          random_state=random_state, n_jobs=-1)
    iso.fit(X_scaled)
    return iso


# ── Evaluation ────────────────────────────────────────────────────────────────
def evaluate(xgb, lgbm, le, scaler, X_test, y_test) -> Dict:
    X_sc = scaler.transform(X_test)
    proba = (xgb.predict_proba(X_sc) + lgbm.predict_proba(X_sc)) / 2
    y_pred = proba.argmax(axis=1)
    report = classification_report(y_test, y_pred,
                                   target_names=le.classes_, zero_division=0, digits=4)
    metrics = {
        "accuracy":        float(accuracy_score(y_test, y_pred)),
        "precision_macro": float(precision_score(y_test, y_pred, average="macro", zero_division=0)),
        "recall_macro":    float(recall_score(y_test, y_pred, average="macro", zero_division=0)),
        "f1_macro":        float(f1_score(y_test, y_pred, average="macro", zero_division=0)),
        "f1_weighted":     float(f1_score(y_test, y_pred, average="weighted", zero_division=0)),
        "labels":          list(le.classes_),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "report":          report,
    }
    for k in ("accuracy", "f1_macro", "f1_weighted"):
        logger.info("%s = %.4f", k, metrics[k])
    logger.info("\n" + report)
    return metrics


# ── Save ──────────────────────────────────────────────────────────────────────
def save_artifacts(xgb, lgbm, iso, le, scaler, feature_names, metrics, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    for name, obj in {
        "xgb.pkl": xgb, "lgbm.pkl": lgbm, "iso.pkl": iso,
        "label_encoder.pkl": le, "scaler.pkl": scaler,
        "feature_names.pkl": feature_names,
    }.items():
        with open(os.path.join(out_dir, name), "wb") as f:
            pickle.dump(obj, f)
    with open(os.path.join(out_dir, "mitre_mapping.json"), "w") as f:
        json.dump(MITRE_MAPPING, f, indent=2, ensure_ascii=False)
    with open(os.path.join(out_dir, "metrics.json"), "w") as f:
        json.dump({k: v for k, v in metrics.items() if k != "report"}, f, indent=2)
    with open(os.path.join(out_dir, "classification_report.txt"), "w") as f:
        f.write(metrics["report"])
    logger.info("✓ Artifacts saved → %s", out_dir)


# ── CLI ───────────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(description="MADRS IDS pipeline v5 — 15-class taxonomy")
    p.add_argument("--data", nargs="+", required=True,
                   help="One or more CSV paths (merged automatically)")
    p.add_argument("--dataset-names", nargs="+",
                   help="Dataset names matching label_map.yaml keys (same order as --data)")
    p.add_argument("--out", default=str(ROOT / "model_artifacts_v5"))
    p.add_argument("--sample-per-class", type=int, default=150_000)
    p.add_argument("--test-size", type=float, default=0.2)
    p.add_argument("--random-state", type=int, default=42)
    p.add_argument("--contamination", type=float, default=0.05)
    return p.parse_args()


def main():
    args = parse_args()

    df = load_and_merge(
        args.data,
        dataset_names=args.dataset_names,
        sample_per_class=args.sample_per_class,
        random_state=args.random_state,
    )

    X = df.drop(columns=["Label"])
    y = df["Label"]
    feature_names = X.columns.tolist()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, stratify=y, random_state=args.random_state
    )
    logger.info("Train=%d  Test=%d  Features=%d", len(X_train), len(X_test), len(feature_names))

    xgb, lgbm, le, scaler = train_ensemble(
        X_train, y_train,
        random_state=args.random_state,
        checkpoint_dir=args.out,
    )
    iso = train_anomaly(scaler.transform(X_train),
                        contamination=args.contamination,
                        random_state=args.random_state)

    y_test_enc = le.transform(y_test)
    metrics = evaluate(xgb, lgbm, le, scaler, X_test, y_test_enc)
    save_artifacts(xgb, lgbm, iso, le, scaler, feature_names, metrics, args.out)


if __name__ == "__main__":
    main()
