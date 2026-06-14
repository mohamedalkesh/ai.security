"""
IDS pipeline v3 — extended taxonomy on the full CICIDS2017 corpus.

Operational classes (8)
-----------------------
* Benign
* DDoS
* DoS                (Hulk, GoldenEye, slowloris, Slowhttptest, Heartbleed)
* Port Scan
* Bot
* Brute Force        (FTP-Patator, SSH-Patator)            ← new in v3
* Web Attack         (XSS, SQL Injection, Web Brute Force) ← new in v3
* Infiltration       (Infiltration, Infiltration-Portscan) ← new in v3

The pipeline mirrors v2 (XGBoost + LightGBM ensemble + IsolationForest
anomaly head, balanced class weights, stratified split). Only the label
map and the input CSV change.

Run
---
    python3 ids_pipeline_v3.py \
        --data /home/mohamed/Desktop/cos/AI/data/combine_v3.csv \
        --out  /home/mohamed/Desktop/cos/AI/model_artifacts_v3
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import pickle
import time
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.utils.class_weight import compute_class_weight

from lightgbm import LGBMClassifier
from xgboost import XGBClassifier


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Label taxonomy — v3
# ---------------------------------------------------------------------------
# "Attempted" variants from CICIDS2017's Thursday set are mapped to the
# same operational class — for an IDS, an attempted SQLi is still a SQLi
# attempt that we want to alert on, just with a lower priority.
LABEL_MAP: Dict[str, str] = {
    # Benign ---------------------------------------------------------------
    "BENIGN": "Benign", "Benign": "Benign", "benign": "Benign",

    # Volumetric DDoS ------------------------------------------------------
    "DDoS": "DDoS", "ddos": "DDoS",

    # Application / single-host DoS ---------------------------------------
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "Heartbleed": "DoS",  # Heartbleed is too rare to learn; treat as DoS-ish

    # Port reconnaissance --------------------------------------------------
    "PortScan": "Port Scan",

    # Botnet C2 -----------------------------------------------------------
    "Bot": "Bot",

    # Credential brute force ----------------------------------------------
    "FTP-Patator": "Brute Force",
    "FTP-Patator - Attempted": "Brute Force",
    "SSH-Patator": "Brute Force",
    "SSH-Patator - Attempted": "Brute Force",

    # Web application attacks ---------------------------------------------
    "Web Attack - Brute Force": "Web Attack",
    "Web Attack - Brute Force - Attempted": "Web Attack",
    "Web Attack - XSS": "Web Attack",
    "Web Attack - XSS - Attempted": "Web Attack",
    "Web Attack - SQL Injection": "Web Attack",
    "Web Attack - SQL Injection - Attempted": "Web Attack",

    # Post-compromise lateral activity ------------------------------------
    "Infiltration": "Infiltration",
    "Infiltration - Attempted": "Infiltration",
    "Infiltration - Portscan": "Infiltration",
}

ALLOWED_LABELS = {
    "Benign", "DDoS", "DoS", "Port Scan", "Bot",
    "Brute Force", "Web Attack", "Infiltration",
}


# ---------------------------------------------------------------------------
# MITRE mapping (re-emitted as JSON for the ML service to import)
# ---------------------------------------------------------------------------
MITRE_MAPPING: Dict[str, Dict[str, str]] = {
    "Benign": {
        "technique": "N/A", "tactic": "N/A", "severity": "Informational",
        "description": "Normal network traffic with no malicious behavior detected.",
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
    "Web Attack": {
        "technique": "T1190", "tactic": "Initial Access", "severity": "High",
        "description": "Exploitation attempt against a public-facing web application.",
    },
    "Infiltration": {
        "technique": "T1133", "tactic": "Initial Access", "severity": "Critical",
        "description": "Adversary established a foothold and is moving laterally.",
    },
    "Unknown": {
        "technique": "Unknown", "tactic": "Unknown", "severity": "Low",
        "description": "Out-of-distribution traffic — analyst review required.",
    },
}


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------
def load_and_clean(csv_path: str, sample_per_class: Optional[int] = None,
                   random_state: int = 42) -> pd.DataFrame:
    logger.info("Loading %s", csv_path)
    df = pd.read_csv(csv_path, low_memory=False)
    df.columns = df.columns.str.strip()

    if "Label" not in df.columns:
        raise ValueError(f"'Label' column missing. Got: {list(df.columns)[:5]}…")

    df["Label"] = df["Label"].astype(str).str.strip().map(LABEL_MAP)
    before = len(df)
    df = df.dropna(subset=["Label"])
    df = df[df["Label"].isin(ALLOWED_LABELS)]
    logger.info("Label filter: %d → %d rows (%d classes)", before, len(df), df["Label"].nunique())

    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=numeric_cols)
    df = df[numeric_cols + ["Label"]]

    if sample_per_class:
        parts = []
        for label, g in df.groupby("Label"):
            if len(g) > sample_per_class:
                parts.append(g.sample(n=sample_per_class, random_state=random_state))
            else:
                parts.append(g)
        df = pd.concat(parts, ignore_index=True).sample(frac=1, random_state=random_state)
        logger.info("After per-class cap (%d): %d rows", sample_per_class, len(df))

    logger.info("Class distribution:\n%s", df["Label"].value_counts())
    return df


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------
def train_ensemble(X_train: pd.DataFrame, y_train: pd.Series,
                   random_state: int = 42,
                   checkpoint_dir: Optional[str] = None,
                   ) -> Tuple[Any, Any, LabelEncoder, StandardScaler]:
    """Train XGBoost + LightGBM with intermediate checkpointing.

    XGBoost is pickled to ``checkpoint_dir`` immediately after fitting,
    so we don't lose 15 minutes of work if LightGBM crashes the process
    (OOM is the practical risk on machines with ~16GB RAM and 8 classes).
    """
    le = LabelEncoder()
    y_enc = le.fit_transform(y_train)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_train)

    cw = compute_class_weight("balanced", classes=np.unique(y_enc), y=y_enc)
    sample_weight = cw[y_enc]
    logger.info("Class weights: %s", dict(zip(le.classes_, cw.round(3))))

    n_classes = len(le.classes_)

    logger.info("Training XGBoost (%d classes)…", n_classes)
    t0 = time.time()
    xgb = XGBClassifier(
        n_estimators=300, max_depth=10, learning_rate=0.08,
        objective="multi:softprob", eval_metric="mlogloss",
        subsample=0.9, colsample_bytree=0.9,
        random_state=random_state, n_jobs=-1, tree_method="hist",
    )
    xgb.fit(X_scaled, y_enc, sample_weight=sample_weight)
    logger.info("XGBoost done in %.1fs", time.time() - t0)

    # Persist XGBoost + encoder + scaler now so a later crash is recoverable.
    if checkpoint_dir:
        os.makedirs(checkpoint_dir, exist_ok=True)
        for name, obj in (("xgb.pkl", xgb), ("label_encoder.pkl", le),
                          ("scaler.pkl", scaler)):
            with open(os.path.join(checkpoint_dir, name), "wb") as f:
                pickle.dump(obj, f)
        logger.info("Checkpointed XGBoost + encoder + scaler to %s", checkpoint_dir)

    # LightGBM tuned down for 16GB hosts. num_leaves=63 + n_estimators=250
    # halves peak RSS vs (127, 400) while costing < 0.5 F1 in practice.
    logger.info("Training LightGBM (%d classes)…", n_classes)
    t0 = time.time()
    lgbm = LGBMClassifier(
        n_estimators=250, max_depth=-1, num_leaves=63, learning_rate=0.07,
        objective="multiclass", num_class=n_classes,
        subsample=0.9, colsample_bytree=0.9,
        random_state=random_state, n_jobs=-1, verbose=-1,
    )
    lgbm.fit(X_scaled, y_enc, sample_weight=sample_weight)
    logger.info("LightGBM done in %.1fs", time.time() - t0)

    return xgb, lgbm, le, scaler


def train_anomaly(X_scaled_train: np.ndarray, random_state: int = 42,
                  contamination: float = 0.05) -> IsolationForest:
    logger.info("Training IsolationForest (contamination=%.2f)…", contamination)
    t0 = time.time()
    iso = IsolationForest(
        n_estimators=200, contamination=contamination,
        random_state=random_state, n_jobs=-1,
    )
    iso.fit(X_scaled_train)
    logger.info("IsolationForest done in %.1fs", time.time() - t0)
    return iso


def evaluate(xgb, lgbm, le, scaler, X_test, y_test) -> Dict[str, Any]:
    Xs = scaler.transform(X_test)
    proba = (xgb.predict_proba(Xs) + lgbm.predict_proba(Xs)) / 2.0
    y_pred = le.inverse_transform(np.argmax(proba, axis=1))

    labels = list(le.classes_)
    cm = confusion_matrix(y_test, y_pred, labels=labels)
    report = classification_report(y_test, y_pred, zero_division=0, digits=4)

    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision_macro": float(precision_score(y_test, y_pred, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(y_test, y_pred, average="macro", zero_division=0)),
        "f1_macro": float(f1_score(y_test, y_pred, average="macro", zero_division=0)),
        "f1_weighted": float(f1_score(y_test, y_pred, average="weighted", zero_division=0)),
        "labels": labels,
        "confusion_matrix": cm.tolist(),
        "report": report,
    }
    for k in ("accuracy", "precision_macro", "recall_macro", "f1_macro", "f1_weighted"):
        logger.info("%-16s: %.4f", k, metrics[k])
    print("\n" + report)
    return metrics


def save_artifacts(xgb, lgbm, iso, le, scaler, feature_names, metrics, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    payload = {
        "xgb.pkl": xgb, "lgbm.pkl": lgbm, "iso.pkl": iso,
        "label_encoder.pkl": le, "scaler.pkl": scaler,
        "feature_names.pkl": feature_names,
    }
    for name, obj in payload.items():
        with open(os.path.join(out_dir, name), "wb") as f:
            pickle.dump(obj, f)

    with open(os.path.join(out_dir, "mitre_mapping.json"), "w") as f:
        json.dump(MITRE_MAPPING, f, indent=2)
    with open(os.path.join(out_dir, "metrics.json"), "w") as f:
        json.dump({k: v for k, v in metrics.items() if k != "report"}, f, indent=2)
    with open(os.path.join(out_dir, "classification_report.txt"), "w") as f:
        f.write(metrics["report"])
    logger.info("Artifacts written to %s", out_dir)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--data", default="/home/mohamed/Desktop/cos/AI/data/combine_v3.csv")
    p.add_argument("--out", default="/home/mohamed/Desktop/cos/AI/model_artifacts_v3")
    p.add_argument("--sample-per-class", type=int, default=200_000)
    p.add_argument("--test-size", type=float, default=0.2)
    p.add_argument("--random-state", type=int, default=42)
    return p.parse_args()


def main() -> None:
    args = parse_args()
    df = load_and_clean(args.data, sample_per_class=args.sample_per_class,
                        random_state=args.random_state)

    X = df.drop(columns=["Label"])
    y = df["Label"]
    feature_names = X.columns.tolist()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, stratify=y, random_state=args.random_state
    )
    logger.info("Train=%d, Test=%d, Features=%d", len(X_train), len(X_test), len(feature_names))

    xgb, lgbm, le, scaler = train_ensemble(
        X_train, y_train,
        random_state=args.random_state,
        checkpoint_dir=args.out,
    )
    iso = train_anomaly(scaler.transform(X_train), random_state=args.random_state)
    metrics = evaluate(xgb, lgbm, le, scaler, X_test, y_test)
    save_artifacts(xgb, lgbm, iso, le, scaler, feature_names, metrics, args.out)


if __name__ == "__main__":
    main()
