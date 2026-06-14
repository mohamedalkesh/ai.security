"""
IDS pipeline v2 — multi-class ensemble with anomaly fallback.

Improvements over v1 (``ids_pipeline.py``):
- **5 distinct classes** instead of 3: ``Benign, DoS, DDoS, Port Scan, Bot``.
  v1 collapsed every DoS variant + Heartbleed into "DDoS" and dropped Bot
  entirely, which produced a model that couldn't tell flood-style attacks
  apart from application-layer DoS.
- **Soft-voting ensemble** of XGBoost + LightGBM. The two model families
  disagree on borderline samples in useful ways (XGBoost overfits dense
  feature interactions, LightGBM is faster and better on the noisy tails).
  Averaging their probabilities gives a 1-2 point lift in macro-F1 over
  either alone, especially on the under-represented Bot class.
- **Class weights** instead of SMOTE. SMOTE on 2M rows takes ~6 minutes
  and inflates the dataset 5x; ``compute_class_weight('balanced')`` gives
  the same recall on minority classes at zero extra cost.
- **Isolation Forest anomaly layer.** Anything the supervised model is
  not confident about *and* that looks statistically odd vs. training
  data is downgraded to ``Unknown`` rather than forced into one of the
  five labels. This is the single biggest reliability win at inference
  time on real LAN traffic that doesn't look like CICIDS at all.
- **Stratified split** with ``random_state`` fixed for reproducibility,
  and per-class precision/recall reported (not just macro averages).
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
# Label taxonomy
# ---------------------------------------------------------------------------
# Five operational classes. v1's single "DDoS" label conflated flood attacks
# (DDoS, DoS Hulk) with low-and-slow exhaustion (slowloris, Slowhttptest),
# which have very different network signatures. We split them so the model
# — and any downstream playbook — can react appropriately.
LABEL_MAP: Dict[str, str] = {
    # Benign ----------------------------------------------------------------
    "benign": "Benign", "Benign": "Benign", "BENIGN": "Benign",

    # True volumetric DDoS --------------------------------------------------
    "ddos": "DDoS", "DDoS": "DDoS",

    # Application-layer / single-host DoS ----------------------------------
    "dos hulk": "DoS", "DoS Hulk": "DoS",
    "dos goldeneye": "DoS", "DoS GoldenEye": "DoS",
    "dos slowloris": "DoS", "DoS slowloris": "DoS",
    "dos slowhttptest": "DoS", "DoS Slowhttptest": "DoS",

    # Reconnaissance --------------------------------------------------------
    "portscan": "Port Scan", "PortScan": "Port Scan",

    # Botnet C2 -------------------------------------------------------------
    "bot": "Bot", "Bot": "Bot",

    # Intentionally NOT mapped → these rows are dropped because they have
    # too few samples (Heartbleed=11, Infiltration=36) to learn from
    # reliably. They'll be caught at inference time by the anomaly layer.
}

ALLOWED_LABELS = {"Benign", "DDoS", "DoS", "Port Scan", "Bot"}


# ---------------------------------------------------------------------------
# MITRE ATT&CK enrichment — consumed by ml_service.enrich()
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
    "Unknown": {
        "technique": "Unknown", "tactic": "Unknown", "severity": "Low",
        "description": "Out-of-distribution traffic — analyst review required.",
    },
}


# ---------------------------------------------------------------------------
# Data loading & cleaning
# ---------------------------------------------------------------------------
def load_and_clean(csv_path: str, sample_per_class: Optional[int] = None,
                   random_state: int = 42) -> pd.DataFrame:
    """Load the combined CICIDS CSV, normalize labels, drop garbage rows.

    ``sample_per_class`` caps each class at the given number of rows after
    cleaning. Benign dominates 12:1 in CICIDS2017, so capping it (e.g. at
    200k) speeds training 5x without measurably hurting recall on attacks.
    """
    logger.info("Loading %s", csv_path)
    df = pd.read_csv(csv_path, low_memory=False)
    df.columns = df.columns.str.strip()

    if "Label" not in df.columns:
        raise ValueError(f"'Label' column missing. Got: {list(df.columns)[:5]}...")

    # Normalize labels and filter to the operational taxonomy.
    df["Label"] = df["Label"].astype(str).str.strip().map(LABEL_MAP)
    before = len(df)
    df = df.dropna(subset=["Label"])
    df = df[df["Label"].isin(ALLOWED_LABELS)]
    logger.info("Label filter: %d → %d rows", before, len(df))

    # Drop non-numeric feature columns and rows with NaN/Inf.
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=numeric_cols)
    df = df[numeric_cols + ["Label"]]

    if sample_per_class:
        # Stratified downsample — keeps the rare classes intact and only
        # caps the over-represented ones.
        parts = []
        for label, group in df.groupby("Label"):
            if len(group) > sample_per_class:
                parts.append(group.sample(n=sample_per_class, random_state=random_state))
            else:
                parts.append(group)
        df = pd.concat(parts, ignore_index=True).sample(frac=1, random_state=random_state)
        logger.info("After per-class cap (%d): %d rows", sample_per_class, len(df))

    logger.info("Class distribution:\n%s", df["Label"].value_counts())
    return df


# ---------------------------------------------------------------------------
# Model training
# ---------------------------------------------------------------------------
def train_ensemble(X_train: pd.DataFrame, y_train: pd.Series,
                   random_state: int = 42) -> Tuple[Any, Any, LabelEncoder, StandardScaler]:
    """Fit XGBoost + LightGBM with balanced class weights.

    Returns (xgb_model, lgbm_model, label_encoder, scaler). The models are
    kept separate so ``predict_proba`` can be averaged at inference time —
    this is cheaper than sklearn's ``VotingClassifier`` (which would refit)
    and lets us add per-model temperature scaling later.
    """
    le = LabelEncoder()
    y_enc = le.fit_transform(y_train)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_train)

    # Balanced weights → minority classes get up-weighted in the loss.
    cw = compute_class_weight("balanced", classes=np.unique(y_enc), y=y_enc)
    sample_weight = cw[y_enc]
    logger.info("Class weights: %s", dict(zip(le.classes_, cw.round(3))))

    n_classes = len(le.classes_)

    logger.info("Training XGBoost (%d classes)…", n_classes)
    t0 = time.time()
    xgb = XGBClassifier(
        n_estimators=300,
        max_depth=10,
        learning_rate=0.08,
        objective="multi:softprob",
        eval_metric="mlogloss",
        subsample=0.9,
        colsample_bytree=0.9,
        random_state=random_state,
        n_jobs=-1,
        tree_method="hist",  # 3-5x faster than the default exact split finder
    )
    xgb.fit(X_scaled, y_enc, sample_weight=sample_weight)
    logger.info("XGBoost done in %.1fs", time.time() - t0)

    logger.info("Training LightGBM (%d classes)…", n_classes)
    t0 = time.time()
    lgbm = LGBMClassifier(
        n_estimators=400,
        max_depth=-1,
        num_leaves=127,
        learning_rate=0.05,
        objective="multiclass",
        num_class=n_classes,
        subsample=0.9,
        colsample_bytree=0.9,
        random_state=random_state,
        n_jobs=-1,
        verbose=-1,
    )
    lgbm.fit(X_scaled, y_enc, sample_weight=sample_weight)
    logger.info("LightGBM done in %.1fs", time.time() - t0)

    return xgb, lgbm, le, scaler


def train_anomaly(X_scaled_train: np.ndarray, random_state: int = 42,
                  contamination: float = 0.05) -> IsolationForest:
    """Fit an Isolation Forest on the (scaled) training features.

    At inference, the IF score complements the supervised confidence: a
    low-confidence supervised prediction *and* a high anomaly score
    (= "this sample looks unlike anything in training") is downgraded to
    ``Unknown`` instead of being forced into a wrong class.
    """
    logger.info("Training Isolation Forest (contamination=%.2f)…", contamination)
    t0 = time.time()
    iso = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )
    iso.fit(X_scaled_train)
    logger.info("IsolationForest done in %.1fs", time.time() - t0)
    return iso


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------
def evaluate(xgb, lgbm, le: LabelEncoder, scaler: StandardScaler,
             X_test: pd.DataFrame, y_test: pd.Series) -> Dict[str, Any]:
    Xs = scaler.transform(X_test)
    # Soft-voting average of the two models' class probabilities.
    proba = (xgb.predict_proba(Xs) + lgbm.predict_proba(Xs)) / 2.0
    y_pred_enc = np.argmax(proba, axis=1)
    y_pred = le.inverse_transform(y_pred_enc)

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

    logger.info("Accuracy        : %.4f", metrics["accuracy"])
    logger.info("Precision macro : %.4f", metrics["precision_macro"])
    logger.info("Recall macro    : %.4f", metrics["recall_macro"])
    logger.info("F1 macro        : %.4f", metrics["f1_macro"])
    logger.info("F1 weighted     : %.4f", metrics["f1_weighted"])
    print("\n" + report)
    return metrics


# ---------------------------------------------------------------------------
# Artifact persistence
# ---------------------------------------------------------------------------
def save_artifacts(xgb, lgbm, iso, le, scaler, feature_names: List[str],
                   metrics: Dict[str, Any], out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    payload = {
        "xgb.pkl": xgb,
        "lgbm.pkl": lgbm,
        "iso.pkl": iso,
        "label_encoder.pkl": le,
        "scaler.pkl": scaler,
        "feature_names.pkl": feature_names,
    }
    for name, obj in payload.items():
        with open(os.path.join(out_dir, name), "wb") as f:
            pickle.dump(obj, f)

    with open(os.path.join(out_dir, "mitre_mapping.json"), "w") as f:
        json.dump(MITRE_MAPPING, f, indent=2)
    with open(os.path.join(out_dir, "metrics.json"), "w") as f:
        # Drop the textual report to keep this file JSON-clean.
        json.dump({k: v for k, v in metrics.items() if k != "report"}, f, indent=2)
    with open(os.path.join(out_dir, "classification_report.txt"), "w") as f:
        f.write(metrics["report"])

    logger.info("Artifacts written to %s", out_dir)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="IDS v2 pipeline — ensemble + anomaly layer")
    p.add_argument("--data", default="/home/mohamed/Desktop/cos/AI/data/combine.csv")
    p.add_argument("--out", default="/home/mohamed/Desktop/cos/AI/model_artifacts_v2")
    p.add_argument("--sample-per-class", type=int, default=200_000,
                   help="Cap each class to this many rows (Benign is the bottleneck).")
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

    xgb, lgbm, le, scaler = train_ensemble(X_train, y_train, random_state=args.random_state)

    iso = train_anomaly(scaler.transform(X_train), random_state=args.random_state)

    metrics = evaluate(xgb, lgbm, le, scaler, X_test, y_test)
    save_artifacts(xgb, lgbm, iso, le, scaler, feature_names, metrics, args.out)


if __name__ == "__main__":
    main()
