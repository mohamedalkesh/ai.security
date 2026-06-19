"""
MADRS — Auto-retraining pipeline.

Reads new labeled samples from PostgreSQL (ml_training_data where
raw_features_json IS NOT NULL), merges with the original CICIDS training CSV,
retrains the XGBoost + LightGBM ensemble + IsolationForest, saves new
artifacts, and signals the ML service to hot-reload.

Schedule: run weekly via systemd timer (madrs-retrain.timer).
Usage:    python3 scripts/retrain.py [--min-new 50] [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import pickle
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import psycopg2
import requests
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score, classification_report, f1_score,
    precision_score, recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier

# ── Paths ──────────────────────────────────────────────────────────────────────
ROOT        = Path(__file__).resolve().parents[1]
AI_DIR      = ROOT / "AI"
ARTIFACTS_V4 = AI_DIR / "model_artifacts_v4"
NEW_ARTIFACTS = AI_DIR / "model_artifacts_v5"   # output of this run
BASE_CSV    = AI_DIR / "data" / "combine_v3.csv"  # original CICIDS training set

ML_RELOAD_URL = "http://127.0.0.1:8001/model/reload"

# ── DB ─────────────────────────────────────────────────────────────────────────
DB_CONFIG = {
    "host":     os.getenv("DB_HOST", "127.0.0.1"),
    "port":     int(os.getenv("DB_PORT", "5432")),
    "dbname":   os.getenv("DB_NAME", "ai_ids"),
    "user":     os.getenv("DB_USER", "aisec"),
    "password": os.getenv("DB_PASSWORD", "aisec_pass"),
}

# ── Attack-type → CICIDS class mapping ────────────────────────────────────────
ATTACK_TYPE_MAP: Dict[str, str] = {
    "benign":      "Benign",
    "ddos":        "DDoS",
    "dos":         "DoS",
    "port scan":   "Port Scan",
    "portscan":    "Port Scan",
    "bot":         "Bot",
    "brute force": "Brute Force",
    "bruteforce":  "Brute Force",
    "web attack":  "Web Attack",
    "webattack":   "Web Attack",
    "infiltration":"Infiltration",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("madrs-retrain")


# ── 1. Fetch new samples from DB ───────────────────────────────────────────────
def fetch_new_samples() -> pd.DataFrame:
    log.info("Connecting to PostgreSQL …")
    conn = psycopg2.connect(**DB_CONFIG)
    cur  = conn.cursor()
    cur.execute("""
        SELECT raw_features_json, true_label, attack_type
        FROM   ml_training_data
        WHERE  raw_features_json IS NOT NULL
    """)
    rows = cur.fetchall()
    cur.close(); conn.close()
    log.info("Fetched %d new labeled samples from DB", len(rows))

    records = []
    for raw_json, true_label, attack_type in rows:
        try:
            feats: Dict[str, float] = json.loads(raw_json)
        except (json.JSONDecodeError, TypeError):
            continue

        # Determine class label
        if true_label == "BENIGN":
            label = "Benign"
        else:
            key = (attack_type or "").lower().strip()
            label = ATTACK_TYPE_MAP.get(key, "Unknown")
            if label == "Unknown":
                continue        # skip classes we can't map yet

        feats["Label"] = label
        records.append(feats)

    if not records:
        return pd.DataFrame()
    return pd.DataFrame(records)


# ── 2. Load original CICIDS training CSV ──────────────────────────────────────
def load_base_csv(feature_names: List[str]) -> Optional[pd.DataFrame]:
    if not BASE_CSV.exists():
        log.warning("Base CSV not found: %s — retraining on new samples only", BASE_CSV)
        return None
    log.info("Loading base CSV: %s", BASE_CSV)
    df = pd.read_csv(BASE_CSV, low_memory=False)
    df.columns = df.columns.str.strip()
    missing = [c for c in feature_names if c not in df.columns and c != "Label"]
    if missing:
        log.warning("Base CSV missing %d features; they will be set to 0", len(missing))
        for c in missing:
            df[c] = 0.0
    return df


# ── 3. Train ensemble ──────────────────────────────────────────────────────────
def train_ensemble(
    X_train: pd.DataFrame, y_encoded: np.ndarray, le: LabelEncoder,
    scaler: StandardScaler, out_dir: Path,
) -> Tuple[XGBClassifier, LGBMClassifier]:

    X_scaled = scaler.transform(X_train)
    n_classes = len(le.classes_)

    log.info("Training XGBoost (n_classes=%d) …", n_classes)
    xgb = XGBClassifier(
        n_estimators=300, max_depth=10, learning_rate=0.08,
        use_label_encoder=False, eval_metric="mlogloss",
        n_jobs=-1, random_state=42,
        subsample=0.9, colsample_bytree=0.9,
    )
    xgb.fit(X_scaled, y_encoded)
    with open(out_dir / "xgb.pkl", "wb") as f:
        pickle.dump(xgb, f)
    log.info("XGBoost saved ✓")

    log.info("Training LightGBM …")
    lgbm = LGBMClassifier(
        n_estimators=250, max_depth=-1, num_leaves=63, learning_rate=0.07,
        n_jobs=-1, random_state=42, verbose=-1,
        subsample=0.9, colsample_bytree=0.9,
    )
    lgbm.fit(X_scaled, y_encoded)
    log.info("LightGBM trained ✓")
    return xgb, lgbm


# ── 4. Save all artifacts ──────────────────────────────────────────────────────
def save_artifacts(
    xgb, lgbm, iso, le, scaler, feature_names: List[str],
    metrics: Dict, out_dir: Path,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, obj in {
        "xgb.pkl": xgb, "lgbm.pkl": lgbm, "iso.pkl": iso,
        "label_encoder.pkl": le, "scaler.pkl": scaler,
        "feature_names.pkl": feature_names,
    }.items():
        with open(out_dir / name, "wb") as f:
            pickle.dump(obj, f)

    mitre_src = ARTIFACTS_V4 / "mitre_mapping.json"
    if mitre_src.exists():
        shutil.copy(mitre_src, out_dir / "mitre_mapping.json")

    with open(out_dir / "metrics.json", "w") as f:
        json.dump({k: v for k, v in metrics.items() if k != "report"}, f, indent=2)
    with open(out_dir / "classification_report.txt", "w") as f:
        f.write(metrics.get("report", ""))
    log.info("Artifacts written → %s", out_dir)


# ── 5. Signal ML service to hot-reload ────────────────────────────────────────
def notify_ml_service(new_dir: Path) -> None:
    try:
        r = requests.post(ML_RELOAD_URL, json={"artifacts_dir": str(new_dir)}, timeout=10)
        if r.ok:
            log.info("ML service reloaded ✓")
        else:
            log.warning("ML service reload returned %d — restart manually", r.status_code)
    except Exception as e:
        log.warning("Could not reach ML service (%s) — restart manually", e)


# ── Main ───────────────────────────────────────────────────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser(description="MADRS auto-retraining pipeline")
    ap.add_argument("--min-new", type=int, default=50,
                    help="Minimum new samples required to trigger retraining (default 50)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Fetch and report only — do not retrain")
    args = ap.parse_args()

    log.info("=" * 60)
    log.info("MADRS Retrain  —  %s", datetime.now(timezone.utc).isoformat())
    log.info("=" * 60)

    # --- load new samples ---
    new_df = fetch_new_samples()
    if new_df.empty or len(new_df) < args.min_new:
        log.info(
            "Not enough new samples (%d < %d required). Skipping retraining.",
            len(new_df), args.min_new,
        )
        sys.exit(0)

    if args.dry_run:
        log.info("DRY RUN — would retrain on %d new samples. Exiting.", len(new_df))
        log.info("Label distribution:\n%s", new_df["Label"].value_counts().to_string())
        sys.exit(0)

    # --- load current feature list ---
    with open(ARTIFACTS_V4 / "feature_names.pkl", "rb") as f:
        feature_names: List[str] = pickle.load(f)

    # --- merge base CSV + new samples ---
    base_df = load_base_csv(feature_names)
    if base_df is not None:
        combined = pd.concat([base_df, new_df], ignore_index=True, sort=False)
        log.info("Combined dataset: %d rows (base=%d, new=%d)",
                 len(combined), len(base_df), len(new_df))
    else:
        combined = new_df
        log.info("Using new samples only: %d rows", len(combined))

    combined = combined.dropna(subset=["Label"])
    combined = combined.fillna(0)

    # align columns
    for col in feature_names:
        if col not in combined.columns:
            combined[col] = 0.0
    X = combined[feature_names]
    y = combined["Label"]

    log.info("Class distribution:\n%s", y.value_counts().to_string())

    # --- encode & scale ---
    le = LabelEncoder()
    y_enc = le.fit_transform(y)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # --- train/test split ---
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y_enc, test_size=0.2, stratify=y_enc, random_state=42
    )
    log.info("Train=%d  Test=%d  Features=%d", len(X_tr), len(X_te), len(feature_names))

    # --- train ---
    xgb, lgbm = train_ensemble(X_tr, y_tr, le, scaler, NEW_ARTIFACTS)

    # --- anomaly head ---
    log.info("Training IsolationForest …")
    iso = IsolationForest(n_estimators=100, contamination=0.05, random_state=42, n_jobs=-1)
    iso.fit(scaler.transform(X_tr))

    # --- evaluate ---
    X_te_sc = scaler.transform(X_te)
    xgb_p   = xgb.predict_proba(X_te_sc)
    lgbm_p  = lgbm.predict_proba(X_te_sc)
    proba   = (xgb_p + lgbm_p) / 2
    y_pred  = proba.argmax(axis=1)

    metrics = {
        "accuracy":         float(accuracy_score(y_te, y_pred)),
        "f1_macro":         float(f1_score(y_te, y_pred, average="macro", zero_division=0)),
        "f1_weighted":      float(f1_score(y_te, y_pred, average="weighted", zero_division=0)),
        "precision_macro":  float(precision_score(y_te, y_pred, average="macro", zero_division=0)),
        "recall_macro":     float(recall_score(y_te, y_pred, average="macro", zero_division=0)),
        "labels":           list(le.classes_),
        "new_samples_used": len(new_df),
        "retrained_at":     datetime.now(timezone.utc).isoformat(),
        "report":           classification_report(y_te, y_pred,
                                target_names=le.classes_, zero_division=0),
    }
    log.info("Accuracy=%.4f  F1_macro=%.4f", metrics["accuracy"], metrics["f1_macro"])
    log.info("\n" + metrics["report"])

    # --- save ---
    save_artifacts(xgb, lgbm, iso, le, scaler, feature_names, metrics, NEW_ARTIFACTS)

    # --- notify ML service ---
    notify_ml_service(NEW_ARTIFACTS)
    log.info("Retraining complete ✓")


if __name__ == "__main__":
    main()
