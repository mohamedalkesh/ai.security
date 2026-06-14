"""
Production-ready IDS pipeline for CICIDS2017.

Features:
1) Load Monday/Tuesday/Wednesday/Friday CSV files (or any CICIDS CSV path)
2) Merge and save combined dataset as combined.csv
3) Clean NaN/Inf and normalize labels
4) Keep only: Benign, DDoS, Brute Force, Port Scan
5) Balance train data using SMOTE
6) Train XGBoost classifier
7) Evaluate with Accuracy/Precision/Recall/F1 + confusion matrix + classification report
8) Plot feature importance
9) Predict with detailed MITRE ATT&CK mapping + confidence filtering
"""

from __future__ import annotations

import argparse
import logging
import os
import pickle
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from imblearn.over_sampling import SMOTE
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
from xgboost import XGBClassifier


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


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


LABEL_MAP: Dict[str, str] = {
    "benign": "Benign",
    "Benign": "Benign",
    "BENIGN": "Benign",
    "ftp-patator": "Brute Force",
    "FTP-Patator": "Brute Force",
    "ssh-patator": "Brute Force",
    "SSH-Patator": "Brute Force",
    "ddos": "DDoS",
    "DDoS": "DDoS",
    "dos hulk": "DDoS",
    "DoS Hulk": "DDoS",
    "dos goldeneye": "DDoS",
    "DoS GoldenEye": "DDoS",
    "dos slowloris": "DDoS",
    "DoS slowloris": "DDoS",
    "dos slowhttptest": "DDoS",
    "DoS Slowhttptest": "DDoS",
    "heartbleed": "DDoS",
    "Heartbleed": "DDoS",
    "portscan": "Port Scan",
    "PortScan": "Port Scan",
}

ALLOWED_LABELS = {"Benign", "Brute Force", "DDoS", "Port Scan"}
REQUIRED_DAYS = ("monday", "tuesday", "wednesday", "friday")


def load_data(data_path: str) -> List[pd.DataFrame]:
    """
    Load CICIDS CSV files.

    - If data_path is a file: load that file only.
    - If data_path is a directory: load CSV files, prioritizing Monday/Tuesday/
      Wednesday/Friday files when available.
    """
    path = Path(data_path)
    if not path.exists():
        raise FileNotFoundError(f"Path not found: {data_path}")

    if path.is_file():
        logger.info("Loading single CSV file: %s", path)
        return [pd.read_csv(path, low_memory=False)]

    csv_files = sorted(path.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in directory: {data_path}")

    day_filtered = [f for f in csv_files if any(day in f.name.lower() for day in REQUIRED_DAYS)]
    selected_files = day_filtered if day_filtered else csv_files

    logger.info("Loading %d CSV files from %s", len(selected_files), path)
    for file in selected_files:
        logger.info(" - %s", file.name)

    return [pd.read_csv(file, low_memory=False) for file in selected_files]


def merge_data(dataframes: List[pd.DataFrame], output_path: str = "./combined.csv") -> pd.DataFrame:
    """Merge multiple CICIDS DataFrames and save to combined.csv."""
    if not dataframes:
        raise ValueError("No dataframes were loaded to merge.")

    if len(dataframes) == 1 and output_path and os.path.exists(output_path):
        merged_df = dataframes[0]
        logger.info("Single dataset already at %s (shape=%s)", output_path, merged_df.shape)
        return merged_df

    merged_df = pd.concat(dataframes, ignore_index=True)
    if output_path:
        merged_df.to_csv(output_path, index=False)
    logger.info("Merged dataset shape=%s", merged_df.shape)
    return merged_df


def clean_data(df: pd.DataFrame, sample_frac: Optional[float] = None, random_state: int = 42) -> pd.DataFrame:
    """Clean and normalize dataset."""
    logger.info("Starting data cleaning")
    data = df.copy()
    data.columns = data.columns.str.strip()

    label_col = None
    for candidate in ["Label", "label", "LABEL", "Class", "class"]:
        if candidate in data.columns:
            label_col = candidate
            break
    if label_col is None:
        raise ValueError("Label column not found. Expected one of: Label/label/Class/class")

    data = data.rename(columns={label_col: "Label"})
    data = data.dropna(how="all", axis=0).dropna(how="all", axis=1)

    numeric_cols = data.select_dtypes(include=[np.number]).columns.tolist()
    if not numeric_cols:
        raise ValueError("No numeric feature columns found in dataset.")

    data[numeric_cols] = data[numeric_cols].replace([np.inf, -np.inf], np.nan)
    data = data.dropna(subset=numeric_cols + ["Label"])

    data["Label"] = data["Label"].astype(str).str.strip().map(LABEL_MAP)
    pre_filter = len(data)
    data = data.dropna(subset=["Label"])
    data = data[data["Label"].isin(ALLOWED_LABELS)]
    logger.info("Dropped %d rows outside target classes", pre_filter - len(data))

    data = data[numeric_cols + ["Label"]]

    if sample_frac is not None:
        if not (0 < sample_frac <= 1):
            raise ValueError("sample_frac must be in range (0, 1].")
        data = data.sample(frac=sample_frac, random_state=random_state)
        logger.info("Applied sampling: sample_frac=%s => shape=%s", sample_frac, data.shape)

    logger.info("Cleaned dataset shape: %s", data.shape)
    logger.info("Class distribution:\n%s", data["Label"].value_counts())
    return data


def prepare_features(data: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    X = data.drop(columns=["Label"]).select_dtypes(include=[np.number])
    y = data["Label"]
    logger.info("Prepared features: X=%s, y=%d", X.shape, len(y))
    return X, y


def split_data(X, y, test_size: float = 0.2, random_state: int = 42):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )
    logger.info("Split complete: train=%d, test=%d", len(X_train), len(X_test))
    return X_train, X_test, y_train, y_test


def train_model(X_train, y_train, n_estimators=200, max_depth=10, learning_rate=0.1, random_state=42, n_jobs=-1):
    """Train XGBoost with SMOTE balancing."""
    label_encoder = LabelEncoder()
    y_train_encoded = label_encoder.fit_transform(y_train)

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    smote = SMOTE(random_state=random_state)
    X_resampled, y_resampled = smote.fit_resample(X_train_scaled, y_train_encoded)
    logger.info("After SMOTE: X=%s, classes=%s", X_resampled.shape, pd.Series(y_resampled).value_counts().to_dict())

    model = XGBClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        learning_rate=learning_rate,
        objective="multi:softprob",
        eval_metric="mlogloss",
        random_state=random_state,
        n_jobs=n_jobs,
        subsample=0.9,
        colsample_bytree=0.9,
    )
    model.fit(X_resampled, y_resampled)
    logger.info("XGBoost model training complete")
    return model, label_encoder, scaler


def evaluate_model(model, label_encoder, scaler, X_test, y_test, save_cm_path=None):
    X_test_scaled = scaler.transform(X_test)
    y_pred_encoded = model.predict(X_test_scaled)
    y_pred = label_encoder.inverse_transform(y_pred_encoded)

    labels = label_encoder.classes_.tolist()
    cm = confusion_matrix(y_test, y_pred, labels=labels)
    report_text = classification_report(y_test, y_pred, zero_division=0)

    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, average="macro", zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, average="macro", zero_division=0)),
        "f1_score": float(f1_score(y_test, y_pred, average="macro", zero_division=0)),
        "labels": labels,
        "confusion_matrix": cm.tolist(),
        "classification_report_text": report_text,
    }

    logger.info("Accuracy : %.4f", metrics["accuracy"])
    logger.info("Precision: %.4f", metrics["precision"])
    logger.info("Recall   : %.4f", metrics["recall"])
    logger.info("F1-Score : %.4f", metrics["f1_score"])

    if save_cm_path:
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=labels, yticklabels=labels)
        plt.title("Confusion Matrix")
        plt.xlabel("Predicted")
        plt.ylabel("True")
        plt.tight_layout()
        plt.savefig(save_cm_path)
        plt.close()
        logger.info("Confusion matrix saved to %s", save_cm_path)

    return metrics


def plot_feature_importance(model, feature_names, output_path="./feature_importance.png", top_n=25):
    importance = model.feature_importances_
    df = pd.DataFrame({"feature": feature_names, "importance": importance})
    df = df.sort_values(by="importance", ascending=False).head(top_n)

    plt.figure(figsize=(10, 8))
    sns.barplot(data=df, x="importance", y="feature", orient="h")
    plt.title(f"Top {top_n} Feature Importances")
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()
    logger.info("Feature importance saved to %s", output_path)


def predict_attack(model, label_encoder, scaler, sample, confidence_threshold=0.6):
    if sample.ndim == 1:
        sample = sample.reshape(1, -1)
    sample_scaled = scaler.transform(sample)
    probabilities = model.predict_proba(sample_scaled)[0]
    pred_idx = int(np.argmax(probabilities))
    confidence = float(np.max(probabilities))
    attack_type = label_encoder.inverse_transform([pred_idx])[0]
    if confidence < confidence_threshold:
        attack_type = "Unknown"
    mitre = MITRE_MAPPING.get(attack_type, MITRE_MAPPING["Unknown"])
    return {
        "attack_type": attack_type,
        "confidence": round(confidence, 4),
        "mitre_technique": mitre["technique"],
        "mitre_tactic": mitre["tactic"],
        "description": mitre["description"],
        "severity": mitre["severity"],
    }


def save_artifacts(model, label_encoder, scaler, feature_names, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, "model.pkl"), "wb") as f:
        pickle.dump(model, f)
    with open(os.path.join(output_dir, "label_encoder.pkl"), "wb") as f:
        pickle.dump(label_encoder, f)
    with open(os.path.join(output_dir, "scaler.pkl"), "wb") as f:
        pickle.dump(scaler, f)
    with open(os.path.join(output_dir, "feature_names.pkl"), "wb") as f:
        pickle.dump(feature_names, f)
    logger.info("Artifacts saved to %s", output_dir)


def parse_args():
    parser = argparse.ArgumentParser(description="CICIDS2017 IDS pipeline (SMOTE + XGBoost + MITRE)")
    parser.add_argument("--data-path", type=str, default="./data/combine.csv")
    parser.add_argument("--combined-output", type=str, default="./data/combine.csv")
    parser.add_argument("--sample-frac", type=float, default=None)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--n-estimators", type=int, default=200)
    parser.add_argument("--max-depth", type=int, default=10)
    parser.add_argument("--learning-rate", type=float, default=0.1)
    parser.add_argument("--confidence-threshold", type=float, default=0.6)
    parser.add_argument("--cm-path", type=str, default="./confusion_matrix.png")
    parser.add_argument("--fi-path", type=str, default="./feature_importance.png")
    parser.add_argument("--artifacts-dir", type=str, default="./model_artifacts")
    return parser.parse_args()


def main():
    args = parse_args()

    dataframes = load_data(args.data_path)
    merged_df = merge_data(dataframes, output_path=args.combined_output)
    clean_df = clean_data(merged_df, sample_frac=args.sample_frac)

    X, y = prepare_features(clean_df)
    feature_names = X.columns.tolist()

    X_train, X_test, y_train, y_test = split_data(X, y, test_size=args.test_size)
    model, label_encoder, scaler = train_model(
        X_train, y_train,
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        learning_rate=args.learning_rate,
    )

    metrics = evaluate_model(model, label_encoder, scaler, X_test, y_test, save_cm_path=args.cm_path)
    plot_feature_importance(model, feature_names, output_path=args.fi_path)

    print("\n========== EVALUATION ==========")
    print(f"Accuracy : {metrics['accuracy']:.4f}")
    print(f"Precision: {metrics['precision']:.4f}")
    print(f"Recall   : {metrics['recall']:.4f}")
    print(f"F1-Score : {metrics['f1_score']:.4f}")
    print("\nClassification Report:")
    print(metrics["classification_report_text"])

    save_artifacts(model, label_encoder, scaler, feature_names, output_dir=args.artifacts_dir)

    sample = X_test.iloc[0].values
    prediction = predict_attack(model, label_encoder, scaler, sample, confidence_threshold=args.confidence_threshold)

    print("========== SAMPLE PREDICTION ==========")
    print(prediction)


if __name__ == "__main__":
    main()
