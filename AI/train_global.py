#!/usr/bin/env python3
"""Global training pipeline spanning multiple public IDS datasets.

1. Loads one or more processed CSV/Parquet files (output of tools/prepare_dataset.py).
2. Normalises labels via LabelMap (per-source dataset if available).
3. Trains the existing ensemble (XGBoost + LightGBM + IsolationForest).
4. Persists artifacts under AI/model_artifacts_global_v1 and logs metrics.
"""

from __future__ import annotations

import argparse
import glob
import json
import logging
import pickle
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Sequence

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

import ids_pipeline_v3 as base_pipeline
from labeling_utils import LabelMap

LOGGER = logging.getLogger("train-global")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

AI_DIR = Path(__file__).resolve().parent
DEFAULT_FEATURE_PATH = AI_DIR / "model_artifacts_v3" / "feature_names.pkl"
DEFAULT_LABEL_MAP = AI_DIR / "datasets" / "label_map.yaml"
DEFAULT_OUTPUT_DIR = AI_DIR / "model_artifacts_global_v1"
DEFAULT_REPORT_DIR = AI_DIR / "reports" / "training"

MITRE_MAPPING = dict(base_pipeline.MITRE_MAPPING)
MITRE_MAPPING.update(
    {
        "ICMP Flood": {
            "technique": "T1498.001",
            "tactic": "Impact",
            "severity": "High",
            "description": "ICMP echo flood saturating the target with Layer-3 traffic.",
        },
        "ICMP Sweep": {
            "technique": "T1018",
            "tactic": "Discovery",
            "severity": "Medium",
            "description": "ICMP ping sweep probing many hosts to map live systems on the network.",
        },
    }
)


# ---------------------------------------------------------------------------
def load_feature_names(path: Path) -> List[str]:
    with open(path, "rb") as fh:
        names = pickle.load(fh)
    if not isinstance(names, list):
        raise ValueError(f"Feature file {path} did not contain a list")
    return names


def expand_files(patterns: Sequence[str]) -> List[Path]:
    files: List[Path] = []
    for pattern in patterns:
        files.extend(Path(p).resolve() for p in glob.glob(pattern))
    deduped = sorted(dict.fromkeys(files))
    return deduped


def read_table(path: Path) -> pd.DataFrame:
    if path.suffix.lower() in {".parquet", ".pq"}:
        return pd.read_parquet(path)
    return pd.read_csv(path)


def normalise_labels(
    df: pd.DataFrame,
    label_map: LabelMap | None,
    label_col: str,
    dataset_col: str,
) -> pd.DataFrame:
    if label_col not in df.columns or label_map is None:
        return df
    dataset_keys = df[dataset_col].tolist() if dataset_col in df.columns else None
    labels = df[label_col].astype(str).tolist()
    df[label_col] = label_map.normalise_many(labels, dataset_keys=dataset_keys)
    return df


def cap_per_class(df: pd.DataFrame, label_col: str, cap: int, seed: int) -> pd.DataFrame:
    if cap <= 0:
        return df
    LOGGER.info("Applying per-class cap=%d", cap)
    capped = (
        df.groupby(label_col, group_keys=False)
        .apply(lambda g: g.sample(n=min(len(g), cap), random_state=seed) if len(g) > cap else g)
        .reset_index(drop=True)
    )
    return capped


def ensure_numeric(df: pd.DataFrame, feature_names: Sequence[str]) -> pd.DataFrame:
    missing = [col for col in feature_names if col not in df.columns]
    if missing:
        raise ValueError(f"Dataset missing {len(missing)} required features (e.g. {missing[:5]})")
    numeric = df.loc[:, feature_names].apply(pd.to_numeric, errors="coerce")
    mask = numeric.notnull().all(axis=1)
    dropped = len(df) - mask.sum()
    if dropped:
        LOGGER.warning("Dropped %d rows due to NaNs / inf in feature columns", dropped)
    df = df.loc[mask].copy()
    df.loc[:, feature_names] = numeric.loc[mask]
    return df


def save_artifacts(
    xgb,
    lgbm,
    iso,
    le,
    scaler,
    feature_names,
    metrics,
    out_dir: Path,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "xgb.pkl": xgb,
        "lgbm.pkl": lgbm,
        "iso.pkl": iso,
        "label_encoder.pkl": le,
        "scaler.pkl": scaler,
        "feature_names.pkl": feature_names,
    }
    for name, obj in payload.items():
        with open(out_dir / name, "wb") as fh:
            pickle.dump(obj, fh)
    with open(out_dir / "mitre_mapping.json", "w") as fh:
        json.dump(MITRE_MAPPING, fh, indent=2)
    metrics_copy = {k: v for k, v in metrics.items() if k != "report"}
    with open(out_dir / "metrics.json", "w") as fh:
        json.dump(metrics_copy, fh, indent=2)
    with open(out_dir / "classification_report.txt", "w") as fh:
        fh.write(metrics["report"])
    LOGGER.info("Artifacts saved to %s", out_dir)


def write_training_report(
    metrics: dict,
    dataset_files: Sequence[Path],
    args: argparse.Namespace,
    report_dir: Path,
) -> None:
    report_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")
    payload = {
        "timestamp": timestamp,
        "dataset_files": [str(p) for p in dataset_files],
        "dataset_globs": args.dataset_glob,
        "test_size": args.test_size,
        "per_class_cap": args.per_class_cap,
        "metrics": {k: v for k, v in metrics.items() if k != "report"},
    }
    with open(report_dir / f"{timestamp}.json", "w") as fh:
        json.dump(payload, fh, indent=2)
    LOGGER.info("Training report written to %s", report_dir)


# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train global IDS ensemble")
    parser.add_argument(
        "--dataset-glob",
        action="append",
        default=[str(AI_DIR / "data" / "processed" / "*.csv")],
        help="Glob(s) pointing to processed datasets",
    )
    parser.add_argument("--label-column", default="label")
    parser.add_argument("--dataset-column", default="source_dataset")
    parser.add_argument("--feature-names", default=str(DEFAULT_FEATURE_PATH))
    parser.add_argument("--label-map", default=str(DEFAULT_LABEL_MAP))
    parser.add_argument("--artifacts-out", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument("--report-dir", default=str(DEFAULT_REPORT_DIR))
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--per-class-cap", type=int, default=0, help="Optional max samples per class")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    dataset_files = expand_files(args.dataset_glob)
    if not dataset_files:
        raise FileNotFoundError(f"No dataset files matched patterns: {args.dataset_glob}")
    LOGGER.info("Loading %d dataset file(s)", len(dataset_files))

    frames = []
    for path in dataset_files:
        df = read_table(path)
        df.columns = df.columns.str.strip()
        frames.append(df)
        LOGGER.info("Loaded %s -> %d rows", path, len(df))
    df = pd.concat(frames, ignore_index=True)
    LOGGER.info("Combined dataset size: %d rows", len(df))

    label_map = LabelMap.from_file(args.label_map) if args.label_map else None
    df = normalise_labels(df, label_map, args.label_column, args.dataset_column)
    if args.per_class_cap:
        df = cap_per_class(df, args.label_column, args.per_class_cap, args.random_state)

    feature_names = load_feature_names(Path(args.feature_names))
    df = ensure_numeric(df, feature_names)

    labels = df[args.label_column].astype(str).str.strip()
    LOGGER.info("Class distribution:\n%s", labels.value_counts())

    X = df[feature_names]
    y = labels

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=args.test_size,
        stratify=y,
        random_state=args.random_state,
    )
    LOGGER.info("Train=%d, Test=%d, Features=%d", len(X_train), len(X_test), len(feature_names))

    xgb, lgbm, le, scaler = base_pipeline.train_ensemble(
        X_train,
        y_train,
        random_state=args.random_state,
        checkpoint_dir=args.artifacts_out,
    )
    iso = base_pipeline.train_anomaly(scaler.transform(X_train), random_state=args.random_state)
    metrics = base_pipeline.evaluate(xgb, lgbm, le, scaler, X_test, y_test)

    save_artifacts(xgb, lgbm, iso, le, scaler, feature_names, metrics, Path(args.artifacts_out))
    write_training_report(metrics, dataset_files, args, Path(args.report_dir))


if __name__ == "__main__":  # pragma: no cover
    main()
