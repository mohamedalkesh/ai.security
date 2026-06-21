#!/usr/bin/env python3
"""
Train IDS v6 — 7-class model on CICIDS2017.

Improvements over v5:
  1. SMOTE oversampling: Bot (1948→8000) and XSS (2143→8000) — fixes low Bot precision
  2. Stronger models: XGBoost 500 trees, LightGBM 400 trees, better regularisation
  3. Weighted ensemble: optimal XGB/LGBM blend weights learned on VALIDATION set (no leakage)
  4. Per-class confidence thresholds: tuned on validation set, evaluated on held-out test set
     → saved to runtime_config.json for the ML service to load at runtime
  5. Proper 60/20/20 train/val/test split — weights and thresholds never see the test set

Expected: Bot precision 93% → 96%+, overall F1-macro stays ≥ 99.3%
"""
import json, logging, pickle, time
import numpy as np
import pandas as pd
from pathlib import Path
from scipy.optimize import minimize
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score, classification_report, f1_score,
    precision_score, recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.utils.class_weight import compute_sample_weight
from imblearn.over_sampling import SMOTE
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

ROOT = Path(__file__).parent
DATA = ROOT / "data"
OUT  = ROOT / "model_artifacts_v6"

ALLOWED = {"Benign", "DDoS", "DoS", "Port Scan", "Bot", "Brute Force", "XSS"}

CICIDS_MAP = {
    "Normal Traffic":               "Benign",
    "DoS":                          "DoS",
    "DDoS":                         "DDoS",
    "Port Scanning":                "Port Scan",
    "Brute Force":                  "Brute Force",
    "Web Attacks":                  "XSS",
    "Bots":                         "Bot",
    "BENIGN":                       "Benign",
    "DoS Hulk":                     "DoS",
    "DoS GoldenEye":                "DoS",
    "DoS slowloris":                "DoS",
    "DoS Slowhttptest":             "DoS",
    "Heartbleed":                   "DoS",
    "PortScan":                     "Port Scan",
    "Bot":                          "Bot",
    "FTP-Patator":                  "Brute Force",
    "SSH-Patator":                  "Brute Force",
    "Web Attack - Brute Force":     "Brute Force",
    "Web Attack - XSS":             "XSS",
    "Web Attack - SQL Injection":   "XSS",
    "Infiltration":                 "Brute Force",
}

MITRE = {
    "Benign":      {"technique":"N/A",       "tactic":"N/A",                "severity":"Informational","description":"Normal network traffic."},
    "DDoS":        {"technique":"T1498",      "tactic":"Impact",             "severity":"High",         "description":"Volumetric DDoS flood."},
    "DoS":         {"technique":"T1499",      "tactic":"Impact",             "severity":"High",         "description":"Application-layer DoS."},
    "Port Scan":   {"technique":"T1046",      "tactic":"Discovery",          "severity":"Medium",       "description":"Network port enumeration."},
    "Bot":         {"technique":"T1071",      "tactic":"Command and Control","severity":"High",         "description":"Botnet C2 communication."},
    "Brute Force": {"technique":"T1110",      "tactic":"Credential Access",  "severity":"High",         "description":"Credential brute force attack."},
    "XSS":         {"technique":"T1059.007", "tactic":"Execution",           "severity":"High",         "description":"Cross-site scripting attack."},
    "SQL Injection":{"technique":"T1190",    "tactic":"Initial Access",      "severity":"Critical",     "description":"SQL injection exploitation."},
    "Infiltration":{"technique":"T1133",     "tactic":"Initial Access",      "severity":"Critical",     "description":"System infiltration / backdoor."},
    "Ransomware":  {"technique":"T1486",     "tactic":"Impact",              "severity":"Critical",     "description":"Ransomware data encryption."},
    "DNS Tunneling":{"technique":"T1071.004","tactic":"Command and Control", "severity":"High",         "description":"DNS-based covert channel."},
    "ICMP Flood":  {"technique":"T1498.001", "tactic":"Impact",              "severity":"Medium",       "description":"ICMP ping flood."},
    "Unknown":     {"technique":"Unknown",   "tactic":"Unknown",             "severity":"Low",          "description":"Out-of-distribution traffic."},
}

# ── Sampling strategy ─────────────────────────────────────────────────────────
# Major classes: capped so they don't drown minority classes after SMOTE.
# Minor classes: ALL available rows (SMOTE will oversample them later).
MAJOR_CAP   = 60_000   # max rows per dominant class
SMOTE_TARGET = 8_000   # post-SMOTE target for minority classes


def load_cicids(path: Path, seed: int = 42) -> pd.DataFrame:
    log.info("Loading CICIDS2017 from %s ...", path)
    df = pd.read_csv(path, low_memory=False)
    df.columns = df.columns.str.strip()

    label_col = "Attack Type" if "Attack Type" in df.columns else "Label"
    df["Label"] = df[label_col].map(CICIDS_MAP)
    df = df[df["Label"].isin(ALLOWED)].copy()

    if label_col != "Label":
        df = df.drop(columns=[label_col])

    num = df.select_dtypes(include=[np.number]).columns.tolist()
    df[num] = df[num].replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=num)[num + ["Label"]]

    log.info("Raw counts:\n%s", df["Label"].value_counts().to_string())

    # Sample major classes to avoid imbalance bloat; keep ALL minor class rows.
    parts = []
    for cls, grp in df.groupby("Label"):
        if len(grp) > MAJOR_CAP:
            parts.append(grp.sample(n=MAJOR_CAP, random_state=seed))
        else:
            parts.append(grp)
    df = pd.concat(parts).sample(frac=1, random_state=seed).reset_index(drop=True)

    log.info("After capping:\n%s", df["Label"].value_counts().to_string())
    return df


# ── Training ──────────────────────────────────────────────────────────────────
def train_model(df: pd.DataFrame, seed: int = 42):
    X = df.drop(columns=["Label"])
    y = df["Label"]
    feature_names = X.columns.tolist()
    log.info("Features: %d | Samples: %d", len(feature_names), len(df))

    X = X.replace([np.inf, -np.inf], np.nan).fillna(0).clip(-1e12, 1e12)

    # 60% train / 20% val (threshold + weight tuning) / 20% test (final eval only)
    X_tmp, X_test, y_tmp, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=seed)
    X_train, X_val, y_train, y_val = train_test_split(
        X_tmp, y_tmp, test_size=0.25, stratify=y_tmp, random_state=seed)

    le = LabelEncoder()
    y_tr  = le.fit_transform(y_train)
    y_val_enc = le.transform(y_val)
    y_te  = le.transform(y_test)

    sc = StandardScaler()
    Xtr  = sc.fit_transform(X_train)
    Xval = sc.transform(X_val)
    Xte  = sc.transform(X_test)

    # ── SMOTE: oversample minority classes on training set only ───────────────
    class_counts = pd.Series(y_tr).value_counts()
    smote_strategy = {}
    for cls_idx, cls_name in enumerate(le.classes_):
        count = class_counts.get(cls_idx, 0)
        if 0 < count < SMOTE_TARGET:
            smote_strategy[cls_idx] = SMOTE_TARGET
            log.info("  SMOTE: %s %d → %d", cls_name, count, SMOTE_TARGET)

    if smote_strategy:
        k_neighbors = min(5, min(class_counts[k] for k in smote_strategy) - 1)
        k_neighbors = max(1, k_neighbors)
        smote = SMOTE(sampling_strategy=smote_strategy,
                      k_neighbors=k_neighbors, random_state=seed)
        Xtr, y_tr = smote.fit_resample(Xtr, y_tr)
        log.info("After SMOTE — training set size: %d", len(y_tr))
        log.info("Class distribution:\n%s",
                 pd.Series(le.inverse_transform(y_tr)).value_counts().to_string())

    sample_weights = compute_sample_weight("balanced", y_tr)

    # ── XGBoost ───────────────────────────────────────────────────────────────
    log.info("Training XGBoost (500 trees) ...")
    t0 = time.time()
    xgb = XGBClassifier(
        n_estimators=500,
        max_depth=8,
        learning_rate=0.07,
        subsample=0.85,
        colsample_bytree=0.85,
        min_child_weight=3,
        reg_alpha=0.1,
        reg_lambda=1.0,
        eval_metric="mlogloss",
        n_jobs=-1,
        random_state=seed,
    )
    xgb.fit(Xtr, y_tr, sample_weight=sample_weights)
    log.info("XGBoost done in %.0fs", time.time() - t0)

    # ── LightGBM ──────────────────────────────────────────────────────────────
    log.info("Training LightGBM (400 trees) ...")
    t0 = time.time()
    lgbm = LGBMClassifier(
        n_estimators=400,
        num_leaves=127,
        learning_rate=0.06,
        subsample=0.85,
        colsample_bytree=0.85,
        min_child_samples=20,
        reg_alpha=0.1,
        reg_lambda=1.0,
        class_weight="balanced",
        n_jobs=-1,
        random_state=seed,
        verbose=-1,
    )
    lgbm.fit(Xtr, y_tr)
    log.info("LightGBM done in %.0fs", time.time() - t0)

    # ── IsolationForest ───────────────────────────────────────────────────────
    log.info("Training IsolationForest ...")
    iso = IsolationForest(n_estimators=150, contamination=0.05,
                          random_state=seed, n_jobs=-1)
    iso.fit(Xtr)

    # ── Optimal ensemble weights (tuned on val, never on test) ────────────────
    log.info("Optimising ensemble weights on validation set ...")
    xgb_val_proba  = xgb.predict_proba(Xval)
    lgbm_val_proba = lgbm.predict_proba(Xval)

    def neg_f1_macro(w: np.ndarray) -> float:
        w = np.abs(w) / (np.abs(w).sum() + 1e-9)
        combined = w[0] * xgb_val_proba + w[1] * lgbm_val_proba
        preds = combined.argmax(axis=1)
        return -float(f1_score(y_val_enc, preds, average="macro", zero_division=0))

    res = minimize(neg_f1_macro, x0=np.array([0.5, 0.5]), method="Nelder-Mead",
                   options={"xatol": 1e-4, "fatol": 1e-4, "maxiter": 200})
    w = np.abs(res.x) / (np.abs(res.x).sum() + 1e-9)
    xgb_w, lgbm_w = float(w[0]), float(w[1])
    log.info("Optimal weights: XGBoost=%.3f  LightGBM=%.3f", xgb_w, lgbm_w)

    val_proba = xgb_w * xgb_val_proba + lgbm_w * lgbm_val_proba

    # ── Per-class threshold optimisation (on val set) ─────────────────────────
    log.info("Optimising per-class thresholds on validation set ...")
    per_class_thresholds: dict = {}
    for i, cls in enumerate(le.classes_):
        y_bin = (y_val_enc == i).astype(int)
        best_f1, best_thr = 0.0, 0.5
        for thr in np.arange(0.30, 0.97, 0.01):
            preds_bin = (val_proba[:, i] >= thr).astype(int)
            prec = precision_score(y_bin, preds_bin, zero_division=0)
            rec  = recall_score(y_bin, preds_bin, zero_division=0)
            f1   = 2 * prec * rec / (prec + rec + 1e-9)
            if f1 > best_f1:
                best_f1, best_thr = f1, float(thr)

        per_class_thresholds[cls] = round(best_thr, 3)
        log.info("  %-15s threshold=%.3f  val-F1=%.4f", cls, best_thr, best_f1)

    # ── Final evaluation on held-out test set (no tuning done here) ───────────
    test_proba = xgb_w * xgb.predict_proba(Xte) + lgbm_w * lgbm.predict_proba(Xte)
    y_pred = []
    for row_proba in test_proba:
        best_label, best_p = le.classes_[0], -1.0
        for i, cls in enumerate(le.classes_):
            thr = per_class_thresholds[cls]
            if row_proba[i] >= thr and row_proba[i] > best_p:
                best_p, best_label = row_proba[i], cls
        y_pred.append(le.transform([best_label])[0])
    y_pred = np.array(y_pred)

    acc = accuracy_score(y_te, y_pred)
    f1  = f1_score(y_te, y_pred, average="macro", zero_division=0)
    rep = classification_report(y_te, y_pred, target_names=le.classes_,
                                 zero_division=0, digits=4)
    log.info("Accuracy=%.4f  F1-macro=%.4f", acc, f1)
    log.info("\n%s", rep)

    return xgb, lgbm, iso, le, sc, feature_names, {
        "accuracy": float(acc),
        "f1_macro": float(f1),
        "labels": list(le.classes_),
        "report": rep,
        "xgb_weight": xgb_w,
        "lgbm_weight": lgbm_w,
        "per_class_thresholds": per_class_thresholds,
    }


# ── Save ──────────────────────────────────────────────────────────────────────
def save_artifacts(xgb, lgbm, iso, le, sc, fn, metrics):
    OUT.mkdir(exist_ok=True)
    for name, obj in {
        "xgb.pkl": xgb, "lgbm.pkl": lgbm, "iso.pkl": iso,
        "label_encoder.pkl": le, "scaler.pkl": sc, "feature_names.pkl": fn,
    }.items():
        with open(OUT / name, "wb") as f:
            pickle.dump(obj, f)

    with open(OUT / "mitre_mapping.json", "w") as f:
        json.dump(MITRE, f, indent=2, ensure_ascii=False)

    metrics_out = {k: v for k, v in metrics.items() if k != "report"}
    with open(OUT / "metrics.json", "w") as f:
        json.dump(metrics_out, f, indent=2)

    with open(OUT / "classification_report.txt", "w") as f:
        f.write(metrics["report"])

    # Per-class thresholds and ensemble weights — loaded by ml_service at runtime
    runtime_cfg = {
        "per_class_thresholds": metrics["per_class_thresholds"],
        "ensemble_weights": {
            "xgb": metrics["xgb_weight"],
            "lgbm": metrics["lgbm_weight"],
        },
    }
    with open(OUT / "runtime_config.json", "w") as f:
        json.dump(runtime_cfg, f, indent=2)

    log.info("Artifacts saved → %s", OUT)
    log.info("runtime_config.json: %s", runtime_cfg)


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    cicids_path = DATA / "cicids2017/cicids2017_cleaned.csv"
    if not cicids_path.exists():
        raise RuntimeError(f"CICIDS2017 not found: {cicids_path}")

    df = load_cicids(cicids_path)
    log.info("Final dataset: %d rows | %d features", len(df), len(df.columns) - 1)

    xgb, lgbm, iso, le, sc, fn, metrics = train_model(df)
    save_artifacts(xgb, lgbm, iso, le, sc, fn, metrics)

    log.info("=" * 60)
    log.info("v6 training complete!")
    log.info("F1-macro: %.4f", metrics["f1_macro"])
    log.info("Per-class thresholds: %s", metrics["per_class_thresholds"])
    log.info("Ensemble weights: XGB=%.3f  LGBM=%.3f",
             metrics["xgb_weight"], metrics["lgbm_weight"])
