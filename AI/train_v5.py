#!/usr/bin/env python3
"""
Train IDS v5 — 7-class model on CICIDS2017 (52 CICFlowMeter features).

Trained exclusively on CICIDS features because the production ML service
generates CICFlowMeter-style features from PCAP files. NF-UQ features
(NetFlow v9) would always be zero at inference, causing feature mismatch.

Classes: Benign, Bot, Brute Force, DDoS, DoS, Port Scan, XSS
Extra attack families (Ransomware, Lateral Movement, DNS Tunneling) are
covered by the hybrid rule engine in ml_service.py.
"""
import json, logging, pickle, time
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

ROOT = Path("/home/mohamed/Desktop/cos/AI")
DATA = ROOT / "data"
OUT  = ROOT / "model_artifacts_v5"

# ── Label maps ────────────────────────────────────────────────────────────────
NFUQ_MAP = {
    # Actual labels in NF-UQ-NIDS-v2.csv
    "Benign":        "Benign",
    "DDoS":          "DDoS",
    "DoS":           "DoS",
    "scanning":      "Port Scan",
    "Reconnaissance":"Port Scan",
    "xss":           "XSS",
    "password":      "Brute Force",
    "injection":     "SQL Injection",
    "Bot":           "Bot",
    "Brute Force":   "Brute Force",
    "Infilteration": "Infiltration",
    "ransomware":    "Ransomware",
    "mitm":          "Infiltration",
    "Exploits":      "Infiltration",
    "Backdoor":      "Infiltration",
    "Shellcode":     "Infiltration",
    "Fuzzers":       "DoS",
    "Generic":       "DDoS",
    "Worms":         "Bot",
    "Theft":         "Bot",
    "Analysis":      "Port Scan",
    # Legacy labels (other NF-UQ variants)
    "BenignTraffic":          "Benign",
    "DDoS-ACK_Fragmentation": "DDoS",
    "DDoS-HTTP_Flood":        "DDoS",
    "DDoS-ICMP_Flood":        "ICMP Flood",
    "DDoS-ICMP_Fragmentation":"DDoS",
    "DDoS-SlowLoris":         "DoS",
    "DDoS-SYN_Flood":         "DDoS",
    "DDoS-TCP_Flood":         "DDoS",
    "DDoS-UDP_Flood":         "DDoS",
    "DoS-HTTP_Flood":         "DoS",
    "DoS-SYN_Flood":          "DoS",
    "DoS-TCP_Flood":           "DoS",
    "DoS-UDP_Flood":           "DoS",
    "Mirai-UDP_Flood":        "Bot",
    "Mirai-HTTP_Flood":       "Bot",
    "Mirai-greeth_flood":     "Bot",
    "BruteForce-Web":         "Brute Force",
    "BruteForce-XSS":         "XSS",
    "DictionaryBruteForce":   "Brute Force",
    "SqlInjection":            "SQL Injection",
    "Backdoor_Malware":        "Infiltration",
    "CommandInjection":        "Infiltration",
    "MITM-ArpSpoofing":        "Infiltration",
    "Recon-HostDiscovery":     "Port Scan",
    "Recon-OSScan":            "Port Scan",
    "Recon-PortScan":          "Port Scan",
    "VulnerabilityScan":       "Port Scan",
    "Ransomware":              "Ransomware",
    "DNS_Spoofing":            "DNS Tunneling",
}

CICIDS_MAP = {
    # Actual labels in cicids2017_cleaned.csv
    "Normal Traffic": "Benign",
    "DoS":            "DoS",
    "DDoS":           "DDoS",
    "Port Scanning":  "Port Scan",
    "Brute Force":    "Brute Force",
    "Web Attacks":    "XSS",
    "Bots":           "Bot",
    # Original CICIDS2017 raw labels
    "BENIGN":                      "Benign",
    "DoS Hulk":                    "DoS",
    "DoS GoldenEye":               "DoS",
    "DoS slowloris":               "DoS",
    "DoS Slowhttptest":            "DoS",
    "Heartbleed":                  "DoS",
    "PortScan":                    "Port Scan",
    "Bot":                         "Bot",
    "FTP-Patator":                 "Brute Force",
    "SSH-Patator":                 "Brute Force",
    "Web Attack - Brute Force":    "Brute Force",
    "Web Attack - XSS":            "XSS",
    "Web Attack - SQL Injection":  "SQL Injection",
    "Infiltration":                "Infiltration",
}

ALLOWED = {
    "Benign", "DDoS", "DoS", "Port Scan", "Bot", "Brute Force", "XSS",
}

MITRE = {
    "Benign":        {"technique":"N/A",        "tactic":"N/A",               "severity":"Informational","description":"Normal network traffic."},
    "DDoS":          {"technique":"T1498",       "tactic":"Impact",            "severity":"High",         "description":"Volumetric DDoS flood."},
    "DoS":           {"technique":"T1499",       "tactic":"Impact",            "severity":"High",         "description":"Application-layer DoS."},
    "Port Scan":     {"technique":"T1046",       "tactic":"Discovery",         "severity":"Medium",       "description":"Network port enumeration."},
    "Bot":           {"technique":"T1071",       "tactic":"Command and Control","severity":"High",        "description":"Botnet C2 communication."},
    "Brute Force":   {"technique":"T1110",       "tactic":"Credential Access", "severity":"High",         "description":"Credential brute force attack."},
    "SQL Injection": {"technique":"T1190",       "tactic":"Initial Access",    "severity":"Critical",     "description":"SQL injection exploitation."},
    "XSS":           {"technique":"T1059.007",   "tactic":"Execution",         "severity":"High",         "description":"Cross-site scripting attack."},
    "Infiltration":  {"technique":"T1133",       "tactic":"Initial Access",    "severity":"Critical",     "description":"System infiltration / backdoor."},
    "Ransomware":    {"technique":"T1486",       "tactic":"Impact",            "severity":"Critical",     "description":"Ransomware data encryption."},
    "DNS Tunneling": {"technique":"T1071.004",   "tactic":"Command and Control","severity":"High",        "description":"DNS-based covert channel."},
    "ICMP Flood":    {"technique":"T1498.001",   "tactic":"Impact",            "severity":"Medium",       "description":"ICMP ping flood."},
    "Unknown":       {"technique":"Unknown",     "tactic":"Unknown",           "severity":"Low",          "description":"Out-of-distribution traffic."},
}


# ── Loaders ───────────────────────────────────────────────────────────────────
def load_nfuq(path, sample=150_000, seed=42, chunksize=100_000):
    log.info("Loading NF-UQ-NIDS-v2 in chunks (chunksize=%d) ...", chunksize)
    drop_cols = ["IPV4_SRC_ADDR","IPV4_DST_ADDR","L4_SRC_PORT",
                 "L4_DST_PORT","Attack","Dataset"]
    frames = []
    total = 0
    for i, chunk in enumerate(pd.read_csv(path, low_memory=False, chunksize=chunksize)):
        chunk["Label"] = chunk["Attack"].map(NFUQ_MAP)
        chunk = chunk[chunk["Label"].isin(ALLOWED)]
        drop = [c for c in drop_cols if c in chunk.columns]
        chunk = chunk.drop(columns=drop)
        num = chunk.select_dtypes(include=[np.number]).columns.tolist()
        chunk[num] = chunk[num].replace([np.inf,-np.inf], np.nan)
        chunk = chunk.dropna(subset=num)[num + ["Label"]]
        # sample 5000 per chunk to limit RAM
        if len(chunk) > 5000:
            chunk = chunk.sample(n=5000, random_state=seed+i)
        frames.append(chunk)
        total += len(chunk)
        if (i+1) % 5 == 0:
            log.info("  chunk %d done — collected %d rows so far", i+1, total)
    df = pd.concat(frames, ignore_index=True)
    log.info("NF-UQ shape: %s | classes: %s", df.shape, sorted(df["Label"].unique()))
    return _sample(df, sample, seed)


def load_cicids(path, sample=50_000, seed=42):
    log.info("Loading CICIDS2017 ...")
    df = pd.read_csv(path, low_memory=False)
    df.columns = df.columns.str.strip()
    label_col = "Attack Type" if "Attack Type" in df.columns else "Label"
    df["Label"] = df[label_col].map(CICIDS_MAP)
    df = df[df["Label"].isin(ALLOWED)]
    if label_col != "Label":
        df = df.drop(columns=[label_col])
    num = df.select_dtypes(include=[np.number]).columns.tolist()
    df[num] = df[num].replace([np.inf,-np.inf], np.nan)
    df = df.dropna(subset=num)[num + ["Label"]]
    log.info("CICIDS shape: %s | classes: %s", df.shape, sorted(df["Label"].unique()))
    return _sample(df, sample, seed)


def _sample(df, n, seed):
    parts = []
    for _, g in df.groupby("Label"):
        parts.append(g.sample(n=min(len(g), n), random_state=seed))
    return pd.concat(parts).sample(frac=1, random_state=seed).reset_index(drop=True)


# ── Training ──────────────────────────────────────────────────────────────────
def train_model(df, seed=42):
    X = df.drop(columns=["Label"])
    y = df["Label"]
    feature_names = X.columns.tolist()
    log.info("Features: %d | Samples: %d", len(feature_names), len(df))
    log.info("Class distribution:\n%s", y.value_counts().to_string())

    # Final safety clean — catches any inf that survived per-dataset cleaning or appeared during merge.
    # Clip to 1e12 so StandardScaler doesn't overflow when squaring large network counters.
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0).clip(lower=-1e12, upper=1e12)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=seed)

    le = LabelEncoder()
    y_tr = le.fit_transform(y_train)
    y_te = le.transform(y_test)

    sc = StandardScaler()
    Xtr = sc.fit_transform(X_train)
    Xte = sc.transform(X_test)

    sample_weights = compute_sample_weight("balanced", y_tr)

    log.info("Training XGBoost (%d classes) ...", len(le.classes_))
    t0 = time.time()
    xgb = XGBClassifier(n_estimators=300, max_depth=10, learning_rate=0.08,
                         eval_metric="mlogloss",
                         n_jobs=-1, random_state=seed, subsample=0.9, colsample_bytree=0.9)
    xgb.fit(Xtr, y_tr, sample_weight=sample_weights)
    log.info("XGBoost done in %.0fs", time.time()-t0)

    log.info("Training LightGBM ...")
    t0 = time.time()
    lgbm = LGBMClassifier(n_estimators=250, num_leaves=63, learning_rate=0.07,
                           class_weight="balanced",
                           n_jobs=-1, random_state=seed, verbose=-1)
    lgbm.fit(Xtr, y_tr)
    log.info("LightGBM done in %.0fs", time.time()-t0)

    log.info("Training IsolationForest ...")
    iso = IsolationForest(n_estimators=100, contamination=0.05,
                          random_state=seed, n_jobs=-1)
    iso.fit(Xtr)

    proba = (xgb.predict_proba(Xte) + lgbm.predict_proba(Xte)) / 2
    y_pred = proba.argmax(axis=1)
    acc = accuracy_score(y_te, y_pred)
    f1  = f1_score(y_te, y_pred, average="macro", zero_division=0)
    rep = classification_report(y_te, y_pred, target_names=le.classes_,
                                 zero_division=0, digits=4)
    log.info("Accuracy=%.4f  F1-macro=%.4f", acc, f1)
    log.info("\n%s", rep)

    return xgb, lgbm, iso, le, sc, feature_names, {
        "accuracy": float(acc), "f1_macro": float(f1),
        "labels": list(le.classes_), "report": rep,
    }


# ── Save ──────────────────────────────────────────────────────────────────────
def save_artifacts(xgb, lgbm, iso, le, sc, fn, metrics):
    OUT.mkdir(exist_ok=True)
    for name, obj in {"xgb.pkl":xgb,"lgbm.pkl":lgbm,"iso.pkl":iso,
                       "label_encoder.pkl":le,"scaler.pkl":sc,
                       "feature_names.pkl":fn}.items():
        with open(OUT/name,"wb") as f:
            pickle.dump(obj, f)
    with open(OUT/"mitre_mapping.json","w") as f:
        json.dump(MITRE, f, indent=2, ensure_ascii=False)
    with open(OUT/"metrics.json","w") as f:
        json.dump({k:v for k,v in metrics.items() if k!="report"}, f, indent=2)
    with open(OUT/"classification_report.txt","w") as f:
        f.write(metrics["report"])
    log.info("✓ Artifacts saved → %s", OUT)


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Train on CICIDS only — its 52 CICFlowMeter features match what pcap_to_features.py
    # generates at inference time. NF-UQ uses NetFlow v9 features that would always be
    # zero in production, causing severe feature mismatch.
    cicids_path = DATA / "cicids2017/cicids2017_cleaned.csv"
    if not cicids_path.exists():
        raise RuntimeError(f"CICIDS2017 not found: {cicids_path}")

    combined = load_cicids(cicids_path, sample=300_000)

    log.info("Final dataset: %s rows | %s features",
             len(combined), len(combined.columns)-1)

    xgb, lgbm, iso, le, sc, fn, metrics = train_model(combined)
    save_artifacts(xgb, lgbm, iso, le, sc, fn, metrics)

    log.info("=" * 60)
    log.info("Training complete!")
    log.info("Classes: %s", metrics["labels"])
    log.info("F1-macro: %.4f", metrics["f1_macro"])
    log.info("Artifacts: %s", OUT)
